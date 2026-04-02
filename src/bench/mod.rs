use ark_ff::{Fp64, Fp128, MontBackend};
use ark_ff_macros::MontConfig;

/// 128-bit Mersenne prime field
#[derive(MontConfig)]
#[modulus = "170141183460469231731687303715884105727"] // 2^127 - 1
#[generator = "3"]
pub struct Fq128Config;

/// 128-bit Mersenne prime field type
pub type Mersenne128Fq = Fp128<MontBackend<Fq128Config, 2>>;

/// 128-bit default SPDZ prime field
#[derive(MontConfig)]
#[modulus = "170141183460469231731687303715885907969"]
#[generator = "3"]
pub struct Fq128SPDZConfig;

/// 128-bit default SPDZ prime field type
pub type SPDZ128Fq = Fp128<MontBackend<Fq128SPDZConfig, 2>>;

/// 64-bit Mersenne prime field
#[derive(MontConfig)]
#[modulus = "2305843009213693951"] // 2^61 - 1
#[generator = "7"]
pub struct Fq64Config;

/// 64-bit Mersenne prime field type
pub type Mersenne64Fq = Fp64<MontBackend<Fq64Config, 1>>;

/// Get the parties info from the environment variables
pub fn get_parties_info() -> (bool, usize, String) {
    let alone = std::env::var("ALONE")
        .map(|v| !(v == "false"))
        .unwrap_or(true);
    let rank: usize = std::env::var("RANK")
            .ok()
            .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let ip_file = std::env::var("IP_FILE")
        .unwrap_or_else(|_| "parties.txt".to_string());

    return (alone, rank, ip_file);
}

#[cfg(any(test, feature = "bench"))]
mod bench_impl {
    use rand::Rng;

    use crate::arithcircop::ArithCircOp;
    use crate::arithcircop::vector_input::VectorInput;
    use crate::arithcircprep::ArithCircPrep;
    use crate::arithcircprep::spdz::SPDZArithCircPrep;
    use crate::arithpermcircop::ArithPermCircOp;
    use crate::arithpermcircop::exec_blind_auth_check::ExecBlindAuthCheck;
    use crate::arithpermcircop::perm_network_shuffle::PermNetworkShuffle;
    use crate::arithpermcircop::shuffle::Shuffle;
    use crate::arithpermcircop::simple_perm_net_shuffle::SimplePermNetShuffle;
    use crate::arithpermcircop::sort::Sort;
    use crate::arithpermcircprep::perm_network::PermNetworkArithPermCircPrep;
    use crate::arithpermcircprep::simple_perm_network::SimplePermNetworkArithPermCircPrep;
    use crate::arithpermcircprep::{ArithPermCircPrep, ShuffleTupleInput};
    use crate::bench::get_parties_info;
    use crate::net::Net;
    use crate::primitives::auth::AuthShare;
    use crate::utils::conversion_utils::{get_number_bits, usize_to_bits};
    use crate::utils::rng_utils::{get_random_permutation_usize, get_random_vector_bounded_usize};
    use crate::utils::testing_utils::generate_random_auth_shares;
    use crate::{
        arithcircprep::dummy::DummyArithCircPrep, arithpermcircprep::dummy::DummyArithPermCircPrep,
    };

    use std::collections::HashMap;
    use std::fs::File;
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::sync::{Arc, Mutex};
    use std::time::Instant;
    use tempfile::NamedTempFile;
    type Fr128 = crate::bench::SPDZ128Fq;
    type Fr64 = crate::bench::SPDZ128Fq;

    fn shuffle_with_simple_perm_network(
        exp: u32,
        dummy: bool,
        bench: &str,
    ) -> (String, String, String, String, String, String) {
        let n = 2_usize.pow(exp);

        let num_auth_triples = 3 * ((n as f64).log2() as usize + 1) * n;
        let num_auth_coins = ((n as f64).log2() as usize + 1) * n + 2 * n;
        dbg!("number of triples", num_auth_triples);
        dbg!("number of coins", num_auth_coins);

        let num_auth_triples_dummy = 10 * n * ((n as f64).log2() as usize + 1);
        let num_auth_coins_dummy = 10 * n * ((n as f64).log2() as usize + 1);

        let shuffle_input = get_random_permutation_usize(n);

        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        let perm_network_shuffle_times = Arc::new(Mutex::new(Vec::<(
            String,
            String,
            String,
            String,
            String,
            String,
        )>::new()));

        let (alone, rank, ip_file) = get_parties_info();
        if !alone {
            let mut net = Net::init_from_file(&ip_file, rank);
            dbg!("doing remote: {}", net.get_party_ip(), rank);
            let time_start = Instant::now();
                let mut state = if dummy {
                    DummyArithCircPrep::<Fr128>::new().run(
                        &mut net,
                        0,
                        num_auth_coins_dummy,
                        0,
                        num_auth_triples_dummy,
                        0,
                    )
                } else {
                    SPDZArithCircPrep::<Fr128>::new().run(
                        &mut net,
                        0,
                        num_auth_coins,
                        0,
                        num_auth_triples,
                        0,
                    )
                };

                let party_auth_shares = generate_random_auth_shares(&mut state, n);

                // Generate arithmetic permutation circuit state with shuffle tuples
                let mut arith_perm_circ_state = DummyArithPermCircPrep::<Fr128>::new().run(&mut net, &mut state, vec![]);

                let spdz_prep_time = time_start.elapsed();

            

                let comm_recv = net.stats().bytes_recv;
                let comm_sent = net.stats().bytes_sent;

                let start_online_time = Instant::now();
                SimplePermNetShuffle::<Fr128>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    (
                        if rank == 0 { Some(shuffle_input.clone()) } else { None },
                        party_auth_shares.clone(),
                        false,
                    ),
                );

                // Executing the batched auths should pass
                ExecBlindAuthCheck::<Fr128>::run(&mut net, &mut arith_perm_circ_state, ());

                let total_offline_time = spdz_prep_time;
                let total_online_time = start_online_time.elapsed();
                let total_time = time_start.elapsed();

                let online_comm_sent = net.stats().bytes_sent - comm_sent;
                let online_comm_recv = net.stats().bytes_recv - comm_recv;

                let sent_bytes = match bench {
                    "offline" => comm_sent,
                    "online" => online_comm_sent,
                    "full" => net.stats().bytes_sent,
                    _ => unreachable!(),
                };

                let recv_bytes = match bench {
                    "offline" => comm_recv,
                    "online" => online_comm_recv,
                    "full" => net.stats().bytes_recv,
                    _ => unreachable!(),
                };

               return (
                    format!("{:.4}", spdz_prep_time.as_micros() as f64 / 1000000.0),
                    format!("{:.4}", total_offline_time.as_micros() as f64 / 1000000.0),
                    format!("{:.4}", total_online_time.as_micros() as f64 / 1000000.0),
                    format!("{:.4}", total_time.as_micros() as f64 / 1000000.0),
                    sent_bytes.to_string(),
                    recv_bytes.to_string(),
                );
        }

        // Shared state to collect outputs
        rayon::scope(|s| {
            let perm_network_shuffle_times_clone = perm_network_shuffle_times.clone();
            // party 0
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 0);

                let time_start = Instant::now();
                let mut state = if dummy {
                    DummyArithCircPrep::<Fr128>::new().run(
                        &mut net,
                        0,
                        num_auth_coins_dummy,
                        0,
                        num_auth_triples_dummy,
                        0,
                    )
                } else {
                    SPDZArithCircPrep::<Fr128>::new().run(
                        &mut net,
                        0,
                        num_auth_coins,
                        0,
                        num_auth_triples,
                        0,
                    )
                };

                let party0_auth_shares = generate_random_auth_shares(&mut state, n);

                // Generate arithmetic permutation circuit state with shuffle tuples
                let mut arith_perm_circ_state = DummyArithPermCircPrep::<Fr128>::new().run(&mut net, &mut state, vec![]);

                let spdz_prep_time = time_start.elapsed();


                let comm_recv = net.stats().bytes_recv;
                let comm_sent = net.stats().bytes_sent;

                let start_online_time = Instant::now();
                SimplePermNetShuffle::<Fr128>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    (
                        Some(shuffle_input.clone()),
                        party0_auth_shares.clone(),
                        false,
                    ),
                );

                // Executing the batched auths should pass
                ExecBlindAuthCheck::<Fr128>::run(&mut net, &mut arith_perm_circ_state, ());

                let total_offline_time = spdz_prep_time;
                let total_online_time = start_online_time.elapsed();
                let total_time = time_start.elapsed();

                let online_comm_sent = net.stats().bytes_sent - comm_sent;
                let online_comm_recv = net.stats().bytes_recv - comm_recv;

                let sent_bytes = match bench {
                    "offline" => comm_sent,
                    "online" => online_comm_sent,
                    "full" => net.stats().bytes_sent,
                    _ => unreachable!(),
                };

                let recv_bytes = match bench {
                    "offline" => comm_recv,
                    "online" => online_comm_recv,
                    "full" => net.stats().bytes_recv,
                    _ => unreachable!(),
                };

                perm_network_shuffle_times_clone.lock().unwrap().push((
                    format!("{:.4}", spdz_prep_time.as_micros() as f64 / 1000000.0),
                    format!("{:.4}", total_offline_time.as_micros() as f64 / 1000000.0),
                    format!("{:.4}", total_online_time.as_micros() as f64 / 1000000.0),
                    format!("{:.4}", total_time.as_micros() as f64 / 1000000.0),
                    sent_bytes.to_string(),
                    recv_bytes.to_string(),
                ));
            });

            // party 1
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);

                let mut state = if dummy {
                    DummyArithCircPrep::<Fr128>::new().run(
                        &mut net,
                        0,
                        num_auth_coins_dummy,
                        0,
                        num_auth_triples_dummy,
                        0,
                    )
                } else {
                    SPDZArithCircPrep::<Fr128>::new().run(
                        &mut net,
                        0,
                        num_auth_coins,
                        0,
                        num_auth_triples,
                        0,
                    )
                };

                let party1_auth_shares = generate_random_auth_shares(&mut state, n);

                // Generate arithmetic permutation circuit state with shuffle tuples

                let mut arith_perm_circ_state = DummyArithPermCircPrep::<Fr128>::new().run(&mut net, &mut state, vec![]);

                SimplePermNetShuffle::<Fr128>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    (None, party1_auth_shares.clone(), false),
                );

                // Executing the batched auths should pass
                ExecBlindAuthCheck::<Fr128>::run(&mut net, &mut arith_perm_circ_state, ());
            });
        });

        perm_network_shuffle_times.lock().unwrap().pop().unwrap()
    }

    fn shuffle_with_perm_network(
        exp: u32,
        dummy: bool,
        bench: &str,
    ) -> (String, String, String, String, String, String) {
        let n = 2_usize.pow(exp);

        let num_auth_triples = 9 * ((n as f64).log2() as usize + 1) * n;
        let num_auth_coins = 9 * ((n as f64).log2() as usize + 1) * n;
        dbg!("number of triples", num_auth_triples);
        dbg!("number of coins", num_auth_coins);

        let num_auth_triples_dummy = 10 * n * ((n as f64).log2() as usize + 1);
        let num_auth_coins_dummy = 10 * n * ((n as f64).log2() as usize + 1);

        let shuffle_input = get_random_permutation_usize(n);

        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        let perm_network_shuffle_times = Arc::new(Mutex::new(Vec::<(
            String,
            String,
            String,
            String,
            String,
            String,
        )>::new()));

        let (alone, rank, ip_file) = get_parties_info();
        if !alone {
            let mut net = Net::init_from_file(&ip_file, rank);
            dbg!("doing remote: {}", net.get_party_ip(), rank);
            let time_start = Instant::now();
                let mut state = if dummy {
                    DummyArithCircPrep::<Fr128>::new().run(
                        &mut net,
                        0,
                        num_auth_coins_dummy,
                        0,
                        num_auth_triples_dummy,
                        0,
                    )
                } else {
                    SPDZArithCircPrep::<Fr128>::new().run(
                        &mut net,
                        0,
                        num_auth_coins,
                        0,
                        num_auth_triples,
                        0,
                    )
                };

                let party_auth_shares = generate_random_auth_shares(&mut state, n);

                // Generate arithmetic permutation circuit state with shuffle tuples
                let mut arith_perm_circ_state = if dummy {
                    DummyArithPermCircPrep::<Fr128>::new().run(&mut net, &mut state, vec![])
                } else {
                    PermNetworkArithPermCircPrep::<Fr128>::new().run(&mut net, &mut state, vec![])
                };

                let spdz_prep_time = time_start.elapsed();

                let mut offline_time_duration = std::time::Duration::ZERO;
                let mut online_time_duration = std::time::Duration::ZERO;
                let mut offline_bandwidth_total = (0_usize, 0_usize);
                let mut online_bandwidth_total = (0_usize, 0_usize);

                let comm_recv = net.stats().bytes_recv;
                let comm_sent = net.stats().bytes_sent;

                PermNetworkShuffle::<Fr128>::run_with_timing(
                    &mut net,
                    &mut arith_perm_circ_state,
                    (
                        if rank == 0 { Some(shuffle_input.clone()) } else { None },
                        party_auth_shares.clone(),
                        false,
                    ),
                    &mut |offline_time, online_time, offline_bandwidth, online_bandwidth| {
                        offline_time_duration += offline_time;
                        online_time_duration += online_time;
                        offline_bandwidth_total = (
                            offline_bandwidth_total.0 + offline_bandwidth.0,
                            offline_bandwidth_total.1 + offline_bandwidth.1,
                        );
                        online_bandwidth_total = (
                            online_bandwidth_total.0 + online_bandwidth.0,
                            online_bandwidth_total.1 + online_bandwidth.1,
                        );
                    },
                );

                let start_auth_check_time = Instant::now();
                // Executing the batched auths should pass
                ExecBlindAuthCheck::<Fr128>::run(&mut net, &mut arith_perm_circ_state, ());
                let auth_check_time =
                    start_auth_check_time.elapsed();

                let total_offline_time = spdz_prep_time + offline_time_duration;
                let total_online_time = auth_check_time + online_time_duration;
                let total_time = time_start.elapsed();

                let sent_bytes = match bench {
                    "offline" => comm_sent + offline_bandwidth_total.0,
                    "online" => online_bandwidth_total.0,
                    "full" => net.stats().bytes_sent,
                    _ => unreachable!(),
                };

                let recv_bytes = match bench {
                    "offline" => comm_recv + offline_bandwidth_total.1,
                    "online" => online_bandwidth_total.1,
                    "full" => net.stats().bytes_recv,
                    _ => unreachable!(),
                };

               return (
                    format!("{:.4}", spdz_prep_time.as_micros() as f64 / 1000000.0),
                    format!("{:.4}", total_offline_time.as_micros() as f64 / 1000000.0),
                    format!("{:.4}", total_online_time.as_micros() as f64 / 1000000.0),
                    format!("{:.4}", total_time.as_micros() as f64 / 1000000.0),
                    sent_bytes.to_string(),
                    recv_bytes.to_string(),
                );
        }

        // Shared state to collect outputs
        rayon::scope(|s| {
            let perm_network_shuffle_times_clone = perm_network_shuffle_times.clone();
            // party 0
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 0);

                let time_start = Instant::now();
                let mut state = if dummy {
                    DummyArithCircPrep::<Fr128>::new().run(
                        &mut net,
                        0,
                        num_auth_coins_dummy,
                        0,
                        num_auth_triples_dummy,
                        0,
                    )
                } else {
                    SPDZArithCircPrep::<Fr128>::new().run(
                        &mut net,
                        0,
                        num_auth_coins,
                        0,
                        num_auth_triples,
                        0,
                    )
                };

                let party0_auth_shares = generate_random_auth_shares(&mut state, n);

                // Generate arithmetic permutation circuit state with shuffle tuples
                let mut arith_perm_circ_state = if dummy {
                    DummyArithPermCircPrep::<Fr128>::new().run(&mut net, &mut state, vec![])
                } else {
                    PermNetworkArithPermCircPrep::<Fr128>::new().run(&mut net, &mut state, vec![])
                };

                let spdz_prep_time = time_start.elapsed();

                let mut offline_time_duration = std::time::Duration::ZERO;
                let mut online_time_duration = std::time::Duration::ZERO;
                let mut offline_bandwidth_total = (0_usize, 0_usize);
                let mut online_bandwidth_total = (0_usize, 0_usize);

                let comm_recv = net.stats().bytes_recv;
                let comm_sent = net.stats().bytes_sent;

                PermNetworkShuffle::<Fr128>::run_with_timing(
                    &mut net,
                    &mut arith_perm_circ_state,
                    (
                        Some(shuffle_input.clone()),
                        party0_auth_shares.clone(),
                        false,
                    ),
                    &mut |offline_time, online_time, offline_bandwidth, online_bandwidth| {
                        offline_time_duration += offline_time;
                        online_time_duration += online_time;
                        offline_bandwidth_total = (
                            offline_bandwidth_total.0 + offline_bandwidth.0,
                            offline_bandwidth_total.1 + offline_bandwidth.1,
                        );
                        online_bandwidth_total = (
                            online_bandwidth_total.0 + online_bandwidth.0,
                            online_bandwidth_total.1 + online_bandwidth.1,
                        );
                    },
                );

                let start_auth_check_time = Instant::now();
                // Executing the batched auths should pass
                ExecBlindAuthCheck::<Fr128>::run(&mut net, &mut arith_perm_circ_state, ());
                let auth_check_time =
                    start_auth_check_time.elapsed();

                let total_offline_time = spdz_prep_time + offline_time_duration;
                let total_online_time = auth_check_time + online_time_duration;
                let total_time = time_start.elapsed();

                let sent_bytes = match bench {
                    "offline" => comm_sent + offline_bandwidth_total.0,
                    "online" => online_bandwidth_total.0,
                    "full" => net.stats().bytes_sent,
                    _ => unreachable!(),
                };

                let recv_bytes = match bench {
                    "offline" => comm_recv + offline_bandwidth_total.1,
                    "online" => online_bandwidth_total.1,
                    "full" => net.stats().bytes_recv,
                    _ => unreachable!(),
                };

                perm_network_shuffle_times_clone.lock().unwrap().push((
                    format!("{:.4}", spdz_prep_time.as_micros() as f64 / 1000000.0),
                    format!("{:.4}", total_offline_time.as_micros() as f64 / 1000000.0),
                    format!("{:.4}", total_online_time.as_micros() as f64 / 1000000.0),
                    format!("{:.4}", total_time.as_micros() as f64 / 1000000.0),
                    sent_bytes.to_string(),
                    recv_bytes.to_string(),
                ));
            });

            // party 1
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);

                let mut state = if dummy {
                    DummyArithCircPrep::<Fr128>::new().run(
                        &mut net,
                        0,
                        num_auth_coins_dummy,
                        0,
                        num_auth_triples_dummy,
                        0,
                    )
                } else {
                    SPDZArithCircPrep::<Fr128>::new().run(
                        &mut net,
                        0,
                        num_auth_coins,
                        0,
                        num_auth_triples,
                        0,
                    )
                };

                let party1_auth_shares = generate_random_auth_shares(&mut state, n);

                // Generate arithmetic permutation circuit state with shuffle tuples

                let mut arith_perm_circ_state = if dummy {
                    DummyArithPermCircPrep::<Fr128>::new().run(&mut net, &mut state, vec![])
                } else {
                    PermNetworkArithPermCircPrep::<Fr128>::new().run(&mut net, &mut state, vec![])
                };

                PermNetworkShuffle::<Fr128>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    (None, party1_auth_shares.clone(), false),
                );

                // Executing the batched auths should pass
                ExecBlindAuthCheck::<Fr128>::run(&mut net, &mut arith_perm_circ_state, ());
            });
        });

        perm_network_shuffle_times.lock().unwrap().pop().unwrap()
    }

    fn shuffle_with_floss(
        exp: u32,
        dummy: bool,
    ) -> (String, String, String, String, String, String) {
        let n = 2_usize.pow(exp);
        let num_shuffle_tuples = 1;

        // exp: (triples, coins)
        let _exp_to_prep = HashMap::from([(8 as u32, (9477, 2566)), (9  as u32, (22400,  5800)), (10 as u32, (48133, 12294)), (11 as u32, (109000, 29500)), (12 as u32, (233477, 57350)), 
        (13 as u32, (526000, 130000)), (14 as u32, (1097733, 262150)), (15 as u32, (2455000, 600000)), 
        (16 as u32, (5046277, 1179654)), (18 as u32, (22806533, 5242886)), (20 as u32, (102629398, 23301623))]);
        // let num_auth_triples = 5 * num_shuffle_tuples * ((n as f64).log2() as usize + 1) * n;
        // let num_auth_coins = ((n as f64).log2() as usize + 1) * n + 2 * n;
        let num_auth_triples = if _exp_to_prep.contains_key(&exp) { _exp_to_prep[&exp].0 as usize } else { 5 * num_shuffle_tuples * ((n as f64).log2() as usize + 1) * n };
        let num_auth_coins = if _exp_to_prep.contains_key(&exp) { _exp_to_prep[&exp].1 as usize } else { ((n as f64).log2() as usize + 1) * n + 2 * n };
        
        let on_flag = false;

        // let num_auth_triples_dummy = 5 * n;
        // let num_auth_coins_dummy = 10 * n;
        let num_auth_triples_dummy = num_auth_triples;
        let num_auth_coins_dummy = num_auth_coins;

        // to be inputted
        let shuffle_input = get_random_permutation_usize(n);
        let shuffle_input_clone = shuffle_input.clone();

        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        let (alone, rank, ip_file) = get_parties_info();
        if !alone {
            let mut net = Net::init_from_file(&ip_file, rank);

                let time_start = Instant::now();
                let mut state = if dummy || on_flag {
                    DummyArithCircPrep::<Fr128>::new().run(
                        &mut net,
                        0,
                        num_auth_coins_dummy,
                        0,
                        num_auth_triples_dummy,
                        0,
                    )
                } else {
                    SPDZArithCircPrep::<Fr128>::new().run(
                        &mut net,
                        0,
                        num_auth_coins,
                        0,
                        num_auth_triples,
                        0,
                    )
                };
                let spdz_prep_time = time_start.elapsed();

                let party_auth_shares = generate_random_auth_shares(&mut state, n);

                let shuffle_tuple_input = ShuffleTupleInput {
                    shuffle_id: "shuffle1".to_string(),
                    shuffle: if rank == 0 { Some(shuffle_input_clone) } else { None },
                    n: n,
                    num_shuffle_tuples: num_shuffle_tuples,
                    with_inverse: false,
                };

                // Generate arithmetic permutation circuit state with shuffle tuples
                let mut arith_perm_circ_state = if dummy {
                    DummyArithPermCircPrep::<Fr128>::new().run(
                        &mut net,
                        &mut state,
                        vec![shuffle_tuple_input],
                    )
                } else {
                    SimplePermNetworkArithPermCircPrep::<Fr128>::new().run(
                        &mut net,
                        &mut state,
                        vec![shuffle_tuple_input],
                    )
                };

                // Executing the batched auths should pass
                ExecBlindAuthCheck::<Fr128>::run(&mut net, &mut arith_perm_circ_state, ());

                dbg!("Post-prep bandwidth: ", net.stats().bytes_sent);
                dbg!("Post-prep bandwidth: ", net.stats().bytes_recv);

                let total_offline_time = time_start.elapsed();
                let online_start_time = Instant::now();
                let comm_recv = if dummy { net.stats().bytes_recv } else { 0 };
                let comm_sent = if dummy { net.stats().bytes_sent } else { 0 };
                Shuffle::<Fr128>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    (0, "shuffle1".to_string(), party_auth_shares.clone()),
                );
                dbg!("Got here");

                let pre_auth_check_time = Instant::now();
                ExecBlindAuthCheck::<Fr128>::run(&mut net, &mut arith_perm_circ_state, ());
                let auth_check_time = pre_auth_check_time.elapsed();
                dbg!("Auth check time: ", auth_check_time);

                let total_online_time = online_start_time.elapsed();
                dbg!("Shuffle time: ", total_online_time - auth_check_time);
                let total_time = time_start.elapsed();

                dbg!("triples used: ", arith_perm_circ_state.inner_mut().count_triples_used());
                dbg!("coins used: ", arith_perm_circ_state.inner_mut().count_coins());

                dbg!("Post-shuffle bandwidth: ", net.stats().bytes_sent);
                dbg!("Post-shuffle bandwidth: ", net.stats().bytes_recv);
                return (
                    format!("{:.4}", spdz_prep_time.as_micros() as f64 / 1000000.0),
                    format!("{:.4}", total_offline_time.as_micros() as f64 / 1000000.0),
                    format!("{:.4}", total_online_time.as_micros() as f64 / 1000000.0),
                    format!("{:.4}", total_time.as_micros() as f64 / 1000000.0),
                    (net.stats().bytes_sent - comm_sent).to_string(),
                    (net.stats().bytes_recv - comm_recv).to_string(),
                );
        }

        let shuffle_times = Arc::new(Mutex::new(Vec::<(
            String,
            String,
            String,
            String,
            String,
            String,
        )>::new()));
        // Shared state to collect outputs
        rayon::scope(|s| {
            let shuffle_times_clone = shuffle_times.clone();
            // party 0
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 0);

                let time_start = Instant::now();
                let mut state = if dummy || on_flag {
                    DummyArithCircPrep::<Fr128>::new().run(
                        &mut net,
                        0,
                        num_auth_coins_dummy,
                        0,
                        num_auth_triples_dummy,
                        0,
                    )
                } else {
                    SPDZArithCircPrep::<Fr128>::new().run(
                        &mut net,
                        0,
                        num_auth_coins,
                        0,
                        num_auth_triples,
                        0,
                    )
                };
                let spdz_prep_time = time_start.elapsed();

                let party0_auth_shares = generate_random_auth_shares(&mut state, n);

                let shuffle_tuple_input = ShuffleTupleInput {
                    shuffle_id: "shuffle1".to_string(),
                    shuffle: Some(shuffle_input_clone),
                    n: n,
                    num_shuffle_tuples: num_shuffle_tuples,
                    with_inverse: false,
                };

                // Generate arithmetic permutation circuit state with shuffle tuples
                let mut arith_perm_circ_state = if dummy {
                    DummyArithPermCircPrep::<Fr128>::new().run(
                        &mut net,
                        &mut state,
                        vec![shuffle_tuple_input],
                    )
                } else {
                    SimplePermNetworkArithPermCircPrep::<Fr128>::new().run(
                        &mut net,
                        &mut state,
                        vec![shuffle_tuple_input],
                    )
                };

                // Executing the batched auths should pass
                ExecBlindAuthCheck::<Fr128>::run(&mut net, &mut arith_perm_circ_state, ());

                dbg!("Post-prep bandwidth: ", net.stats().bytes_sent);
                dbg!("Post-prep bandwidth: ", net.stats().bytes_recv);

                let total_offline_time = time_start.elapsed();
                let online_start_time = Instant::now();
                let comm_recv = if dummy { net.stats().bytes_recv } else { 0 };
                let comm_sent = if dummy { net.stats().bytes_sent } else { 0 };
                Shuffle::<Fr128>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    (0, "shuffle1".to_string(), party0_auth_shares.clone()),
                );
                dbg!("Got here");

                let pre_auth_check_time = Instant::now();
                ExecBlindAuthCheck::<Fr128>::run(&mut net, &mut arith_perm_circ_state, ());
                let auth_check_time = pre_auth_check_time.elapsed();
                dbg!("Auth check time: ", auth_check_time);

                let total_online_time = online_start_time.elapsed();
                let total_time = time_start.elapsed();

                dbg!("triples used: ", arith_perm_circ_state.inner_mut().count_triples_used());
                dbg!("coins used: ", arith_perm_circ_state.inner_mut().count_coins());

                dbg!("Post-shuffle bandwidth: ", net.stats().bytes_sent);
                dbg!("Post-shuffle bandwidth: ", net.stats().bytes_recv);
                shuffle_times_clone.lock().unwrap().push((
                    format!("{:.4}", spdz_prep_time.as_micros() as f64 / 1000000.0),
                    format!("{:.4}", total_offline_time.as_micros() as f64 / 1000000.0),
                    format!("{:.4}", total_online_time.as_micros() as f64 / 1000000.0),
                    format!("{:.4}", total_time.as_micros() as f64 / 1000000.0),
                    (net.stats().bytes_sent - comm_sent).to_string(),
                    (net.stats().bytes_recv - comm_recv).to_string(),
                ));
            });

            // party 1
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);

                let mut state = if dummy || on_flag {
                    DummyArithCircPrep::<Fr128>::new().run(
                        &mut net,
                        0,
                        num_auth_coins_dummy,
                        0,
                        num_auth_triples_dummy,
                        0,
                    )
                } else {
                    SPDZArithCircPrep::<Fr128>::new().run(
                        &mut net,
                        0,
                        num_auth_coins,
                        0,
                        num_auth_triples,
                        0,
                    )
                };

                let party1_auth_shares = generate_random_auth_shares(&mut state, n);

                let shuffle_tuple_input = ShuffleTupleInput {
                    shuffle_id: "shuffle1".to_string(),
                    shuffle: None,
                    n: n,
                    num_shuffle_tuples: num_shuffle_tuples,
                    with_inverse: false,
                };

                // Generate arithmetic permutation circuit state with shuffle tuples
                let mut arith_perm_circ_state = if dummy {
                    DummyArithPermCircPrep::<Fr128>::new().run(
                        &mut net,
                        &mut state,
                        vec![shuffle_tuple_input],
                    )
                } else {
                    SimplePermNetworkArithPermCircPrep::<Fr128>::new().run(
                        &mut net,
                        &mut state,
                        vec![shuffle_tuple_input],
                    )
                };

                // Executing the batched auths should pass
                ExecBlindAuthCheck::<Fr128>::run(&mut net, &mut arith_perm_circ_state, ());

                Shuffle::<Fr128>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    (0, "shuffle1".to_string(), party1_auth_shares.clone()),
                );

                ExecBlindAuthCheck::<Fr128>::run(&mut net, &mut arith_perm_circ_state, ());
            });
        });

        shuffle_times.lock().unwrap().pop().unwrap()
    }

    fn sort_with_simple_perm_network(
        key_length: usize,
        record_num: usize,
        dummy: bool,
    ) -> (String, String, String, String, String, String, String) {
        let n = 2_usize.pow(record_num as u32);
        let low = usize::MIN;
        let high = 2_usize.pow(key_length as u32) - 2;
        let num_bits = get_number_bits(high as u64);
        assert_eq!(num_bits, key_length);


        let num_auth_triples = 2 * num_bits * n * ((n as f64).log2() as usize + 1) * ((n as f64).log2() as usize + 2);
        let num_auth_coins = 6 *  num_bits * (((n as f64).log2() as usize + 1) * n + 2 * n);
        dbg!("number of triples", num_auth_triples);
        dbg!("number of coins", num_auth_coins);

    
        // let num_auth_triples_dummy = 5 * num_bits * n * ((n as f64).log2() as usize + 1);
        // let num_auth_coins_dummy = 5 * num_bits * n * ((n as f64).log2() as usize + 1);
        let num_auth_triples_dummy = num_auth_triples;
        let num_auth_coins_dummy = num_auth_coins;

        let random_input =
            get_random_vector_bounded_usize(rand::rng().random_range(0..u64::MAX), low, high, n);
        let random_input_clone: Vec<usize> = random_input.clone();

        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        let (alone, rank, ip_file) = get_parties_info();
        if !alone {
            dbg!(alone, rank);
            let mut net = Net::init_from_file(&ip_file, rank);

            let time_start = Instant::now();
            // Generate arithmetic permutation circuit state with shuffle tuples
            

            let mut state = if dummy {
                DummyArithCircPrep::<Fr64>::new().run(
                    &mut net,
                    0,
                    num_auth_coins_dummy,
                    0,
                    num_auth_triples_dummy,
                    0,
                )
            } else {
                SPDZArithCircPrep::<Fr64>::new().run(
                    &mut net,
                    0,
                    num_auth_coins,
                    0,
                    num_auth_triples,
                    0,
                )
            };
            let spdz_prep_time = time_start.elapsed();

            let mut arith_perm_circ_state =
                DummyArithPermCircPrep::<Fr64>::new().run(&mut net, &mut state, vec![]);

            let preprocessing_time = time_start.elapsed();

            let input_bits = random_input_clone
                .iter()
                .map(|share| usize_to_bits(*share, num_bits))
                .collect::<Vec<Vec<Fr64>>>();

            assert_eq!(input_bits[0].len(), num_bits);

            let input_bits_p0 = (0..input_bits.len())
                .map(|i| {
                    if rank == 0 {
                        VectorInput::<Fr64>::run(
                        &mut net,
                        &mut arith_perm_circ_state.inner_mut(),
                        (0, Some(input_bits[i].clone()), None),
                    )
                    } else {
                        VectorInput::<Fr64>::run(
                            &mut net,
                            &mut arith_perm_circ_state.inner_mut(),
                            (0, None, Some(num_bits)),
                        )
                    }
                })
                .collect::<Vec<Vec<AuthShare<Fr64>>>>();


            let online_start_time = Instant::now();

            let comm_recv = net.stats().bytes_recv;
            let comm_sent = net.stats().bytes_sent;

            let mut shuffle_time_duration_sort = std::time::Duration::ZERO;

            let _sort_output = Sort::run_with_simple_perm_network_timing(
                &mut net,
                &mut arith_perm_circ_state,
                input_bits_p0,
                &mut |shuffle_time| {
                    shuffle_time_duration_sort += shuffle_time;
                },
            );

            let pre_auth_check_time = Instant::now();
            ExecBlindAuthCheck::<Fr64>::run(&mut net, &mut arith_perm_circ_state, ());
            let auth_check_time = pre_auth_check_time.elapsed();
            dbg!("Auth check time (floss sort): ", auth_check_time);

            let total_online_time = online_start_time.elapsed();
            let total_time = time_start.elapsed();

            dbg!("(triples, coins) used: ", (arith_perm_circ_state.inner_mut().count_triples_used(), arith_perm_circ_state.inner_mut().count_coins()));

            return (
                format!("{:.4}", spdz_prep_time.as_micros() as f64 / 1000000.0),
                format!("{:.4}", preprocessing_time.as_micros() as f64 / 1000000.0),
                format!(
                    "{:.4}",
                    (shuffle_time_duration_sort).as_micros() as f64 / 1000000.0
                ),
                format!("{:.4}", total_online_time.as_micros() as f64 / 1000000.0),
                format!("{:.4}", total_time.as_micros() as f64 / 1000000.0),
                (net.stats().bytes_sent - comm_sent).to_string(),
                (net.stats().bytes_recv - comm_recv).to_string(),
            );
        }

        // Shared state to collect outputs
        let sort_times = Arc::new(Mutex::new(Vec::<(
            String,
            String,
            String,
            String,
            String,
            String,
            String,
        )>::new()));

        rayon::scope(|s| {
            let sort_times_clone = sort_times.clone();

            // party 0
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 0);

                let time_start = Instant::now();
                // Generate arithmetic permutation circuit state with shuffle tuples
               
                let mut state = 
                    DummyArithCircPrep::<Fr64>::new().run(
                        &mut net,
                        0,
                        num_auth_coins_dummy,
                        0,
                        num_auth_triples_dummy,
                        0,
                    );
                
                let spdz_prep_time = time_start.elapsed();

                let mut arith_perm_circ_state =
                    DummyArithPermCircPrep::<Fr64>::new().run(&mut net, &mut state, vec![]);

                let preprocessing_time = time_start.elapsed();

                let input_bits = random_input_clone
                    .iter()
                    .map(|share| usize_to_bits(*share, num_bits))
                    .collect::<Vec<Vec<Fr64>>>();

                assert_eq!(input_bits[0].len(), num_bits);

                let input_bits_p0 = (0..input_bits.len())
                    .map(|i| {
                        VectorInput::<Fr64>::run(
                            &mut net,
                            &mut arith_perm_circ_state.inner_mut(),
                            (0, Some(input_bits[i].clone()), None),
                        )
                    })
                    .collect::<Vec<Vec<AuthShare<Fr64>>>>();


                let online_start_time = Instant::now();

                let comm_recv = net.stats().bytes_recv;
                let comm_sent = net.stats().bytes_sent;

                let mut shuffle_time_duration_sort = std::time::Duration::ZERO;

                let _sort_output = Sort::run_with_simple_perm_network_timing(
                    &mut net,
                    &mut arith_perm_circ_state,
                    input_bits_p0,
                    &mut |shuffle_time| {
                        shuffle_time_duration_sort += shuffle_time;
                    },
                );

                let pre_auth_check_time = Instant::now();
                ExecBlindAuthCheck::<Fr64>::run(&mut net, &mut arith_perm_circ_state, ());
                let auth_check_time = pre_auth_check_time.elapsed();
                dbg!("Auth check time (floss sort): ", auth_check_time);

                let total_online_time = online_start_time.elapsed();
                let total_time = time_start.elapsed();

                dbg!("(triples, coins) used: ", (arith_perm_circ_state.inner_mut().count_triples_used(), arith_perm_circ_state.inner_mut().count_coins()));

                sort_times_clone.lock().unwrap().push((
                    format!("{:.4}", spdz_prep_time.as_micros() as f64 / 1000000.0),
                    format!("{:.4}", preprocessing_time.as_micros() as f64 / 1000000.0),
                    format!(
                        "{:.4}",
                        (shuffle_time_duration_sort).as_micros() as f64 / 1000000.0
                    ),
                    format!("{:.4}", total_online_time.as_micros() as f64 / 1000000.0),
                    format!("{:.4}", total_time.as_micros() as f64 / 1000000.0),
                    (net.stats().bytes_sent - comm_sent).to_string(),
                    (net.stats().bytes_recv - comm_recv).to_string(),
                ));
            });

            // party 1
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);

                dbg!("start circ prep");
                let mut state = 
                    DummyArithCircPrep::<Fr64>::new().run(&mut net, 0, num_auth_coins_dummy, 0, num_auth_triples_dummy, 0);
                dbg!("end circ prep");


                dbg!("start shuffle tuple prep");
                let mut arith_perm_circ_state =
                    DummyArithPermCircPrep::<Fr64>::new().run(&mut net, &mut state, vec![]);

                dbg!("end shuffle tuple prep");

                dbg!("start input bits prep");
                let input_bits_p1 = (0..n)
                    .map(|_| {
                        VectorInput::<Fr64>::run(
                            &mut net,
                            &mut arith_perm_circ_state.inner_mut(),
                            (0, None, Some(num_bits)),
                        )
                    })
                    .collect::<Vec<Vec<AuthShare<Fr64>>>>();
                dbg!("end input bits prep");

                dbg!("start sort");
                let mut shuffle_time_duration_sort = std::time::Duration::ZERO;
                let _sort_output = Sort::run_with_simple_perm_network_timing(
                    &mut net,
                    &mut arith_perm_circ_state,
                    input_bits_p1,
                    &mut |shuffle_time| {
                        shuffle_time_duration_sort += shuffle_time;
                    },
                );

                dbg!("end sort");

                ExecBlindAuthCheck::<Fr64>::run(&mut net, &mut arith_perm_circ_state, ());
            });
        });

        sort_times.lock().unwrap().pop().unwrap()
    }

    fn sort_with_floss(
        key_length: usize,
        record_num: usize,
        dummy: bool,
    ) -> (String, String, String, String, String, String, String) {
        let n = 2_usize.pow(record_num as u32);
        let low = usize::MIN;
        let high = 2_usize.pow(key_length as u32) - 2;
        let num_bits = get_number_bits(high as u64);
        assert_eq!(num_bits, key_length);

        let _exp_to_prep = HashMap::from([(8, (4409600_u32, 672960_u32)), (9, (9996544_u32, 1475776_u32)), (10, (22350080_u32, 3212480_u32)), (11, (49416448_u32, 6948032_u32)), (12, (109160698_u32, 15027377_u32)),  (13, (241356361_u32,  32501587_u32)),
            (14, (533643460_u32,  70295244_u32)),
            (15, (1179895745_u32, 152036308_u32)),
            (16, (2608771723_u32, 328827925_u32)),
        ]);
        let on_flag = false;
        // let num_auth_triples =
        //     20 * num_bits * ((n as f64).log2() as usize + 1) * ((n as f64).log2() as usize + 1) * n;
        // let num_auth_coins =
        //     15 * num_bits * ((n as f64).log2() as usize + 1) * ((n as f64).log2() as usize + 1) * n;

        let num_auth_triples = if _exp_to_prep.contains_key(&record_num) { _exp_to_prep[&record_num].0 as usize } else { 20 * num_bits * ((n as f64).log2() as usize + 1) * ((n as f64).log2() as usize + 1) * n };
        let num_auth_coins = if _exp_to_prep.contains_key(&record_num) { _exp_to_prep[&record_num].1 as usize } else { 15 * num_bits * ((n as f64).log2() as usize + 1) * ((n as f64).log2() as usize + 1) * n };

        // let num_auth_triples = 5 * num_bits * n * ((n as f64).log2() as usize + 1) * ((n as f64).log2() as usize + 2);
        // let num_auth_coins = 4 *  num_bits * (((n as f64).log2() as usize + 1) * n + 2 * n);

        // let num_auth_triples_dummy = 5 * num_bits * n * ((n as f64).log2() as usize + 1);
        // let num_auth_coins_dummy = 5 * num_bits * n * ((n as f64).log2() as usize + 1);
        let num_auth_triples_dummy = num_auth_triples;
        let num_auth_coins_dummy = num_auth_coins;

        // to be inputted
        let random_shuffles_a_p0 = (0..num_bits)
            .map(|_| get_random_permutation_usize(n))
            .collect::<Vec<Vec<usize>>>();
        let random_shuffles_b_p0 = (0..num_bits)
            .map(|_| get_random_permutation_usize(n))
            .collect::<Vec<Vec<usize>>>();
        let random_shuffles_a_p1 = (0..num_bits)
            .map(|_| get_random_permutation_usize(n))
            .collect::<Vec<Vec<usize>>>();
        let random_shuffles_b_p1 = (0..num_bits)
            .map(|_| get_random_permutation_usize(n))
            .collect::<Vec<Vec<usize>>>();

      
        let random_input =
            get_random_vector_bounded_usize(rand::rng().random_range(0..u64::MAX), low, high, n);
        let random_input_clone: Vec<usize> = random_input.clone();

        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        let (alone, rank, ip_file) = get_parties_info();
        if !alone {
            dbg!(alone, rank);
            let mut net = Net::init_from_file(&ip_file, rank);

            let time_start = Instant::now();
            // Generate arithmetic permutation circuit state with shuffle tuples
            let shuffle_tuples_a_p0 = (0..num_bits)
                .map(|j| ShuffleTupleInput {
                    shuffle_id: "random_shuffle_A_p0_".to_string() + &j.to_string(),
                    shuffle: if rank == 0 { Some(random_shuffles_a_p0[j].clone()) } else { None },
                    n: n,
                    num_shuffle_tuples: 2,
                    with_inverse: false,
                })
                .collect::<Vec<ShuffleTupleInput>>();
            let shuffle_tuples_b_p0 = (0..num_bits)
                .map(|j| ShuffleTupleInput {
                    shuffle_id: "random_shuffle_B_p0_".to_string() + &j.to_string(),
                    shuffle: if rank == 0 { Some(random_shuffles_b_p0[j].clone()) } else { None },
                    n: n,
                    num_shuffle_tuples: 1,
                    with_inverse: true,
                })
                .collect::<Vec<ShuffleTupleInput>>();
            let shuffle_tuples_a_p1 = (0..num_bits)
                .map(|j| ShuffleTupleInput {
                    shuffle_id: "random_shuffle_A_p1_".to_string() + &j.to_string(),
                    shuffle: if rank == 0 { None } else { Some(random_shuffles_a_p1[j].clone()) },
                    n: n,
                    num_shuffle_tuples: 2,
                    with_inverse: false,
                })
                .collect::<Vec<ShuffleTupleInput>>();
            let shuffle_tuples_b_p1 = (0..num_bits)
                .map(|j| ShuffleTupleInput {
                    shuffle_id: "random_shuffle_B_p1_".to_string() + &j.to_string(),
                    shuffle: if rank == 0 { None } else { Some(random_shuffles_b_p1[j].clone()) },
                    n: n,
                    num_shuffle_tuples: 1,
                    with_inverse: true,
                })
                .collect::<Vec<ShuffleTupleInput>>();

            let shuffle_tuples = shuffle_tuples_a_p0
                .into_iter()
                .chain(shuffle_tuples_b_p0.into_iter())
                .chain(shuffle_tuples_a_p1.into_iter())
                .chain(shuffle_tuples_b_p1.into_iter())
                .collect::<Vec<ShuffleTupleInput>>();

            let mut state = if dummy || on_flag {
                DummyArithCircPrep::<Fr64>::new().run(
                    &mut net,
                    0,
                    num_auth_coins_dummy,
                    0,
                    num_auth_triples_dummy,
                    0,
                )
            } else {
                SPDZArithCircPrep::<Fr64>::new().run(
                    &mut net,
                    0,
                    num_auth_coins,
                    0,
                    num_auth_triples,
                    0,
                )
            };
            let spdz_prep_time = time_start.elapsed();

            let mut arith_perm_circ_state = if dummy {
                DummyArithPermCircPrep::<Fr64>::new().run(&mut net, &mut state, shuffle_tuples)
            } else {
                SimplePermNetworkArithPermCircPrep::<Fr64>::new().run(
                    &mut net,
                    &mut state,
                    shuffle_tuples,
                )
            };

            let preprocessing_time = time_start.elapsed();

            let input_bits = random_input_clone
                .iter()
                .map(|share| usize_to_bits(*share, num_bits))
                .collect::<Vec<Vec<Fr64>>>();

            assert_eq!(input_bits[0].len(), num_bits);

            let input_bits_p0 = (0..input_bits.len())
                .map(|i| {
                    if rank == 0 {
                        VectorInput::<Fr64>::run(
                        &mut net,
                        &mut arith_perm_circ_state.inner_mut(),
                        (0, Some(input_bits[i].clone()), None),
                    )
                    } else {
                        VectorInput::<Fr64>::run(
                            &mut net,
                            &mut arith_perm_circ_state.inner_mut(),
                            (0, None, Some(num_bits)),
                        )
                    }
                })
                .collect::<Vec<Vec<AuthShare<Fr64>>>>();


            let online_start_time = Instant::now();

            let comm_recv = if dummy { net.stats().bytes_recv } else { 0 };
            let comm_sent = if dummy { net.stats().bytes_sent } else { 0 };

            let mut shuffle_time_duration_sort = std::time::Duration::ZERO;

            let _sort_output = Sort::run_with_floss_timing(
                &mut net,
                &mut arith_perm_circ_state,
                input_bits_p0,
                &mut |shuffle_time| {
                    shuffle_time_duration_sort += shuffle_time;
                },
            );

            let pre_auth_check_time = Instant::now();
            ExecBlindAuthCheck::<Fr64>::run(&mut net, &mut arith_perm_circ_state, ());
            let auth_check_time = pre_auth_check_time.elapsed();
            dbg!("Auth check time (floss sort): ", auth_check_time);

            let total_online_time = online_start_time.elapsed();
            let total_time = time_start.elapsed();

            dbg!("(triples, coins) used: ", (arith_perm_circ_state.inner_mut().count_triples_used(), arith_perm_circ_state.inner_mut().count_coins()));

            return (
                format!("{:.4}", spdz_prep_time.as_micros() as f64 / 1000000.0),
                format!("{:.4}", preprocessing_time.as_micros() as f64 / 1000000.0),
                format!(
                    "{:.4}",
                    (shuffle_time_duration_sort).as_micros() as f64 / 1000000.0
                ),
                format!("{:.4}", total_online_time.as_micros() as f64 / 1000000.0),
                format!("{:.4}", total_time.as_micros() as f64 / 1000000.0),
                (net.stats().bytes_sent - comm_sent).to_string(),
                (net.stats().bytes_recv - comm_recv).to_string(),
            );
        }

        // Shared state to collect outputs
        let sort_times = Arc::new(Mutex::new(Vec::<(
            String,
            String,
            String,
            String,
            String,
            String,
            String,
        )>::new()));

        rayon::scope(|s| {
            let sort_times_clone = sort_times.clone();

            // party 0
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 0);

                let time_start = Instant::now();
                // Generate arithmetic permutation circuit state with shuffle tuples
                let shuffle_tuples_a_p0 = (0..num_bits)
                    .map(|j| ShuffleTupleInput {
                        shuffle_id: "random_shuffle_A_p0_".to_string() + &j.to_string(),
                        shuffle: Some(random_shuffles_a_p0[j].clone()),
                        n: n,
                        num_shuffle_tuples: 2,
                        with_inverse: false,
                    })
                    .collect::<Vec<ShuffleTupleInput>>();
                let shuffle_tuples_b_p0 = (0..num_bits)
                    .map(|j| ShuffleTupleInput {
                        shuffle_id: "random_shuffle_B_p0_".to_string() + &j.to_string(),
                        shuffle: Some(random_shuffles_b_p0[j].clone()),
                        n: n,
                        num_shuffle_tuples: 1,
                        with_inverse: true,
                    })
                    .collect::<Vec<ShuffleTupleInput>>();
                let shuffle_tuples_a_p1 = (0..num_bits)
                    .map(|j| ShuffleTupleInput {
                        shuffle_id: "random_shuffle_A_p1_".to_string() + &j.to_string(),
                        shuffle: None,
                        n: n,
                        num_shuffle_tuples: 2,
                        with_inverse: false,
                    })
                    .collect::<Vec<ShuffleTupleInput>>();
                let shuffle_tuples_b_p1 = (0..num_bits)
                    .map(|j| ShuffleTupleInput {
                        shuffle_id: "random_shuffle_B_p1_".to_string() + &j.to_string(),
                        shuffle: None,
                        n: n,
                        num_shuffle_tuples: 1,
                        with_inverse: true,
                    })
                    .collect::<Vec<ShuffleTupleInput>>();

                let shuffle_tuples = shuffle_tuples_a_p0
                    .into_iter()
                    .chain(shuffle_tuples_b_p0.into_iter())
                    .chain(shuffle_tuples_a_p1.into_iter())
                    .chain(shuffle_tuples_b_p1.into_iter())
                    .collect::<Vec<ShuffleTupleInput>>();

                let mut state = if dummy || on_flag {
                    DummyArithCircPrep::<Fr64>::new().run(
                        &mut net,
                        0,
                        num_auth_coins_dummy,
                        0,
                        num_auth_triples_dummy,
                        0,
                    )
                } else {
                    SPDZArithCircPrep::<Fr64>::new().run(
                        &mut net,
                        0,
                        num_auth_coins,
                        0,
                        num_auth_triples,
                        0,
                    )
                };
                let spdz_prep_time = time_start.elapsed();

                let mut arith_perm_circ_state = if dummy {
                    DummyArithPermCircPrep::<Fr64>::new().run(&mut net, &mut state, shuffle_tuples)
                } else {
                    SimplePermNetworkArithPermCircPrep::<Fr64>::new().run(
                        &mut net,
                        &mut state,
                        shuffle_tuples,
                    )
                };

                let preprocessing_time = time_start.elapsed();

                let input_bits = random_input_clone
                    .iter()
                    .map(|share| usize_to_bits(*share, num_bits))
                    .collect::<Vec<Vec<Fr64>>>();

                assert_eq!(input_bits[0].len(), num_bits);

                let input_bits_p0 = (0..input_bits.len())
                    .map(|i| {
                        VectorInput::<Fr64>::run(
                            &mut net,
                            &mut arith_perm_circ_state.inner_mut(),
                            (0, Some(input_bits[i].clone()), None),
                        )
                    })
                    .collect::<Vec<Vec<AuthShare<Fr64>>>>();


                let online_start_time = Instant::now();

                let comm_recv = if dummy { net.stats().bytes_recv } else { 0 };
                let comm_sent = if dummy { net.stats().bytes_sent } else { 0 };

                let mut shuffle_time_duration_sort = std::time::Duration::ZERO;

                let _sort_output = Sort::run_with_floss_timing(
                    &mut net,
                    &mut arith_perm_circ_state,
                    input_bits_p0,
                    &mut |shuffle_time| {
                        shuffle_time_duration_sort += shuffle_time;
                    },
                );

                let pre_auth_check_time = Instant::now();
                ExecBlindAuthCheck::<Fr64>::run(&mut net, &mut arith_perm_circ_state, ());
                let auth_check_time = pre_auth_check_time.elapsed();
                dbg!("Auth check time (floss sort): ", auth_check_time);

                let total_online_time = online_start_time.elapsed();
                let total_time = time_start.elapsed();

                dbg!("(triples, coins) used: ", (arith_perm_circ_state.inner_mut().count_triples_used(), arith_perm_circ_state.inner_mut().count_coins()));

                sort_times_clone.lock().unwrap().push((
                    format!("{:.4}", spdz_prep_time.as_micros() as f64 / 1000000.0),
                    format!("{:.4}", preprocessing_time.as_micros() as f64 / 1000000.0),
                    format!(
                        "{:.4}",
                        (shuffle_time_duration_sort).as_micros() as f64 / 1000000.0
                    ),
                    format!("{:.4}", total_online_time.as_micros() as f64 / 1000000.0),
                    format!("{:.4}", total_time.as_micros() as f64 / 1000000.0),
                    (net.stats().bytes_sent - comm_sent).to_string(),
                    (net.stats().bytes_recv - comm_recv).to_string(),
                ));
            });

            // party 1
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);

                dbg!("start circ prep");
                let mut state = if dummy || on_flag {
                    DummyArithCircPrep::<Fr64>::new().run(
                        &mut net,
                        0,
                        num_auth_coins_dummy,
                        0,
                        num_auth_triples_dummy,
                        0,
                    )
                } else {
                    SPDZArithCircPrep::<Fr64>::new().run(
                        &mut net,
                        0,
                        num_auth_coins,
                        0,
                        num_auth_triples,
                        0,
                    )
                };
                dbg!("end circ prep");

                // Generate arithmetic permutation circuit state with shuffle tuples
                let shuffle_tuples_a_p0 = (0..num_bits)
                    .map(|j| ShuffleTupleInput {
                        shuffle_id: "random_shuffle_A_p0_".to_string() + &j.to_string(),
                        shuffle: None,
                        n: n,
                        num_shuffle_tuples: 2,
                        with_inverse: false,
                    })
                    .collect::<Vec<ShuffleTupleInput>>();
                let shuffle_tuples_b_p0 = (0..num_bits)
                    .map(|j| ShuffleTupleInput {
                        shuffle_id: "random_shuffle_B_p0_".to_string() + &j.to_string(),
                        shuffle: None,
                        n: n,
                        num_shuffle_tuples: 1,
                        with_inverse: true,
                    })
                    .collect::<Vec<ShuffleTupleInput>>();
                let shuffle_tuples_a_p1 = (0..num_bits)
                    .map(|j| ShuffleTupleInput {
                        shuffle_id: "random_shuffle_A_p1_".to_string() + &j.to_string(),
                        shuffle: Some(random_shuffles_a_p1[j].clone()),
                        n: n,
                        num_shuffle_tuples: 2,
                        with_inverse: false,
                    })
                    .collect::<Vec<ShuffleTupleInput>>();
                let shuffle_tuples_b_p1 = (0..num_bits)
                    .map(|j| ShuffleTupleInput {
                        shuffle_id: "random_shuffle_B_p1_".to_string() + &j.to_string(),
                        shuffle: Some(random_shuffles_b_p1[j].clone()),
                        n: n,
                        num_shuffle_tuples: 1,
                        with_inverse: true,
                    })
                    .collect::<Vec<ShuffleTupleInput>>();

                let shuffle_tuples = shuffle_tuples_a_p0
                    .into_iter()
                    .chain(shuffle_tuples_b_p0.into_iter())
                    .chain(shuffle_tuples_a_p1.into_iter())
                    .chain(shuffle_tuples_b_p1.into_iter())
                    .collect::<Vec<ShuffleTupleInput>>();

                dbg!("start shuffle tuple prep");
                let mut arith_perm_circ_state = if dummy {
                    DummyArithPermCircPrep::<Fr64>::new().run(&mut net, &mut state, shuffle_tuples)
                } else {
                    SimplePermNetworkArithPermCircPrep::<Fr64>::new().run(
                        &mut net,
                        &mut state,
                        shuffle_tuples,
                    )
                };

                dbg!("end shuffle tuple prep");

                dbg!("start input bits prep");
                let input_bits_p1 = (0..n)
                    .map(|_| {
                        VectorInput::<Fr64>::run(
                            &mut net,
                            &mut arith_perm_circ_state.inner_mut(),
                            (0, None, Some(num_bits)),
                        )
                    })
                    .collect::<Vec<Vec<AuthShare<Fr64>>>>();
                dbg!("end input bits prep");

                dbg!("start sort");
                let mut shuffle_time_duration_sort = std::time::Duration::ZERO;
                let _sort_output = Sort::run_with_floss_timing(
                    &mut net,
                    &mut arith_perm_circ_state,
                    input_bits_p1,
                    &mut |shuffle_time| {
                        shuffle_time_duration_sort += shuffle_time;
                    },
                );

                dbg!("end sort");

                ExecBlindAuthCheck::<Fr64>::run(&mut net, &mut arith_perm_circ_state, ());
            });
        });

        sort_times.lock().unwrap().pop().unwrap()
    }

    fn sort_with_perm_network(
        key_length: usize,
        record_num: usize,
        dummy: bool,
        bench: &str,
    ) -> (String, String, String, String, String, String, String) {
        let n = 2_usize.pow(record_num as u32);
        let low = usize::MIN;
        let high = 2_usize.pow(key_length as u32) - 2;
        let num_bits = get_number_bits(high as u64);
        assert_eq!(num_bits, key_length);

        let random_input =
            get_random_vector_bounded_usize(rand::rng().random_range(0..u64::MAX), low, high, n);
        let random_input_clone: Vec<usize> = random_input.clone();

        let num_auth_triples =
            10 * num_bits * ((n as f64).log2() as usize + 1) * ((n as f64).log2() as usize + 1) * n;
        let num_auth_coins =
            10 * num_bits * ((n as f64).log2() as usize + 1) * ((n as f64).log2() as usize + 1) * n;

        let num_auth_triples_dummy = num_auth_triples; // same since no shuffle tuples are generated
        let num_auth_coins_dummy = num_auth_coins;

        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        let (alone, rank, ip_file) = get_parties_info();
        if !alone {
            let mut net = Net::init_from_file(&ip_file, rank);

            let time_start = Instant::now();

                let mut state = if dummy {
                    DummyArithCircPrep::<Fr64>::new().run(
                        &mut net,
                        0,
                        num_auth_coins_dummy,
                        0,
                        num_auth_triples_dummy,
                        0,
                    )
                } else {
                    SPDZArithCircPrep::<Fr64>::new().run(
                        &mut net,
                        0,
                        num_auth_coins,
                        0,
                        num_auth_triples,
                        0,
                    )
                };

                let spdz_prep_time = time_start.elapsed();

                let mut arith_perm_circ_state = if dummy {
                    DummyArithPermCircPrep::<Fr64>::new().run(&mut net, &mut state, vec![])
                } else {
                    PermNetworkArithPermCircPrep::<Fr64>::new().run(&mut net, &mut state, vec![])
                };

                let preprocessing_time = time_start.elapsed();

                let input_bits = random_input_clone
                    .iter()
                    .map(|share| usize_to_bits(*share, num_bits))
                    .collect::<Vec<Vec<Fr64>>>();

                assert_eq!(input_bits[0].len(), num_bits);

                let input_bits = (0..input_bits.len())
                    .map(|i| {
                        if rank == 0 {
                            VectorInput::<Fr64>::run(
                            &mut net,
                            &mut arith_perm_circ_state.inner_mut(),
                            (0, Some(input_bits[i].clone()), None),
                            )
                        } else {
                            VectorInput::<Fr64>::run(
                                &mut net,
                                &mut arith_perm_circ_state.inner_mut(),
                                (0, None, Some(num_bits)),
                            )
                        }
                    })
                    .collect::<Vec<Vec<AuthShare<Fr64>>>>();

                let input_bit_time = time_start.elapsed() - preprocessing_time;

                let mut offline_time_duration_sort = std::time::Duration::ZERO;
                let mut online_time_duration_sort = std::time::Duration::ZERO;

                let comm_recv = net.stats().bytes_recv;
                let comm_sent = net.stats().bytes_sent;

                let mut offline_bandwidth_total = (0_usize, 0_usize);
                let mut online_bandwidth_total = (0_usize, 0_usize);
                let _sort_output = Sort::<Fr64>::run_with_perm_network_timing(
                    &mut net,
                    &mut arith_perm_circ_state,
                    input_bits,
                    &mut |offline_time, online_time, offline_bandwidth, online_bandwidth| {
                        offline_time_duration_sort += offline_time; // Accumulate instead of assign
                        online_time_duration_sort += online_time; // Accumulate instead of assign
                        offline_bandwidth_total = (
                            offline_bandwidth_total.0 + offline_bandwidth.0,
                            offline_bandwidth_total.1 + offline_bandwidth.1,
                        );
                        online_bandwidth_total = (
                            online_bandwidth_total.0 + online_bandwidth.0,
                            online_bandwidth_total.1 + online_bandwidth.1,
                        );
                    },
                );

                let pre_auth_check_time = Instant::now();
                ExecBlindAuthCheck::<Fr64>::run(&mut net, &mut arith_perm_circ_state, ());
                let auth_check_time = pre_auth_check_time.elapsed();
                dbg!("Auth check time (perm network sort): ", auth_check_time);

                let sent_bytes = match bench {
                    "offline" => comm_sent + offline_bandwidth_total.0,
                    "online" => online_bandwidth_total.0,
                    "full" => net.stats().bytes_sent,
                    _ => unreachable!(),
                };

                let recv_bytes = match bench {
                    "offline" => comm_recv + offline_bandwidth_total.1,
                    "online" => online_bandwidth_total.1,
                    "full" => net.stats().bytes_recv,
                    _ => unreachable!(),
                };

                let total_online_time = time_start.elapsed()
                    - preprocessing_time
                    - input_bit_time
                    - offline_time_duration_sort;

                let total_offline_time =
                    input_bit_time + preprocessing_time + offline_time_duration_sort;

                let total_time = time_start.elapsed();

                return (
                    format!("{:.4}", spdz_prep_time.as_micros() as f64 / 1000000.0),
                    format!("{:.4}", total_offline_time.as_micros() as f64 / 1000000.0),
                    format!(
                        "{:.4}",
                        (online_time_duration_sort).as_micros() as f64 / 1000000.0
                    ),
                    format!("{:.4}", total_online_time.as_micros() as f64 / 1000000.0),
                    format!("{:.4}", total_time.as_micros() as f64 / 1000000.0),
                    sent_bytes.to_string(),
                    recv_bytes.to_string(),
                );
        }

        // Shared state to collect outputs
        let sort_times = Arc::new(Mutex::new(Vec::<(
            String,
            String,
            String,
            String,
            String,
            String,
            String,
        )>::new()));

        rayon::scope(|s| {
            let sort_times_clone = sort_times.clone();

            // party 0
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 0);

                let time_start = Instant::now();

                let mut state = if dummy {
                    DummyArithCircPrep::<Fr64>::new().run(
                        &mut net,
                        0,
                        num_auth_coins_dummy,
                        0,
                        num_auth_triples_dummy,
                        0,
                    )
                } else {
                    SPDZArithCircPrep::<Fr64>::new().run(
                        &mut net,
                        0,
                        num_auth_coins,
                        0,
                        num_auth_triples,
                        0,
                    )
                };

                let spdz_prep_time = time_start.elapsed();

                let mut arith_perm_circ_state = if dummy {
                    DummyArithPermCircPrep::<Fr64>::new().run(&mut net, &mut state, vec![])
                } else {
                    PermNetworkArithPermCircPrep::<Fr64>::new().run(&mut net, &mut state, vec![])
                };

                let preprocessing_time = time_start.elapsed();

                let input_bits = random_input_clone
                    .iter()
                    .map(|share| usize_to_bits(*share, num_bits))
                    .collect::<Vec<Vec<Fr64>>>();

                assert_eq!(input_bits[0].len(), num_bits);

                let input_bits_p0 = (0..input_bits.len())
                    .map(|i| {
                        VectorInput::<Fr64>::run(
                            &mut net,
                            &mut arith_perm_circ_state.inner_mut(),
                            (0, Some(input_bits[i].clone()), None),
                        )
                    })
                    .collect::<Vec<Vec<AuthShare<Fr64>>>>();

                let input_bit_time = time_start.elapsed() - preprocessing_time;

                let mut offline_time_duration_sort = std::time::Duration::ZERO;
                let mut online_time_duration_sort = std::time::Duration::ZERO;

                let comm_recv = net.stats().bytes_recv;
                let comm_sent = net.stats().bytes_sent;

                let mut offline_bandwidth_total = (0_usize, 0_usize);
                let mut online_bandwidth_total = (0_usize, 0_usize);
                let _sort_output = Sort::<Fr64>::run_with_perm_network_timing(
                    &mut net,
                    &mut arith_perm_circ_state,
                    input_bits_p0,
                    &mut |offline_time, online_time, offline_bandwidth, online_bandwidth| {
                        offline_time_duration_sort += offline_time; // Accumulate instead of assign
                        online_time_duration_sort += online_time; // Accumulate instead of assign
                        offline_bandwidth_total = (
                            offline_bandwidth_total.0 + offline_bandwidth.0,
                            offline_bandwidth_total.1 + offline_bandwidth.1,
                        );
                        online_bandwidth_total = (
                            online_bandwidth_total.0 + online_bandwidth.0,
                            online_bandwidth_total.1 + online_bandwidth.1,
                        );
                    },
                );

                let pre_auth_check_time = Instant::now();
                ExecBlindAuthCheck::<Fr64>::run(&mut net, &mut arith_perm_circ_state, ());
                let auth_check_time = pre_auth_check_time.elapsed();
                dbg!("Auth check time (perm network sort): ", auth_check_time);

                let sent_bytes = match bench {
                    "offline" => comm_sent + offline_bandwidth_total.0,
                    "online" => online_bandwidth_total.0,
                    "full" => net.stats().bytes_sent,
                    _ => unreachable!(),
                };

                let recv_bytes = match bench {
                    "offline" => comm_recv + offline_bandwidth_total.1,
                    "online" => online_bandwidth_total.1,
                    "full" => net.stats().bytes_recv,
                    _ => unreachable!(),
                };

                let total_online_time = time_start.elapsed()
                    - preprocessing_time
                    - input_bit_time
                    - offline_time_duration_sort;

                let total_offline_time =
                    input_bit_time + preprocessing_time + offline_time_duration_sort;

                let total_time = time_start.elapsed();

                sort_times_clone.lock().unwrap().push((
                    format!("{:.4}", spdz_prep_time.as_micros() as f64 / 1000000.0),
                    format!("{:.4}", total_offline_time.as_micros() as f64 / 1000000.0),
                    format!(
                        "{:.4}",
                        (online_time_duration_sort).as_micros() as f64 / 1000000.0
                    ),
                    format!("{:.4}", total_online_time.as_micros() as f64 / 1000000.0),
                    format!("{:.4}", total_time.as_micros() as f64 / 1000000.0),
                    sent_bytes.to_string(),
                    recv_bytes.to_string(),
                ));
            });

            // party 1
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);

                dbg!("start circ prep");
                let mut state = if dummy {
                    DummyArithCircPrep::<Fr64>::new().run(
                        &mut net,
                        0,
                        num_auth_coins_dummy,
                        0,
                        num_auth_triples_dummy,
                        0,
                    )
                } else {
                    SPDZArithCircPrep::<Fr64>::new().run(
                        &mut net,
                        0,
                        num_auth_coins,
                        0,
                        num_auth_triples,
                        0,
                    )
                };
                dbg!("end circ prep");

                dbg!("start shuffle tuple prep");
                let mut arith_perm_circ_state = if dummy {
                    DummyArithPermCircPrep::<Fr64>::new().run(&mut net, &mut state, vec![])
                } else {
                    PermNetworkArithPermCircPrep::<Fr64>::new().run(&mut net, &mut state, vec![])
                };

                dbg!("end shuffle tuple prep");

                dbg!("start input bits prep");
                let input_bits_p1 = (0..n)
                    .map(|_| {
                        VectorInput::<Fr64>::run(
                            &mut net,
                            &mut arith_perm_circ_state.inner_mut(),
                            (0, None, Some(num_bits)),
                        )
                    })
                    .collect::<Vec<Vec<AuthShare<Fr64>>>>();
                dbg!("end input bits prep");

                dbg!("start sort");
                let mut offline_time_duration_sort = std::time::Duration::ZERO;
                let mut online_time_duration_sort = std::time::Duration::ZERO;
                let mut offline_bandwidth_total = (0_usize, 0_usize);
                let mut online_bandwidth_total = (0_usize, 0_usize);

                let _sort_output = Sort::<Fr64>::run_with_perm_network_timing(
                    &mut net,
                    &mut arith_perm_circ_state,
                    input_bits_p1,
                    &mut |offline_time, online_time, offline_bandwidth, online_bandwidth| {
                        offline_time_duration_sort += offline_time; // Accumulate instead of assign
                        online_time_duration_sort += online_time; // Accumulate instead of assign
                        offline_bandwidth_total = (
                            offline_bandwidth_total.0 + offline_bandwidth.0,
                            offline_bandwidth_total.1 + offline_bandwidth.1,
                        );
                        online_bandwidth_total = (
                            online_bandwidth_total.0 + online_bandwidth.0,
                            online_bandwidth_total.1 + online_bandwidth.1,
                        );
                    },
                );

                ExecBlindAuthCheck::<Fr64>::run(&mut net, &mut arith_perm_circ_state, ());
            });
        });

        sort_times.lock().unwrap().pop().unwrap()
    }

    fn sort_with_quicksort(
        record_num: usize
    ) -> (String, String, String, String, String) {
        let key_length = 32;    
        let n = 2_usize.pow(record_num as u32);
        let high = 2_usize.pow(key_length as u32) - 2;
        let num_bits = get_number_bits(high as u64);
        assert_eq!(num_bits, key_length);

        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let program = "quicksort_rand";
        let filename = f.path().to_str().unwrap();

        let (alone, rank, ip_file) = get_parties_info();
        if !alone {
            let net = Net::init_from_file(&ip_file, rank);
            
            Command::new("sh")
                    .arg("-c")
                    .arg(&format!("seq {} -1 1 > Input-P0-0", n))
                    .current_dir("mp-spdz-0.4.2/Player-Data")
                    .status()
                    .unwrap();

                let compile_circ = Command::new("./compile.py")
                    .current_dir("mp-spdz-0.4.2")
                    .args([&format!("Programs/Source/{}.mpc", program), n.to_string().as_str()])
                    .status()
                    .unwrap();

                if compile_circ.code().unwrap_or(-1) != 0 {
                    panic!(
                        "compile.py failed: exit={}",
                        compile_circ.code().unwrap_or(-1)
                    );
                }

                let status = Command::new("./lowgear-party.x")
                    .current_dir("mp-spdz-0.4.2")
                    .args([
                        "-N",
                        "2",
                        "-h",
                        &net.get_host_ip(),
                        "-p",
                        &net.party_id().to_string(),
                        "-pn",
                        "5100",
                        &format!("{}-{}", program, n),
                        "-v",
                    ])
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .output()
                    .unwrap();

                    let combined = format!(
                        "{}{}",
                        String::from_utf8_lossy(&status.stdout),
                        String::from_utf8_lossy(&status.stderr)
                    );

                    dbg!("combined: {}", &combined);
    
                    // Parse the output to extract timing and communication data
                    use regex::Regex;
                    // Match either: "spent a total of X seconds (Y MB" or "Spent X seconds (Y MB" (new format)
                    let online_time_re = Regex::new(r"(?:spent a total of|Spent)\s+(-?[0-9]+(?:\.[0-9]+)?)\s+seconds\s+\(([0-9]+(?:\.[0-9]+)?)\s+MB").unwrap();
                    // Match either: "on the online phase, X seconds (Y MB" (old format) or "and X seconds (Y MB" (new format, offline part)
                    let offline_time_re = Regex::new(r"(?:on the online phase,\s+|and\s+)(-?[0-9]+(?:\.[0-9]+)?)\s+seconds\s+\(([0-9]+(?:\.[0-9]+)?)\s+MB").unwrap();

                    let online_time = if let Some(caps) = online_time_re.captures(&combined) {
                        caps[1].parse::<f64>().unwrap()
                    } else {
                        0.0
                    };
                    
                    let online_communication = if let Some(caps) = online_time_re.captures(&combined) {
                        caps[2].parse::<f64>().unwrap()
                    } else {
                        0.0
                    };
                    
                    let offline_time = if let Some(caps) = offline_time_re.captures(&combined) {
                        caps[1].parse::<f64>().unwrap()
                    } else {
                        0.0
                    };
                    
                    let offline_communication = if let Some(caps) = offline_time_re.captures(&combined) {
                        caps[2].parse::<f64>().unwrap()
                    } else {
                        0.0
                    };

                    return (
                        format!("{}", n),
                        format!("{:.4}", offline_time),
                        format!("{:.4}", if online_time < 0.0 { -1.0 * online_time } else { online_time }),
                        format!("{:.4}", offline_communication * 2.0 * 1024.0 * 1024.0),
                        format!("{:.4}", online_communication * 2.0 * 1024.0 * 1024.0),
                    );
        }

        let sort_times = Arc::new(Mutex::new(Vec::<(String, String, String, String, String)>::new()));
        rayon::scope(|s| {
            let sort_times_clone = sort_times.clone();

            // party 0
            s.spawn(move |_| {
                let net = Net::init_from_file(filename, 0);

                Command::new("sh")
                    .arg("-c")
                    .arg(&format!("seq {} -1 1 > Input-P0-0", n))
                    .current_dir("mp-spdz-0.4.2/Player-Data")
                    .status()
                    .unwrap();

                let compile_circ = Command::new("./compile.py")
                    .current_dir("mp-spdz-0.4.2")
                    .args([&format!("Programs/Source/{}.mpc", program), n.to_string().as_str()])
                    .status()
                    .unwrap();

                if compile_circ.code().unwrap_or(-1) != 0 {
                    panic!(
                        "compile.py failed: exit={}",
                        compile_circ.code().unwrap_or(-1)
                    );
                }

                let status = Command::new("./lowgear-party.x")
                    .current_dir("mp-spdz-0.4.2")
                    .args([
                        "-N",
                        "2",
                        "-p",
                        &net.party_id().to_string(),
                        "-pn",
                        "5100",
                        &format!("{}-{}", program, n),
                        "-v",
                    ])
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .output()
                    .unwrap();

                    let combined = format!(
                        "{}{}",
                        String::from_utf8_lossy(&status.stdout),
                        String::from_utf8_lossy(&status.stderr)
                    );

                    dbg!("combined: {}", &combined);
    
                    // Parse the output to extract timing and communication data
                    use regex::Regex;
                    // Match either: "spent a total of X seconds (Y MB" or "Spent X seconds (Y MB" (new format)
                    let online_time_re = Regex::new(r"(?:spent a total of|Spent)\s+(-?[0-9]+(?:\.[0-9]+)?)\s+seconds\s+\(([0-9]+(?:\.[0-9]+)?)\s+MB").unwrap();
                    // Match either: "on the online phase, X seconds (Y MB" (old format) or "and X seconds (Y MB" (new format, offline part)
                    let offline_time_re = Regex::new(r"(?:on the online phase,\s+|and\s+)(-?[0-9]+(?:\.[0-9]+)?)\s+seconds\s+\(([0-9]+(?:\.[0-9]+)?)\s+MB").unwrap();

                    let online_time = if let Some(caps) = online_time_re.captures(&combined) {
                        caps[1].parse::<f64>().unwrap()
                    } else {
                        0.0
                    };
                    
                    let online_communication = if let Some(caps) = online_time_re.captures(&combined) {
                        caps[2].parse::<f64>().unwrap()
                    } else {
                        0.0
                    };
                    
                    let offline_time = if let Some(caps) = offline_time_re.captures(&combined) {
                        caps[1].parse::<f64>().unwrap()
                    } else {
                        0.0
                    };
                    
                    let offline_communication = if let Some(caps) = offline_time_re.captures(&combined) {
                        caps[2].parse::<f64>().unwrap()
                    } else {
                        0.0
                    };

                    sort_times_clone.lock().unwrap().push((
                        format!("{}", n),
                        format!("{:.4}", offline_time),
                        format!("{:.4}", if online_time < 0.0 { -1.0 * online_time } else { online_time }),
                        format!("{:.4}", offline_communication * 2.0 * 1024.0 * 1024.0),
                        format!("{:.4}", online_communication * 2.0 * 1024.0 * 1024.0),
                    ));

            });

            s.spawn(move |_| {
                let net = Net::init_from_file(filename, 1);

                let compile_circ = Command::new("./compile.py")
                    .current_dir("mp-spdz-0.4.2")
                    .args([&format!("Programs/Source/{}.mpc", program), n.to_string().as_str()])
                    .status()
                    .unwrap();

                if compile_circ.code().unwrap_or(-1) != 0 {
                    panic!(
                        "compile.py failed: exit={}",
                        compile_circ.code().unwrap_or(-1)
                    );
                }

                let _status = Command::new("./lowgear-party.x")
                    .current_dir("mp-spdz-0.4.2")
                    .args([
                        "-N",
                        "2",
                        "-p",
                        &net.party_id().to_string(),
                        "-pn",
                        "5100",
                        &format!("{}-{}", program, n),
                        "-v",
                    ])
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .output()
                    .unwrap();
            });
        });

        sort_times.lock().unwrap().pop().unwrap()
    }

    fn sort_with_sorting_network(
        record_num: usize
    ) -> (String, String, String, String, String) {
        let key_length = 32;
        let n = 2_usize.pow(record_num as u32);
        let high = 2_usize.pow(key_length as u32) - 2;
        let num_bits = get_number_bits(high as u64);
        assert_eq!(num_bits, key_length);

        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        let (alone, rank, ip_file) = get_parties_info();
        if !alone {
            let net = Net::init_from_file(&ip_file, rank);

            Command::new("sh")
                    .arg("-c")
                    .arg(&format!("seq {} -1 1 > Input-P0-0", n))
                    .current_dir("mp-spdz-0.4.2/Player-Data")
                    .status()
                    .unwrap();

                let compile_circ = Command::new("./compile.py")
                    .current_dir("mp-spdz-0.4.2")
                    .args(["sort-bench.py", n.to_string().as_str(), key_length.to_string().as_str()])
                    .status()
                    .unwrap();

                if compile_circ.code().unwrap_or(-1) != 0 {
                    panic!(
                        "compile.py failed: exit={}",
                        compile_circ.code().unwrap_or(-1)
                    );
                }

                let status = Command::new("./lowgear-party.x")
                    .current_dir("mp-spdz-0.4.2")
                    .args([
                        "-N",
                        "2",
                        "-h",
                        &net.get_host_ip(),
                        "-p",
                        &net.party_id().to_string(),
                        "-pn",
                        "5100",
                        &format!("sort-bench-{}-{}", n, key_length),
                        "-v",
                    ])
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .output()
                    .unwrap();

                    let combined = format!(
                        "{}{}",
                        String::from_utf8_lossy(&status.stdout),
                        String::from_utf8_lossy(&status.stderr)
                    );

                    dbg!("combined: {}", &combined);
    
                    // Parse the output to extract timing and communication data
                    use regex::Regex;
                    // Match either: "spent a total of X seconds (Y MB" or "Spent X seconds (Y MB" (new format)
                    let online_time_re = Regex::new(r"(?:spent a total of|Spent)\s+(-?[0-9]+(?:\.[0-9]+)?)\s+seconds\s+\(([0-9]+(?:\.[0-9]+)?)\s+MB").unwrap();
                    // Match either: "on the online phase, X seconds (Y MB" (old format) or "and X seconds (Y MB" (new format, offline part)
                    let offline_time_re = Regex::new(r"(?:on the online phase,\s+|and\s+)(-?[0-9]+(?:\.[0-9]+)?)\s+seconds\s+\(([0-9]+(?:\.[0-9]+)?)\s+MB").unwrap();

                    let online_time = if let Some(caps) = online_time_re.captures(&combined) {
                        caps[1].parse::<f64>().unwrap()
                    } else {
                        0.0
                    };
                    
                    let online_communication = if let Some(caps) = online_time_re.captures(&combined) {
                        caps[2].parse::<f64>().unwrap()
                    } else {
                        0.0
                    };
                    
                    let offline_time = if let Some(caps) = offline_time_re.captures(&combined) {
                        caps[1].parse::<f64>().unwrap()
                    } else {
                        0.0
                    };
                    
                    let offline_communication = if let Some(caps) = offline_time_re.captures(&combined) {
                        caps[2].parse::<f64>().unwrap()
                    } else {
                        0.0
                    };

                    return (
                        format!("{}", n),
                        format!("{:.4}", offline_time),
                        format!("{:.4}", if online_time < 0.0 { -1.0 * online_time } else { online_time }),
                        format!("{:.4}", offline_communication * 2.0 * 1024.0 * 1024.0),
                        format!("{:.4}", online_communication * 2.0 * 1024.0 * 1024.0),
                    );
        }

        let sort_times = Arc::new(Mutex::new(Vec::<(String, String, String, String, String)>::new()));
        rayon::scope(|s| {
            let sort_times_clone = sort_times.clone();

            // party 0
            s.spawn(move |_| {
                let net = Net::init_from_file(filename, 0);

                Command::new("sh")
                    .arg("-c")
                    .arg(&format!("seq {} -1 1 > Input-P0-0", n))
                    .current_dir("mp-spdz-0.4.2/Player-Data")
                    .status()
                    .unwrap();

                let compile_circ = Command::new("./compile.py")
                    .current_dir("mp-spdz-0.4.2")
                    .args(["sort-bench.py", n.to_string().as_str(), key_length.to_string().as_str()])
                    .status()
                    .unwrap();

                if compile_circ.code().unwrap_or(-1) != 0 {
                    panic!(
                        "compile.py failed: exit={}",
                        compile_circ.code().unwrap_or(-1)
                    );
                }

                let status = Command::new("./lowgear-party.x")
                    .current_dir("mp-spdz-0.4.2")
                    .args([
                        "-N",
                        "2",
                        "-p",
                        &net.party_id().to_string(),
                        "-pn",
                        "5100",
                        &format!("sort-bench-{}-{}", n, key_length),
                        "-v",
                    ])
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .output()
                    .unwrap();

                    let combined = format!(
                        "{}{}",
                        String::from_utf8_lossy(&status.stdout),
                        String::from_utf8_lossy(&status.stderr)
                    );

                    dbg!("combined: {}", &combined);
    
                    // Parse the output to extract timing and communication data
                    use regex::Regex;
                    // Match either: "spent a total of X seconds (Y MB" or "Spent X seconds (Y MB" (new format)
                    let online_time_re = Regex::new(r"(?:spent a total of|Spent)\s+(-?[0-9]+(?:\.[0-9]+)?)\s+seconds\s+\(([0-9]+(?:\.[0-9]+)?)\s+MB").unwrap();
                    // Match either: "on the online phase, X seconds (Y MB" (old format) or "and X seconds (Y MB" (new format, offline part)
                    let offline_time_re = Regex::new(r"(?:on the online phase,\s+|and\s+)(-?[0-9]+(?:\.[0-9]+)?)\s+seconds\s+\(([0-9]+(?:\.[0-9]+)?)\s+MB").unwrap();

                    let online_time = if let Some(caps) = online_time_re.captures(&combined) {
                        caps[1].parse::<f64>().unwrap()
                    } else {
                        0.0
                    };
                    
                    let online_communication = if let Some(caps) = online_time_re.captures(&combined) {
                        caps[2].parse::<f64>().unwrap()
                    } else {
                        0.0
                    };
                    
                    let offline_time = if let Some(caps) = offline_time_re.captures(&combined) {
                        caps[1].parse::<f64>().unwrap()
                    } else {
                        0.0
                    };
                    
                    let offline_communication = if let Some(caps) = offline_time_re.captures(&combined) {
                        caps[2].parse::<f64>().unwrap()
                    } else {
                        0.0
                    };

                    sort_times_clone.lock().unwrap().push((
                        format!("{}", n),
                        format!("{:.4}", offline_time),
                        format!("{:.4}", if online_time < 0.0 { -1.0 * online_time } else { online_time }),
                        format!("{:.4}", offline_communication * 2.0 * 1024.0 * 1024.0),
                        format!("{:.4}", online_communication * 2.0 * 1024.0 * 1024.0),
                    ));

            });

            s.spawn(move |_| {
                let net = Net::init_from_file(filename, 1);

                let compile_circ = Command::new("./compile.py")
                .current_dir("mp-spdz-0.4.2")
                .args(["sort-bench.py", n.to_string().as_str(), key_length.to_string().as_str()])
                .status()
                .unwrap();

                if compile_circ.code().unwrap_or(-1) != 0 {
                    panic!(
                        "compile.py failed: exit={}",
                        compile_circ.code().unwrap_or(-1)
                    );
                }

                let _status = Command::new("./lowgear-party.x")
                    .current_dir("mp-spdz-0.4.2")
                    .args([
                        "-N",
                        "2",
                        "-p",
                        &net.party_id().to_string(),
                        "-pn",
                        "5100",
                        &format!("sort-bench-{}-{}", n, key_length),
                        "-v",
                    ])
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .output()
                    .unwrap();
            });
        });

        sort_times.lock().unwrap().pop().unwrap()
    }

    /// Run the simple perm-network shuffle benchmark (writes CSV files in the working directory).
    pub fn run_bench_simple_perm_network_shuffle() {
        let mut online_simple_perm_network_shuffle_benchmarks =
            File::create("shuffle_simple_perm_network_online.csv".to_owned()).unwrap();
        writeln!(
            online_simple_perm_network_shuffle_benchmarks,
            "InputSize,OnlineTime,BytesSent,BytesRecv"
        )
        .unwrap();

        let (alone, _, _) = get_parties_info();

        let online_tests: Vec<u32> = if alone {
            vec![8, 9, 10, 11, 12, 13, 14, 16]
        } else {
            vec![8, 9, 10, 11, 12, 13, 14, 16, 18, 20]
        };
        for i in online_tests {
            println!(
                "Running simple perm network shuffle benchmark with n = 2^{} = {}",
                i,
                2_usize.pow(i)
            );
            let (_, _, online_time, _, bytes_sent, bytes_recv) =
                shuffle_with_simple_perm_network(i, true, "online");
            writeln!(
                online_simple_perm_network_shuffle_benchmarks,
                "{},{},{},{}",
                i, online_time, bytes_sent, bytes_recv
            )
            .unwrap();
        }

        online_simple_perm_network_shuffle_benchmarks.flush().unwrap();


        // Offline and full tests
        let mut offline_simple_perm_network_shuffle_benchmarks =
            File::create("shuffle_simple_perm_network_offline.csv".to_owned()).unwrap();
        writeln!(
            offline_simple_perm_network_shuffle_benchmarks,
            "InputSize,SPDZPrepTime,OfflinePrepTime,BytesSent,BytesRecv"
        )
        .unwrap();

        let offline_tests: Vec<u32> = if alone {
            vec![8, 9, 10, 11, 12, 13, 14, 16]
        } else {
            vec![8, 9, 10, 11, 12, 13, 14, 16, 18, 20]
        };
        for i in offline_tests {
            println!(
                "Running perm network shuffle benchmark with n = 2^{} = {}",
                i,
                2_usize.pow(i)
            );
            let (spdz_prep_time, offline_prep_time, _, _, bytes_sent, bytes_recv) =
                shuffle_with_simple_perm_network(i, false, "offline");
            writeln!(
                offline_simple_perm_network_shuffle_benchmarks,
                "{},{},{},{},{}",
                i, spdz_prep_time, offline_prep_time, bytes_sent, bytes_recv
            )
            .unwrap();
        }

        offline_simple_perm_network_shuffle_benchmarks.flush().unwrap();
    }

    /// Run the perm-network shuffle benchmark (writes CSV files in the working directory).
    pub fn run_bench_perm_network_shuffle() {
        // Online tests
        let mut online_perm_network_shuffle_benchmarks =
            File::create("shuffle_perm_network_online.csv".to_owned()).unwrap();
        writeln!(
            online_perm_network_shuffle_benchmarks,
            "InputSize,OnlineTime,BytesSent,BytesRecv"
        )
        .unwrap();

        let (alone, _, _) = get_parties_info();

        let online_tests: Vec<u32> = if alone {
            vec![8, 9, 10, 11, 12, 13, 14, 16]
        } else {
            vec![8, 9, 10, 11, 12, 13, 14, 16, 18, 20]
        };

        for i in online_tests {
            println!(
                "Running perm network shuffle benchmark with n = 2^{} = {}",
                i,
                2_usize.pow(i)
            );
            let (_, _, online_time, _, bytes_sent, bytes_recv) =
                shuffle_with_perm_network(i, true, "online");
            writeln!(
                online_perm_network_shuffle_benchmarks,
                "{},{},{},{}",
                i, online_time, bytes_sent, bytes_recv
            )
            .unwrap();
        }

        online_perm_network_shuffle_benchmarks.flush().unwrap();

        // Offline and full tests
        let mut offline_perm_network_shuffle_benchmarks =
            File::create("shuffle_perm_network_offline.csv".to_owned()).unwrap();
        writeln!(
            offline_perm_network_shuffle_benchmarks,
            "InputSize,SPDZPrepTime,OfflinePrepTime,TotalTime,BytesSent,BytesRecv"
        )
        .unwrap();

        let offline_tests: Vec<u32> = if alone {
            vec![8, 9, 10, 11, 12, 13, 14, 16]
        } else {
            vec![8, 9, 10, 11, 12, 13, 14, 16, 18, 20]
        };
        for i in offline_tests {
            println!(
                "Running perm network shuffle benchmark with n = 2^{} = {}",
                i,
                2_usize.pow(i)
            );
            let (spdz_prep_time, offline_prep_time, _, total_time, bytes_sent, bytes_recv) =
                shuffle_with_perm_network(i, false, "offline");
            writeln!(
                offline_perm_network_shuffle_benchmarks,
                "{},{},{},{},{},{}",
                i, spdz_prep_time, offline_prep_time, total_time, bytes_sent, bytes_recv
            )
            .unwrap();
        }

        offline_perm_network_shuffle_benchmarks.flush().unwrap();
    }

    /// Run the FLoSS shuffle benchmark (writes CSV files in the working directory).
    pub fn run_bench_floss_shuffle() {
        let (alone, _, _) = get_parties_info();


        // Online tests
        let online_tests: Vec<u32> = if alone {
            vec![8, 9, 10, 11, 12, 13, 14, 16]
        } else {
            vec![8, 9, 10, 11, 12, 13, 14, 16, 18, 20, 21, 22]
        };
        let mut online_shuffle_benchmarks =
            File::create("shuffle_floss_online.csv".to_owned()).unwrap();
        writeln!(
            online_shuffle_benchmarks,
            "InputSize,OnlineTime,BytesSent,BytesRecv"
        )
        .unwrap();

        for i in online_tests {
            println!(
                "Running full shuffle benchmark with n = 2^{} = {}",
                i,
                2_usize.pow(i)
            );
            let (_, _, online_time, _, bytes_sent, bytes_recv) = shuffle_with_floss(i, true);
            writeln!(
                online_shuffle_benchmarks,
                "{},{},{},{}",
                i, online_time, bytes_sent, bytes_recv
            )
            .unwrap();
        }
        online_shuffle_benchmarks.flush().unwrap();

        // Offline and full tests
        let offline_tests: Vec<u32> = if alone {
            vec![8, 9, 10, 11, 12, 13, 14, 16]
        } else {
            vec![8, 9, 10, 11, 12, 13, 14, 16, 18, 20]
        };

        let mut offline_shuffle_benchmarks =
            File::create("shuffle_floss_offline.csv".to_owned()).unwrap();
        writeln!(
            offline_shuffle_benchmarks,
            "InputSize,SPDZPrepTime,OfflinePrepTime,TotalTime,BytesSent,BytesRecv"
        )
        .unwrap();

        for i in offline_tests {
            println!(
                "Running full shuffle benchmark with n = 2^{} = {}",
                i,
                2_usize.pow(i)
            );
            let (spdz_prep_time, offline_prep_time, _, total_time, bytes_sent, bytes_recv) =
                shuffle_with_floss(i, false);
            writeln!(
                offline_shuffle_benchmarks,
                "{},{},{},{},{},{}",
                i, spdz_prep_time, offline_prep_time, total_time, bytes_sent, bytes_recv
            )
            .unwrap();
        }
        offline_shuffle_benchmarks.flush().unwrap();
    }

    /// Run the sort-with-FLoSS benchmark (writes CSV files in the working directory).
    pub fn run_bench_sort_with_floss() {
        // Online tests
        let mut online_sort_with_floss_benchmarks =
            File::create("sort_floss_online.csv".to_owned()).unwrap();
        writeln!(
            online_sort_with_floss_benchmarks,
            "KeyLength,InputSize,OnlineShuffleTime,OnlineTime,BytesSent,BytesRecv"
        )
        .unwrap();

        let (alone, _, _) = get_parties_info();

        let online_key_lengths = [32];
        // let online_records = [];
        let online_records: Vec<usize> = if alone {
            vec![9, 10]
        } else {
            vec![9, 10, 11, 12, 13]
        };

        for key_length in online_key_lengths {
            for record in online_records.clone() {
                println!(
                    "Running sort benchmark with key length = {} and record num = {}",
                    key_length, record
                );
                let (_, _, online_shuffle_time, online_time, _, bytes_sent, bytes_recv) =
                    sort_with_floss(key_length, record, true);
                writeln!(
                    online_sort_with_floss_benchmarks,
                    "{},{},{},{},{},{}",
                    key_length, record, online_shuffle_time, online_time, bytes_sent, bytes_recv
                )
                .unwrap();
            }
        }
        online_sort_with_floss_benchmarks.flush().unwrap();

        // Offline tests and full tests
        let mut offline_sort_with_floss_benchmarks =
            File::create("sort_floss_offline.csv".to_owned()).unwrap();
        writeln!(
            offline_sort_with_floss_benchmarks,
            "KeyLength,InputSize,SPDZPrepTime,OfflinePrepTime,TotalTime,BytesSent,BytesRecv"
        )
        .unwrap();

        let offline_key_lengths = [32];
        let offline_records: Vec<usize> = if alone {
            vec![9, 10]
        } else {
            vec![9, 10, 11, 12, 13]
        };
        for key_length in offline_key_lengths {
            for record in offline_records.clone() {
                println!(
                    "Running sort benchmark with key length = {} and record num = {}",
                    key_length, record
                );
                let (spdz_prep_time, offline_prep_time, _, _, total_time, bytes_sent, bytes_recv) =
                    sort_with_floss(key_length, record, false);
                writeln!(
                    offline_sort_with_floss_benchmarks,
                    "{},{},{},{},{},{},{}",
                    key_length,
                    record,
                    spdz_prep_time,
                    offline_prep_time,
                    total_time,
                    bytes_sent,
                    bytes_recv
                )
                .unwrap();
            }
        }

        offline_sort_with_floss_benchmarks.flush().unwrap();
    }

    /// Run the sort-with-perm-network benchmark (writes CSV files in the working directory).
    pub fn run_bench_sort_with_perm_network() {
        // Online tests
        let mut online_sort_with_perm_network_benchmarks =
            File::create("sort_perm_network_online.csv".to_owned()).unwrap();
        writeln!(
            online_sort_with_perm_network_benchmarks,
            "KeyLength,InputSize,OnlineShuffleTime,OnlineTime,BytesSent,BytesRecv"
        )
        .unwrap();

        let (alone, _, _) = get_parties_info();

        let online_key_lengths = [32];
        let online_records: Vec<usize> = if alone {
            vec![9, 10]
        } else {
            vec![9, 10, 11, 12, 13]
        };
        for key_length in online_key_lengths {
            for record in online_records.clone() {
                println!(
                    "Running sort benchmark with key length = {} and record num = {}",
                    key_length, record
                );
                let (_, _, online_shuffle_time, online_time, _, bytes_sent, bytes_recv) =
                    sort_with_perm_network(key_length, record, true, "online");
                writeln!(
                    online_sort_with_perm_network_benchmarks,
                    "{},{},{},{},{},{}",
                    key_length, record, online_shuffle_time, online_time, bytes_sent, bytes_recv
                )
                .unwrap();
            }
        }
        online_sort_with_perm_network_benchmarks.flush().unwrap();

        // Offline tests and full tests
        let mut offline_sort_with_perm_network_benchmarks =
            File::create("sort_perm_network_offline.csv".to_owned()).unwrap();
        writeln!(
            offline_sort_with_perm_network_benchmarks,
            "KeyLength,InputSize,SPDZPrepTime,OfflinePrepTime,TotalTime,BytesSent,BytesRecv"
        )
        .unwrap();

        let offline_key_lengths = [32];
        let offline_records: Vec<usize> = if alone {
            vec![9, 10]
        } else {
            vec![9, 10, 11, 12, 13]
        };
        //let records = [11, 12];
        for key_length in offline_key_lengths {
            for record in offline_records.clone() {
                println!(
                    "Running sort benchmark with key length = {} and record num = {}",
                    key_length, record
                );
                let (spdz_prep_time, offline_prep_time, _, _, total_time, bytes_sent, bytes_recv) =
                    sort_with_perm_network(key_length, record, false, "offline");
                writeln!(
                    offline_sort_with_perm_network_benchmarks,
                    "{},{},{},{},{},{},{}",
                    key_length,
                    record,
                    spdz_prep_time,
                    offline_prep_time,
                    total_time,
                    bytes_sent,
                    bytes_recv
                )
                .unwrap();
            }
        }

        offline_sort_with_perm_network_benchmarks.flush().unwrap();
    }

    /// Run the quicksort benchmark (writes CSV files in the working directory).
    pub fn run_bench_sort_with_quicksort() {
        let mut quicksort_benchmarks = File::create("sort_quicksort.csv".to_owned()).unwrap();
        writeln!(
            quicksort_benchmarks,
            "InputSize,OfflinePrepTime,OnlineTime,OfflineCommunication,OnlineCommunication"
        )
        .unwrap();

        let (alone, _, _) = get_parties_info();

        let input_sizes: Vec<usize> = if alone {
            vec![9, 10]
        } else {
            vec![9, 10, 11, 12, 13]
        };

        for size in input_sizes {
            println!(
                "Running quicksort benchmark with n = 2^{} = {}",
                size,
                2_usize.pow(size as u32)
            );
            let (_, offline_prep_time, online_time, offline_communication, online_communication) = sort_with_quicksort(size);
            writeln!(
                quicksort_benchmarks,
                "{},{},{},{},{}",
                size, offline_prep_time, online_time, offline_communication, online_communication
            )
            .unwrap();
        }
    }

    /// Run the sorting-network benchmark (writes CSV files in the working directory).
    pub fn run_bench_sort_with_sorting_network() {
        let mut sorting_network_benchmarks = File::create("sort_sorting_network.csv".to_owned()).unwrap();
        writeln!(
            sorting_network_benchmarks,
            "InputSize,OfflinePrepTime,OnlineTime,OfflineCommunication,OnlineCommunication"
        )
        .unwrap();

        let (alone, _, _) = get_parties_info();

        let input_sizes: Vec<usize> = if alone {
            vec![9, 10]
        } else {
            vec![9, 10, 11, 12, 13]
        };
        for size in input_sizes {
            println!(
                "Running sorting network benchmark with n = 2^{} = {}",
                size,
                2_usize.pow(size as u32)
            );
            let (_, offline_prep_time, online_time, offline_communication, online_communication) = sort_with_sorting_network(size);
            writeln!(
                sorting_network_benchmarks,
                "{},{},{},{},{}",
                size, offline_prep_time, online_time, offline_communication, online_communication
            )
            .unwrap();
        }
        sorting_network_benchmarks.flush().unwrap();
    }

    /// Run the sort-with-simple-perm-network benchmark (writes CSV files in the working directory).
    pub fn run_bench_sort_with_simple_perm_network() {
        // Online tests
        let mut online_sort_with_simple_perm_network_benchmarks =
        File::create("sort_simple_perm_network_online.csv".to_owned()).unwrap();
        writeln!(
            online_sort_with_simple_perm_network_benchmarks,
            "KeyLength,InputSize,OnlineShuffleTime,OnlineTime,BytesSent,BytesRecv"
        )
        .unwrap();

        let (alone, _, _) = get_parties_info();

        let online_records: Vec<usize> = if alone {
            vec![9, 10]
        } else {
            vec![9, 10, 11, 12, 13]
        };

        for record in online_records {
            println!(
                "Running sort benchmark with key length = {} and record num = {}",
                32, record
            );
            let (_, _, online_shuffle_time, online_time, _, bytes_sent, bytes_recv) =
                sort_with_simple_perm_network(32, record, true);
            writeln!(
                online_sort_with_simple_perm_network_benchmarks,
                "{},{},{},{},{},{}",
                32, record, online_shuffle_time, online_time, bytes_sent, bytes_recv
            )
            .unwrap();
        }
        online_sort_with_simple_perm_network_benchmarks.flush().unwrap();

        // Offline tests and full tests
        let mut offline_sort_with_simple_perm_network_benchmarks =
            File::create("sort_simple_perm_network_offline.csv".to_owned()).unwrap();
        writeln!(
            offline_sort_with_simple_perm_network_benchmarks,
            "KeyLength,InputSize,SPDZPrepTime,OfflinePrepTime,TotalTime,BytesSent,BytesRecv"
        )
        .unwrap();


        let offline_records: Vec<usize> = if alone {
            vec![9, 10]
        } else {
            vec![9, 10, 11, 12, 13]
        };

        for record in offline_records {
            println!(
                "Running sort benchmark with key length = {} and record num = {}",
                32, record
            );
            let (spdz_prep_time, offline_prep_time, _, _, total_time, bytes_sent, bytes_recv) =
                sort_with_simple_perm_network(32, record, false);
            writeln!(
                offline_sort_with_simple_perm_network_benchmarks,
                "{},{},{},{},{},{},{}",
                32,
                record,
                spdz_prep_time,
                offline_prep_time,
                total_time,
                bytes_sent,
                bytes_recv
            )
            .unwrap();
        
        }
        offline_sort_with_simple_perm_network_benchmarks.flush().unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::bench_impl::*;

    #[test]
    fn bench_simple_perm_network_shuffle() {
        run_bench_simple_perm_network_shuffle();
    }

    #[test]
    fn bench_perm_network_shuffle() {
        run_bench_perm_network_shuffle();
    }

    #[test]
    fn bench_floss_shuffle() {
        run_bench_floss_shuffle();
    }

    #[test]
    fn bench_sort_with_floss() {
        run_bench_sort_with_floss();
    }

    #[test]
    fn bench_sort_with_perm_network() {
        run_bench_sort_with_perm_network();
    }

    #[test]
    fn bench_sort_with_quicksort() {
        run_bench_sort_with_quicksort();
    }

    #[test]
    fn bench_sort_with_sorting_network() {
        run_bench_sort_with_sorting_network();
    }

    #[test]
    fn bench_sort_with_simple_perm_network() {
        run_bench_sort_with_simple_perm_network();
    }
}

// Same cfg as `bench_impl`: `cargo bench` enables the `bench` feature by default (see Cargo.toml).
#[cfg(any(test, feature = "bench"))]
pub use bench_impl::{
    run_bench_floss_shuffle, run_bench_perm_network_shuffle, run_bench_simple_perm_network_shuffle,
    run_bench_sort_with_floss, run_bench_sort_with_perm_network, run_bench_sort_with_quicksort,
    run_bench_sort_with_simple_perm_network, run_bench_sort_with_sorting_network,
};
