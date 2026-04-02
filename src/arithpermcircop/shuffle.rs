// use std::time::Instant;

use std::time::Instant;

use ark_ff::Field;
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};

use crate::{
    arithpermcircop::{ArithPermCircOp, ArithPermCircState, blind_auth_queue::BlindAuthQueue},
    net::Net,
    primitives::auth::AuthShare,
    utils::{
        rng_utils::local_shuffle_vector,
        vector_utils::{elementwise_ref, elementwise_ref_scalar},
    },
};

/// Shuffle(perm_party_i, (perm, [x]_i), ([x]_{1-i})) -> perm(x)
/// One-sided shuffle.
pub struct Shuffle<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> Shuffle<F> {
    /// Create a new ArithCircOp instance
    pub fn new() -> Self {
        Shuffle {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<F: Field> ArithPermCircOp<F> for Shuffle<F> {
    type In = (
        usize,             // shuffle party
        String,            // shuffle_id
        Vec<AuthShare<F>>, // input auth shares
    );
    type Out = Vec<AuthShare<F>>;

    fn run(net: &mut Net, state: &mut ArithPermCircState<F>, input: Self::In) -> Self::Out {
        let time_start = Instant::now();
        dbg!("time start A: ", Instant::now());

        // Assert that our 2-party shuffle is only run with two parties
        assert!(net.n_parties() == 2);
        let (shuffle_party, shuffle_id, input_auth_shares) = input;

        let n = input_auth_shares.len();
        let (data_shares, auth_shares): (Vec<F>, Vec<F>) = input_auth_shares
            .par_iter()
            .map(|share| (share.value, share.mac))
            .collect();

        let shuffle_tuple = state.pop_shuffle_tuple(shuffle_id.clone());
        let shuffle = shuffle_tuple.shuffle.clone();
        let tuples_a = shuffle_tuple.tuples_a.clone();
        let tuples_b = shuffle_tuple.tuples_b.clone();
        let a = shuffle_tuple.a.clone();
        let b = shuffle_tuple.b.clone();
        let k = tuples_a[0].clone().k;

        let (pa_shares, kpa_shares): (Vec<F>, Vec<F>) =
            tuples_a.par_iter().map(|x| (x.value, x.kvalue)).collect();
        let (pb_shares, kpb_shares): (Vec<F>, Vec<F>) =
            tuples_b.par_iter().map(|x| (x.value, x.kvalue)).collect();

        dbg!("start B: Time accumulating inputs: ", time_start.elapsed());

        // Step 2: Party 1 masks their input shares and sends to Party 0
        if net.party_id() == 1 - shuffle_party {
            let a_vals = a.unwrap();
            let b_vals = b.unwrap();
            let c_shares: Vec<F> = (0..n)
                .into_par_iter()
                .map(|i| data_shares[i] - a_vals[i])
                .collect();
            let d_shares: Vec<F> = (0..n)
                .into_par_iter()
                .map(|i| auth_shares[i] - b_vals[i])
                .collect();

            net.send_to_party(shuffle_party, &c_shares);
            net.send_to_party(shuffle_party, &d_shares);
        }

        if net.party_id() == shuffle_party {
            let c2_time = Instant::now();
            let c_shares: Vec<F> = net.recv_from_party(1 - shuffle_party);
            let d_shares: Vec<F> = net.recv_from_party(1 - shuffle_party);
            dbg!("start C: Time receiving inputs: ", c2_time.elapsed());

            // dbg!("time C: ", time_start.elapsed());
            // dbg!("sending time: ", sending_time.elapsed());
            // dbg!("comm sending: ", net.stats().bytes_recv - comm_sending);
            // let start_local_comp_time = Instant::now();
            // let local_comp_bytes = net.stats().bytes_recv;

            let local_shuffle_time = Instant::now();
            let data_c_share_pre_shuffle = elementwise_ref(&data_shares, &c_shares, |a, b| a + b);
            let data_c_share =
                local_shuffle_vector(shuffle.as_ref().unwrap(), &data_c_share_pre_shuffle);

            let auth_d_share_pre_shuffle = elementwise_ref(&auth_shares, &d_shares, |a, b| a + b);
            let auth_d_share =
                local_shuffle_vector(shuffle.as_ref().unwrap(), &auth_d_share_pre_shuffle);

            let ps_shares = elementwise_ref(&data_c_share, &pa_shares, |a, b| a + b);
            let ps_auth_shares = elementwise_ref(&auth_d_share, &pb_shares, |a, b| a + b);

            let k_data_c_share = elementwise_ref_scalar(&data_c_share, k.unwrap(), |a, b| a * b);
            let kps_shares = elementwise_ref(&k_data_c_share, &kpa_shares, |a, b| a + b);
            let k_auth_d_share = elementwise_ref_scalar(&auth_d_share, k.unwrap(), |a, b| a * b);
            let kps_auth_shares = elementwise_ref(&k_auth_d_share, &kpb_shares, |a, b| a + b);

            dbg!(
                "time D, time to local shuffle: ",
                local_shuffle_time.elapsed()
            );
            // dbg!("time C1: ", time_start.elapsed());

            let n_ps = ps_shares.len();
            let ps_output_time = Instant::now();
            let ps_output: Vec<AuthShare<F>> = (0..n_ps)
                .into_par_iter()
                .map(|i| AuthShare {
                    value: ps_shares[i],
                    mac: ps_auth_shares[i],
                })
                .collect();

            let n_kps = kps_shares.len();
            let kps_output: Vec<AuthShare<F>> = (0..n_kps)
                .into_par_iter()
                .map(|i| AuthShare {
                    value: kps_shares[i],
                    mac: kps_auth_shares[i],
                })
                .collect();

            // Combine ps_output and kps_output in parallel
            let auth_shares: Vec<AuthShare<F>> = ps_output
                .par_iter()
                .chain(kps_output.par_iter())
                .copied()
                .collect();
            dbg!(
                "start D: Time to accumulate outputs: ",
                ps_output_time.elapsed()
            );
            // dbg!("time D: ", time_start.elapsed());
            // Step 4: queue blinded auth shares for auth check
            let auth_queue_time = Instant::now();
            BlindAuthQueue::<F>::run(net, state, auth_shares);
            dbg!(
                "start E: Time to queue auth shares: ",
                auth_queue_time.elapsed()
            );

            // dbg!("time E: ", time_start.elapsed());

            // dbg!("local comp time: ", start_local_comp_time.elapsed());
            // dbg!(
            //     "local comp bytes: ",
            //     net.stats().bytes_recv - local_comp_bytes
            // );

            return ps_output;
        }

        // Step 4: queue blinded auth shares for auth check
        let ps_output = pa_shares
            .iter()
            .zip(pb_shares.iter())
            .map(|(a, b)| AuthShare { value: *a, mac: *b })
            .collect::<Vec<_>>();

        let kps_output = kpa_shares
            .iter()
            .zip(kpb_shares.iter())
            .map(|(a, b)| AuthShare { value: *a, mac: *b })
            .collect::<Vec<_>>();

        let auth_shares = ps_output
            .iter()
            .chain(kps_output.iter())
            .map(|a| a.clone())
            .collect::<Vec<_>>();
        BlindAuthQueue::<F>::run(net, state, auth_shares);

        return ps_output;
    }
}

#[cfg(test)]
mod test {
    use rand::Rng;

    use crate::arithcircop::ArithCircOp;
    use crate::arithcircop::vector_reveal::VectorReveal;
    use crate::arithcircprep::ArithCircPrep;
    use crate::arithpermcircprep::{ArithPermCircPrep, ShuffleTupleInput};
    use crate::bench::Mersenne128Fq;
    use crate::utils::rng_utils::{get_random_permutation_usize, local_unshuffle_vector};
    use crate::utils::testing_utils::generate_random_auth_shares;
    use crate::{
        arithcircprep::dummy::DummyArithCircPrep, arithpermcircprep::dummy::DummyArithPermCircPrep,
    };

    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use tempfile::NamedTempFile;
    type Fr = crate::bench::Mersenne128Fq;

    #[test]
    fn test_online_shuffle_party0() {
        let n = 25;
        let permuter_id = 0;

        let shuffle_input = get_random_permutation_usize(n);
        let shuffle_input_clone = shuffle_input.clone();
        let shuffle_input_clone_3 = shuffle_input.clone();

        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        // Shared state to collect outputs
        let outputs = Arc::new(Mutex::new(Vec::new()));
        let mac_shares = Arc::new(Mutex::new(Vec::new()));

        rayon::scope(|s| {
            let outputs_clone = outputs.clone();
            let mac_shares_party0 = mac_shares.clone();
            // party 0
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 0);

                let mut state = DummyArithCircPrep::<Fr>::new().run(
                    &mut net,
                    5 * n + 2,
                    6 * n + 2,
                    0,
                    5 * n,
                    0,
                );

                let party0_auth_shares = generate_random_auth_shares(&mut state, n);

                mac_shares_party0.lock().unwrap().push(state.key_share());

                // Generate arithmetic permutation circuit state with shuffle tuples
                let mut arith_perm_circ_prep: DummyArithPermCircPrep<Mersenne128Fq> =
                    DummyArithPermCircPrep::<Fr>::new();
                let mut arith_perm_circ_state = arith_perm_circ_prep.run(
                    &mut net,
                    &mut state, // permuter_id (party 0 is the permuter)
                    vec![ShuffleTupleInput {
                        shuffle_id: "shuffle1".to_string(),
                        shuffle: Some(shuffle_input_clone.clone()),
                        n: n,
                        num_shuffle_tuples: 1,
                        with_inverse: false,
                    }],
                );

                let party0_regular_shuffle_output = Shuffle::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    (
                        permuter_id,
                        "shuffle1".to_string(),
                        party0_auth_shares.clone(),
                    ),
                );

                let party0_inverse_shuffle_output = Shuffle::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    (
                        permuter_id,
                        "shuffle1_inverse".to_string(),
                        party0_auth_shares.clone(),
                    ),
                );

                let regular_shuffle_output = VectorReveal::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state.inner_mut(),
                    party0_regular_shuffle_output.clone(),
                );

                let inverse_shuffle_output = VectorReveal::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state.inner_mut(),
                    party0_inverse_shuffle_output.clone(),
                );

                // Store party 0's results
                outputs_clone.lock().unwrap().push((
                    party0_auth_shares,
                    regular_shuffle_output,
                    inverse_shuffle_output,
                ));
            });

            let outputs_clone = outputs.clone();
            let mac_shares_party1 = mac_shares.clone();
            // party 1
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);

                let mut state = DummyArithCircPrep::<Fr>::new().run(
                    &mut net,
                    5 * n + 2,
                    6 * n + 2,
                    0,
                    5 * n,
                    0,
                );

                let party1_auth_shares = generate_random_auth_shares(&mut state, n);
                mac_shares_party1.lock().unwrap().push(state.key_share());

                // Generate arithmetic permutation circuit state with shuffle tuples
                let mut arith_perm_circ_prep = DummyArithPermCircPrep::<Fr>::new();
                let mut arith_perm_circ_state = arith_perm_circ_prep.run(
                    &mut net,
                    &mut state,
                    vec![ShuffleTupleInput {
                        shuffle_id: "shuffle1".to_string(),
                        shuffle: None,
                        n: n,
                        num_shuffle_tuples: 1,
                        with_inverse: false,
                    }],
                );

                let party1_regular_shuffle_output = Shuffle::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    (
                        permuter_id,
                        "shuffle1".to_string(),
                        party1_auth_shares.clone(),
                    ),
                );

                let party1_inverse_shuffle_output = Shuffle::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    (
                        permuter_id,
                        "shuffle1_inverse".to_string(),
                        party1_auth_shares.clone(),
                    ),
                );

                let regular_shuffle_output = VectorReveal::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state.inner_mut(),
                    party1_regular_shuffle_output.clone(),
                );

                let inverse_shuffle_output = VectorReveal::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state.inner_mut(),
                    party1_inverse_shuffle_output.clone(),
                );

                // Store party 1's results
                outputs_clone.lock().unwrap().push((
                    party1_auth_shares,
                    regular_shuffle_output,
                    inverse_shuffle_output,
                ));
            });
        });

        let combined_outputs = outputs.lock().unwrap();
        let mac = mac_shares.lock().unwrap().iter().sum::<Fr>();

        // Verify the results
        if combined_outputs.len() == 2 {
            let (party0_auth_shares, regular_shuffle_output, inverse_shuffle_output) =
                combined_outputs[0].clone();
            let (party1_auth_shares, _, _) = combined_outputs[1].clone();
            let party0_shuffled_auth_shares = local_shuffle_vector::<AuthShare<Fr>>(
                &shuffle_input_clone_3.clone(),
                &party0_auth_shares,
            );
            let party1_shuffled_auth_shares = local_shuffle_vector::<AuthShare<Fr>>(
                &shuffle_input_clone_3.clone(),
                &party1_auth_shares,
            );
            let party0_unshuffled_auth_shares = local_unshuffle_vector::<AuthShare<Fr>>(
                &shuffle_input_clone_3.clone(),
                &party0_auth_shares,
            );
            let party1_unshuffled_auth_shares = local_unshuffle_vector::<AuthShare<Fr>>(
                &shuffle_input_clone_3.clone(),
                &party1_auth_shares,
            );

            // Verify that the sum of a_share from both parties equals the shuffled input a vector
            for i in 0..n {
                assert_eq!(
                    regular_shuffle_output[i],
                    party0_shuffled_auth_shares[i].value + party1_shuffled_auth_shares[i].value,
                    "ps_share sum mismatch at index {}",
                    i
                );
                assert_eq!(
                    inverse_shuffle_output[i],
                    party0_unshuffled_auth_shares[i].value + party1_unshuffled_auth_shares[i].value,
                    "ps_inverse_share sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    regular_shuffle_output[i] * mac,
                    party0_shuffled_auth_shares[i].mac + party1_shuffled_auth_shares[i].mac,
                    "ps_regular_auth_share sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    inverse_shuffle_output[i] * mac,
                    party0_unshuffled_auth_shares[i].mac + party1_unshuffled_auth_shares[i].mac,
                    "ps_inverse_auth_share sum mismatch at index {}",
                    i
                );
            }
        }
    }

    #[test]
    fn test_online_shuffle_party1() {
        let n = 25;
        let permuter_id = 1;

        // to be inputted
        let shuffle_input = get_random_permutation_usize(n);
        let shuffle_input_clone = shuffle_input.clone();
        let shuffle_input_clone_3 = shuffle_input.clone();

        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        // Shared state to collect outputs
        let outputs = Arc::new(Mutex::new(Vec::new()));
        let mac_shares = Arc::new(Mutex::new(Vec::new()));

        rayon::scope(|s| {
            let outputs_clone = outputs.clone();
            let mac_shares_party0 = mac_shares.clone();
            // party 0
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 0);

                let mut state = DummyArithCircPrep::<Fr>::new().run(
                    &mut net,
                    5 * n + 2,
                    6 * n + 2,
                    0,
                    5 * n,
                    0,
                );

                let party0_auth_shares = generate_random_auth_shares(&mut state, n);

                mac_shares_party0.lock().unwrap().push(state.key_share());

                // Generate arithmetic permutation circuit state with shuffle tuples
                let mut arith_perm_circ_prep = DummyArithPermCircPrep::<Fr>::new();
                let mut arith_perm_circ_state = arith_perm_circ_prep.run(
                    &mut net,
                    &mut state,
                    vec![ShuffleTupleInput {
                        shuffle_id: "shuffle1".to_string(),
                        shuffle: None,
                        n: n,
                        num_shuffle_tuples: 1,
                        with_inverse: false,
                    }],
                );

                let party0_regular_shuffle_output = Shuffle::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    (
                        permuter_id,
                        "shuffle1".to_string(),
                        party0_auth_shares.clone(),
                    ),
                );

                let party0_inverse_shuffle_output = Shuffle::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    (
                        permuter_id,
                        "shuffle1_inverse".to_string(),
                        party0_auth_shares.clone(),
                    ),
                );

                let regular_shuffle_output = VectorReveal::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state.inner_mut(),
                    party0_regular_shuffle_output.clone(),
                );

                let inverse_shuffle_output = VectorReveal::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state.inner_mut(),
                    party0_inverse_shuffle_output.clone(),
                );

                // Store party 0's results
                outputs_clone.lock().unwrap().push((
                    party0_auth_shares,
                    regular_shuffle_output,
                    inverse_shuffle_output,
                ));
            });

            let outputs_clone = outputs.clone();
            let mac_shares_party1 = mac_shares.clone();
            // party 1
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);

                let mut state = DummyArithCircPrep::<Fr>::new().run(
                    &mut net,
                    5 * n + 2,
                    6 * n + 2,
                    0,
                    5 * n,
                    0,
                );

                let party1_auth_shares = generate_random_auth_shares(&mut state, n);
                mac_shares_party1.lock().unwrap().push(state.key_share());

                // Generate arithmetic permutation circuit state with shuffle tuples
                let mut arith_perm_circ_prep = DummyArithPermCircPrep::<Fr>::new();

                let mut arith_perm_circ_state = arith_perm_circ_prep.run(
                    &mut net,
                    &mut state,
                    vec![ShuffleTupleInput {
                        shuffle_id: "shuffle1".to_string(),
                        shuffle: Some(shuffle_input_clone.clone()),
                        n: n,
                        num_shuffle_tuples: 1,
                        with_inverse: false,
                    }],
                );

                let party1_regular_shuffle_output = Shuffle::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    (
                        permuter_id,
                        "shuffle1".to_string(),
                        party1_auth_shares.clone(),
                    ),
                );

                let party1_inverse_shuffle_output = Shuffle::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    (
                        permuter_id,
                        "shuffle1_inverse".to_string(),
                        party1_auth_shares.clone(),
                    ),
                );

                let regular_shuffle_output = VectorReveal::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state.inner_mut(),
                    party1_regular_shuffle_output.clone(),
                );

                let inverse_shuffle_output = VectorReveal::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state.inner_mut(),
                    party1_inverse_shuffle_output.clone(),
                );

                // Store party 1's results
                outputs_clone.lock().unwrap().push((
                    party1_auth_shares,
                    regular_shuffle_output,
                    inverse_shuffle_output,
                ));
            });
        });

        let combined_outputs = outputs.lock().unwrap();
        let mac = mac_shares.lock().unwrap().iter().sum::<Fr>();
        // Verify the results
        if combined_outputs.len() == 2 {
            let (party0_auth_shares, regular_shuffle_output, inverse_shuffle_output) =
                combined_outputs[0].clone();
            let (party1_auth_shares, _, _) = combined_outputs[1].clone();
            let party0_shuffled_auth_shares = local_shuffle_vector::<AuthShare<Fr>>(
                &shuffle_input_clone_3.clone(),
                &party0_auth_shares,
            );
            let party1_shuffled_auth_shares = local_shuffle_vector::<AuthShare<Fr>>(
                &shuffle_input_clone_3.clone(),
                &party1_auth_shares,
            );
            let party0_unshuffled_auth_shares = local_unshuffle_vector::<AuthShare<Fr>>(
                &shuffle_input_clone_3.clone(),
                &party0_auth_shares,
            );
            let party1_unshuffled_auth_shares = local_unshuffle_vector::<AuthShare<Fr>>(
                &shuffle_input_clone_3.clone(),
                &party1_auth_shares,
            );

            // Verify that the sum of a_share from both parties equals the shuffled input a vector
            for i in 0..n {
                assert_eq!(
                    regular_shuffle_output[i],
                    party0_shuffled_auth_shares[i].value + party1_shuffled_auth_shares[i].value,
                    "ps_share sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    regular_shuffle_output[i] * mac,
                    party0_shuffled_auth_shares[i].mac + party1_shuffled_auth_shares[i].mac,
                    "ps_auth_share sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    inverse_shuffle_output[i],
                    party0_unshuffled_auth_shares[i].value + party1_unshuffled_auth_shares[i].value,
                    "ps_inverse_share sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    inverse_shuffle_output[i] * mac,
                    party0_unshuffled_auth_shares[i].mac + party1_unshuffled_auth_shares[i].mac,
                    "ps_inverse_auth_share sum mismatch at index {}",
                    i
                );
            }
        }
    }
}
