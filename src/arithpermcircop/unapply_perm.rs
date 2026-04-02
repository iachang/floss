use std::time::Instant;

use ark_ff::Field;

use crate::{
    arithpermcircop::{
        ArithPermCircOp, ArithPermCircState, perm_network_shuffle::PermNetworkShuffle,
        shuffle::Shuffle, simple_perm_net_shuffle::SimplePermNetShuffle,
        vector_reveal::VectorReveal,
    },
    net::Net,
    primitives::auth::AuthShare,
    utils::rng_utils::{
        get_inverse_permutation, get_random_permutation_usize, shuffle_vector_testing,
    },
};

/// UnapplyPerm(([perm_share]_0, [y]_0), ([perm_share]_1, [y]_1))) -> inverse_perm(y)
pub struct UnapplyPerm<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> UnapplyPerm<F> {
    /// Create a new ArithCircOp instance
    pub fn new() -> Self {
        UnapplyPerm {
            _phantom: std::marker::PhantomData,
        }
    }

    /// Run the apply perm operation with perm network with timing callback
    pub fn run_with_perm_network_timing(
        net: &mut Net,
        state: &mut ArithPermCircState<F>,
        input: (
            String,            // p0_random_shuffle_id
            String,            // p1_random_shuffle_id
            Vec<AuthShare<F>>, // shuffle share
            Vec<AuthShare<F>>, // input auth shares
        ),
        mut timing_callback: &mut dyn FnMut(
            std::time::Duration,
            std::time::Duration,
            (usize, usize),
            (usize, usize),
        ),
    ) -> Vec<AuthShare<F>> {
        let (_, _, perm_auth_share, input_auth_share) = input;

        // Generate random permutation on the fly for perm network shuffle
        let p0_random_perm_for_network = get_random_permutation_usize(perm_auth_share.len());
        let p1_random_perm_for_network = get_random_permutation_usize(perm_auth_share.len());

        let p0_perm_share = if net.party_id() == 0 {
            PermNetworkShuffle::<F>::run_with_timing(
                net,
                state,
                (
                    Some(p0_random_perm_for_network.clone()),
                    perm_auth_share.clone(),
                    false,
                ),
                &mut timing_callback,
            )
        } else {
            PermNetworkShuffle::<F>::run(net, state, (None, perm_auth_share.clone(), false))
        };

        // Apply P1 random shuffle to the P0 + perm share
        let p1p0_shuffle_share = if net.party_id() == 0 {
            PermNetworkShuffle::<F>::run_with_timing(
                net,
                state,
                (None, p0_perm_share.clone(), false),
                &mut timing_callback,
            )
        } else {
            PermNetworkShuffle::<F>::run(
                net,
                state,
                (
                    Some(p1_random_perm_for_network.clone()),
                    p0_perm_share.clone(),
                    false,
                ),
            )
        };

        // Reveal the randomized composed perm shuffle
        let p1p0_perm_shuffle = VectorReveal::<F>::run(net, state, p1p0_shuffle_share.clone());

        // Invert the revealed randomized composed perm shuffle
        let inverse_perm_p0p1_shuffle = get_inverse_permutation(&p1p0_perm_shuffle);

        // Apply P0 random shuffle to the input auth share
        let p0_perm_auth_share = if net.party_id() == 0 {
            PermNetworkShuffle::<F>::run_with_timing(
                net,
                state,
                (
                    Some(p0_random_perm_for_network),
                    input_auth_share.clone(),
                    false,
                ),
                &mut timing_callback,
            )
        } else {
            PermNetworkShuffle::<F>::run(net, state, (None, input_auth_share.clone(), false))
        };

        // Apply P1 random shuffle  to the P0 perm share
        let p1p0_perm_auth_share = if net.party_id() == 0 {
            PermNetworkShuffle::<F>::run_with_timing(
                net,
                state,
                (None, p0_perm_auth_share.clone(), false),
                &mut timing_callback,
            )
        } else {
            PermNetworkShuffle::<F>::run(
                net,
                state,
                (
                    Some(p1_random_perm_for_network),
                    p0_perm_auth_share.clone(),
                    false,
                ),
            )
        };

        // Applying public permutation to secret shares creates permutation shares
        let unapply_perm_output =
            shuffle_vector_testing(&inverse_perm_p0p1_shuffle, &p1p0_perm_auth_share);

        unapply_perm_output
    }

    /// Run the unapply perm operation with floss with timing callback
    pub fn run_with_floss_timing(
        net: &mut Net,
        state: &mut ArithPermCircState<F>,
        input: (
            String,            // p0_random_shuffle_id
            String,            // p1_random_shuffle_id
            Vec<AuthShare<F>>, // shuffle share
            Vec<AuthShare<F>>, // input auth shares
        ),
        timing_callback: &mut dyn FnMut(std::time::Duration),
    ) -> Vec<AuthShare<F>> {
        let (p0_random_shuffle_id, p1_random_shuffle_id, perm_auth_share, input_auth_share) = input;

        let shuffle_time_0 = Instant::now();
        let p0_perm_share = Shuffle::<F>::run(
            net,
            state,
            (0, p0_random_shuffle_id.clone(), perm_auth_share.clone()),
        );
        let p1p0_shuffle_share = Shuffle::<F>::run(
            net,
            state,
            (1, p1_random_shuffle_id.clone(), p0_perm_share.clone()),
        );
        timing_callback(shuffle_time_0.elapsed());

        let p1p0_perm_shuffle = VectorReveal::<F>::run(net, state, p1p0_shuffle_share.clone());
        let inverse_perm_p0p1_shuffle = get_inverse_permutation(&p1p0_perm_shuffle);
        let shuffle_time_1 = Instant::now();
        let p0_perm_auth_share = Shuffle::<F>::run(
            net,
            state,
            (0, p0_random_shuffle_id.clone(), input_auth_share.clone()),
        );
        let p1p0_perm_auth_share = Shuffle::<F>::run(
            net,
            state,
            (1, p1_random_shuffle_id.clone(), p0_perm_auth_share.clone()),
        );
        timing_callback(shuffle_time_1.elapsed());
        let unapply_perm_output =
            shuffle_vector_testing(&inverse_perm_p0p1_shuffle, &p1p0_perm_auth_share);

        unapply_perm_output
    }

    /// Run the unapply perm operation with simple perm network with timing callback
    pub fn run_with_simple_perm_network_timing(
        net: &mut Net,
        state: &mut ArithPermCircState<F>,
        input: (
            Vec<AuthShare<F>>, // shuffle share
            Vec<AuthShare<F>>, // input auth shares
        ),
        timing_callback: &mut dyn FnMut(std::time::Duration),
    ) -> Vec<AuthShare<F>> {
        let (perm_auth_share, input_auth_share) = input;
        // Generate random permutation on the fly for perm network shuffle
        let p0_random_perm_for_network = get_random_permutation_usize(perm_auth_share.len());
        let p1_random_perm_for_network = get_random_permutation_usize(perm_auth_share.len());

        let shuffle_time_0 = Instant::now();
        let p0_perm_share = if net.party_id() == 0 {
            SimplePermNetShuffle::<F>::run(
                net,
                state,
                (
                    Some(p0_random_perm_for_network.clone()),
                    perm_auth_share.clone(),
                    false,
                ),
            )
        } else {
            SimplePermNetShuffle::<F>::run(net, state, (None, perm_auth_share.clone(), false))
        };
        timing_callback(shuffle_time_0.elapsed());

        // Apply P1 random shuffle to the P0 + perm share
        let shuffle_time_1 = Instant::now();
        let p1p0_shuffle_share = if net.party_id() == 0 {
            SimplePermNetShuffle::<F>::run(net, state, (None, p0_perm_share.clone(), false))
        } else {
            SimplePermNetShuffle::<F>::run(
                net,
                state,
                (
                    Some(p1_random_perm_for_network.clone()),
                    p0_perm_share.clone(),
                    false,
                ),
            )
        };
        timing_callback(shuffle_time_1.elapsed());

        // Reveal the randomized composed perm shuffle
        let p1p0_perm_shuffle = VectorReveal::<F>::run(net, state, p1p0_shuffle_share.clone());

        // Invert the revealed randomized composed perm shuffle
        let inverse_perm_p0p1_shuffle = get_inverse_permutation(&p1p0_perm_shuffle);

        // Apply P0 random shuffle to the input auth share
        let shuffle_time_2 = Instant::now();
        let p0_perm_auth_share = if net.party_id() == 0 {
            SimplePermNetShuffle::<F>::run(
                net,
                state,
                (
                    Some(p0_random_perm_for_network),
                    input_auth_share.clone(),
                    false,
                ),
            )
        } else {
            SimplePermNetShuffle::<F>::run(net, state, (None, input_auth_share.clone(), false))
        };
        timing_callback(shuffle_time_2.elapsed());

        // Apply P1 random shuffle  to the P0 perm share
        let shuffle_time_3 = Instant::now();
        let p1p0_perm_auth_share = if net.party_id() == 0 {
            SimplePermNetShuffle::<F>::run(net, state, (None, p0_perm_auth_share.clone(), false))
        } else {
            SimplePermNetShuffle::<F>::run(
                net,
                state,
                (
                    Some(p1_random_perm_for_network),
                    p0_perm_auth_share.clone(),
                    false,
                ),
            )
        };
        timing_callback(shuffle_time_3.elapsed());

        // Applying public permutation to secret shares creates permutation shares
        let unapply_perm_output =
            shuffle_vector_testing(&inverse_perm_p0p1_shuffle, &p1p0_perm_auth_share);

        unapply_perm_output
    }
}

impl<F: Field> ArithPermCircOp<F> for UnapplyPerm<F> {
    type In = (
        String,            // p0_random_shuffle_id
        String,            // p1_random_shuffle_id
        Vec<AuthShare<F>>, // shuffle share
        Vec<AuthShare<F>>, // input auth shares (to perform inverse shuffle)
        bool,              // with perm network
    );
    type Out = Vec<AuthShare<F>>;

    // Requires two regular shuffle tuples, no inverse shuffle tuples.
    fn run(net: &mut Net, state: &mut ArithPermCircState<F>, input: Self::In) -> Self::Out {
        let (
            p0_random_shuffle_id,
            p1_random_shuffle_id,
            perm_auth_share,
            input_auth_share,
            with_perm_network,
        ) = input;

        // Generate random permutation on the fly for perm network shuffle
        let p0_random_perm_for_network = get_random_permutation_usize(perm_auth_share.len());
        let p1_random_perm_for_network = get_random_permutation_usize(perm_auth_share.len());

        let p0_perm_share = if with_perm_network {
            if net.party_id() == 0 {
                PermNetworkShuffle::<F>::run(
                    net,
                    state,
                    (
                        Some(p0_random_perm_for_network.clone()),
                        perm_auth_share.clone(),
                        false,
                    ),
                )
            } else {
                PermNetworkShuffle::<F>::run(net, state, (None, perm_auth_share.clone(), false))
            }
        } else {
            Shuffle::<F>::run(
                net,
                state,
                (0, p0_random_shuffle_id.clone(), perm_auth_share.clone()),
            )
        };

        // Apply P1 random shuffle to the P0 + perm share
        let p1p0_shuffle_share = if with_perm_network {
            if net.party_id() == 0 {
                PermNetworkShuffle::<F>::run(net, state, (None, p0_perm_share.clone(), false))
            } else {
                PermNetworkShuffle::<F>::run(
                    net,
                    state,
                    (
                        Some(p1_random_perm_for_network.clone()),
                        p0_perm_share.clone(),
                        false,
                    ),
                )
            }
        } else {
            Shuffle::<F>::run(
                net,
                state,
                (1, p1_random_shuffle_id.clone(), p0_perm_share.clone()),
            )
        };

        // Reveal the randomized composed perm shuffle
        let p1p0_perm_shuffle = VectorReveal::<F>::run(net, state, p1p0_shuffle_share.clone());

        // Invert the revealed randomized composed perm shuffle
        let inverse_perm_p0p1_shuffle = get_inverse_permutation(&p1p0_perm_shuffle);

        // Apply P0 random shuffle to the input auth share
        let p0_perm_auth_share = if with_perm_network {
            if net.party_id() == 0 {
                PermNetworkShuffle::<F>::run(
                    net,
                    state,
                    (
                        Some(p0_random_perm_for_network),
                        input_auth_share.clone(),
                        false,
                    ),
                )
            } else {
                PermNetworkShuffle::<F>::run(net, state, (None, input_auth_share.clone(), false))
            }
        } else {
            Shuffle::<F>::run(
                net,
                state,
                (0, p0_random_shuffle_id.clone(), input_auth_share.clone()),
            )
        };

        // Apply P1 random shuffle  to the P0 perm share
        let p1p0_perm_auth_share = if with_perm_network {
            if net.party_id() == 0 {
                PermNetworkShuffle::<F>::run(net, state, (None, p0_perm_auth_share.clone(), false))
            } else {
                PermNetworkShuffle::<F>::run(
                    net,
                    state,
                    (
                        Some(p1_random_perm_for_network),
                        p0_perm_auth_share.clone(),
                        false,
                    ),
                )
            }
        } else {
            Shuffle::<F>::run(
                net,
                state,
                (1, p1_random_shuffle_id.clone(), p0_perm_auth_share.clone()),
            )
        };

        // Applying public permutation to secret shares creates permutation shares
        let unapply_perm_output =
            shuffle_vector_testing(&inverse_perm_p0p1_shuffle, &p1p0_perm_auth_share);

        unapply_perm_output
    }
}

#[cfg(test)]
mod test {
    use rand::Rng;

    use crate::arithcircop::ArithCircOp;
    use crate::arithcircop::vector_input::VectorInput;
    use crate::arithcircprep::ArithCircPrep;
    use crate::arithpermcircprep::{ArithPermCircPrep, ShuffleTupleInput};
    use crate::utils::rng_utils::{get_random_permutation_usize, unshuffle_vector_testing};
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
    fn test_unapply_perm() {
        let n = 25;

        // to be inputted
        let random_shuffle_p0 = get_random_permutation_usize(n);
        let random_shuffle_p1 = get_random_permutation_usize(n);

        let random_shuffle_to_share = get_random_permutation_usize(n)
            .into_iter()
            .map(|x| Fr::from(x as u64))
            .collect::<Vec<Fr>>();
        let random_shuffle_to_share_clone = random_shuffle_to_share.clone();
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
                    20 * n + 2,
                    21 * n + 2,
                    0,
                    20 * n,
                    0,
                );

                let party0_auth_shares = generate_random_auth_shares(&mut state, n);
                mac_shares_party0.lock().unwrap().push(state.key_share());

                let random_shuffle_shares_p0 = VectorInput::<Fr>::run(
                    &mut net,
                    &mut state,
                    (0, Some(random_shuffle_to_share.clone()), None),
                );

                // Generate arithmetic permutation circuit state with shuffle tuples
                let mut arith_perm_circ_prep = DummyArithPermCircPrep::<Fr>::new();
                let mut arith_perm_circ_state = arith_perm_circ_prep.run(
                    &mut net,
                    &mut state,
                    vec![
                        ShuffleTupleInput {
                            shuffle_id: "random_shuffle_p0".to_string(),
                            shuffle: Some(random_shuffle_p0.clone()),
                            n: n,
                            num_shuffle_tuples: 2,
                            with_inverse: true,
                        },
                        ShuffleTupleInput {
                            shuffle_id: "random_shuffle_p1".to_string(),
                            shuffle: None,
                            n: n,
                            num_shuffle_tuples: 2,
                            with_inverse: false,
                        },
                    ],
                );

                let party0_unapply_perm_output = UnapplyPerm::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    (
                        "random_shuffle_p0".to_string(),
                        "random_shuffle_p1".to_string(),
                        random_shuffle_shares_p0.clone(),
                        party0_auth_shares.clone(),
                        false,
                    ),
                );

                let unapply_perm_output = VectorReveal::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    party0_unapply_perm_output.clone(),
                );

                // Store party 0's results
                outputs_clone
                    .lock()
                    .unwrap()
                    .push((party0_auth_shares, unapply_perm_output));
            });

            let outputs_clone = outputs.clone();
            let mac_shares_party1 = mac_shares.clone();
            // party 1
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);

                let mut state = DummyArithCircPrep::<Fr>::new().run(
                    &mut net,
                    20 * n + 2,
                    21 * n + 2,
                    0,
                    20 * n,
                    0,
                );

                let party1_auth_shares = generate_random_auth_shares(&mut state, n);
                mac_shares_party1.lock().unwrap().push(state.key_share());

                let random_shuffle_shares_p1 =
                    VectorInput::<Fr>::run(&mut net, &mut state, (0, None, Some(n)));

                // Generate arithmetic permutation circuit state with shuffle tuples
                let mut arith_perm_circ_prep = DummyArithPermCircPrep::<Fr>::new();
                let mut arith_perm_circ_state = arith_perm_circ_prep.run(
                    &mut net,
                    &mut state,
                    vec![
                        ShuffleTupleInput {
                            shuffle_id: "random_shuffle_p0".to_string(),
                            shuffle: None,
                            n: n,
                            num_shuffle_tuples: 2,
                            with_inverse: true,
                        },
                        ShuffleTupleInput {
                            shuffle_id: "random_shuffle_p1".to_string(),
                            shuffle: Some(random_shuffle_p1.clone()),
                            n: n,
                            num_shuffle_tuples: 2,
                            with_inverse: true,
                        },
                    ],
                );

                let party1_unapply_perm_output = UnapplyPerm::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    (
                        "random_shuffle_p0".to_string(),
                        "random_shuffle_p1".to_string(),
                        random_shuffle_shares_p1.clone(),
                        party1_auth_shares.clone(),
                        false,
                    ),
                );

                let unapply_perm_output = VectorReveal::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    party1_unapply_perm_output.clone(),
                );

                // Store party 1's results
                outputs_clone
                    .lock()
                    .unwrap()
                    .push((party1_auth_shares, unapply_perm_output));
            });
        });

        let combined_outputs = outputs.lock().unwrap();
        let mac = mac_shares.lock().unwrap().iter().sum::<Fr>();
        // Verify the results
        if combined_outputs.len() == 2 {
            let (party0_auth_shares, unapply_perm_output) = combined_outputs[0].clone();
            let (party1_auth_shares, _) = combined_outputs[1].clone();
            let party0_unshuffled_auth_shares = unshuffle_vector_testing::<Fr, AuthShare<Fr>>(
                &random_shuffle_to_share_clone.clone(),
                &party0_auth_shares,
            );
            let party1_unshuffled_auth_shares = unshuffle_vector_testing::<Fr, AuthShare<Fr>>(
                &random_shuffle_to_share_clone.clone(),
                &party1_auth_shares,
            );

            // TODO: run VectorReveal to reconstruct the authenticated shares instead of summing them afterwards
            // Verify that the sum of a_share from both parties equals the shuffled input a vector
            for i in 0..n {
                assert_eq!(
                    unapply_perm_output[i],
                    party0_unshuffled_auth_shares[i].value + party1_unshuffled_auth_shares[i].value,
                    "ps_share sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    unapply_perm_output[i] * mac,
                    party0_unshuffled_auth_shares[i].mac + party1_unshuffled_auth_shares[i].mac,
                    "ps_auth_share sum mismatch at index {}",
                    i,
                );
            }
        }
    }

    #[test]
    fn test_unapply_perm_with_perm_network() {
        let n = 25;

        let random_shuffle_to_share = get_random_permutation_usize(n)
            .into_iter()
            .map(|x| Fr::from(x as u64))
            .collect::<Vec<Fr>>();
        let random_shuffle_to_share_clone = random_shuffle_to_share.clone();
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
                    80 * n + 2,
                    160 * n + 2,
                    80 * n,
                    160 * n,
                    0,
                );

                let party0_auth_shares = generate_random_auth_shares(&mut state, n);
                mac_shares_party0.lock().unwrap().push(state.key_share());

                let random_shuffle_shares_p0 = VectorInput::<Fr>::run(
                    &mut net,
                    &mut state,
                    (0, Some(random_shuffle_to_share.clone()), None),
                );

                // Generate arithmetic permutation circuit state with shuffle tuples
                let mut arith_perm_circ_prep = DummyArithPermCircPrep::<Fr>::new();
                let mut arith_perm_circ_state =
                    arith_perm_circ_prep.run(&mut net, &mut state, vec![]);

                let party0_unapply_perm_output = UnapplyPerm::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    (
                        "random_shuffle_p0".to_string(),
                        "random_shuffle_p1".to_string(),
                        random_shuffle_shares_p0.clone(),
                        party0_auth_shares.clone(),
                        true,
                    ),
                );

                let unapply_perm_output = VectorReveal::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    party0_unapply_perm_output.clone(),
                );

                // Store party 0's results
                outputs_clone
                    .lock()
                    .unwrap()
                    .push((party0_auth_shares, unapply_perm_output));
            });

            let outputs_clone = outputs.clone();
            let mac_shares_party1 = mac_shares.clone();
            // party 1
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);

                let mut state = DummyArithCircPrep::<Fr>::new().run(
                    &mut net,
                    80 * n + 2,
                    160 * n + 2,
                    80 * n,
                    160 * n,
                    0,
                );

                let party1_auth_shares = generate_random_auth_shares(&mut state, n);
                mac_shares_party1.lock().unwrap().push(state.key_share());

                let random_shuffle_shares_p1 =
                    VectorInput::<Fr>::run(&mut net, &mut state, (0, None, Some(n)));

                // Generate arithmetic permutation circuit state with shuffle tuples
                let mut arith_perm_circ_prep = DummyArithPermCircPrep::<Fr>::new();
                let mut arith_perm_circ_state =
                    arith_perm_circ_prep.run(&mut net, &mut state, vec![]);

                let party1_unapply_perm_output = UnapplyPerm::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    (
                        "random_shuffle_p0".to_string(),
                        "random_shuffle_p1".to_string(),
                        random_shuffle_shares_p1.clone(),
                        party1_auth_shares.clone(),
                        true,
                    ),
                );

                let unapply_perm_output = VectorReveal::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    party1_unapply_perm_output.clone(),
                );

                // Store party 1's results
                outputs_clone
                    .lock()
                    .unwrap()
                    .push((party1_auth_shares, unapply_perm_output));
            });
        });

        let combined_outputs = outputs.lock().unwrap();
        let mac = mac_shares.lock().unwrap().iter().sum::<Fr>();
        // Verify the results
        if combined_outputs.len() == 2 {
            let (party0_auth_shares, unapply_perm_output) = combined_outputs[0].clone();
            let (party1_auth_shares, _) = combined_outputs[1].clone();
            let party0_unshuffled_auth_shares = unshuffle_vector_testing::<Fr, AuthShare<Fr>>(
                &random_shuffle_to_share_clone.clone(),
                &party0_auth_shares,
            );
            let party1_unshuffled_auth_shares = unshuffle_vector_testing::<Fr, AuthShare<Fr>>(
                &random_shuffle_to_share_clone.clone(),
                &party1_auth_shares,
            );

            // TODO: run VectorReveal to reconstruct the authenticated shares instead of summing them afterwards
            // Verify that the sum of a_share from both parties equals the shuffled input a vector
            for i in 0..n {
                assert_eq!(
                    unapply_perm_output[i],
                    party0_unshuffled_auth_shares[i].value + party1_unshuffled_auth_shares[i].value,
                    "ps_share sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    unapply_perm_output[i] * mac,
                    party0_unshuffled_auth_shares[i].mac + party1_unshuffled_auth_shares[i].mac,
                    "ps_auth_share sum mismatch at index {}",
                    i,
                );
            }
        }
    }

    /// Run the unapply perm operation with simple perm network with timing callback
    #[test]
    fn test_unapply_perm_with_simple_perm_network() {
        let n = 25;

        let random_shuffle_to_share = get_random_permutation_usize(n)
            .into_iter()
            .map(|x| Fr::from(x as u64))
            .collect::<Vec<Fr>>();
        let random_shuffle_to_share_clone = random_shuffle_to_share.clone();
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
                    80 * n + 2,
                    160 * n + 2,
                    80 * n,
                    160 * n,
                    0,
                );

                let party0_auth_shares = generate_random_auth_shares(&mut state, n);
                mac_shares_party0.lock().unwrap().push(state.key_share());

                let random_shuffle_shares_p0 = VectorInput::<Fr>::run(
                    &mut net,
                    &mut state,
                    (0, Some(random_shuffle_to_share.clone()), None),
                );

                // Generate arithmetic permutation circuit state with shuffle tuples
                let mut arith_perm_circ_prep = DummyArithPermCircPrep::<Fr>::new();
                let mut arith_perm_circ_state =
                    arith_perm_circ_prep.run(&mut net, &mut state, vec![]);

                let mut shuffle_time_duration_unapply_perm = std::time::Duration::ZERO;
                let party0_unapply_perm_output =
                    UnapplyPerm::<Fr>::run_with_simple_perm_network_timing(
                        &mut net,
                        &mut arith_perm_circ_state,
                        (random_shuffle_shares_p0.clone(), party0_auth_shares.clone()),
                        &mut |shuffle_time| {
                            shuffle_time_duration_unapply_perm += shuffle_time;
                        },
                    );

                let unapply_perm_output = VectorReveal::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    party0_unapply_perm_output.clone(),
                );

                // Store party 0's results
                outputs_clone
                    .lock()
                    .unwrap()
                    .push((party0_auth_shares, unapply_perm_output));
            });

            let outputs_clone = outputs.clone();
            let mac_shares_party1 = mac_shares.clone();
            // party 1
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);

                let mut state = DummyArithCircPrep::<Fr>::new().run(
                    &mut net,
                    80 * n + 2,
                    160 * n + 2,
                    80 * n,
                    160 * n,
                    0,
                );

                let party1_auth_shares = generate_random_auth_shares(&mut state, n);
                mac_shares_party1.lock().unwrap().push(state.key_share());

                let random_shuffle_shares_p1 =
                    VectorInput::<Fr>::run(&mut net, &mut state, (0, None, Some(n)));

                // Generate arithmetic permutation circuit state with shuffle tuples
                let mut arith_perm_circ_prep = DummyArithPermCircPrep::<Fr>::new();
                let mut arith_perm_circ_state =
                    arith_perm_circ_prep.run(&mut net, &mut state, vec![]);

                let mut shuffle_time_duration_unapply_perm = std::time::Duration::ZERO;
                let party1_unapply_perm_output =
                    UnapplyPerm::<Fr>::run_with_simple_perm_network_timing(
                        &mut net,
                        &mut arith_perm_circ_state,
                        (random_shuffle_shares_p1.clone(), party1_auth_shares.clone()),
                        &mut |shuffle_time| {
                            shuffle_time_duration_unapply_perm += shuffle_time;
                        },
                    );

                let unapply_perm_output = VectorReveal::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    party1_unapply_perm_output.clone(),
                );

                // Store party 1's results
                outputs_clone
                    .lock()
                    .unwrap()
                    .push((party1_auth_shares, unapply_perm_output));
            });
        });

        let combined_outputs = outputs.lock().unwrap();
        let mac = mac_shares.lock().unwrap().iter().sum::<Fr>();
        // Verify the results
        if combined_outputs.len() == 2 {
            let (party0_auth_shares, unapply_perm_output) = combined_outputs[0].clone();
            let (party1_auth_shares, _) = combined_outputs[1].clone();
            let party0_unshuffled_auth_shares = unshuffle_vector_testing::<Fr, AuthShare<Fr>>(
                &random_shuffle_to_share_clone.clone(),
                &party0_auth_shares,
            );
            let party1_unshuffled_auth_shares = unshuffle_vector_testing::<Fr, AuthShare<Fr>>(
                &random_shuffle_to_share_clone.clone(),
                &party1_auth_shares,
            );

            // TODO: run VectorReveal to reconstruct the authenticated shares instead of summing them afterwards
            // Verify that the sum of a_share from both parties equals the shuffled input a vector
            for i in 0..n {
                assert_eq!(
                    unapply_perm_output[i],
                    party0_unshuffled_auth_shares[i].value + party1_unshuffled_auth_shares[i].value,
                    "ps_share sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    unapply_perm_output[i] * mac,
                    party0_unshuffled_auth_shares[i].mac + party1_unshuffled_auth_shares[i].mac,
                    "ps_auth_share sum mismatch at index {}",
                    i,
                );
            }
        }
    }
}
