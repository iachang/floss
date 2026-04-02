//! Implementations of shuffle tuple preprocessing schemes for the MPC protocol.

use ark_ff::Field;

use crate::{
    arithcircop::{ArithCircOp, ArithCircState, vector_input::VectorInput, vector_mul::VectorMul},
    arithpermcircop::{
        ArithPermCircOp, ArithPermCircState, ShuffleVecType, blind_auth_queue::BlindAuthQueue,
    },
    net::Net,
    primitives::auth::{AuthShare, KAuthShare},
    utils::vector_utils::extend_vector,
};

/// Struct for a shuffle tuple input
#[derive(Clone)]
pub struct ShuffleTupleInput {
    pub(crate) shuffle_id: String,
    pub(crate) shuffle: Option<ShuffleVecType>,
    pub(crate) n: usize,
    pub(crate) num_shuffle_tuples: usize,
    pub(crate) with_inverse: bool,
}

/// Trait for shuffle tuple preprocessing schemes.
pub trait ArithPermCircPrep<F: Field> {
    // Preprocesses everything in ArithCircPrep, but also generates shuffle and inverse shuffle tuples.
    /// Returns the preprocessing outputs.
    fn run(
        &mut self,
        net: &mut Net,
        arith_circ_state: &mut ArithCircState<F>,
        shuffle_tuples: Vec<ShuffleTupleInput>,
    ) -> ArithPermCircState<F>;
}

/// Apply k to shuffle tuples.
pub fn apply_k_to_shuffle_tuples<F: Field>(
    permuting_party: usize,
    input_shares: Vec<Vec<AuthShare<F>>>,
    state: &mut ArithPermCircState<F>,
    net: &mut Net,
    k_values: Option<Vec<F>>,
) -> Vec<Vec<KAuthShare<F>>> {
    let num_k = input_shares.len();
    let k_shares = VectorInput::<F>::run(
        net,
        state.inner_mut(),
        (permuting_party, k_values.clone(), Some(num_k)),
    );
    let flattened_input_shares: Vec<AuthShare<F>> = input_shares.into_iter().flatten().collect();
    let input_size = flattened_input_shares.len() / k_shares.len();

    let flattened_input_k_shares: Vec<AuthShare<F>> = VectorMul::<F>::run(
        net,
        state.inner_mut(),
        (
            flattened_input_shares.clone(),
            (0..k_shares.len())
                .map(|i| vec![k_shares[i]; input_size])
                .collect::<Vec<Vec<AuthShare<F>>>>()
                .into_iter()
                .flatten()
                .collect(),
        ),
    );

    // Queue blinded auth shares for auth check for |a| and |K*a| over keys alpha, beta, alpha * beta
    BlindAuthQueue::<F>::run(
        net,
        state,
        extend_vector::<F, AuthShare<F>>(
            flattened_input_shares.clone(),
            flattened_input_k_shares.clone(),
        ),
    );

    let shuffle_tuples = (0..k_shares.len())
        .map(|i| {
            (0..input_size)
                .map(|j| KAuthShare {
                    k: if permuting_party == net.party_id() {
                        Some(k_values.as_ref().unwrap()[i])
                    } else {
                        None
                    },
                    value: flattened_input_shares[i * input_size + j].value,
                    mac: flattened_input_shares[i * input_size + j].mac,
                    kvalue: flattened_input_k_shares[i * input_size + j].value,
                    kmac: flattened_input_k_shares[i * input_size + j].mac,
                })
                .collect::<Vec<KAuthShare<F>>>()
        })
        .collect::<Vec<Vec<KAuthShare<F>>>>();
    return shuffle_tuples;
}

/// Apply kappa rand to shuffle and inverse shuffle tuples.
pub fn apply_k_to_shuffle_and_inverse_shuffle_tuples<F: Field>(
    permuting_party: usize,
    input_shares: Vec<Vec<AuthShare<F>>>,
    inverse_input_shares: Vec<Vec<AuthShare<F>>>,
    state: &mut ArithPermCircState<F>,
    net: &mut Net,
    k_values: Option<Vec<F>>,
) -> (Vec<Vec<KAuthShare<F>>>, Vec<Vec<KAuthShare<F>>>) {
    let num_k = input_shares.len();
    let k_shares = VectorInput::<F>::run(
        net,
        state.inner_mut(),
        (permuting_party, k_values.clone(), Some(num_k)),
    );
    let flattened_input_shares: Vec<AuthShare<F>> = input_shares.into_iter().flatten().collect();
    let flattened_inverse_input_shares: Vec<AuthShare<F>> =
        inverse_input_shares.into_iter().flatten().collect();
    let input_size = flattened_input_shares.len() / k_shares.len();

    let flattened_input_k_shares: Vec<AuthShare<F>> = VectorMul::<F>::run(
        net,
        state.inner_mut(),
        (
            flattened_input_shares.clone(),
            (0..k_shares.len())
                .map(|i| vec![k_shares[i]; input_size])
                .collect::<Vec<Vec<AuthShare<F>>>>()
                .into_iter()
                .flatten()
                .collect(),
        ),
    );
    let flattened_inverse_input_k_shares: Vec<AuthShare<F>> = VectorMul::<F>::run(
        net,
        state.inner_mut(),
        (
            flattened_inverse_input_shares.clone(),
            (0..k_shares.len())
                .map(|i| vec![k_shares[i]; input_size])
                .collect::<Vec<Vec<AuthShare<F>>>>()
                .into_iter()
                .flatten()
                .collect(),
        ),
    );
    // Queue blinded auth shares for auth check for |a| and |K*a| over keys alpha, beta, alpha * beta
    BlindAuthQueue::<F>::run(
        net,
        state,
        extend_vector::<F, AuthShare<F>>(
            extend_vector::<F, AuthShare<F>>(
                flattened_input_shares.clone(),
                flattened_input_k_shares.clone(),
            ),
            extend_vector::<F, AuthShare<F>>(
                flattened_inverse_input_shares.clone(),
                flattened_inverse_input_k_shares.clone(),
            ),
        ),
    );

    // Flushing the auth share check queue should pass
    // let to_check_auth_shares = state.inner_mut().drain_to_check_auth_shares();
    // let (opened_values, auth_shares) = (
    //     to_check_auth_shares
    //         .iter()
    //         .map(|(opened_value, _)| *opened_value)
    //         .collect(),
    //     to_check_auth_shares
    //         .iter()
    //         .map(|(_, auth_share)| *auth_share)
    //         .collect(),
    // );
    // OpenedAuthCheck::<F>::run(
    //     net,
    //     state.inner_mut(),
    //     (key_share.0, opened_values, auth_shares),
    // );

    // If passes, Auth(|x|, |K*x|) is good. Store values in preprocessing.
    let shuffle_tuples = (0..k_shares.len())
        .map(|i| {
            (0..input_size)
                .map(|j| KAuthShare {
                    k: if permuting_party == net.party_id() {
                        Some(k_values.as_ref().unwrap()[i])
                    } else {
                        None
                    },
                    value: flattened_input_shares[i * input_size + j].value,
                    mac: flattened_input_shares[i * input_size + j].mac,
                    kvalue: flattened_input_k_shares[i * input_size + j].value,
                    kmac: flattened_input_k_shares[i * input_size + j].mac,
                })
                .collect::<Vec<KAuthShare<F>>>()
        })
        .collect::<Vec<Vec<KAuthShare<F>>>>();
    let inverse_shuffle_tuples = (0..k_shares.len())
        .map(|i| {
            (0..input_size)
                .map(|j| KAuthShare {
                    k: if permuting_party == net.party_id() {
                        Some(k_values.as_ref().unwrap()[i])
                    } else {
                        None
                    },
                    value: flattened_inverse_input_shares[i * input_size + j].value,
                    mac: flattened_inverse_input_shares[i * input_size + j].mac,
                    kvalue: flattened_inverse_input_k_shares[i * input_size + j].value,
                    kmac: flattened_inverse_input_k_shares[i * input_size + j].mac,
                })
                .collect::<Vec<KAuthShare<F>>>()
        })
        .collect::<Vec<Vec<KAuthShare<F>>>>();
    return (shuffle_tuples, inverse_shuffle_tuples);
}

/// Dummy preprocessing that implements the shuffle tuple generation functionality.
pub mod dummy;

/// O(1) round Perm network implementation of preprocessing for shuffling
pub mod perm_network;

/// O(log n) round Perm Network implementation of preprocessing for shuffling
pub mod simple_perm_network;

/// Waksman helper
pub mod waksman;

#[cfg(test)]
mod test {
    use ark_ff::UniformRand;
    use rand::Rng;

    use crate::{
        arithcircprep::{ArithCircPrep, dummy::DummyArithCircPrep},
        arithpermcircop::{ShuffleTuple, exec_blind_auth_check::ExecBlindAuthCheck},
        arithpermcircprep::{
            dummy::DummyArithPermCircPrep, perm_network::PermNetworkArithPermCircPrep,
            simple_perm_network::SimplePermNetworkArithPermCircPrep,
        },
        primitives::auth::KAuthShare,
        utils::{
            rng_utils::{
                get_random_permutation_usize, get_random_rng, local_shuffle_vector,
                local_unshuffle_vector,
            },
            testing_utils::generate_random_auth_shares,
        },
    };

    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use tempfile::NamedTempFile;
    type Fr = crate::bench::Mersenne64Fq;

    #[test]
    fn test_apply_k_and_reshare_dim1() {
        let n = 25;

        // Party 0 owns key K
        let k = Fr::rand(&mut get_random_rng());
        let k_values = vec![k; 1];

        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        let party0_input_shares = Arc::new(Mutex::new(Vec::<AuthShare<Fr>>::new()));
        let party1_input_shares = Arc::new(Mutex::new(Vec::<AuthShare<Fr>>::new()));

        // Shared state to collect outputs
        let outputs = Arc::new(Mutex::new(Vec::<Vec<KAuthShare<Fr>>>::new()));
        let mac_shares = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Fr>::new()));
        rayon::scope(|s| {
            let outputs_clone = outputs.clone();
            let mac_shares_party0 = mac_shares.clone();
            let party0_input_shares_clone = party0_input_shares.clone();
            // party 0
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 0);

                let mut state =
                    DummyArithCircPrep::<Fr>::new().run(&mut net, 2 * n, 3 * n, 0, 2 * n, 0);

                mac_shares_party0.lock().unwrap().push(state.key_share());
                let party0_auth_shares = generate_random_auth_shares(&mut state, n);
                *party0_input_shares_clone.lock().unwrap() = party0_auth_shares.clone();

                let mut perm_state =
                    DummyArithPermCircPrep::<Fr>::new().run(&mut net, &mut state, vec![]);

                // Input k as authenticated share
                let (k_shuffle_tuples, _) = apply_k_to_shuffle_and_inverse_shuffle_tuples(
                    0,
                    vec![party0_auth_shares.clone()],
                    vec![party0_auth_shares.clone()],
                    &mut perm_state,
                    &mut net,
                    Some(k_values.clone()),
                );

                // Store party 0's results
                outputs_clone
                    .lock()
                    .unwrap()
                    .push(k_shuffle_tuples.into_iter().flatten().collect());
            });

            let outputs_clone = outputs.clone();
            let mac_shares_party1 = mac_shares.clone();
            let party1_input_shares_clone = party1_input_shares.clone();
            // party 1
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);

                let mut state =
                    DummyArithCircPrep::<Fr>::new().run(&mut net, 2 * n, 3 * n, 0, 2 * n, 0);

                mac_shares_party1.lock().unwrap().push(state.key_share());

                let party1_auth_shares = generate_random_auth_shares(&mut state, n);
                *party1_input_shares_clone.lock().unwrap() = party1_auth_shares.clone();

                let mut perm_state =
                    DummyArithPermCircPrep::<Fr>::new().run(&mut net, &mut state, vec![]);

                // Input k as authenticated share
                let (k_shuffle_tuples, _) = apply_k_to_shuffle_and_inverse_shuffle_tuples(
                    0,
                    vec![party1_auth_shares.clone()],
                    vec![party1_auth_shares.clone()],
                    &mut perm_state,
                    &mut net,
                    None,
                );

                // Store party 1's results
                outputs_clone
                    .lock()
                    .unwrap()
                    .push(k_shuffle_tuples.into_iter().flatten().collect());
            });
        });

        let mac = mac_shares.lock().unwrap().iter().sum::<Fr>();
        let combined_outputs = outputs.lock().unwrap();

        // Verify the results
        if combined_outputs.len() == 2 {
            let party0_idx = if combined_outputs[0][0].k == None {
                1
            } else {
                0
            };

            let party0_output: Vec<KAuthShare<Fr>> =
                combined_outputs[party0_idx].clone().into_iter().collect();

            let party1_output: Vec<KAuthShare<Fr>> = combined_outputs[1 - party0_idx]
                .clone()
                .into_iter()
                .collect();

            // Check that party 0 has the key k and party 1 does not
            for i in 0..n {
                assert_eq!(party0_output[i].k, Some(k));
                assert_eq!(party1_output[i].k, None);
            }

            // Generate same input shares (with same seed) to deal with borrowing issues
            let party0_input_shares: Vec<AuthShare<Fr>> =
                party0_input_shares.lock().unwrap().clone();
            let party1_input_shares: Vec<AuthShare<Fr>> =
                party1_input_shares.lock().unwrap().clone();

            // Verify input shares sum correctly
            for i in 0..n {
                // Verify that the shares can be combined (structure check)
                let output_sum = party0_output[i].value + party1_output[i].value;
                assert_eq!(
                    output_sum,
                    party0_input_shares[i].value + party1_input_shares[i].value
                );

                // Verify k * input shares sum correctly
                let k_output_sum = party0_output[i].kvalue + party1_output[i].kvalue;
                assert_eq!(
                    k_output_sum,
                    k * (party0_input_shares[i].value + party1_input_shares[i].value)
                );

                let auth_output_sum = party0_output[i].mac + party1_output[i].mac;
                assert_eq!(
                    auth_output_sum,
                    mac * (party0_input_shares[i].value + party1_input_shares[i].value)
                );

                let k_auth_output_sum = party0_output[i].kmac + party1_output[i].kmac;
                assert_eq!(
                    k_auth_output_sum,
                    k * (party0_input_shares[i].mac + party1_input_shares[i].mac)
                );
            }
        }
    }

    #[test]
    fn test_apply_k_and_reshare_dim_multiple() {
        let n = 25;
        let dim = 3;

        // Party 0 owns key K
        let k_values = (0..dim)
            .map(|_| Fr::rand(&mut get_random_rng()))
            .collect::<Vec<Fr>>();
        let k_values_clone = k_values.clone();
        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        let party0_input_shares = Arc::new(Mutex::new(Vec::<Vec<AuthShare<Fr>>>::new()));
        let party1_input_shares = Arc::new(Mutex::new(Vec::<Vec<AuthShare<Fr>>>::new()));

        // Shared state to collect outputs
        let outputs = Arc::new(Mutex::new(Vec::<Vec<Vec<KAuthShare<Fr>>>>::new()));
        let mac_shares = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Fr>::new()));

        rayon::scope(|s| {
            let outputs_clone = outputs.clone();
            let mac_shares_party0 = mac_shares.clone();
            let party0_input_shares_clone = party0_input_shares.clone();
            // party 0
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 0);

                let mut state = DummyArithCircPrep::<Fr>::new().run(
                    &mut net,
                    4 * dim,
                    3 * dim * n,
                    0,
                    2 * dim * n,
                    0,
                );

                mac_shares_party0.lock().unwrap().push(state.key_share());

                let party0_auth_shares = (0..dim)
                    .map(|_| generate_random_auth_shares(&mut state, n))
                    .collect::<Vec<Vec<AuthShare<Fr>>>>();
                *party0_input_shares_clone.lock().unwrap() = party0_auth_shares.clone();

                let mut perm_state =
                    DummyArithPermCircPrep::<Fr>::new().run(&mut net, &mut state, vec![]);

                // Input k as authenticated share
                let (k_shuffle_tuples, _) = apply_k_to_shuffle_and_inverse_shuffle_tuples(
                    0,
                    party0_auth_shares.clone(),
                    party0_auth_shares.clone(),
                    &mut perm_state,
                    &mut net,
                    Some(k_values.clone()),
                );

                // Store party 0's results
                outputs_clone.lock().unwrap().push(k_shuffle_tuples);
            });

            let outputs_clone = outputs.clone();
            let mac_shares_party1 = mac_shares.clone();
            let party1_input_shares_clone = party1_input_shares.clone();
            // party 1
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);

                let mut state = DummyArithCircPrep::<Fr>::new().run(
                    &mut net,
                    4 * dim,
                    3 * dim * n,
                    0,
                    2 * dim * n,
                    0,
                );

                mac_shares_party1.lock().unwrap().push(state.key_share());

                let party1_auth_shares = (0..dim)
                    .map(|_| generate_random_auth_shares(&mut state, n))
                    .collect::<Vec<Vec<AuthShare<Fr>>>>();
                *party1_input_shares_clone.lock().unwrap() = party1_auth_shares.clone();

                let mut perm_state =
                    DummyArithPermCircPrep::<Fr>::new().run(&mut net, &mut state, vec![]);

                // Input k as authenticated share
                let (k_shuffle_tuples, _) = apply_k_to_shuffle_and_inverse_shuffle_tuples(
                    0,
                    party1_auth_shares.clone(),
                    party1_auth_shares.clone(),
                    &mut perm_state,
                    &mut net,
                    None,
                );

                // Store party 1's results
                outputs_clone.lock().unwrap().push(k_shuffle_tuples);
            });
        });

        let combined_outputs = outputs.lock().unwrap();
        let mac = mac_shares.lock().unwrap().iter().sum::<Fr>();
        // Verify the results
        if combined_outputs.len() == 2 {
            let party0_idx = if combined_outputs[0][0][0].k == None {
                1
            } else {
                0
            };

            let party0_output: Vec<Vec<KAuthShare<Fr>>> = combined_outputs[party0_idx].clone();

            let party1_output: Vec<Vec<KAuthShare<Fr>>> = combined_outputs[1 - party0_idx].clone();

            // Generate same input shares (with same seed) to deal with borrowing issues
            let party0_input_shares: Vec<Vec<AuthShare<Fr>>> =
                party0_input_shares.lock().unwrap().clone();
            let party1_input_shares: Vec<Vec<AuthShare<Fr>>> =
                party1_input_shares.lock().unwrap().clone();

            // Verify input shares sum correctly
            for j in 0..dim {
                // Check that party 0 has the key k and party 1 does not
                for i in 0..n {
                    assert_eq!(party0_output[j][i].k, Some(k_values_clone[j]));
                    assert_eq!(party1_output[j][i].k, None);
                }

                for i in 0..n {
                    // Verify that the shares can be combined (structure check)
                    let output_sum = party0_output[j][i].value + party1_output[j][i].value;
                    assert_eq!(
                        output_sum,
                        party0_input_shares[j][i].value + party1_input_shares[j][i].value
                    );

                    // Verify k * input shares sum correctly
                    let k_output_sum = party0_output[j][i].kvalue + party1_output[j][i].kvalue;
                    assert_eq!(
                        k_output_sum,
                        k_values_clone[j]
                            * (party0_input_shares[j][i].value + party1_input_shares[j][i].value)
                    );

                    let auth_output_sum = party0_output[j][i].mac + party1_output[j][i].mac;
                    assert_eq!(
                        auth_output_sum,
                        mac * (party0_input_shares[j][i].value + party1_input_shares[j][i].value)
                    );

                    let k_auth_output_sum = party0_output[j][i].kmac + party1_output[j][i].kmac;
                    assert_eq!(
                        k_auth_output_sum,
                        k_values_clone[j]
                            * (party0_input_shares[j][i].mac + party1_input_shares[j][i].mac)
                    );
                }
            }
        }
    }

    #[test]
    fn test_dummy_shuffle_tuple_generate() {
        let n = 25;
        let num_shuffle_tuples = 4;

        // to be inputted
        let shuffle_input = get_random_permutation_usize(n);
        let shuffle_input_clone = shuffle_input.clone();

        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        // Shared state to collect outputs
        let p0_regular_shuffle_tuple_outputs = Arc::new(Mutex::new(Vec::<ShuffleTuple<Fr>>::new()));
        let p1_regular_shuffle_tuple_outputs = Arc::new(Mutex::new(Vec::<ShuffleTuple<Fr>>::new()));
        let p0_inverse_shuffle_tuple_outputs = Arc::new(Mutex::new(Vec::<ShuffleTuple<Fr>>::new()));
        let p1_inverse_shuffle_tuple_outputs = Arc::new(Mutex::new(Vec::<ShuffleTuple<Fr>>::new()));

        let mac_shares = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Fr>::new()));
        rayon::scope(|s| {
            let p0_regular_shuffle_tuple_outputs_clone = p0_regular_shuffle_tuple_outputs.clone();
            let p0_inverse_shuffle_tuple_outputs_clone = p0_inverse_shuffle_tuple_outputs.clone();
            let mac_shares_party0 = mac_shares.clone();
            // party 0
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 0);

                let mut state = DummyArithCircPrep::<Fr>::new().run(
                    &mut net,
                    n,
                    5 * num_shuffle_tuples * n + 2,
                    0,
                    5 * num_shuffle_tuples * n,
                    0,
                );

                mac_shares_party0.lock().unwrap().push(state.key_share());

                let shuffle_tuple_input = ShuffleTupleInput {
                    shuffle_id: "shuffle1".to_string(),
                    shuffle: Some(shuffle_input_clone),
                    n: n,
                    num_shuffle_tuples: num_shuffle_tuples,
                    with_inverse: true,
                };

                // Generate arithmetic permutation circuit state with shuffle tuples
                let mut arith_perm_circ_prep = DummyArithPermCircPrep::<Fr>::new();
                let mut arith_perm_circ_state =
                    arith_perm_circ_prep.run(&mut net, &mut state, vec![shuffle_tuple_input]);

                let regular_shuffle_tuple = arith_perm_circ_state
                    .take_shuffle_tuples("shuffle1".to_string(), num_shuffle_tuples);
                let inverse_shuffle_tuple = arith_perm_circ_state
                    .take_shuffle_tuples("shuffle1_inverse".to_string(), num_shuffle_tuples);

                // Store party 0's results
                p0_regular_shuffle_tuple_outputs_clone
                    .lock()
                    .unwrap()
                    .extend(regular_shuffle_tuple);
                p0_inverse_shuffle_tuple_outputs_clone
                    .lock()
                    .unwrap()
                    .extend(inverse_shuffle_tuple);
            });

            let p1_regular_shuffle_tuple_outputs_clone = p1_regular_shuffle_tuple_outputs.clone();
            let p1_inverse_shuffle_tuple_outputs_clone = p1_inverse_shuffle_tuple_outputs.clone();
            let mac_shares_party1 = mac_shares.clone();
            // party 1
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);

                let mut state = DummyArithCircPrep::<Fr>::new().run(
                    &mut net,
                    n,
                    5 * num_shuffle_tuples * n + 2,
                    0,
                    5 * num_shuffle_tuples * n,
                    0,
                );

                mac_shares_party1.lock().unwrap().push(state.key_share());

                let shuffle_tuple_input = ShuffleTupleInput {
                    shuffle_id: "shuffle1".to_string(),
                    shuffle: None,
                    n: n,
                    num_shuffle_tuples: num_shuffle_tuples,
                    with_inverse: true,
                };

                // Generate arithmetic permutation circuit state with shuffle tuples
                let mut arith_perm_circ_prep = DummyArithPermCircPrep::<Fr>::new();
                let mut arith_perm_circ_state =
                    arith_perm_circ_prep.run(&mut net, &mut state, vec![shuffle_tuple_input]);

                // Extract shuffle tuples (alt version for non-permuter)
                // Each vector contains n tuples, so we get 2*n total when flattened
                let regular_shuffle_tuple = arith_perm_circ_state
                    .take_shuffle_tuples("shuffle1".to_string(), num_shuffle_tuples);
                let inverse_shuffle_tuple = arith_perm_circ_state
                    .take_shuffle_tuples("shuffle1_inverse".to_string(), num_shuffle_tuples);

                // Store party 1's results
                p1_regular_shuffle_tuple_outputs_clone
                    .lock()
                    .unwrap()
                    .extend(regular_shuffle_tuple);
                p1_inverse_shuffle_tuple_outputs_clone
                    .lock()
                    .unwrap()
                    .extend(inverse_shuffle_tuple);
            });
        });

        let p0_regular_combined_outputs = p0_regular_shuffle_tuple_outputs.lock().unwrap();
        let p1_regular_combined_outputs = p1_regular_shuffle_tuple_outputs.lock().unwrap();
        let p0_inverse_combined_outputs = p0_inverse_shuffle_tuple_outputs.lock().unwrap();
        let p1_inverse_combined_outputs = p1_inverse_shuffle_tuple_outputs.lock().unwrap();
        let mac = mac_shares.lock().unwrap().iter().sum::<Fr>();
        // Test correctness of shuffle tuple and inverse shuffle tuple generation

        for tuple_idx in 0..num_shuffle_tuples {
            let party0_regular_shuffle_tuple: ShuffleTuple<Fr> =
                p0_regular_combined_outputs[tuple_idx].clone();

            let party1_regular_shuffle_tuple: ShuffleTuple<Fr> =
                p1_regular_combined_outputs[tuple_idx].clone();

            let party0_inverse_shuffle_tuple: ShuffleTuple<Fr> =
                p0_inverse_combined_outputs[tuple_idx].clone();

            let party1_inverse_shuffle_tuple: ShuffleTuple<Fr> =
                p1_inverse_combined_outputs[tuple_idx].clone();

            //Test 1: Verify that the unshuffling the reconstructed regular shuffle tuples gives the input vector
            let reconstructed_a_inputs = local_unshuffle_vector(
                &shuffle_input,
                &(0..n)
                    .map(|i| {
                        party0_regular_shuffle_tuple.tuples_a[i].value
                            + party1_regular_shuffle_tuple.tuples_a[i].value
                    })
                    .collect(),
            );
            let reconstructed_a_macs = local_unshuffle_vector(
                &shuffle_input,
                &(0..n)
                    .map(|i| {
                        party0_regular_shuffle_tuple.tuples_a[i].mac
                            + party1_regular_shuffle_tuple.tuples_a[i].mac
                    })
                    .collect(),
            );
            let reconstructed_a_ks = local_unshuffle_vector(
                &shuffle_input,
                &(0..n)
                    .map(|i| {
                        party0_regular_shuffle_tuple.tuples_a[i].kvalue
                            + party1_regular_shuffle_tuple.tuples_a[i].kvalue
                    })
                    .collect(),
            );

            let reconstructed_b_inputs = local_unshuffle_vector(
                &shuffle_input,
                &(0..n)
                    .map(|i| {
                        party0_regular_shuffle_tuple.tuples_b[i].value
                            + party1_regular_shuffle_tuple.tuples_b[i].value
                    })
                    .collect(),
            );
            let reconstructed_b_macs = local_unshuffle_vector(
                &shuffle_input,
                &(0..n)
                    .map(|i| {
                        party0_regular_shuffle_tuple.tuples_b[i].mac
                            + party1_regular_shuffle_tuple.tuples_b[i].mac
                    })
                    .collect(),
            );
            let reconstructed_b_ks = local_unshuffle_vector(
                &shuffle_input,
                &(0..n)
                    .map(|i| {
                        party0_regular_shuffle_tuple.tuples_b[i].kvalue
                            + party1_regular_shuffle_tuple.tuples_b[i].kvalue
                    })
                    .collect(),
            );

            for i in 0..n {
                assert_eq!(
                    reconstructed_a_inputs[i],
                    party1_regular_shuffle_tuple.a.as_ref().unwrap()[i],
                    "t_value sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    reconstructed_a_macs[i],
                    party1_regular_shuffle_tuple.a.as_ref().unwrap()[i] * mac,
                    "t_mac sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    reconstructed_a_ks[i],
                    party1_regular_shuffle_tuple.a.as_ref().unwrap()[i]
                        * party0_regular_shuffle_tuple.tuples_a[i].k.unwrap(),
                    "a_k sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    reconstructed_b_inputs[i],
                    party1_regular_shuffle_tuple.b.as_ref().unwrap()[i],
                    "t_value sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    reconstructed_b_macs[i],
                    party1_regular_shuffle_tuple.b.as_ref().unwrap()[i] * mac,
                    "t_mac sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    reconstructed_b_ks[i],
                    party1_regular_shuffle_tuple.b.as_ref().unwrap()[i]
                        * party0_regular_shuffle_tuple.tuples_b[i].k.unwrap(),
                    "a_k sum mismatch at index {}",
                    i
                );
            }

            // Test 2: Verify that shuffling the reconstructed inverse shuffle tuples gives the input vector
            let reconstructed_inverse_a_values = local_shuffle_vector(
                &shuffle_input,
                &((0..n)
                    .map(|i| {
                        party0_inverse_shuffle_tuple.tuples_a[i].value
                            + party1_inverse_shuffle_tuple.tuples_a[i].value
                    })
                    .collect()),
            );

            let reconstructed_inverse_b_values = local_shuffle_vector(
                &shuffle_input,
                &((0..n)
                    .map(|i| {
                        party0_inverse_shuffle_tuple.tuples_b[i].value
                            + party1_inverse_shuffle_tuple.tuples_b[i].value
                    })
                    .collect()),
            );

            let reconstructed_inverse_a_macs = local_shuffle_vector(
                &shuffle_input,
                &((0..n)
                    .map(|i| {
                        party0_inverse_shuffle_tuple.tuples_a[i].mac
                            + party1_inverse_shuffle_tuple.tuples_a[i].mac
                    })
                    .collect()),
            );

            let reconstructed_inverse_b_macs = local_shuffle_vector(
                &shuffle_input,
                &((0..n)
                    .map(|i| {
                        party0_inverse_shuffle_tuple.tuples_b[i].mac
                            + party1_inverse_shuffle_tuple.tuples_b[i].mac
                    })
                    .collect()),
            );

            let reconstructed_inverse_a_ks = local_shuffle_vector(
                &shuffle_input,
                &((0..n)
                    .map(|i| {
                        party0_inverse_shuffle_tuple.tuples_a[i].kvalue
                            + party1_inverse_shuffle_tuple.tuples_a[i].kvalue
                    })
                    .collect()),
            );

            let reconstructed_inverse_b_ks = local_shuffle_vector(
                &shuffle_input,
                &((0..n)
                    .map(|i| {
                        party0_inverse_shuffle_tuple.tuples_b[i].kvalue
                            + party1_inverse_shuffle_tuple.tuples_b[i].kvalue
                    })
                    .collect()),
            );

            for i in 0..n {
                assert_eq!(
                    reconstructed_inverse_a_values[i],
                    party1_inverse_shuffle_tuple.a.as_ref().unwrap()[i],
                    "a_value sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    reconstructed_inverse_a_macs[i],
                    party1_inverse_shuffle_tuple.a.as_ref().unwrap()[i] * mac,
                    "a_mac sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    reconstructed_inverse_a_ks[i],
                    party1_inverse_shuffle_tuple.a.as_ref().unwrap()[i]
                        * party0_inverse_shuffle_tuple.tuples_a[i].k.unwrap(),
                    "a_k sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    reconstructed_inverse_b_values[i],
                    party1_inverse_shuffle_tuple.b.as_ref().unwrap()[i],
                    "b_value sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    reconstructed_inverse_b_macs[i],
                    party1_inverse_shuffle_tuple.b.as_ref().unwrap()[i] * mac,
                    "b_mac sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    reconstructed_inverse_b_ks[i],
                    party1_inverse_shuffle_tuple.b.as_ref().unwrap()[i]
                        * party0_inverse_shuffle_tuple.tuples_b[i].k.unwrap(),
                    "b_k sum mismatch at index {}",
                    i
                );
            }
        }
    }

    #[test]
    fn test_perm_network_shuffle_tuple_generate() {
        let n = 25;
        let num_shuffle_tuples = 4;

        // to be inputted
        let shuffle_input = get_random_permutation_usize(n);
        let shuffle_input_clone = shuffle_input.clone();

        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        // Shared state to collect outputs
        let p0_regular_shuffle_tuple_outputs = Arc::new(Mutex::new(Vec::<ShuffleTuple<Fr>>::new()));
        let p1_regular_shuffle_tuple_outputs = Arc::new(Mutex::new(Vec::<ShuffleTuple<Fr>>::new()));
        let p0_inverse_shuffle_tuple_outputs = Arc::new(Mutex::new(Vec::<ShuffleTuple<Fr>>::new()));
        let p1_inverse_shuffle_tuple_outputs = Arc::new(Mutex::new(Vec::<ShuffleTuple<Fr>>::new()));
        let mac_shares = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Fr>::new()));

        rayon::scope(|s| {
            let p0_regular_shuffle_tuple_outputs_clone = p0_regular_shuffle_tuple_outputs.clone();
            let p0_inverse_shuffle_tuple_outputs_clone = p0_inverse_shuffle_tuple_outputs.clone();
            let mac_shares_party0 = mac_shares.clone();
            // party 0
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 0);

                let mut state = DummyArithCircPrep::<Fr>::new().run(
                    &mut net,
                    50 * n * num_shuffle_tuples,
                    100 * num_shuffle_tuples * n + 2,
                    0,
                    150 * num_shuffle_tuples * n,
                    0,
                );

                mac_shares_party0.lock().unwrap().push(state.key_share());

                let shuffle_tuple_input = ShuffleTupleInput {
                    shuffle_id: "shuffle1".to_string(),
                    shuffle: Some(shuffle_input_clone),
                    n: n,
                    num_shuffle_tuples: num_shuffle_tuples,
                    with_inverse: true,
                };

                // Generate arithmetic permutation circuit state with shuffle tuples
                let mut arith_perm_circ_prep = PermNetworkArithPermCircPrep::<Fr>::new();
                let mut arith_perm_circ_state =
                    arith_perm_circ_prep.run(&mut net, &mut state, vec![shuffle_tuple_input]);

                let regular_shuffle_tuple = arith_perm_circ_state
                    .take_shuffle_tuples("shuffle1".to_string(), num_shuffle_tuples);
                let inverse_shuffle_tuple = arith_perm_circ_state
                    .take_shuffle_tuples("shuffle1_inverse".to_string(), num_shuffle_tuples);

                // Flushing the auth share check queue should pass
                ExecBlindAuthCheck::<Fr>::run(&mut net, &mut arith_perm_circ_state, ());

                // Store party 0's results
                p0_regular_shuffle_tuple_outputs_clone
                    .lock()
                    .unwrap()
                    .extend(regular_shuffle_tuple);
                p0_inverse_shuffle_tuple_outputs_clone
                    .lock()
                    .unwrap()
                    .extend(inverse_shuffle_tuple);
            });

            let p1_regular_shuffle_tuple_outputs_clone = p1_regular_shuffle_tuple_outputs.clone();
            let p1_inverse_shuffle_tuple_outputs_clone = p1_inverse_shuffle_tuple_outputs.clone();
            let mac_shares_party1 = mac_shares.clone();
            // party 1
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);

                let mut state = DummyArithCircPrep::<Fr>::new().run(
                    &mut net,
                    50 * n * num_shuffle_tuples,
                    100 * num_shuffle_tuples * n + 2,
                    0,
                    150 * num_shuffle_tuples * n,
                    0,
                );

                mac_shares_party1.lock().unwrap().push(state.key_share());

                let shuffle_tuple_input = ShuffleTupleInput {
                    shuffle_id: "shuffle1".to_string(),
                    shuffle: None,
                    n: n,
                    num_shuffle_tuples: num_shuffle_tuples,
                    with_inverse: true,
                };

                // Generate arithmetic permutation circuit state with shuffle tuples
                let mut arith_perm_circ_prep = PermNetworkArithPermCircPrep::<Fr>::new();
                let mut arith_perm_circ_state =
                    arith_perm_circ_prep.run(&mut net, &mut state, vec![shuffle_tuple_input]);

                // Extract shuffle tuples (alt version for non-permuter)
                // Each vector contains n tuples, so we get 2*n total when flattened
                let regular_shuffle_tuple = arith_perm_circ_state
                    .take_shuffle_tuples("shuffle1".to_string(), num_shuffle_tuples);
                let inverse_shuffle_tuple = arith_perm_circ_state
                    .take_shuffle_tuples("shuffle1_inverse".to_string(), num_shuffle_tuples);

                // Flushing the auth share check queue should pass
                ExecBlindAuthCheck::<Fr>::run(&mut net, &mut arith_perm_circ_state, ());
                // Store party 1's results
                p1_regular_shuffle_tuple_outputs_clone
                    .lock()
                    .unwrap()
                    .extend(regular_shuffle_tuple);
                p1_inverse_shuffle_tuple_outputs_clone
                    .lock()
                    .unwrap()
                    .extend(inverse_shuffle_tuple);
            });
        });

        let p0_regular_combined_outputs = p0_regular_shuffle_tuple_outputs.lock().unwrap();
        let p1_regular_combined_outputs = p1_regular_shuffle_tuple_outputs.lock().unwrap();
        let p0_inverse_combined_outputs = p0_inverse_shuffle_tuple_outputs.lock().unwrap();
        let p1_inverse_combined_outputs = p1_inverse_shuffle_tuple_outputs.lock().unwrap();
        let mac = mac_shares.lock().unwrap().iter().sum::<Fr>();
        // Test correctness of shuffle tuple and inverse shuffle tuple generation

        for tuple_idx in 0..num_shuffle_tuples {
            let party0_regular_shuffle_tuple: ShuffleTuple<Fr> =
                p0_regular_combined_outputs[tuple_idx].clone();

            let party1_regular_shuffle_tuple: ShuffleTuple<Fr> =
                p1_regular_combined_outputs[tuple_idx].clone();

            let party0_inverse_shuffle_tuple: ShuffleTuple<Fr> =
                p0_inverse_combined_outputs[tuple_idx].clone();

            let party1_inverse_shuffle_tuple: ShuffleTuple<Fr> =
                p1_inverse_combined_outputs[tuple_idx].clone();

            //Test 1: Verify that the unshuffling the reconstructed regular shuffle tuples gives the input vector
            let reconstructed_a_inputs = local_unshuffle_vector(
                &shuffle_input,
                &(0..n)
                    .map(|i| {
                        party0_regular_shuffle_tuple.tuples_a[i].value
                            + party1_regular_shuffle_tuple.tuples_a[i].value
                    })
                    .collect(),
            );
            let reconstructed_a_macs = local_unshuffle_vector(
                &shuffle_input,
                &(0..n)
                    .map(|i| {
                        party0_regular_shuffle_tuple.tuples_a[i].mac
                            + party1_regular_shuffle_tuple.tuples_a[i].mac
                    })
                    .collect(),
            );
            let reconstructed_a_ks = local_unshuffle_vector(
                &shuffle_input,
                &(0..n)
                    .map(|i| {
                        party0_regular_shuffle_tuple.tuples_a[i].kvalue
                            + party1_regular_shuffle_tuple.tuples_a[i].kvalue
                    })
                    .collect(),
            );

            let reconstructed_b_inputs = local_unshuffle_vector(
                &shuffle_input,
                &(0..n)
                    .map(|i| {
                        party0_regular_shuffle_tuple.tuples_b[i].value
                            + party1_regular_shuffle_tuple.tuples_b[i].value
                    })
                    .collect(),
            );
            let reconstructed_b_macs = local_unshuffle_vector(
                &shuffle_input,
                &(0..n)
                    .map(|i| {
                        party0_regular_shuffle_tuple.tuples_b[i].mac
                            + party1_regular_shuffle_tuple.tuples_b[i].mac
                    })
                    .collect(),
            );
            let reconstructed_b_ks = local_unshuffle_vector(
                &shuffle_input,
                &(0..n)
                    .map(|i| {
                        party0_regular_shuffle_tuple.tuples_b[i].kvalue
                            + party1_regular_shuffle_tuple.tuples_b[i].kvalue
                    })
                    .collect(),
            );

            for i in 0..n {
                assert_eq!(
                    reconstructed_a_inputs[i],
                    party1_regular_shuffle_tuple.a.as_ref().unwrap()[i],
                    "t_value sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    reconstructed_a_macs[i],
                    party1_regular_shuffle_tuple.a.as_ref().unwrap()[i] * mac,
                    "t_mac sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    reconstructed_a_ks[i],
                    party1_regular_shuffle_tuple.a.as_ref().unwrap()[i]
                        * party0_regular_shuffle_tuple.tuples_a[i].k.unwrap(),
                    "a_k sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    reconstructed_b_inputs[i],
                    party1_regular_shuffle_tuple.b.as_ref().unwrap()[i],
                    "t_value sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    reconstructed_b_macs[i],
                    party1_regular_shuffle_tuple.b.as_ref().unwrap()[i] * mac,
                    "t_mac sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    reconstructed_b_ks[i],
                    party1_regular_shuffle_tuple.b.as_ref().unwrap()[i]
                        * party0_regular_shuffle_tuple.tuples_b[i].k.unwrap(),
                    "a_k sum mismatch at index {}",
                    i
                );
            }

            // Test 2: Verify that shuffling the reconstructed inverse shuffle tuples gives the input vector
            let reconstructed_inverse_a_values = local_shuffle_vector(
                &shuffle_input,
                &((0..n)
                    .map(|i| {
                        party0_inverse_shuffle_tuple.tuples_a[i].value
                            + party1_inverse_shuffle_tuple.tuples_a[i].value
                    })
                    .collect()),
            );

            let reconstructed_inverse_b_values = local_shuffle_vector(
                &shuffle_input,
                &((0..n)
                    .map(|i| {
                        party0_inverse_shuffle_tuple.tuples_b[i].value
                            + party1_inverse_shuffle_tuple.tuples_b[i].value
                    })
                    .collect()),
            );

            let reconstructed_inverse_a_macs = local_shuffle_vector(
                &shuffle_input,
                &((0..n)
                    .map(|i| {
                        party0_inverse_shuffle_tuple.tuples_a[i].mac
                            + party1_inverse_shuffle_tuple.tuples_a[i].mac
                    })
                    .collect()),
            );

            let reconstructed_inverse_b_macs = local_shuffle_vector(
                &shuffle_input,
                &((0..n)
                    .map(|i| {
                        party0_inverse_shuffle_tuple.tuples_b[i].mac
                            + party1_inverse_shuffle_tuple.tuples_b[i].mac
                    })
                    .collect()),
            );

            let reconstructed_inverse_a_ks = local_shuffle_vector(
                &shuffle_input,
                &((0..n)
                    .map(|i| {
                        party0_inverse_shuffle_tuple.tuples_a[i].kvalue
                            + party1_inverse_shuffle_tuple.tuples_a[i].kvalue
                    })
                    .collect()),
            );

            let reconstructed_inverse_b_ks = local_shuffle_vector(
                &shuffle_input,
                &((0..n)
                    .map(|i| {
                        party0_inverse_shuffle_tuple.tuples_b[i].kvalue
                            + party1_inverse_shuffle_tuple.tuples_b[i].kvalue
                    })
                    .collect()),
            );

            for i in 0..n {
                assert_eq!(
                    reconstructed_inverse_a_values[i],
                    party1_inverse_shuffle_tuple.a.as_ref().unwrap()[i],
                    "a_value sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    reconstructed_inverse_a_macs[i],
                    party1_inverse_shuffle_tuple.a.as_ref().unwrap()[i] * mac,
                    "a_mac sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    reconstructed_inverse_a_ks[i],
                    party1_inverse_shuffle_tuple.a.as_ref().unwrap()[i]
                        * party0_inverse_shuffle_tuple.tuples_a[i].k.unwrap(),
                    "a_k sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    reconstructed_inverse_b_values[i],
                    party1_inverse_shuffle_tuple.b.as_ref().unwrap()[i],
                    "b_value sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    reconstructed_inverse_b_macs[i],
                    party1_inverse_shuffle_tuple.b.as_ref().unwrap()[i] * mac,
                    "b_mac sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    reconstructed_inverse_b_ks[i],
                    party1_inverse_shuffle_tuple.b.as_ref().unwrap()[i]
                        * party0_inverse_shuffle_tuple.tuples_b[i].k.unwrap(),
                    "b_k sum mismatch at index {}",
                    i
                );
            }
        }
    }

    #[test]
    fn test_simple_perm_network_shuffle_tuple_generate() {
        let n = 25;
        let num_shuffle_tuples = 4;

        // to be inputted
        let shuffle_input = get_random_permutation_usize(n);
        let shuffle_input_clone = shuffle_input.clone();

        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        // Shared state to collect outputs
        let p0_regular_shuffle_tuple_outputs = Arc::new(Mutex::new(Vec::<ShuffleTuple<Fr>>::new()));
        let p1_regular_shuffle_tuple_outputs = Arc::new(Mutex::new(Vec::<ShuffleTuple<Fr>>::new()));
        let p0_inverse_shuffle_tuple_outputs = Arc::new(Mutex::new(Vec::<ShuffleTuple<Fr>>::new()));
        let p1_inverse_shuffle_tuple_outputs = Arc::new(Mutex::new(Vec::<ShuffleTuple<Fr>>::new()));
        let mac_shares = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Fr>::new()));

        rayon::scope(|s| {
            let p0_regular_shuffle_tuple_outputs_clone = p0_regular_shuffle_tuple_outputs.clone();
            let p0_inverse_shuffle_tuple_outputs_clone = p0_inverse_shuffle_tuple_outputs.clone();
            let mac_shares_party0 = mac_shares.clone();
            // party 0
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 0);

                let mut state = DummyArithCircPrep::<Fr>::new().run(
                    &mut net,
                    50 * n * num_shuffle_tuples,
                    100 * num_shuffle_tuples * n + 2,
                    0,
                    150 * num_shuffle_tuples * n,
                    0,
                );

                mac_shares_party0.lock().unwrap().push(state.key_share());

                let shuffle_tuple_input = ShuffleTupleInput {
                    shuffle_id: "shuffle1".to_string(),
                    shuffle: Some(shuffle_input_clone),
                    n: n,
                    num_shuffle_tuples: num_shuffle_tuples,
                    with_inverse: true,
                };

                // Generate arithmetic permutation circuit state with shuffle tuples
                let mut arith_perm_circ_prep = SimplePermNetworkArithPermCircPrep::<Fr>::new();
                let mut arith_perm_circ_state =
                    arith_perm_circ_prep.run(&mut net, &mut state, vec![shuffle_tuple_input]);

                let regular_shuffle_tuple = arith_perm_circ_state
                    .take_shuffle_tuples("shuffle1".to_string(), num_shuffle_tuples);
                let inverse_shuffle_tuple = arith_perm_circ_state
                    .take_shuffle_tuples("shuffle1_inverse".to_string(), num_shuffle_tuples);

                // Flushing the auth share check queue should pass
                ExecBlindAuthCheck::<Fr>::run(&mut net, &mut arith_perm_circ_state, ());

                // Store party 0's results
                p0_regular_shuffle_tuple_outputs_clone
                    .lock()
                    .unwrap()
                    .extend(regular_shuffle_tuple);
                p0_inverse_shuffle_tuple_outputs_clone
                    .lock()
                    .unwrap()
                    .extend(inverse_shuffle_tuple);
            });

            let p1_regular_shuffle_tuple_outputs_clone = p1_regular_shuffle_tuple_outputs.clone();
            let p1_inverse_shuffle_tuple_outputs_clone = p1_inverse_shuffle_tuple_outputs.clone();
            let mac_shares_party1 = mac_shares.clone();
            // party 1
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);

                let mut state = DummyArithCircPrep::<Fr>::new().run(
                    &mut net,
                    50 * n * num_shuffle_tuples,
                    100 * num_shuffle_tuples * n + 2,
                    0,
                    150 * num_shuffle_tuples * n,
                    0,
                );

                mac_shares_party1.lock().unwrap().push(state.key_share());

                let shuffle_tuple_input = ShuffleTupleInput {
                    shuffle_id: "shuffle1".to_string(),
                    shuffle: None,
                    n: n,
                    num_shuffle_tuples: num_shuffle_tuples,
                    with_inverse: true,
                };

                // Generate arithmetic permutation circuit state with shuffle tuples
                let mut arith_perm_circ_prep = SimplePermNetworkArithPermCircPrep::<Fr>::new();
                let mut arith_perm_circ_state =
                    arith_perm_circ_prep.run(&mut net, &mut state, vec![shuffle_tuple_input]);

                // Extract shuffle tuples (alt version for non-permuter)
                // Each vector contains n tuples, so we get 2*n total when flattened
                let regular_shuffle_tuple = arith_perm_circ_state
                    .take_shuffle_tuples("shuffle1".to_string(), num_shuffle_tuples);
                let inverse_shuffle_tuple = arith_perm_circ_state
                    .take_shuffle_tuples("shuffle1_inverse".to_string(), num_shuffle_tuples);

                // Flushing the auth share check queue should pass
                ExecBlindAuthCheck::<Fr>::run(&mut net, &mut arith_perm_circ_state, ());
                // Store party 1's results
                p1_regular_shuffle_tuple_outputs_clone
                    .lock()
                    .unwrap()
                    .extend(regular_shuffle_tuple);
                p1_inverse_shuffle_tuple_outputs_clone
                    .lock()
                    .unwrap()
                    .extend(inverse_shuffle_tuple);
            });
        });

        let p0_regular_combined_outputs = p0_regular_shuffle_tuple_outputs.lock().unwrap();
        let p1_regular_combined_outputs = p1_regular_shuffle_tuple_outputs.lock().unwrap();
        let p0_inverse_combined_outputs = p0_inverse_shuffle_tuple_outputs.lock().unwrap();
        let p1_inverse_combined_outputs = p1_inverse_shuffle_tuple_outputs.lock().unwrap();
        let mac = mac_shares.lock().unwrap().iter().sum::<Fr>();
        // Test correctness of shuffle tuple and inverse shuffle tuple generation

        for tuple_idx in 0..num_shuffle_tuples {
            let party0_regular_shuffle_tuple: ShuffleTuple<Fr> =
                p0_regular_combined_outputs[tuple_idx].clone();

            let party1_regular_shuffle_tuple: ShuffleTuple<Fr> =
                p1_regular_combined_outputs[tuple_idx].clone();

            let party0_inverse_shuffle_tuple: ShuffleTuple<Fr> =
                p0_inverse_combined_outputs[tuple_idx].clone();

            let party1_inverse_shuffle_tuple: ShuffleTuple<Fr> =
                p1_inverse_combined_outputs[tuple_idx].clone();

            //Test 1: Verify that the unshuffling the reconstructed regular shuffle tuples gives the input vector
            let reconstructed_a_inputs = local_unshuffle_vector(
                &shuffle_input,
                &(0..n)
                    .map(|i| {
                        party0_regular_shuffle_tuple.tuples_a[i].value
                            + party1_regular_shuffle_tuple.tuples_a[i].value
                    })
                    .collect(),
            );
            let reconstructed_a_macs = local_unshuffle_vector(
                &shuffle_input,
                &(0..n)
                    .map(|i| {
                        party0_regular_shuffle_tuple.tuples_a[i].mac
                            + party1_regular_shuffle_tuple.tuples_a[i].mac
                    })
                    .collect(),
            );
            let reconstructed_a_ks = local_unshuffle_vector(
                &shuffle_input,
                &(0..n)
                    .map(|i| {
                        party0_regular_shuffle_tuple.tuples_a[i].kvalue
                            + party1_regular_shuffle_tuple.tuples_a[i].kvalue
                    })
                    .collect(),
            );

            let reconstructed_b_inputs = local_unshuffle_vector(
                &shuffle_input,
                &(0..n)
                    .map(|i| {
                        party0_regular_shuffle_tuple.tuples_b[i].value
                            + party1_regular_shuffle_tuple.tuples_b[i].value
                    })
                    .collect(),
            );
            let reconstructed_b_macs = local_unshuffle_vector(
                &shuffle_input,
                &(0..n)
                    .map(|i| {
                        party0_regular_shuffle_tuple.tuples_b[i].mac
                            + party1_regular_shuffle_tuple.tuples_b[i].mac
                    })
                    .collect(),
            );
            let reconstructed_b_ks = local_unshuffle_vector(
                &shuffle_input,
                &(0..n)
                    .map(|i| {
                        party0_regular_shuffle_tuple.tuples_b[i].kvalue
                            + party1_regular_shuffle_tuple.tuples_b[i].kvalue
                    })
                    .collect(),
            );

            for i in 0..n {
                assert_eq!(
                    reconstructed_a_inputs[i],
                    party1_regular_shuffle_tuple.a.as_ref().unwrap()[i],
                    "t_value sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    reconstructed_a_macs[i],
                    party1_regular_shuffle_tuple.a.as_ref().unwrap()[i] * mac,
                    "t_mac sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    reconstructed_a_ks[i],
                    party1_regular_shuffle_tuple.a.as_ref().unwrap()[i]
                        * party0_regular_shuffle_tuple.tuples_a[i].k.unwrap(),
                    "a_k sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    reconstructed_b_inputs[i],
                    party1_regular_shuffle_tuple.b.as_ref().unwrap()[i],
                    "t_value sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    reconstructed_b_macs[i],
                    party1_regular_shuffle_tuple.b.as_ref().unwrap()[i] * mac,
                    "t_mac sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    reconstructed_b_ks[i],
                    party1_regular_shuffle_tuple.b.as_ref().unwrap()[i]
                        * party0_regular_shuffle_tuple.tuples_b[i].k.unwrap(),
                    "a_k sum mismatch at index {}",
                    i
                );
            }

            // Test 2: Verify that shuffling the reconstructed inverse shuffle tuples gives the input vector
            let reconstructed_inverse_a_values = local_shuffle_vector(
                &shuffle_input,
                &((0..n)
                    .map(|i| {
                        party0_inverse_shuffle_tuple.tuples_a[i].value
                            + party1_inverse_shuffle_tuple.tuples_a[i].value
                    })
                    .collect()),
            );

            let reconstructed_inverse_b_values = local_shuffle_vector(
                &shuffle_input,
                &((0..n)
                    .map(|i| {
                        party0_inverse_shuffle_tuple.tuples_b[i].value
                            + party1_inverse_shuffle_tuple.tuples_b[i].value
                    })
                    .collect()),
            );

            let reconstructed_inverse_a_macs = local_shuffle_vector(
                &shuffle_input,
                &((0..n)
                    .map(|i| {
                        party0_inverse_shuffle_tuple.tuples_a[i].mac
                            + party1_inverse_shuffle_tuple.tuples_a[i].mac
                    })
                    .collect()),
            );

            let reconstructed_inverse_b_macs = local_shuffle_vector(
                &shuffle_input,
                &((0..n)
                    .map(|i| {
                        party0_inverse_shuffle_tuple.tuples_b[i].mac
                            + party1_inverse_shuffle_tuple.tuples_b[i].mac
                    })
                    .collect()),
            );

            let reconstructed_inverse_a_ks = local_shuffle_vector(
                &shuffle_input,
                &((0..n)
                    .map(|i| {
                        party0_inverse_shuffle_tuple.tuples_a[i].kvalue
                            + party1_inverse_shuffle_tuple.tuples_a[i].kvalue
                    })
                    .collect()),
            );

            let reconstructed_inverse_b_ks = local_shuffle_vector(
                &shuffle_input,
                &((0..n)
                    .map(|i| {
                        party0_inverse_shuffle_tuple.tuples_b[i].kvalue
                            + party1_inverse_shuffle_tuple.tuples_b[i].kvalue
                    })
                    .collect()),
            );

            for i in 0..n {
                assert_eq!(
                    reconstructed_inverse_a_values[i],
                    party1_inverse_shuffle_tuple.a.as_ref().unwrap()[i],
                    "a_value sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    reconstructed_inverse_a_macs[i],
                    party1_inverse_shuffle_tuple.a.as_ref().unwrap()[i] * mac,
                    "a_mac sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    reconstructed_inverse_a_ks[i],
                    party1_inverse_shuffle_tuple.a.as_ref().unwrap()[i]
                        * party0_inverse_shuffle_tuple.tuples_a[i].k.unwrap(),
                    "a_k sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    reconstructed_inverse_b_values[i],
                    party1_inverse_shuffle_tuple.b.as_ref().unwrap()[i],
                    "b_value sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    reconstructed_inverse_b_macs[i],
                    party1_inverse_shuffle_tuple.b.as_ref().unwrap()[i] * mac,
                    "b_mac sum mismatch at index {}",
                    i
                );

                assert_eq!(
                    reconstructed_inverse_b_ks[i],
                    party1_inverse_shuffle_tuple.b.as_ref().unwrap()[i]
                        * party0_inverse_shuffle_tuple.tuples_b[i].k.unwrap(),
                    "b_k sum mismatch at index {}",
                    i
                );
            }
        }
    }
}
