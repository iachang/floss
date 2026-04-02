use ark_ff::Field;

use crate::arithcircop::ArithCircOp;
use crate::arithcircop::vector_input::VectorInput;
use crate::arithcircop::vector_mul::VectorMul;
use crate::arithcircop::vector_neg::VectorNeg;
use crate::arithcircop::vector_shift::VectorShift;
use crate::arithpermcircop::vector_reveal::VectorReveal;
use crate::arithpermcircop::{ArithPermCircOp, ArithPermCircState, ShuffleVecType};
use crate::arithpermcircprep::waksman::{
    Config, build_schedule, symbolic_apply_batched_log_rounds,
    symbolic_apply_batched_log_rounds_rev,
};

use crate::net::Net;
use crate::primitives::auth::AuthShare;

/// Simple log(n) round implementation of permutation network shuffle
pub struct SimplePermNetShuffle<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> SimplePermNetShuffle<F> {
    /// Create a new ArithCircOp instance
    pub fn new() -> Self {
        SimplePermNetShuffle {
            _phantom: std::marker::PhantomData,
        }
    }

    /// Simple perm network for inverse shuffle
    pub fn perm_network_inverse_shuffle_helper(
        net: &mut Net,
        state: &mut ArithPermCircState<F>,
        shuffle: Option<ShuffleVecType>,
        auth_shares: Vec<AuthShare<F>>,
    ) -> Vec<AuthShare<F>> {
        let permuter_id = if shuffle.is_some() {
            net.party_id()
        } else {
            1 - net.party_id()
        };

        let inputted_switch_bits = if net.party_id() == permuter_id {
            let shuffle: ShuffleVecType = shuffle.as_ref().unwrap().clone();

            let cfg = Config::for_permuting::<usize>(shuffle);
            let switches = cfg.switches();
            let switches_bits: Vec<F> = switches
                .iter()
                .enumerate()
                .map(|s| if *(s.1) { F::one() } else { F::zero() })
                .collect();

            VectorInput::<F>::run(
                net,
                state.inner_mut(),
                (permuter_id, Some(switches_bits), None),
            )
        } else {
            let cfg =
                Config::for_permuting::<usize>((0..auth_shares.len()).collect::<Vec<usize>>());
            let num_switches = cfg.switches().len();
            VectorInput::<F>::run(
                net,
                state.inner_mut(),
                (permuter_id, None, Some(num_switches)),
            )
        };

        // Step 2: check the bits.
        let neg_bits = VectorNeg::<F>::run(net, state.inner_mut(), inputted_switch_bits.clone());
        let one_minus_bits = VectorShift::<F>::run(net, state.inner_mut(), (neg_bits, F::one()));
        let eq = VectorMul::<F>::run(
            net,
            state.inner_mut(),
            (inputted_switch_bits.clone(), one_minus_bits.clone()),
        );
        let z = VectorReveal::<F>::run(net, state, eq);

        assert!(z.iter().all(|z| z.is_zero()), "Vector Bit Check failed");

        // Step 4: run the perm network circuit
        let schedule = build_schedule(auth_shares.len());
        let px_output = symbolic_apply_batched_log_rounds_rev::<F>(
            net,
            state.inner_mut(),
            auth_shares.clone(),
            &inputted_switch_bits.clone(),
            &schedule,
        );

        return px_output;
    }

    /// Simple perm network for forward shuffle
    pub fn perm_network_shuffle_helper(
        net: &mut Net,
        state: &mut ArithPermCircState<F>,
        shuffle: Option<ShuffleVecType>,
        auth_shares: Vec<AuthShare<F>>,
    ) -> Vec<AuthShare<F>> {
        let permuter_id = if shuffle.is_some() {
            net.party_id()
        } else {
            1 - net.party_id()
        };

        let inputted_switch_bits = if net.party_id() == permuter_id {
            let shuffle: ShuffleVecType = shuffle.as_ref().unwrap().clone();

            let cfg = Config::for_permuting::<usize>(shuffle);
            let switches = cfg.switches();
            let switches_bits: Vec<F> = switches
                .iter()
                .enumerate()
                .map(|s| if *(s.1) { F::one() } else { F::zero() })
                .collect();

            VectorInput::<F>::run(
                net,
                state.inner_mut(),
                (permuter_id, Some(switches_bits), None),
            )
        } else {
            let cfg =
                Config::for_permuting::<usize>((0..auth_shares.len()).collect::<Vec<usize>>());
            let num_switches = cfg.switches().len();
            VectorInput::<F>::run(
                net,
                state.inner_mut(),
                (permuter_id, None, Some(num_switches)),
            )
        };

        // Step 2: check the bits.
        let neg_bits = VectorNeg::<F>::run(net, state.inner_mut(), inputted_switch_bits.clone());
        let one_minus_bits = VectorShift::<F>::run(net, state.inner_mut(), (neg_bits, F::one()));
        let eq = VectorMul::<F>::run(
            net,
            state.inner_mut(),
            (inputted_switch_bits.clone(), one_minus_bits.clone()),
        );
        let z = VectorReveal::<F>::run(net, state, eq);

        assert!(z.iter().all(|z| z.is_zero()), "Vector Bit Check failed");

        // Step 4: run the perm network circuit
        let schedule = build_schedule(auth_shares.len());

        let px_output = symbolic_apply_batched_log_rounds::<F>(
            net,
            state.inner_mut(),
            auth_shares.clone(),
            &inputted_switch_bits.clone(),
            &schedule,
        );

        return px_output;
    }
}

impl<F: Field> ArithPermCircOp<F> for SimplePermNetShuffle<F> {
    type In = (
        Option<ShuffleVecType>, // shuffle
        Vec<AuthShare<F>>,      // input auth shares
        bool,                   // with inverse
    );
    type Out = Vec<AuthShare<F>>;

    fn run(net: &mut Net, state: &mut ArithPermCircState<F>, input: Self::In) -> Self::Out {
        let (shuffle, input_auth_shares, with_inverse) = input;

        let output_auth_shares = if with_inverse {
            Self::perm_network_inverse_shuffle_helper(net, state, shuffle, input_auth_shares)
        } else {
            Self::perm_network_shuffle_helper(net, state, shuffle, input_auth_shares)
        };

        output_auth_shares.clone()
    }
}

#[cfg(test)]
mod test {
    use rand::Rng;

    use crate::arithcircop::ArithCircOp;
    use crate::arithcircop::vector_reveal::VectorReveal;
    use crate::arithcircprep::ArithCircPrep;
    use crate::arithpermcircprep::ArithPermCircPrep;
    use crate::bench::Mersenne128Fq;
    use crate::utils::rng_utils::{
        get_random_permutation_usize, local_shuffle_vector, local_unshuffle_vector,
    };
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
    fn test_simple_perm_net_shuffle() {
        let n = 25;

        let shuffle_input = get_random_permutation_usize(n);
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
                    20 * n + 2,
                    80 * n + 2,
                    20 * n,
                    80 * n,
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
                    vec![],
                );

                let party0_regular_shuffle_output = SimplePermNetShuffle::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    (
                        Some(shuffle_input.clone()),
                        party0_auth_shares.clone(),
                        false,
                    ),
                );

                let party0_inverse_shuffle_output = SimplePermNetShuffle::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    (
                        Some(shuffle_input.clone()),
                        party0_auth_shares.clone(),
                        true,
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
                    20 * n + 2,
                    80 * n + 2,
                    20 * n,
                    80 * n,
                    0,
                );

                let party1_auth_shares = generate_random_auth_shares(&mut state, n);
                mac_shares_party1.lock().unwrap().push(state.key_share());

                // Generate arithmetic permutation circuit state with shuffle tuples
                let mut arith_perm_circ_prep = DummyArithPermCircPrep::<Fr>::new();
                let mut arith_perm_circ_state =
                    arith_perm_circ_prep.run(&mut net, &mut state, vec![]);

                let party1_regular_shuffle_output = SimplePermNetShuffle::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    (None, party1_auth_shares.clone(), false),
                );

                let party1_inverse_shuffle_output = SimplePermNetShuffle::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    (None, party1_auth_shares.clone(), true),
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
}
