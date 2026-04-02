use ark_ff::Field;

use crate::arithcircop::vector_input::VectorInput;
use crate::arithcircop::vector_mul::VectorMul;
use crate::arithcircop::vector_neg::VectorNeg;
use crate::arithcircop::vector_reveal::VectorReveal;
use crate::arithcircop::vector_shift::VectorShift;
use crate::arithcircop::{ArithCircOp, ArithCircState};
use crate::arithpermcircop::{ArithPermCircState, ShuffleTuple, ShuffleVecType};
use crate::arithpermcircprep::waksman::symbolic_apply_batched_log_rounds_rev;
use crate::arithpermcircprep::waksman::{
    Config, build_schedule, symbolic_apply_batched_log_rounds,
};

use crate::arithpermcircprep::{
    ArithPermCircPrep, ShuffleTupleInput, apply_k_to_shuffle_and_inverse_shuffle_tuples,
    apply_k_to_shuffle_tuples,
};
use crate::net::Net;
use crate::primitives::auth::AuthShare;
use crate::utils::rng_utils::{get_inverse_permutation_usize_option, get_random_rng};
use crate::utils::testing_utils::generate_random_vector;
use crate::utils::vector_utils::roll_vector;

/// Simple Perm Network O(log n) round implementation of preprocessing
pub struct SimplePermNetworkArithPermCircPrep<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> SimplePermNetworkArithPermCircPrep<F> {
    /// Create a new simple perm network preprocessing instance
    pub fn new() -> Self {
        SimplePermNetworkArithPermCircPrep {
            _phantom: std::marker::PhantomData,
        }
    }

    /// Generate shuffle tuples for a given shuffle tuple input
    pub fn generate_shuffle_tuple_helper(
        &mut self,
        net: &mut Net,
        state: &mut ArithPermCircState<F>,
        shuffle_tuple: &ShuffleTupleInput,
    ) {
        let permuter_id = if shuffle_tuple.shuffle.is_some() {
            net.party_id()
        } else {
            1 - net.party_id()
        };

        let num_shuffle_tuples = shuffle_tuple.num_shuffle_tuples;

        let inputted_switch_bits = if net.party_id() == permuter_id {
            let shuffle: ShuffleVecType = shuffle_tuple.shuffle.as_ref().unwrap().clone();

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
            let cfg = Config::for_permuting::<usize>((0..shuffle_tuple.n).collect::<Vec<usize>>());
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
        let z = VectorReveal::<F>::run(net, state.inner_mut(), eq);

        assert!(z.iter().all(|z| z.is_zero()), "Vector Bit Check failed");

        // Step 3: prepare a and b random vector inputs
        let (a_vector_unrolled, a_vector_rolled) = if net.party_id() != permuter_id {
            let a_vector = generate_random_vector(shuffle_tuple.n * num_shuffle_tuples);
            let a_vector_rolled =
                roll_vector(a_vector.clone(), shuffle_tuple.n, num_shuffle_tuples);
            (Some(a_vector), Some(a_vector_rolled))
        } else {
            (None, None)
        };
        let a_vector_unrolled_shares = VectorInput::<F>::run(
            net,
            state.inner_mut(),
            (
                1 - permuter_id,
                a_vector_unrolled,
                Some(shuffle_tuple.n * num_shuffle_tuples),
            ),
        );
        let a_vector_rolled_shares = roll_vector(
            a_vector_unrolled_shares.clone(),
            shuffle_tuple.n,
            num_shuffle_tuples,
        );

        let (b_vector_unrolled, b_vector_rolled) = if net.party_id() != permuter_id {
            let b_vector = generate_random_vector(shuffle_tuple.n * num_shuffle_tuples);
            let b_vector_rolled =
                roll_vector(b_vector.clone(), shuffle_tuple.n, num_shuffle_tuples);
            (Some(b_vector), Some(b_vector_rolled))
        } else {
            (None, None)
        };

        let b_vector_unrolled_shares = VectorInput::<F>::run(
            net,
            state.inner_mut(),
            (
                1 - permuter_id,
                b_vector_unrolled,
                Some(shuffle_tuple.n * num_shuffle_tuples),
            ),
        );
        let b_vector_rolled_shares = roll_vector(
            b_vector_unrolled_shares.clone(),
            shuffle_tuple.n,
            num_shuffle_tuples,
        );

        // Step 4: run the perm network circuit
        let mut pa_shares = Vec::new();
        let mut pb_shares = Vec::new();
        for i in 0..num_shuffle_tuples {
            let schedule = build_schedule(shuffle_tuple.n);

            let pa_output = symbolic_apply_batched_log_rounds::<F>(
                net,
                state.inner_mut(),
                a_vector_rolled_shares[i].clone(),
                &inputted_switch_bits.clone(),
                &schedule,
            );
            let pb_output = symbolic_apply_batched_log_rounds::<F>(
                net,
                state.inner_mut(),
                b_vector_rolled_shares[i].clone(),
                &inputted_switch_bits.clone(),
                &schedule,
            );
            pa_shares.push(pa_output);
            pb_shares.push(pb_output);
        }

        let k_vals = if net.party_id() == permuter_id {
            Some(generate_random_vector::<F>(num_shuffle_tuples))
        } else {
            None
        };

        let (shuffle_id, shuffle, num_shuffle_tuples) = (
            shuffle_tuple.shuffle_id.clone(),
            shuffle_tuple.shuffle.clone(),
            shuffle_tuple.num_shuffle_tuples,
        );
        // dbg!("Finished", shuffle_id.clone());

        if shuffle_tuple.with_inverse {
            let mut pa_shares_inverse = Vec::new();
            let mut pb_shares_inverse = Vec::new();
            for i in 0..num_shuffle_tuples {
                let schedule = build_schedule(shuffle_tuple.n);
                let pa_output = symbolic_apply_batched_log_rounds_rev::<F>(
                    net,
                    state.inner_mut(),
                    a_vector_rolled_shares[i].clone(),
                    &inputted_switch_bits.clone(),
                    &schedule,
                );
                let pb_output = symbolic_apply_batched_log_rounds_rev::<F>(
                    net,
                    state.inner_mut(),
                    b_vector_rolled_shares[i].clone(),
                    &inputted_switch_bits.clone(),
                    &schedule,
                );
                pa_shares_inverse.push(pa_output);
                pb_shares_inverse.push(pb_output);
            }

            let (shuffle_tuples_a, inverse_shuffle_tuples_a) =
                apply_k_to_shuffle_and_inverse_shuffle_tuples(
                    permuter_id,
                    pa_shares,
                    pa_shares_inverse,
                    state,
                    net,
                    k_vals.clone(),
                );
            let (shuffle_tuples_b, inverse_shuffle_tuples_b) =
                apply_k_to_shuffle_and_inverse_shuffle_tuples(
                    permuter_id,
                    pb_shares,
                    pb_shares_inverse,
                    state,
                    net,
                    k_vals,
                );

            state.push_multiple_shuffle_tuples(
                shuffle_id.clone(),
                shuffle_tuples_a
                    .into_iter()
                    .zip(shuffle_tuples_b.into_iter())
                    .enumerate()
                    .map(|(i, (st_a, st_b))| ShuffleTuple {
                        shuffle: shuffle.clone(),
                        tuples_a: st_a,
                        tuples_b: st_b,
                        a: if a_vector_rolled.is_some() {
                            Some(a_vector_rolled.as_ref().unwrap()[i].clone())
                        } else {
                            None
                        },
                        b: if b_vector_rolled.is_some() {
                            Some(b_vector_rolled.as_ref().unwrap()[i].clone())
                        } else {
                            None
                        },
                    })
                    .collect(),
            );
            state.push_multiple_shuffle_tuples(
                shuffle_id.clone() + "_inverse",
                inverse_shuffle_tuples_a
                    .into_iter()
                    .zip(inverse_shuffle_tuples_b.into_iter())
                    .enumerate()
                    .map(|(i, (inverse_st_a, inverse_st_b))| ShuffleTuple {
                        shuffle: get_inverse_permutation_usize_option(&shuffle.clone()),
                        tuples_a: inverse_st_a,
                        tuples_b: inverse_st_b,
                        a: if a_vector_rolled.is_some() {
                            Some(a_vector_rolled.as_ref().unwrap()[i].clone())
                        } else {
                            None
                        },
                        b: if b_vector_rolled.is_some() {
                            Some(b_vector_rolled.as_ref().unwrap()[i].clone())
                        } else {
                            None
                        },
                    })
                    .collect(),
            );
        } else {
            let shuffle_tuples_a =
                apply_k_to_shuffle_tuples(permuter_id, pa_shares, state, net, k_vals.clone());
            let shuffle_tuples_b =
                apply_k_to_shuffle_tuples(permuter_id, pb_shares, state, net, k_vals);

            state.push_multiple_shuffle_tuples(
                shuffle_id.clone(),
                shuffle_tuples_a
                    .into_iter()
                    .zip(shuffle_tuples_b.into_iter())
                    .enumerate()
                    .map(|(i, (st_a, st_b))| ShuffleTuple {
                        shuffle: shuffle.clone(),
                        tuples_a: st_a,
                        tuples_b: st_b,
                        a: if a_vector_rolled.is_some() {
                            Some(a_vector_rolled.as_ref().unwrap()[i].clone())
                        } else {
                            None
                        },
                        b: if b_vector_rolled.is_some() {
                            Some(b_vector_rolled.as_ref().unwrap()[i].clone())
                        } else {
                            None
                        },
                    })
                    .collect(),
            );
        }
    }
}

impl<F: Field> ArithPermCircPrep<F> for SimplePermNetworkArithPermCircPrep<F> {
    fn run(
        &mut self,
        net: &mut Net,
        arith_circ_state: &mut ArithCircState<F>,
        shuffle_tuples: Vec<ShuffleTupleInput>,
    ) -> ArithPermCircState<F> {
        let shared_beta_alphabeta_share: AuthShare<F> = if net.am_king() {
            VectorInput::<F>::run(
                net,
                arith_circ_state,
                (0, Some(vec![F::rand(&mut get_random_rng())]), Some(1)),
            )[0]
        } else {
            VectorInput::<F>::run(net, arith_circ_state, (0, None, Some(1)))[0]
        };

        let alpha_share = arith_circ_state.key_share();
        let beta_share = shared_beta_alphabeta_share.value;
        let alpha_beta_share = shared_beta_alphabeta_share.mac;

        let inner = std::mem::take(arith_circ_state);
        let mut state = ArithPermCircState::new(inner, (alpha_share, beta_share, alpha_beta_share));

        shuffle_tuples.into_iter().for_each(|st| {
            // dbg!("Generating shuffle tuple: {:?}", st.shuffle_id.clone());
            self.generate_shuffle_tuple_helper(net, &mut state, &st);
        });

        state
    }
}
