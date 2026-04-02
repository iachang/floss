use std::collections::VecDeque;
use std::time::Instant;

use ark_ff::Field;
use itertools::max;

use crate::arithcircop::vector_add::VectorAdd;
use crate::arithcircop::vector_input::VectorInput;
use crate::arithcircop::vector_mul::VectorMul;
use crate::arithcircop::vector_neg::VectorNeg;
use crate::arithcircop::vector_reveal::VectorReveal;
use crate::arithcircop::vector_scale_by_vector::VectorScaleByVector;
use crate::arithcircop::vector_shift::VectorShift;
use crate::arithcircop::vector_sub::VectorSub;
use crate::arithcircop::{ArithCircOp, ArithCircState};
use crate::arithpermcircop::{ArithPermCircState, ShuffleTuple, ShuffleTupleTest, ShuffleVecType};
use crate::arithpermcircprep::waksman::{
    Config, get_indexed_switches, symbolic_apply_circ, symbolic_apply_circ_rev,
};
use crate::arithpermcircprep::{
    ArithPermCircPrep, ShuffleTupleInput, apply_k_to_shuffle_and_inverse_shuffle_tuples,
    apply_k_to_shuffle_tuples,
};
use crate::net::Net;
use crate::primitives::auth::AuthShare;
use crate::utils::rng_utils::{get_inverse_permutation_usize_option, get_random_rng};
use crate::utils::testing_utils::generate_random_vector;
use crate::utils::vector_utils::{dupe_vector, roll_vector, unroll_vector};

/// Mohassel et. al (2014) Perm Network O(1) round implementation of preprocessing
pub struct PermNetworkArithPermCircPrep<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> PermNetworkArithPermCircPrep<F> {
    /// Create a new Mohassel perm net preprocessing instance
    pub fn new() -> Self {
        PermNetworkArithPermCircPrep {
            _phantom: std::marker::PhantomData,
        }
    }

    /// Generate shuffle tuples for a given shuffle tuple input
    pub fn generate_shuffle_tuple_with_inverse(
        &mut self,
        net: &mut Net,
        state: &mut ArithPermCircState<F>,
        shuffle_tuple: &ShuffleTupleInput,
    ) {
        let (shuffle_id, shuffle, num_shuffle_tuples) = (
            shuffle_tuple.shuffle_id.clone(),
            shuffle_tuple.shuffle.clone(),
            shuffle_tuple.num_shuffle_tuples,
        );

        let permuter_id = if shuffle.is_some() {
            net.party_id()
        } else {
            1 - net.party_id()
        };

        let time_start = Instant::now();
        println!("time start: {:?}", Instant::now());
        let regular_shares =
            self.generate_regular_shuffle_tuples_helper(net, state.inner_mut(), shuffle_tuple);
        println!("time end: {:?}", time_start.elapsed());
        let inverse_shares =
            self.generate_inverse_shuffle_tuples_helper(net, state.inner_mut(), shuffle_tuple);
        dbg!("got here");
        let k_vals = if net.party_id() == permuter_id {
            Some(generate_random_vector::<F>(num_shuffle_tuples))
        } else {
            None
        };

        let pa_share = regular_shares
            .iter()
            .map(|r| r.tuples_a.clone())
            .collect::<Vec<Vec<AuthShare<F>>>>();
        let pb_share = regular_shares
            .iter()
            .map(|r| r.tuples_b.clone())
            .collect::<Vec<Vec<AuthShare<F>>>>();
        let pa_share_inverse = inverse_shares
            .iter()
            .map(|r| r.tuples_a.clone())
            .collect::<Vec<Vec<AuthShare<F>>>>();
        let pb_share_inverse = inverse_shares
            .iter()
            .map(|r| r.tuples_b.clone())
            .collect::<Vec<Vec<AuthShare<F>>>>();

        let (shuffle_tuples_a, inverse_shuffle_tuples_a) =
            apply_k_to_shuffle_and_inverse_shuffle_tuples(
                permuter_id,
                pa_share,
                pa_share_inverse,
                state,
                net,
                k_vals.clone(),
            );
        let (shuffle_tuples_b, inverse_shuffle_tuples_b) =
            apply_k_to_shuffle_and_inverse_shuffle_tuples(
                permuter_id,
                pb_share,
                pb_share_inverse,
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
                    a: regular_shares[i].a.clone(),
                    b: regular_shares[i].b.clone(),
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
                    a: inverse_shares[i].a.clone(),
                    b: inverse_shares[i].b.clone(),
                })
                .collect(),
        );
    }

    /// Generate shuffle tuple.
    pub fn generate_shuffle_tuple(
        &mut self,
        net: &mut Net,
        state: &mut ArithPermCircState<F>,
        shuffle_tuple: &ShuffleTupleInput,
    ) {
        let (shuffle_id, shuffle, num_shuffle_tuples) = (
            shuffle_tuple.shuffle_id.clone(),
            shuffle_tuple.shuffle.clone(),
            shuffle_tuple.num_shuffle_tuples,
        );

        let permuter_id = if shuffle.is_some() {
            net.party_id()
        } else {
            1 - net.party_id()
        };

        let regular_shares =
            self.generate_regular_shuffle_tuples_helper(net, state.inner_mut(), shuffle_tuple);

        let k_vals = if net.party_id() == permuter_id {
            Some(generate_random_vector::<F>(num_shuffle_tuples))
        } else {
            None
        };

        let pa_share = regular_shares
            .iter()
            .map(|r| r.tuples_a.clone())
            .collect::<Vec<Vec<AuthShare<F>>>>();
        let pb_share = regular_shares
            .iter()
            .map(|r| r.tuples_b.clone())
            .collect::<Vec<Vec<AuthShare<F>>>>();

        let shuffle_tuples_a =
            apply_k_to_shuffle_tuples(permuter_id, pa_share, state, net, k_vals.clone());
        let shuffle_tuples_b = apply_k_to_shuffle_tuples(permuter_id, pb_share, state, net, k_vals);

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
                    a: regular_shares[i].a.clone(),
                    b: regular_shares[i].b.clone(),
                })
                .collect(),
        );
    }

    /// Generate shuffle tuples for a given shuffle tuple input
    pub fn generate_regular_shuffle_tuples_helper(
        &mut self,
        net: &mut Net,
        state: &mut ArithCircState<F>,
        shuffle_tuple: &ShuffleTupleInput,
    ) -> Vec<ShuffleTupleTest<F>> {
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

            VectorInput::<F>::run(net, state, (permuter_id, Some(switches_bits), None))
        } else {
            let cfg = Config::for_permuting::<usize>((0..shuffle_tuple.n).collect::<Vec<usize>>());
            let num_switches = cfg.switches().len();
            VectorInput::<F>::run(net, state, (permuter_id, None, Some(num_switches)))
        };

        // Step 2: check the bits.
        let neg_bits = VectorNeg::<F>::run(net, state, inputted_switch_bits.clone());
        let one_minus_bits = VectorShift::<F>::run(net, state, (neg_bits, F::one()));
        let eq = VectorMul::<F>::run(
            net,
            state,
            (inputted_switch_bits.clone(), one_minus_bits.clone()),
        );
        let z = VectorReveal::<F>::run(net, state, eq);

        assert!(z.iter().all(|z| z.is_zero()), "Vector Bit Check failed");

        // Step 3: create the perm network circuit
        let input_wires = (0..shuffle_tuple.n).collect::<Vec<usize>>();
        let mut switches_to_return = Vec::new();
        let mut global_index = shuffle_tuple.n;
        let output_wires = get_indexed_switches(
            input_wires.clone(),
            &mut global_index,
            &mut switches_to_return,
        );
        let coins_to_take = max(output_wires.clone()).unwrap() + 1;
        let coins_a = state.take_auth_coins(num_shuffle_tuples * coins_to_take);
        let a_coins = roll_vector(coins_a, coins_to_take, num_shuffle_tuples);

        let coins_b = state.take_auth_coins(num_shuffle_tuples * coins_to_take);
        let b_coins = roll_vector(coins_b, coins_to_take, num_shuffle_tuples);

        let coins_mac_a = state.take_auth_coins(num_shuffle_tuples * coins_to_take);
        let a_coins_mac = roll_vector(coins_mac_a, coins_to_take, num_shuffle_tuples);
        // let coins_mac_b = state.take_auth_coins(num_shuffle_tuples * coins_to_take);
        // let b_coins_mac = roll_vector(coins_mac_b, coins_to_take, num_shuffle_tuples);

        let k_a = state.take_auth_coins(1)[0];
        // let k_b = state.take_auth_coins(1)[0];

        let switch_vector_in_0_coins_a = unroll_vector(
            a_coins
                .iter()
                .map(|a| {
                    switches_to_return
                        .iter()
                        .map(|s| a[s.in_0_idx])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );
        let switch_vector_in_0_coins_mac_a = unroll_vector(
            a_coins_mac
                .iter()
                .map(|a| {
                    switches_to_return
                        .iter()
                        .map(|s| a[s.in_0_idx])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );
        let switch_vector_in_1_coins_a = unroll_vector(
            a_coins
                .iter()
                .map(|a| {
                    switches_to_return
                        .iter()
                        .map(|s| a[s.in_1_idx])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );
        let switch_vector_in_1_coins_mac_a = unroll_vector(
            a_coins_mac
                .iter()
                .map(|a| {
                    switches_to_return
                        .iter()
                        .map(|s| a[s.in_1_idx])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );
        let switch_vector_out_0_coins_a = unroll_vector(
            a_coins
                .iter()
                .map(|a| {
                    switches_to_return
                        .iter()
                        .map(|s| a[s.out_0_idx])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );
        let switch_vector_out_0_coins_mac_a = unroll_vector(
            a_coins_mac
                .iter()
                .map(|a| {
                    switches_to_return
                        .iter()
                        .map(|s| a[s.out_0_idx])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );
        let switch_vector_out_1_coins_a = unroll_vector(
            a_coins
                .iter()
                .map(|a| {
                    switches_to_return
                        .iter()
                        .map(|s| a[s.out_1_idx])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );
        let switch_vector_out_1_coins_mac_a = unroll_vector(
            a_coins_mac
                .iter()
                .map(|a| {
                    switches_to_return
                        .iter()
                        .map(|s| a[s.out_1_idx])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );

        let switch_vector_in_0_coins_b = unroll_vector(
            b_coins
                .iter()
                .map(|b| {
                    switches_to_return
                        .iter()
                        .map(|s| b[s.in_0_idx])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );
        // let switch_vector_in_0_coins_mac_b = unroll_vector(
        //     b_coins_mac
        //         .iter()
        //         .map(|b| {
        //             switches_to_return
        //                 .iter()
        //                 .map(|s| b[s.in_0_idx])
        //                 .collect::<Vec<AuthShare<F>>>()
        //         })
        //         .collect::<Vec<Vec<AuthShare<F>>>>(),
        // );
        let switch_vector_in_1_coins_b = unroll_vector(
            b_coins
                .iter()
                .map(|b| {
                    switches_to_return
                        .iter()
                        .map(|s| b[s.in_1_idx])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );
        // let switch_vector_in_1_coins_mac_b = unroll_vector(
        //     b_coins_mac
        //         .iter()
        //         .map(|b| {
        //             switches_to_return
        //                 .iter()
        //                 .map(|s| b[s.in_1_idx])
        //                 .collect::<Vec<AuthShare<F>>>()
        //         })
        //         .collect::<Vec<Vec<AuthShare<F>>>>(),
        // );
        let switch_vector_out_0_coins_b = unroll_vector(
            b_coins
                .iter()
                .map(|b| {
                    switches_to_return
                        .iter()
                        .map(|s| b[s.out_0_idx])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );
        // let switch_vector_out_0_coins_mac_b = unroll_vector(
        //     b_coins_mac
        //         .iter()
        //         .map(|b| {
        //             switches_to_return
        //                 .iter()
        //                 .map(|s| b[s.out_0_idx])
        //                 .collect::<Vec<AuthShare<F>>>()
        //         })
        //         .collect::<Vec<Vec<AuthShare<F>>>>(),
        // );
        let switch_vector_out_1_coins_b = unroll_vector(
            b_coins
                .iter()
                .map(|b| {
                    switches_to_return
                        .iter()
                        .map(|s| b[s.out_1_idx])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );
        // let switch_vector_out_1_coins_mac_b = unroll_vector(
        //     b_coins_mac
        //         .iter()
        //         .map(|b| {
        //             switches_to_return
        //                 .iter()
        //                 .map(|s| b[s.out_1_idx])
        //                 .collect::<Vec<AuthShare<F>>>()
        //         })
        //         .collect::<Vec<Vec<AuthShare<F>>>>(),
        // );

        let vector_sub_in_0_first = VectorSub::<F>::run(
            net,
            state,
            (
                switch_vector_out_0_coins_a.clone(),
                switch_vector_in_0_coins_a.clone(),
            ),
        );

        let vector_sub_in_0_first_mac = VectorSub::<F>::run(
            net,
            state,
            (
                switch_vector_out_0_coins_mac_a.clone(),
                switch_vector_in_0_coins_mac_a.clone(),
            ),
        );

        let s_in_0_first_term_a = VectorMul::<F>::run(
            net,
            state,
            (
                dupe_vector(one_minus_bits.clone(), num_shuffle_tuples),
                vector_sub_in_0_first,
            ),
        );

        let delta_in_0_first_term_a = VectorMul::<F>::run(
            net,
            state,
            (
                dupe_vector(one_minus_bits.clone(), num_shuffle_tuples),
                vector_sub_in_0_first_mac,
            ),
        );

        let vector_sub_in_0_second = VectorSub::<F>::run(
            net,
            state,
            (
                switch_vector_out_1_coins_a.clone(),
                switch_vector_in_0_coins_a.clone(),
            ),
        );

        let vector_sub_in_0_second_mac = VectorSub::<F>::run(
            net,
            state,
            (
                switch_vector_out_1_coins_mac_a.clone(),
                switch_vector_in_0_coins_mac_a.clone(),
            ),
        );

        let s_in_0_second_term_a = VectorMul::<F>::run(
            net,
            state,
            (
                dupe_vector(inputted_switch_bits.clone(), num_shuffle_tuples),
                vector_sub_in_0_second,
            ),
        );

        let delta_in_0_second_term_a = VectorMul::<F>::run(
            net,
            state,
            (
                dupe_vector(inputted_switch_bits.clone(), num_shuffle_tuples),
                vector_sub_in_0_second_mac,
            ),
        );

        let vector_add_in_0 =
            VectorAdd::<F>::run(net, state, (s_in_0_first_term_a, s_in_0_second_term_a));
        let s_in_0_a = VectorReveal::<F>::run(net, state, vector_add_in_0);

        let delta_in_0_third_term_a = VectorScaleByVector::<F>::run(
            net,
            state,
            (vec![k_a; s_in_0_a.len()], s_in_0_a.clone()),
        );

        let delta_in_0_a_pt1 = VectorAdd::<F>::run(
            net,
            state,
            (delta_in_0_first_term_a, delta_in_0_second_term_a),
        );

        let vector_add_delta_in_0_a =
            VectorAdd::<F>::run(net, state, (delta_in_0_a_pt1, delta_in_0_third_term_a));

        let delta_in_0_a = VectorReveal::<F>::run(net, state, vector_add_delta_in_0_a);

        let vector_sub_in_1_first = VectorSub::<F>::run(
            net,
            state,
            (
                switch_vector_out_1_coins_a.clone(),
                switch_vector_in_1_coins_a.clone(),
            ),
        );

        let vector_sub_in_1_first_mac = VectorSub::<F>::run(
            net,
            state,
            (
                switch_vector_out_1_coins_mac_a.clone(),
                switch_vector_in_1_coins_mac_a.clone(),
            ),
        );

        let s_in_1_first_term_a = VectorMul::<F>::run(
            net,
            state,
            (
                dupe_vector(one_minus_bits.clone(), num_shuffle_tuples),
                vector_sub_in_1_first,
            ),
        );

        let delta_in_1_first_term_a = VectorMul::<F>::run(
            net,
            state,
            (
                dupe_vector(one_minus_bits.clone(), num_shuffle_tuples),
                vector_sub_in_1_first_mac,
            ),
        );

        let vector_sub_in_1_second = VectorSub::<F>::run(
            net,
            state,
            (
                switch_vector_out_0_coins_a.clone(),
                switch_vector_in_1_coins_a.clone(),
            ),
        );

        let vector_sub_in_1_second_mac = VectorSub::<F>::run(
            net,
            state,
            (
                switch_vector_out_0_coins_mac_a.clone(),
                switch_vector_in_1_coins_mac_a.clone(),
            ),
        );

        let s_in_1_second_term_a = VectorMul::<F>::run(
            net,
            state,
            (
                dupe_vector(inputted_switch_bits.clone(), num_shuffle_tuples),
                vector_sub_in_1_second,
            ),
        );

        let delta_in_1_second_term_a = VectorMul::<F>::run(
            net,
            state,
            (
                dupe_vector(inputted_switch_bits.clone(), num_shuffle_tuples),
                vector_sub_in_1_second_mac,
            ),
        );

        let vector_add_in_1 =
            VectorAdd::<F>::run(net, state, (s_in_1_first_term_a, s_in_1_second_term_a));
        let s_in_1_a = VectorReveal::<F>::run(net, state, vector_add_in_1);

        let delta_in_1_third_term_a = VectorScaleByVector::<F>::run(
            net,
            state,
            (vec![k_a; s_in_1_a.len()], s_in_1_a.clone()),
        );

        let delta_in_1_a_pt1 = VectorAdd::<F>::run(
            net,
            state,
            (delta_in_1_first_term_a, delta_in_1_second_term_a),
        );
        let vector_add_delta_in_1_a =
            VectorAdd::<F>::run(net, state, (delta_in_1_a_pt1, delta_in_1_third_term_a));

        let delta_in_1_a = VectorReveal::<F>::run(net, state, vector_add_delta_in_1_a);

        let vector_sub_in_0_first = VectorSub::<F>::run(
            net,
            state,
            (
                switch_vector_out_0_coins_b.clone(),
                switch_vector_in_0_coins_b.clone(),
            ),
        );
        // let vector_sub_in_0_first_mac = VectorSub::<F>::run(
        //     net,
        //     state,
        //     (
        //         switch_vector_out_0_coins_mac_b.clone(),
        //         switch_vector_in_0_coins_mac_b.clone(),
        //     ),
        // );
        let s_in_0_first_term_b = VectorMul::<F>::run(
            net,
            state,
            (
                dupe_vector(one_minus_bits.clone(), num_shuffle_tuples),
                vector_sub_in_0_first,
            ),
        );

        // let delta_in_0_first_term_b = VectorMul::<F>::run(
        //     net,
        //     state,
        //     (
        //         dupe_vector(one_minus_bits.clone(), num_shuffle_tuples),
        //         vector_sub_in_0_first_mac,
        //     ),
        // );

        let vector_sub_in_0_second = VectorSub::<F>::run(
            net,
            state,
            (
                switch_vector_out_1_coins_b.clone(),
                switch_vector_in_0_coins_b.clone(),
            ),
        );
        // let vector_sub_in_0_second_mac = VectorSub::<F>::run(
        //     net,
        //     state,
        //     (
        //         switch_vector_out_1_coins_mac_b.clone(),
        //         switch_vector_in_0_coins_mac_b.clone(),
        //     ),
        // );
        let s_in_0_second_term_b = VectorMul::<F>::run(
            net,
            state,
            (
                dupe_vector(inputted_switch_bits.clone(), num_shuffle_tuples),
                vector_sub_in_0_second,
            ),
        );
        // let delta_in_0_second_term_b = VectorMul::<F>::run(
        //     net,
        //     state,
        //     (
        //         dupe_vector(inputted_switch_bits.clone(), num_shuffle_tuples),
        //         vector_sub_in_0_second_mac,
        //     ),
        // );

        let vector_add_in_0 =
            VectorAdd::<F>::run(net, state, (s_in_0_first_term_b, s_in_0_second_term_b));
        let s_in_0_b = VectorReveal::<F>::run(net, state, vector_add_in_0);

        // let delta_in_0_third_term_b = VectorScaleByVector::<F>::run(
        //     net,
        //     state,
        //     (vec![k_b; s_in_0_b.len()], s_in_0_b.clone()),
        // );

        // let delta_in_0_b_pt1 = VectorAdd::<F>::run(
        //     net,
        //     state,
        //     (delta_in_0_first_term_b, delta_in_0_second_term_b),
        // );
        // let vector_add_delta_in_0_b =
        //     VectorAdd::<F>::run(net, state, (delta_in_0_b_pt1, delta_in_0_third_term_b));

        // let delta_in_0_b = VectorReveal::<F>::run(net, state, vector_add_delta_in_0_b);

        let vector_sub_in_1_first = VectorSub::<F>::run(
            net,
            state,
            (
                switch_vector_out_1_coins_b.clone(),
                switch_vector_in_1_coins_b.clone(),
            ),
        );
        // let vector_sub_in_1_first_mac = VectorSub::<F>::run(
        //     net,
        //     state,
        //     (
        //         switch_vector_out_1_coins_mac_b.clone(),
        //         switch_vector_in_1_coins_mac_b.clone(),
        //     ),
        // );
        let s_in_1_first_term_b = VectorMul::<F>::run(
            net,
            state,
            (
                dupe_vector(one_minus_bits.clone(), num_shuffle_tuples),
                vector_sub_in_1_first,
            ),
        );
        // let delta_in_1_first_term_b = VectorMul::<F>::run(
        //     net,
        //     state,
        //     (
        //         dupe_vector(one_minus_bits.clone(), num_shuffle_tuples),
        //         vector_sub_in_1_first_mac,
        //     ),
        // );

        let vector_sub_in_1_second = VectorSub::<F>::run(
            net,
            state,
            (
                switch_vector_out_0_coins_b.clone(),
                switch_vector_in_1_coins_b.clone(),
            ),
        );
        // let vector_sub_in_1_second_mac = VectorSub::<F>::run(
        //     net,
        //     state,
        //     (
        //         switch_vector_out_0_coins_mac_b.clone(),
        //         switch_vector_in_1_coins_mac_b.clone(),
        //     ),
        // );
        let s_in_1_second_term_b = VectorMul::<F>::run(
            net,
            state,
            (
                dupe_vector(inputted_switch_bits.clone(), num_shuffle_tuples),
                vector_sub_in_1_second,
            ),
        );
        // let delta_in_1_second_term_b = VectorMul::<F>::run(
        //     net,
        //     state,
        //     (
        //         dupe_vector(inputted_switch_bits.clone(), num_shuffle_tuples),
        //         vector_sub_in_1_second_mac,
        //     ),
        // );

        let vector_add_in_1 =
            VectorAdd::<F>::run(net, state, (s_in_1_first_term_b, s_in_1_second_term_b));
        let s_in_1_b = VectorReveal::<F>::run(net, state, vector_add_in_1);

        // let delta_in_1_third_term_b = VectorScaleByVector::<F>::run(
        //     net,
        //     state,
        //     (vec![k_b; s_in_1_b.len()], s_in_1_b.clone()),
        // );

        // let delta_in_1_b_pt1 = VectorAdd::<F>::run(
        //     net,
        //     state,
        //     (delta_in_1_first_term_b, delta_in_1_second_term_b),
        // );
        // let vector_add_delta_in_1_b =
        //     VectorAdd::<F>::run(net, state, (delta_in_1_b_pt1, delta_in_1_third_term_b));

        // let delta_in_1_b = VectorReveal::<F>::run(net, state, vector_add_delta_in_1_b);

        // Online stage:
        let input_wires_coins_a = unroll_vector(
            a_coins
                .iter()
                .map(|a| {
                    input_wires
                        .iter()
                        .map(|w| a[*w])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );
        let input_wires_coins_a_mac = unroll_vector(
            a_coins_mac
                .iter()
                .map(|a| {
                    input_wires
                        .iter()
                        .map(|w| a[*w])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );
        let input_wires_coins_b = unroll_vector(
            b_coins
                .iter()
                .map(|b| {
                    input_wires
                        .iter()
                        .map(|w| b[*w])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );
        // let input_wires_coins_b_mac = unroll_vector(
        //     b_coins_mac
        //         .iter()
        //         .map(|b| {
        //             input_wires
        //                 .iter()
        //                 .map(|w| b[*w])
        //                 .collect::<Vec<AuthShare<F>>>()
        //         })
        //         .collect::<Vec<Vec<AuthShare<F>>>>(),
        // );
        let output_wires_coins_a = unroll_vector(
            a_coins
                .iter()
                .map(|a| {
                    output_wires
                        .iter()
                        .map(|w| a[*w])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );
        let output_wires_coins_a_mac = unroll_vector(
            a_coins_mac
                .iter()
                .map(|a| {
                    output_wires
                        .iter()
                        .map(|w| a[*w])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );
        let output_wires_coins_b = unroll_vector(
            b_coins
                .iter()
                .map(|b| {
                    output_wires
                        .iter()
                        .map(|w| b[*w])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );

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
            state,
            (
                1 - permuter_id,
                a_vector_unrolled,
                Some(shuffle_tuple.n * num_shuffle_tuples),
            ),
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
            state,
            (
                1 - permuter_id,
                b_vector_unrolled,
                Some(shuffle_tuple.n * num_shuffle_tuples),
            ),
        );

        let vector_add_t_a =
            VectorAdd::<F>::run(net, state, (a_vector_unrolled_shares, input_wires_coins_a));
        let t_vector_a = VectorReveal::<F>::run(net, state, vector_add_t_a);

        let kappa_t_a = VectorScaleByVector::<F>::run(
            net,
            state,
            (vec![k_a; t_vector_a.len()], t_vector_a.clone()),
        );
        let vector_add_tau_a =
            VectorAdd::<F>::run(net, state, (kappa_t_a, input_wires_coins_a_mac));
        let tau_vector_a = VectorReveal::<F>::run(net, state, vector_add_tau_a);

        let vector_add_t_b =
            VectorAdd::<F>::run(net, state, (b_vector_unrolled_shares, input_wires_coins_b));
        let t_vector_b = VectorReveal::<F>::run(net, state, vector_add_t_b);

        // let kappa_t_b = VectorScaleByVector::<F>::run(
        //     net,
        //     state,
        //     (vec![k_b; t_vector_b.len()], t_vector_b.clone()),
        // );
        // let vector_add_tau_b =
        //     VectorAdd::<F>::run(net, state, (kappa_t_b, input_wires_coins_b_mac));
        // let tau_vector_b = VectorReveal::<F>::run(net, state, vector_add_tau_b);

        if net.party_id() == permuter_id {
            let shuffle: ShuffleVecType = shuffle_tuple.shuffle.as_ref().unwrap().clone();

            let cfg = Config::for_permuting::<usize>(shuffle);
            let switches = cfg.switches();

            let t_vector_rolled_a =
                roll_vector(t_vector_a.clone(), shuffle_tuple.n, num_shuffle_tuples);
            let tau_vector_rolled_a =
                roll_vector(tau_vector_a.clone(), shuffle_tuple.n, num_shuffle_tuples);
            let s_in_0_rolled_a = roll_vector(s_in_0_a.clone(), switches.len(), num_shuffle_tuples);
            let delta_in_0_rolled_a =
                roll_vector(delta_in_0_a.clone(), switches.len(), num_shuffle_tuples);
            let s_in_1_rolled_a = roll_vector(s_in_1_a.clone(), switches.len(), num_shuffle_tuples);
            let delta_in_1_rolled_a =
                roll_vector(delta_in_1_a.clone(), switches.len(), num_shuffle_tuples);
            let t_vector_rolled_b =
                roll_vector(t_vector_b.clone(), shuffle_tuple.n, num_shuffle_tuples);
            // let tau_vector_rolled_b =
            //     roll_vector(tau_vector_b.clone(), shuffle_tuple.n, num_shuffle_tuples);
            let s_in_0_rolled_b = roll_vector(s_in_0_b.clone(), switches.len(), num_shuffle_tuples);
            // let delta_in_0_rolled_b =
            //     roll_vector(delta_in_0_b.clone(), switches.len(), num_shuffle_tuples);
            let s_in_1_rolled_b = roll_vector(s_in_1_b.clone(), switches.len(), num_shuffle_tuples);
            // let delta_in_1_rolled_b =
            //     roll_vector(delta_in_1_b.clone(), switches.len(), num_shuffle_tuples);
            let combined_shares_a = unroll_vector(
                t_vector_rolled_a
                    .iter()
                    .enumerate()
                    .map(|(i, t)| {
                        symbolic_apply_circ::<F>(
                            t.clone(),
                            &mut VecDeque::from(switches.clone()),
                            &mut VecDeque::from(s_in_0_rolled_a[i].clone()),
                            &mut VecDeque::from(s_in_1_rolled_a[i].clone()),
                        )
                    })
                    .collect::<Vec<Vec<F>>>(),
            );

            let tau_vector = unroll_vector(
                tau_vector_rolled_a
                    .iter()
                    .enumerate()
                    .map(|(i, tau)| {
                        symbolic_apply_circ::<F>(
                            tau.clone(),
                            &mut VecDeque::from(switches.clone()),
                            &mut VecDeque::from(delta_in_0_rolled_a[i].clone()),
                            &mut VecDeque::from(delta_in_1_rolled_a[i].clone()),
                        )
                    })
                    .collect::<Vec<Vec<F>>>(),
            );

            let combined_auth_shares_a =
                VectorInput::<F>::run(net, state, (permuter_id, Some(combined_shares_a), None));

            // Perform K auth check
            // Permuter assists with performing K auth check
            // Permuter sends Tau vector to Sender, observe that alterting Tau will cause the K auth check to fail

            // E.g. uncomment these lines will fail auth check
            // let mut tau_vector = tau_vector.clone();
            // tau_vector[0] = tau_vector[0] + F::one();

            net.send_to_party(1 - permuter_id, &tau_vector);

            let k_auth_shares = VectorMul::<F>::run(
                net,
                state,
                (
                    combined_auth_shares_a.clone(),
                    vec![k_a; combined_auth_shares_a.len()],
                ),
            );
            let gamma_auth_shares =
                VectorAdd::<F>::run(net, state, (output_wires_coins_a_mac, k_auth_shares));
            VectorReveal::<F>::run(net, state, gamma_auth_shares);

            // End K auth check

            let neg_output_wires_coins_a = VectorNeg::<F>::run(net, state, output_wires_coins_a);
            let output_shares_a = roll_vector(
                VectorAdd::<F>::run(
                    net,
                    state,
                    (neg_output_wires_coins_a, combined_auth_shares_a),
                ),
                shuffle_tuple.n,
                num_shuffle_tuples,
            );

            let combined_shares_b = unroll_vector(
                t_vector_rolled_b
                    .iter()
                    .enumerate()
                    .map(|(i, t)| {
                        symbolic_apply_circ::<F>(
                            t.clone(),
                            &mut VecDeque::from(switches.clone()),
                            &mut VecDeque::from(s_in_0_rolled_b[i].clone()),
                            &mut VecDeque::from(s_in_1_rolled_b[i].clone()),
                        )
                    })
                    .collect::<Vec<Vec<F>>>(),
            );

            let combined_auth_shares_b =
                VectorInput::<F>::run(net, state, (permuter_id, Some(combined_shares_b), None));

            let neg_output_wires_coins_b = VectorNeg::<F>::run(net, state, output_wires_coins_b);
            let output_shares_b = roll_vector(
                VectorAdd::<F>::run(
                    net,
                    state,
                    (neg_output_wires_coins_b, combined_auth_shares_b),
                ),
                shuffle_tuple.n,
                num_shuffle_tuples,
            );

            output_shares_a
                .into_iter()
                .zip(output_shares_b.into_iter())
                .enumerate()
                .map(|(_i, (a, b))| ShuffleTupleTest {
                    shuffle: shuffle_tuple.shuffle.clone(),
                    tuples_a: a,
                    tuples_b: b,
                    a: None,
                    b: None,
                })
                .collect::<Vec<ShuffleTupleTest<F>>>()
        } else {
            let combined_auth_shares_a = VectorInput::<F>::run(
                net,
                state,
                (
                    permuter_id,
                    None,
                    Some(shuffle_tuple.n * num_shuffle_tuples),
                ),
            );

            // Perform K auth check
            // Sender verifies K auth check
            let combined_tau_vector = net.recv_from_party::<Vec<F>>(permuter_id);
            let k_auth_shares = VectorMul::<F>::run(
                net,
                state,
                (
                    combined_auth_shares_a.clone(),
                    vec![k_a; combined_auth_shares_a.len()],
                ),
            );
            let gamma_auth_shares =
                VectorAdd::<F>::run(net, state, (output_wires_coins_a_mac, k_auth_shares));
            let gamma = VectorReveal::<F>::run(net, state, gamma_auth_shares); // Reveal gamma
            let zero_check = gamma
                .into_iter()
                .zip(combined_tau_vector.into_iter())
                .map(|(g, t)| g - t)
                .collect::<Vec<F>>();

            if !zero_check.iter().all(|z| z == &F::zero()) {
                // Failure
                assert!(false, "K auth check failed");
            }
            // End K auth check

            let neg_output_wires_coins_a = VectorNeg::<F>::run(net, state, output_wires_coins_a);
            let output_shares_a = roll_vector(
                VectorAdd::<F>::run(
                    net,
                    state,
                    (neg_output_wires_coins_a, combined_auth_shares_a),
                ),
                shuffle_tuple.n,
                num_shuffle_tuples,
            );

            let combined_shares_b = VectorInput::<F>::run(
                net,
                state,
                (
                    permuter_id,
                    None,
                    Some(shuffle_tuple.n * num_shuffle_tuples),
                ),
            );

            let neg_output_wires_coins_b = VectorNeg::<F>::run(net, state, output_wires_coins_b);
            let output_shares_b = roll_vector(
                VectorAdd::<F>::run(net, state, (neg_output_wires_coins_b, combined_shares_b)),
                shuffle_tuple.n,
                num_shuffle_tuples,
            );

            output_shares_a
                .into_iter()
                .zip(output_shares_b.into_iter())
                .enumerate()
                .map(|(i, (a, b))| ShuffleTupleTest {
                    shuffle: shuffle_tuple.shuffle.clone(),
                    tuples_a: a,
                    tuples_b: b,
                    a: Some(a_vector_rolled.as_ref().unwrap()[i].clone()),
                    b: Some(b_vector_rolled.as_ref().unwrap()[i].clone()),
                })
                .collect::<Vec<ShuffleTupleTest<F>>>()
        }
    }

    /// Generate shuffle tuples for a given shuffle tuple input
    pub fn generate_inverse_shuffle_tuples_helper(
        &mut self,
        net: &mut Net,
        state: &mut ArithCircState<F>,
        shuffle_tuple: &ShuffleTupleInput,
    ) -> Vec<ShuffleTupleTest<F>> {
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

            VectorInput::<F>::run(net, state, (permuter_id, Some(switches_bits), None))
        } else {
            let cfg = Config::for_permuting::<usize>((0..shuffle_tuple.n).collect::<Vec<usize>>());
            let num_switches = cfg.switches().len();
            VectorInput::<F>::run(net, state, (permuter_id, None, Some(num_switches)))
        };

        // Step 2: check the bits.
        let neg_bits = VectorNeg::<F>::run(net, state, inputted_switch_bits.clone());
        let one_minus_bits = VectorShift::<F>::run(net, state, (neg_bits, F::one()));
        let eq = VectorMul::<F>::run(
            net,
            state,
            (inputted_switch_bits.clone(), one_minus_bits.clone()),
        );
        let z = VectorReveal::<F>::run(net, state, eq);

        assert!(z.iter().all(|z| z.is_zero()), "Vector Bit Check failed");

        // Step 3: create the perm network circuit
        let input_wires = (0..shuffle_tuple.n).collect::<Vec<usize>>();
        let mut switches_to_return = Vec::new();
        let mut global_index = shuffle_tuple.n;
        let output_wires = get_indexed_switches(
            input_wires.clone(),
            &mut global_index,
            &mut switches_to_return,
        );
        let coins_to_take = max(output_wires.clone()).unwrap() + 1;
        let coins_a = state.take_auth_coins(num_shuffle_tuples * coins_to_take);
        let a_coins = roll_vector(coins_a, coins_to_take, num_shuffle_tuples);

        let coins_b = state.take_auth_coins(num_shuffle_tuples * coins_to_take);
        let b_coins = roll_vector(coins_b, coins_to_take, num_shuffle_tuples);

        let coins_mac_a = state.take_auth_coins(num_shuffle_tuples * coins_to_take);
        let a_coins_mac = roll_vector(coins_mac_a, coins_to_take, num_shuffle_tuples);

        let k_a = state.take_auth_coins(1)[0];

        let switch_vector_in_0_coins_a = unroll_vector(
            a_coins
                .iter()
                .map(|a| {
                    switches_to_return
                        .iter()
                        .map(|s| a[s.in_0_idx])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );
        let switch_vector_in_0_coins_mac_a = unroll_vector(
            a_coins_mac
                .iter()
                .map(|a| {
                    switches_to_return
                        .iter()
                        .map(|s| a[s.in_0_idx])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );
        let switch_vector_in_1_coins_a = unroll_vector(
            a_coins
                .iter()
                .map(|a| {
                    switches_to_return
                        .iter()
                        .map(|s| a[s.in_1_idx])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );
        let switch_vector_in_1_coins_mac_a = unroll_vector(
            a_coins_mac
                .iter()
                .map(|a| {
                    switches_to_return
                        .iter()
                        .map(|s| a[s.in_1_idx])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );
        let switch_vector_out_0_coins_a = unroll_vector(
            a_coins
                .iter()
                .map(|a| {
                    switches_to_return
                        .iter()
                        .map(|s| a[s.out_0_idx])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );
        let switch_vector_out_0_coins_mac_a = unroll_vector(
            a_coins_mac
                .iter()
                .map(|a| {
                    switches_to_return
                        .iter()
                        .map(|s| a[s.out_0_idx])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );
        let switch_vector_out_1_coins_a = unroll_vector(
            a_coins
                .iter()
                .map(|a| {
                    switches_to_return
                        .iter()
                        .map(|s| a[s.out_1_idx])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );
        let switch_vector_out_1_coins_mac_a = unroll_vector(
            a_coins_mac
                .iter()
                .map(|a| {
                    switches_to_return
                        .iter()
                        .map(|s| a[s.out_1_idx])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );

        let switch_vector_in_0_coins_b = unroll_vector(
            b_coins
                .iter()
                .map(|b| {
                    switches_to_return
                        .iter()
                        .map(|s| b[s.in_0_idx])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );
        let switch_vector_in_1_coins_b = unroll_vector(
            b_coins
                .iter()
                .map(|b| {
                    switches_to_return
                        .iter()
                        .map(|s| b[s.in_1_idx])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );
        let switch_vector_out_0_coins_b = unroll_vector(
            b_coins
                .iter()
                .map(|b| {
                    switches_to_return
                        .iter()
                        .map(|s| b[s.out_0_idx])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );
        let switch_vector_out_1_coins_b = unroll_vector(
            b_coins
                .iter()
                .map(|b| {
                    switches_to_return
                        .iter()
                        .map(|s| b[s.out_1_idx])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );

        let vector_sub_out_0_first_term_a = VectorSub::<F>::run(
            net,
            state,
            (
                switch_vector_in_0_coins_a.clone(),
                switch_vector_out_0_coins_a.clone(),
            ),
        );
        let vector_sub_out_0_first_term_mac_a = VectorSub::<F>::run(
            net,
            state,
            (
                switch_vector_in_0_coins_mac_a.clone(),
                switch_vector_out_0_coins_mac_a.clone(),
            ),
        );
        let s_out_0_first_term_a = VectorMul::<F>::run(
            net,
            state,
            (
                dupe_vector(one_minus_bits.clone(), num_shuffle_tuples),
                vector_sub_out_0_first_term_a,
            ),
        );
        let delta_out_0_first_term_a = VectorMul::<F>::run(
            net,
            state,
            (
                dupe_vector(one_minus_bits.clone(), num_shuffle_tuples),
                vector_sub_out_0_first_term_mac_a,
            ),
        );

        let vector_sub_out_0_second_term_a = VectorSub::<F>::run(
            net,
            state,
            (
                switch_vector_in_1_coins_a.clone(),
                switch_vector_out_0_coins_a.clone(),
            ),
        );
        let vector_sub_out_0_second_term_mac_a = VectorSub::<F>::run(
            net,
            state,
            (
                switch_vector_in_1_coins_mac_a.clone(),
                switch_vector_out_0_coins_mac_a.clone(),
            ),
        );

        let s_out_0_second_term_a = VectorMul::<F>::run(
            net,
            state,
            (
                dupe_vector(inputted_switch_bits.clone(), num_shuffle_tuples),
                vector_sub_out_0_second_term_a,
            ),
        );
        let delta_out_0_second_term_a = VectorMul::<F>::run(
            net,
            state,
            (
                dupe_vector(inputted_switch_bits.clone(), num_shuffle_tuples),
                vector_sub_out_0_second_term_mac_a,
            ),
        );

        let vector_add_out_0 =
            VectorAdd::<F>::run(net, state, (s_out_0_first_term_a, s_out_0_second_term_a));
        let s_out_0_a = VectorReveal::<F>::run(net, state, vector_add_out_0);

        let delta_out_0_third_term_a = VectorScaleByVector::<F>::run(
            net,
            state,
            (vec![k_a; s_out_0_a.len()], s_out_0_a.clone()),
        );

        let delta_out_0_a_pt1 = VectorAdd::<F>::run(
            net,
            state,
            (delta_out_0_first_term_a, delta_out_0_second_term_a),
        );

        let vector_add_delta_out_0_a =
            VectorAdd::<F>::run(net, state, (delta_out_0_third_term_a, delta_out_0_a_pt1));
        let delta_out_0_a = VectorReveal::<F>::run(net, state, vector_add_delta_out_0_a);

        let vector_sub_out_1_first_term_a = VectorSub::<F>::run(
            net,
            state,
            (
                switch_vector_in_1_coins_a.clone(),
                switch_vector_out_1_coins_a.clone(),
            ),
        );
        let vector_sub_out_1_first_term_mac_a = VectorSub::<F>::run(
            net,
            state,
            (
                switch_vector_in_1_coins_mac_a.clone(),
                switch_vector_out_1_coins_mac_a.clone(),
            ),
        );
        let s_out_1_first_term_a = VectorMul::<F>::run(
            net,
            state,
            (
                dupe_vector(one_minus_bits.clone(), num_shuffle_tuples),
                vector_sub_out_1_first_term_a,
            ),
        );
        let delta_out_1_first_term_a = VectorMul::<F>::run(
            net,
            state,
            (
                dupe_vector(one_minus_bits.clone(), num_shuffle_tuples),
                vector_sub_out_1_first_term_mac_a,
            ),
        );

        let vector_sub_out_1_second_term_a = VectorSub::<F>::run(
            net,
            state,
            (
                switch_vector_in_0_coins_a.clone(),
                switch_vector_out_1_coins_a.clone(),
            ),
        );
        let vector_sub_out_1_second_term_mac_a = VectorSub::<F>::run(
            net,
            state,
            (
                switch_vector_in_0_coins_mac_a.clone(),
                switch_vector_out_1_coins_mac_a.clone(),
            ),
        );
        let s_out_1_second_term_a = VectorMul::<F>::run(
            net,
            state,
            (
                dupe_vector(inputted_switch_bits.clone(), num_shuffle_tuples),
                vector_sub_out_1_second_term_a,
            ),
        );
        let delta_out_1_second_term_a = VectorMul::<F>::run(
            net,
            state,
            (
                dupe_vector(inputted_switch_bits.clone(), num_shuffle_tuples),
                vector_sub_out_1_second_term_mac_a,
            ),
        );
        let vector_add_out_1 =
            VectorAdd::<F>::run(net, state, (s_out_1_first_term_a, s_out_1_second_term_a));
        let s_out_1_a = VectorReveal::<F>::run(net, state, vector_add_out_1);

        let delta_out_1_third_term_a = VectorScaleByVector::<F>::run(
            net,
            state,
            (vec![k_a; s_out_1_a.len()], s_out_1_a.clone()),
        );

        let delta_out_1_a_pt1 = VectorAdd::<F>::run(
            net,
            state,
            (delta_out_1_first_term_a, delta_out_1_second_term_a),
        );

        let vector_add_delta_out_1_a =
            VectorAdd::<F>::run(net, state, (delta_out_1_third_term_a, delta_out_1_a_pt1));
        let delta_out_1_a = VectorReveal::<F>::run(net, state, vector_add_delta_out_1_a);

        let vector_sub_out_0_first_term_b = VectorSub::<F>::run(
            net,
            state,
            (
                switch_vector_in_0_coins_b.clone(),
                switch_vector_out_0_coins_b.clone(),
            ),
        );

        let s_out_0_first_term_b = VectorMul::<F>::run(
            net,
            state,
            (
                dupe_vector(one_minus_bits.clone(), num_shuffle_tuples),
                vector_sub_out_0_first_term_b,
            ),
        );

        let vector_sub_out_0_second_term_b = VectorSub::<F>::run(
            net,
            state,
            (
                switch_vector_in_1_coins_b.clone(),
                switch_vector_out_0_coins_b.clone(),
            ),
        );
        let s_out_0_second_term_b = VectorMul::<F>::run(
            net,
            state,
            (
                dupe_vector(inputted_switch_bits.clone(), num_shuffle_tuples),
                vector_sub_out_0_second_term_b,
            ),
        );

        let vector_add_out_0 =
            VectorAdd::<F>::run(net, state, (s_out_0_first_term_b, s_out_0_second_term_b));
        let s_out_0_b = VectorReveal::<F>::run(net, state, vector_add_out_0);

        let vector_sub_out_1_first_term_b = VectorSub::<F>::run(
            net,
            state,
            (
                switch_vector_in_1_coins_b.clone(),
                switch_vector_out_1_coins_b.clone(),
            ),
        );
        let s_out_1_first_term_b = VectorMul::<F>::run(
            net,
            state,
            (
                dupe_vector(one_minus_bits.clone(), num_shuffle_tuples),
                vector_sub_out_1_first_term_b,
            ),
        );

        let vector_sub_out_1_second_term_b = VectorSub::<F>::run(
            net,
            state,
            (
                switch_vector_in_0_coins_b.clone(),
                switch_vector_out_1_coins_b.clone(),
            ),
        );
        let s_out_1_second_term_b = VectorMul::<F>::run(
            net,
            state,
            (
                dupe_vector(inputted_switch_bits.clone(), num_shuffle_tuples),
                vector_sub_out_1_second_term_b,
            ),
        );

        let vector_add_out_1 =
            VectorAdd::<F>::run(net, state, (s_out_1_first_term_b, s_out_1_second_term_b));
        let s_out_1_b = VectorReveal::<F>::run(net, state, vector_add_out_1);

        // Online stage:
        let input_wires_coins_a = unroll_vector(
            a_coins
                .iter()
                .map(|a| {
                    input_wires
                        .iter()
                        .map(|w| a[*w])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );
        let input_wires_coins_a_mac = unroll_vector(
            a_coins_mac
                .iter()
                .map(|a| {
                    input_wires
                        .iter()
                        .map(|w| a[*w])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );
        let input_wires_coins_b = unroll_vector(
            b_coins
                .iter()
                .map(|b| {
                    input_wires
                        .iter()
                        .map(|w| b[*w])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );
        let output_wires_coins_a = unroll_vector(
            a_coins
                .iter()
                .map(|a| {
                    output_wires
                        .iter()
                        .map(|w| a[*w])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );
        let output_wires_coins_a_mac = unroll_vector(
            a_coins_mac
                .iter()
                .map(|a| {
                    output_wires
                        .iter()
                        .map(|w| a[*w])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );
        let output_wires_coins_b = unroll_vector(
            b_coins
                .iter()
                .map(|b| {
                    output_wires
                        .iter()
                        .map(|w| b[*w])
                        .collect::<Vec<AuthShare<F>>>()
                })
                .collect::<Vec<Vec<AuthShare<F>>>>(),
        );
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
            state,
            (
                1 - permuter_id,
                a_vector_unrolled,
                Some(shuffle_tuple.n * num_shuffle_tuples),
            ),
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
            state,
            (
                1 - permuter_id,
                b_vector_unrolled,
                Some(shuffle_tuple.n * num_shuffle_tuples),
            ),
        );

        let vector_add_t_a =
            VectorAdd::<F>::run(net, state, (a_vector_unrolled_shares, output_wires_coins_a));
        let t_vector_a = VectorReveal::<F>::run(net, state, vector_add_t_a);

        let kappa_t_a = VectorScaleByVector::<F>::run(
            net,
            state,
            (vec![k_a; t_vector_a.len()], t_vector_a.clone()),
        );
        let vector_add_tau_a =
            VectorAdd::<F>::run(net, state, (kappa_t_a, output_wires_coins_a_mac));
        let tau_vector_a = VectorReveal::<F>::run(net, state, vector_add_tau_a);

        let vector_add_t_b =
            VectorAdd::<F>::run(net, state, (b_vector_unrolled_shares, output_wires_coins_b));
        let t_vector_b = VectorReveal::<F>::run(net, state, vector_add_t_b);

        if net.party_id() == permuter_id {
            let shuffle: ShuffleVecType = shuffle_tuple.shuffle.as_ref().unwrap().clone();

            let cfg = Config::for_permuting::<usize>(shuffle);
            let switches = cfg.switches();

            let t_vector_rolled_a =
                roll_vector(t_vector_a.clone(), shuffle_tuple.n, num_shuffle_tuples);
            let tau_vector_rolled_a =
                roll_vector(tau_vector_a.clone(), shuffle_tuple.n, num_shuffle_tuples);
            let t_vector_rolled_b =
                roll_vector(t_vector_b.clone(), shuffle_tuple.n, num_shuffle_tuples);
            let s_out_0_rolled_a =
                roll_vector(s_out_0_a.clone(), switches.len(), num_shuffle_tuples);
            let delta_out_0_rolled_a =
                roll_vector(delta_out_0_a.clone(), switches.len(), num_shuffle_tuples);
            let s_out_0_rolled_b =
                roll_vector(s_out_0_b.clone(), switches.len(), num_shuffle_tuples);
            let s_out_1_rolled_a =
                roll_vector(s_out_1_a.clone(), switches.len(), num_shuffle_tuples);
            let delta_out_1_rolled_a =
                roll_vector(delta_out_1_a.clone(), switches.len(), num_shuffle_tuples);
            let s_out_1_rolled_b =
                roll_vector(s_out_1_b.clone(), switches.len(), num_shuffle_tuples);

            let combined_shares_a = unroll_vector(
                t_vector_rolled_a
                    .iter()
                    .enumerate()
                    .map(|(i, t)| {
                        symbolic_apply_circ_rev::<F>(
                            t.clone(),
                            &mut VecDeque::from(switches.clone()),
                            &mut VecDeque::from(s_out_0_rolled_a[i].clone()),
                            &mut VecDeque::from(s_out_1_rolled_a[i].clone()),
                        )
                    })
                    .collect::<Vec<Vec<F>>>(),
            );

            let tau_vector = unroll_vector(
                tau_vector_rolled_a
                    .iter()
                    .enumerate()
                    .map(|(i, tau)| {
                        symbolic_apply_circ_rev::<F>(
                            tau.clone(),
                            &mut VecDeque::from(switches.clone()),
                            &mut VecDeque::from(delta_out_0_rolled_a[i].clone()),
                            &mut VecDeque::from(delta_out_1_rolled_a[i].clone()),
                        )
                    })
                    .collect::<Vec<Vec<F>>>(),
            );

            let combined_auth_shares_a =
                VectorInput::<F>::run(net, state, (permuter_id, Some(combined_shares_a), None));

            // Perform K auth check
            // Permuter assists with performing K auth check
            // Permuter sends Tau vector to Sender, observe that alterting Tau will cause the K auth check to fail

            // E.g. uncomment these lines will fail auth check
            // let mut tau_vector = tau_vector.clone();
            // tau_vector[0] = tau_vector[0] + F::one();

            net.send_to_party(1 - permuter_id, &tau_vector);

            let k_auth_shares = VectorMul::<F>::run(
                net,
                state,
                (
                    combined_auth_shares_a.clone(),
                    vec![k_a; combined_auth_shares_a.len()],
                ),
            );
            let gamma_auth_shares =
                VectorAdd::<F>::run(net, state, (input_wires_coins_a_mac, k_auth_shares));
            VectorReveal::<F>::run(net, state, gamma_auth_shares);

            // End K auth check

            let vector_neg_input_wires_coins_a =
                VectorNeg::<F>::run(net, state, input_wires_coins_a);
            let output_shares_a = roll_vector(
                VectorAdd::<F>::run(
                    net,
                    state,
                    (vector_neg_input_wires_coins_a, combined_auth_shares_a),
                ),
                shuffle_tuple.n,
                num_shuffle_tuples,
            );

            let combined_shares_b = unroll_vector(
                t_vector_rolled_b
                    .iter()
                    .enumerate()
                    .map(|(i, t)| {
                        symbolic_apply_circ_rev::<F>(
                            t.clone(),
                            &mut VecDeque::from(switches.clone()),
                            &mut VecDeque::from(s_out_0_rolled_b[i].clone()),
                            &mut VecDeque::from(s_out_1_rolled_b[i].clone()),
                        )
                    })
                    .collect::<Vec<Vec<F>>>(),
            );

            let combined_auth_shares_b =
                VectorInput::<F>::run(net, state, (permuter_id, Some(combined_shares_b), None));

            let vector_neg_input_wires_coins_b =
                VectorNeg::<F>::run(net, state, input_wires_coins_b);
            let output_shares_b = roll_vector(
                VectorAdd::<F>::run(
                    net,
                    state,
                    (vector_neg_input_wires_coins_b, combined_auth_shares_b),
                ),
                shuffle_tuple.n,
                num_shuffle_tuples,
            );

            output_shares_a
                .into_iter()
                .zip(output_shares_b.into_iter())
                .enumerate()
                .map(|(_i, (a, b))| ShuffleTupleTest {
                    shuffle: shuffle_tuple.shuffle.clone(),
                    tuples_a: a,
                    tuples_b: b,
                    a: None,
                    b: None,
                })
                .collect::<Vec<ShuffleTupleTest<F>>>()
        } else {
            let combined_auth_shares_a = VectorInput::<F>::run(
                net,
                state,
                (
                    permuter_id,
                    None,
                    Some(shuffle_tuple.n * num_shuffle_tuples),
                ),
            );

            // Perform K auth check
            // Sender verifies K auth check
            let combined_tau_vector = net.recv_from_party::<Vec<F>>(permuter_id);
            let k_auth_shares = VectorMul::<F>::run(
                net,
                state,
                (
                    combined_auth_shares_a.clone(),
                    vec![k_a; combined_auth_shares_a.len()],
                ),
            );
            let gamma_auth_shares =
                VectorAdd::<F>::run(net, state, (input_wires_coins_a_mac, k_auth_shares));
            let gamma = VectorReveal::<F>::run(net, state, gamma_auth_shares); // Reveal gamma
            let zero_check = gamma
                .into_iter()
                .zip(combined_tau_vector.into_iter())
                .map(|(g, t)| g - t)
                .collect::<Vec<F>>();

            if !zero_check.iter().all(|z| z == &F::zero()) {
                // Failure
                assert!(false, "K auth check failed");
            }
            // End K auth check

            let vector_neg_input_wires_coins_a =
                VectorNeg::<F>::run(net, state, input_wires_coins_a);
            let output_shares_a = roll_vector(
                VectorAdd::<F>::run(
                    net,
                    state,
                    (vector_neg_input_wires_coins_a, combined_auth_shares_a),
                ),
                shuffle_tuple.n,
                num_shuffle_tuples,
            );

            let combined_shares_b = VectorInput::<F>::run(
                net,
                state,
                (
                    permuter_id,
                    None,
                    Some(shuffle_tuple.n * num_shuffle_tuples),
                ),
            );

            let vector_neg_input_wires_coins_b =
                VectorNeg::<F>::run(net, state, input_wires_coins_b);
            let output_shares_b = roll_vector(
                VectorAdd::<F>::run(
                    net,
                    state,
                    (vector_neg_input_wires_coins_b, combined_shares_b),
                ),
                shuffle_tuple.n,
                num_shuffle_tuples,
            );

            output_shares_a
                .into_iter()
                .zip(output_shares_b.into_iter())
                .enumerate()
                .map(|(i, (a, b))| ShuffleTupleTest {
                    shuffle: shuffle_tuple.shuffle.clone(),
                    tuples_a: a,
                    tuples_b: b,
                    a: Some(a_vector_rolled.as_ref().unwrap()[i].clone()),
                    b: Some(b_vector_rolled.as_ref().unwrap()[i].clone()),
                })
                .collect::<Vec<ShuffleTupleTest<F>>>()
        }
    }
}

impl<F: Field> ArithPermCircPrep<F> for PermNetworkArithPermCircPrep<F> {
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
            if st.with_inverse {
                self.generate_shuffle_tuple_with_inverse(net, &mut state, &st)
            } else {
                self.generate_shuffle_tuple(net, &mut state, &st)
            }
        });

        state
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;

    use super::*;
    use crate::{
        arithcircop::{ArithCircOp, opened_auth_check::OpenedAuthCheck},
        arithcircprep::{ArithCircPrep, dummy::DummyArithCircPrep},
        utils::rng_utils::get_random_permutation_usize,
        utils::rng_utils::local_shuffle_vector,
        utils::rng_utils::local_unshuffle_vector,
    };
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use tempfile::NamedTempFile;
    type Fr = crate::bench::Mersenne128Fq;

    #[test]
    fn test_perm_network() {
        let n = 25;
        let num_shuffle_tuples = 3;

        // to be inputted
        let shuffle_input = get_random_permutation_usize(n);
        let shuffle_input_clone = shuffle_input.clone();
        let shuffle_input_clone_2 = shuffle_input.clone();

        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        // Shared state to collect outputs
        let p0_regular_shuffle_tuple_outputs =
            Arc::new(Mutex::new(Vec::<Vec<ShuffleTupleTest<Fr>>>::new()));
        let p1_regular_shuffle_tuple_outputs =
            Arc::new(Mutex::new(Vec::<Vec<ShuffleTupleTest<Fr>>>::new()));
        let p0_inverse_shuffle_tuple_outputs =
            Arc::new(Mutex::new(Vec::<Vec<ShuffleTupleTest<Fr>>>::new()));
        let p1_inverse_shuffle_tuple_outputs =
            Arc::new(Mutex::new(Vec::<Vec<ShuffleTupleTest<Fr>>>::new()));

        let mac_shares = Arc::new(Mutex::new(Vec::<Fr>::new()));
        rayon::scope(|s| {
            let p0_regular_shuffle_tuple_outputs_clone = p0_regular_shuffle_tuple_outputs.clone();
            let p0_inverse_shuffle_tuple_outputs_clone = p0_inverse_shuffle_tuple_outputs.clone();
            let mac_shares_party0 = mac_shares.clone();
            // party 0
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 0);

                let mut state = DummyArithCircPrep::<Fr>::new().run(
                    &mut net,
                    4 * n * num_shuffle_tuples,
                    100 * n * num_shuffle_tuples + 2,
                    0,
                    150 * n * num_shuffle_tuples,
                    0,
                );

                mac_shares_party0.lock().unwrap().push(state.key_share());

                let shuffle_tuple_input = ShuffleTupleInput {
                    shuffle_id: "shuffle1".to_string(),
                    shuffle: Some(shuffle_input_clone.clone()),
                    n: n,
                    num_shuffle_tuples: num_shuffle_tuples,
                    with_inverse: false,
                };

                let shuffle_tuple_inv_input = ShuffleTupleInput {
                    shuffle_id: "shuffle1_inverse".to_string(),
                    shuffle: Some(shuffle_input_clone.clone()),
                    n: n,
                    num_shuffle_tuples: num_shuffle_tuples,
                    with_inverse: true,
                };

                // Generate arithmetic permutation circuit state with shuffle tuples
                let mut arith_perm_circ_prep = PermNetworkArithPermCircPrep::<Fr>::new();
                let shuffle_tuple = arith_perm_circ_prep.generate_regular_shuffle_tuples_helper(
                    &mut net,
                    &mut state,
                    &shuffle_tuple_input,
                );

                let shuffle_tuple_inv = arith_perm_circ_prep
                    .generate_inverse_shuffle_tuples_helper(
                        &mut net,
                        &mut state,
                        &shuffle_tuple_inv_input,
                    );

                // Flushing the auth share check queue should pass
                let to_check_auth_shares = state.drain_to_check_auth_shares();
                let (opened_values, auth_shares): (Vec<Fr>, Vec<Fr>) = to_check_auth_shares
                    .iter()
                    .map(|(opened_value, auth_share)| (*opened_value, *auth_share))
                    .unzip();
                OpenedAuthCheck::<Fr>::run(&mut net, &mut state, (opened_values, auth_shares));

                // Store party 0's results
                p0_regular_shuffle_tuple_outputs_clone
                    .lock()
                    .unwrap()
                    .push(shuffle_tuple);
                p0_inverse_shuffle_tuple_outputs_clone
                    .lock()
                    .unwrap()
                    .push(shuffle_tuple_inv);
            });

            let p1_regular_shuffle_tuple_outputs_clone = p1_regular_shuffle_tuple_outputs.clone();
            let p1_inverse_shuffle_tuple_outputs_clone = p1_inverse_shuffle_tuple_outputs.clone();
            let mac_shares_party1 = mac_shares.clone();
            // party 1
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);

                let mut state = DummyArithCircPrep::<Fr>::new().run(
                    &mut net,
                    4 * n * num_shuffle_tuples,
                    100 * n * num_shuffle_tuples + 2,
                    0,
                    150 * n * num_shuffle_tuples,
                    0,
                );

                mac_shares_party1.lock().unwrap().push(state.key_share());
                let shuffle_tuple_input = ShuffleTupleInput {
                    shuffle_id: "shuffle1".to_string(),
                    shuffle: None,
                    n: n,
                    num_shuffle_tuples: num_shuffle_tuples,
                    with_inverse: false,
                };

                let shuffle_tuple_inv_input = ShuffleTupleInput {
                    shuffle_id: "shuffle1_inverse".to_string(),
                    shuffle: None,
                    n: n,
                    num_shuffle_tuples: num_shuffle_tuples,
                    with_inverse: true,
                };

                // Generate arithmetic permutation circuit state with shuffle tuples
                let mut arith_perm_circ_prep = PermNetworkArithPermCircPrep::<Fr>::new();
                let shuffle_tuple = arith_perm_circ_prep.generate_regular_shuffle_tuples_helper(
                    &mut net,
                    &mut state,
                    &shuffle_tuple_input,
                );

                let shuffle_tuple_inv = arith_perm_circ_prep
                    .generate_inverse_shuffle_tuples_helper(
                        &mut net,
                        &mut state,
                        &shuffle_tuple_inv_input,
                    );

                // Flushing the auth share check queue should pass
                let to_check_auth_shares = state.drain_to_check_auth_shares();
                let (opened_values, auth_shares): (Vec<Fr>, Vec<Fr>) = to_check_auth_shares
                    .iter()
                    .map(|(opened_value, auth_share)| (*opened_value, *auth_share))
                    .unzip();
                OpenedAuthCheck::<Fr>::run(&mut net, &mut state, (opened_values, auth_shares));

                // Store party 1's results
                p1_regular_shuffle_tuple_outputs_clone
                    .lock()
                    .unwrap()
                    .push(shuffle_tuple);
                p1_inverse_shuffle_tuple_outputs_clone
                    .lock()
                    .unwrap()
                    .push(shuffle_tuple_inv);
            });
        });

        let p0_shuffle_tuples = p0_regular_shuffle_tuple_outputs
            .lock()
            .unwrap()
            .pop()
            .unwrap();
        let p1_shuffle_tuples = p1_regular_shuffle_tuple_outputs
            .lock()
            .unwrap()
            .pop()
            .unwrap();

        let p0_inverse_shuffle_tuple = p0_inverse_shuffle_tuple_outputs
            .lock()
            .unwrap()
            .pop()
            .unwrap();
        let p1_inverse_shuffle_tuple = p1_inverse_shuffle_tuple_outputs
            .lock()
            .unwrap()
            .pop()
            .unwrap();

        let mac = mac_shares.lock().unwrap().iter().sum::<Fr>();

        for (i, _) in p0_shuffle_tuples.iter().enumerate() {
            assert_eq!(
                p0_shuffle_tuples[i]
                    .tuples_a
                    .iter()
                    .zip(p1_shuffle_tuples[i].tuples_a.iter())
                    .map(|(a, b)| a.value + b.value)
                    .collect::<Vec<Fr>>(),
                local_shuffle_vector(
                    &shuffle_input_clone_2,
                    &p1_shuffle_tuples[i].a.as_ref().unwrap().clone()
                )
            );

            assert_eq!(
                p0_shuffle_tuples[i]
                    .tuples_a
                    .iter()
                    .zip(p1_shuffle_tuples[i].tuples_a.iter())
                    .map(|(a, b)| a.mac + b.mac)
                    .collect::<Vec<Fr>>(),
                local_shuffle_vector(
                    &shuffle_input_clone_2,
                    &p1_shuffle_tuples[i]
                        .a
                        .as_ref()
                        .unwrap()
                        .clone()
                        .iter()
                        .map(|a| a.clone() * mac)
                        .collect::<Vec<Fr>>()
                )
            );

            assert_eq!(
                p0_shuffle_tuples[i]
                    .tuples_b
                    .iter()
                    .zip(p1_shuffle_tuples[i].tuples_b.iter())
                    .map(|(a, b)| a.value + b.value)
                    .collect::<Vec<Fr>>(),
                local_shuffle_vector(
                    &shuffle_input_clone_2,
                    &p1_shuffle_tuples[i].b.as_ref().unwrap()
                )
            );
            assert_eq!(
                p0_shuffle_tuples[i]
                    .tuples_b
                    .iter()
                    .zip(p1_shuffle_tuples[i].tuples_b.iter())
                    .map(|(a, b)| a.mac + b.mac)
                    .collect::<Vec<Fr>>(),
                local_shuffle_vector(
                    &shuffle_input_clone_2,
                    &p1_shuffle_tuples[i]
                        .b
                        .as_ref()
                        .unwrap()
                        .clone()
                        .iter()
                        .map(|b| b.clone() * mac)
                        .collect::<Vec<Fr>>()
                )
            );
        }

        for (i, _) in p0_inverse_shuffle_tuple.iter().enumerate() {
            assert_eq!(
                p0_inverse_shuffle_tuple[i]
                    .tuples_a
                    .iter()
                    .zip(p1_inverse_shuffle_tuple[i].tuples_a.iter())
                    .map(|(a, b)| a.value + b.value)
                    .collect::<Vec<Fr>>(),
                local_unshuffle_vector(
                    &shuffle_input_clone_2,
                    &p1_inverse_shuffle_tuple[i].a.as_ref().unwrap().clone()
                )
            );

            assert_eq!(
                p0_inverse_shuffle_tuple[i]
                    .tuples_a
                    .iter()
                    .zip(p1_inverse_shuffle_tuple[i].tuples_a.iter())
                    .map(|(a, b)| a.mac + b.mac)
                    .collect::<Vec<Fr>>(),
                local_unshuffle_vector(
                    &shuffle_input_clone_2,
                    &p1_inverse_shuffle_tuple[i]
                        .a
                        .as_ref()
                        .unwrap()
                        .clone()
                        .iter()
                        .map(|a| a.clone() * mac)
                        .collect::<Vec<Fr>>()
                )
            );

            assert_eq!(
                p0_inverse_shuffle_tuple[i]
                    .tuples_b
                    .iter()
                    .zip(p1_inverse_shuffle_tuple[i].tuples_b.iter())
                    .map(|(a, b)| a.value + b.value)
                    .collect::<Vec<Fr>>(),
                local_unshuffle_vector(
                    &shuffle_input_clone_2,
                    &p1_inverse_shuffle_tuple[i].b.as_ref().unwrap()
                )
            );
            assert_eq!(
                p0_inverse_shuffle_tuple[i]
                    .tuples_b
                    .iter()
                    .zip(p1_inverse_shuffle_tuple[i].tuples_b.iter())
                    .map(|(a, b)| a.mac + b.mac)
                    .collect::<Vec<Fr>>(),
                local_unshuffle_vector(
                    &shuffle_input_clone_2,
                    &p1_inverse_shuffle_tuple[i]
                        .b
                        .as_ref()
                        .unwrap()
                        .clone()
                        .iter()
                        .map(|b| b.clone() * mac)
                        .collect::<Vec<Fr>>()
                )
            );
        }
    }
}
