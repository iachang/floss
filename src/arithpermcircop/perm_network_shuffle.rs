use std::collections::VecDeque;
use std::time::Instant;

use ark_ff::Field;
use itertools::max;

use crate::arithcircop::ArithCircOp;
use crate::arithcircop::vector_add::VectorAdd;
use crate::arithcircop::vector_input::VectorInput;
use crate::arithcircop::vector_mul::VectorMul;
use crate::arithcircop::vector_neg::VectorNeg;
use crate::arithcircop::vector_scale_by_vector::VectorScaleByVector;
use crate::arithcircop::vector_shift::VectorShift;
use crate::arithcircop::vector_sub::VectorSub;
use crate::arithpermcircop::vector_reveal::VectorReveal;
use crate::arithpermcircop::{ArithPermCircOp, ArithPermCircState, ShuffleVecType};
use crate::arithpermcircprep::waksman::{
    Config, get_indexed_switches, symbolic_apply_circ, symbolic_apply_circ_rev,
};

use crate::net::Net;
use crate::primitives::auth::AuthShare;
use crate::utils::vector_utils::{dupe_vector, roll_vector, unroll_vector};

/// Shuffle(perm_party_i, (perm, [x]_i), ([x]_{1-i})) -> perm(x)
/// One-sided shuffle.
pub struct PermNetworkShuffle<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> PermNetworkShuffle<F> {
    /// Create a new ArithCircOp instance
    pub fn new() -> Self {
        PermNetworkShuffle {
            _phantom: std::marker::PhantomData,
        }
    }

    /// Generate Mohassel et. al (2014) maliciously secure shuffle for auth inputs
    fn perm_network_shuffle_helper(
        net: &mut Net,
        state: &mut ArithPermCircState<F>,
        shuffle: Option<ShuffleVecType>,
        auth_shares: Vec<AuthShare<F>>,
    ) -> Vec<AuthShare<F>> {
        PermNetworkShuffle::perm_network_shuffle_helper_with_timing(
            net,
            state,
            shuffle,
            auth_shares,
            None,
        )
    }

    /// Generate Mohassel et. al (2014) maliciously secure shuffle for auth inputs with timing
    fn perm_network_shuffle_helper_with_timing(
        net: &mut Net,
        state: &mut ArithPermCircState<F>,
        shuffle: Option<ShuffleVecType>,
        auth_shares: Vec<AuthShare<F>>,
        timing_callback: Option<
            &mut dyn FnMut(
                std::time::Duration,
                std::time::Duration,
                (usize, usize),
                (usize, usize),
            ),
        >,
    ) -> Vec<AuthShare<F>> {
        let permuter_id = if shuffle.is_some() {
            net.party_id()
        } else {
            1 - net.party_id()
        };

        let n = auth_shares.len();

        let start_time = Instant::now();
        let start_bytes_sent = net.stats().bytes_sent;
        let start_bytes_recv = net.stats().bytes_recv;

        let inputted_switch_bits = if net.party_id() == permuter_id {
            let shuffle: ShuffleVecType = shuffle.clone().unwrap();
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
            let cfg = Config::for_permuting::<usize>((0..n).collect::<Vec<usize>>());
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

        // Step 3: create the perm network circuit
        let input_wires = (0..n).collect::<Vec<usize>>();
        let mut switches_to_return = Vec::new();
        let mut global_index = n;
        let output_wires = get_indexed_switches(
            input_wires.clone(),
            &mut global_index,
            &mut switches_to_return,
        );
        let coins_to_take = max(output_wires.clone()).unwrap() + 1;
        let coins_a = state.inner_mut().take_auth_coins(coins_to_take);
        let a_coins = roll_vector(coins_a, coins_to_take, 1);

        let coins_mac_a = state.inner_mut().take_auth_coins(coins_to_take);
        let a_coins_mac = roll_vector(coins_mac_a, coins_to_take, 1);

        let k_a = state.inner_mut().take_auth_coins(1)[0];

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

        let vector_sub_in_0_first = VectorSub::<F>::run(
            net,
            state.inner_mut(),
            (
                switch_vector_out_0_coins_a.clone(),
                switch_vector_in_0_coins_a.clone(),
            ),
        );

        let vector_sub_in_0_first_mac = VectorSub::<F>::run(
            net,
            state.inner_mut(),
            (
                switch_vector_out_0_coins_mac_a.clone(),
                switch_vector_in_0_coins_mac_a.clone(),
            ),
        );

        let s_in_0_first_term_a = VectorMul::<F>::run(
            net,
            state.inner_mut(),
            (
                dupe_vector(one_minus_bits.clone(), 1),
                vector_sub_in_0_first,
            ),
        );

        let delta_in_0_first_term_a = VectorMul::<F>::run(
            net,
            state.inner_mut(),
            (
                dupe_vector(one_minus_bits.clone(), 1),
                vector_sub_in_0_first_mac,
            ),
        );

        let vector_sub_in_0_second = VectorSub::<F>::run(
            net,
            state.inner_mut(),
            (
                switch_vector_out_1_coins_a.clone(),
                switch_vector_in_0_coins_a.clone(),
            ),
        );

        let vector_sub_in_0_second_mac = VectorSub::<F>::run(
            net,
            state.inner_mut(),
            (
                switch_vector_out_1_coins_mac_a.clone(),
                switch_vector_in_0_coins_mac_a.clone(),
            ),
        );

        let s_in_0_second_term_a = VectorMul::<F>::run(
            net,
            state.inner_mut(),
            (
                dupe_vector(inputted_switch_bits.clone(), 1),
                vector_sub_in_0_second,
            ),
        );

        let delta_in_0_second_term_a = VectorMul::<F>::run(
            net,
            state.inner_mut(),
            (
                dupe_vector(inputted_switch_bits.clone(), 1),
                vector_sub_in_0_second_mac,
            ),
        );

        let vector_add_in_0 = VectorAdd::<F>::run(
            net,
            state.inner_mut(),
            (s_in_0_first_term_a, s_in_0_second_term_a),
        );
        let s_in_0_a = VectorReveal::<F>::run(net, state, vector_add_in_0);

        let delta_in_0_third_term_a = VectorScaleByVector::<F>::run(
            net,
            state.inner_mut(),
            (vec![k_a; s_in_0_a.len()], s_in_0_a.clone()),
        );

        let delta_in_0_a_pt1 = VectorAdd::<F>::run(
            net,
            state.inner_mut(),
            (delta_in_0_first_term_a, delta_in_0_second_term_a),
        );

        let vector_add_delta_in_0_a = VectorAdd::<F>::run(
            net,
            state.inner_mut(),
            (delta_in_0_a_pt1, delta_in_0_third_term_a),
        );

        let delta_in_0_a = VectorReveal::<F>::run(net, state, vector_add_delta_in_0_a);

        let vector_sub_in_1_first = VectorSub::<F>::run(
            net,
            state.inner_mut(),
            (
                switch_vector_out_1_coins_a.clone(),
                switch_vector_in_1_coins_a.clone(),
            ),
        );

        let vector_sub_in_1_first_mac = VectorSub::<F>::run(
            net,
            state.inner_mut(),
            (
                switch_vector_out_1_coins_mac_a.clone(),
                switch_vector_in_1_coins_mac_a.clone(),
            ),
        );

        let s_in_1_first_term_a = VectorMul::<F>::run(
            net,
            state.inner_mut(),
            (
                dupe_vector(one_minus_bits.clone(), 1),
                vector_sub_in_1_first,
            ),
        );

        let delta_in_1_first_term_a = VectorMul::<F>::run(
            net,
            state.inner_mut(),
            (
                dupe_vector(one_minus_bits.clone(), 1),
                vector_sub_in_1_first_mac,
            ),
        );

        let vector_sub_in_1_second = VectorSub::<F>::run(
            net,
            state.inner_mut(),
            (
                switch_vector_out_0_coins_a.clone(),
                switch_vector_in_1_coins_a.clone(),
            ),
        );

        let vector_sub_in_1_second_mac = VectorSub::<F>::run(
            net,
            state.inner_mut(),
            (
                switch_vector_out_0_coins_mac_a.clone(),
                switch_vector_in_1_coins_mac_a.clone(),
            ),
        );

        let s_in_1_second_term_a = VectorMul::<F>::run(
            net,
            state.inner_mut(),
            (
                dupe_vector(inputted_switch_bits.clone(), 1),
                vector_sub_in_1_second,
            ),
        );

        let delta_in_1_second_term_a = VectorMul::<F>::run(
            net,
            state.inner_mut(),
            (
                dupe_vector(inputted_switch_bits.clone(), 1),
                vector_sub_in_1_second_mac,
            ),
        );

        let vector_add_in_1 = VectorAdd::<F>::run(
            net,
            state.inner_mut(),
            (s_in_1_first_term_a, s_in_1_second_term_a),
        );
        let s_in_1_a = VectorReveal::<F>::run(net, state, vector_add_in_1);

        let delta_in_1_third_term_a = VectorScaleByVector::<F>::run(
            net,
            state.inner_mut(),
            (vec![k_a; s_in_1_a.len()], s_in_1_a.clone()),
        );

        let delta_in_1_a_pt1 = VectorAdd::<F>::run(
            net,
            state.inner_mut(),
            (delta_in_1_first_term_a, delta_in_1_second_term_a),
        );
        let vector_add_delta_in_1_a = VectorAdd::<F>::run(
            net,
            state.inner_mut(),
            (delta_in_1_a_pt1, delta_in_1_third_term_a),
        );

        let delta_in_1_a = VectorReveal::<F>::run(net, state, vector_add_delta_in_1_a);

        let offline_time = start_time.elapsed();
        let offline_bandwidth = (
            net.stats().bytes_sent - start_bytes_sent,
            net.stats().bytes_recv - start_bytes_recv,
        );
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

        let vector_add_t_a = VectorAdd::<F>::run(
            net,
            state.inner_mut(),
            (auth_shares.clone(), input_wires_coins_a.clone()),
        );
        let t_vector_a = VectorReveal::<F>::run(net, state, vector_add_t_a);

        let kappa_t_a = VectorScaleByVector::<F>::run(
            net,
            state.inner_mut(),
            (vec![k_a; t_vector_a.len()], t_vector_a.clone()),
        );
        let vector_add_tau_a =
            VectorAdd::<F>::run(net, state.inner_mut(), (kappa_t_a, input_wires_coins_a_mac));
        let tau_vector_a = VectorReveal::<F>::run(net, state, vector_add_tau_a);

        let output = if net.party_id() == permuter_id {
            let cfg = Config::for_permuting::<usize>(shuffle.clone().unwrap());
            let switches = cfg.switches();

            let t_vector_rolled_a = roll_vector(t_vector_a.clone(), n, 1);
            let tau_vector_rolled_a = roll_vector(tau_vector_a.clone(), n, 1);
            let s_in_0_rolled_a = roll_vector(s_in_0_a.clone(), switches.len(), 1);
            let delta_in_0_rolled_a = roll_vector(delta_in_0_a.clone(), switches.len(), 1);
            let s_in_1_rolled_a = roll_vector(s_in_1_a.clone(), switches.len(), 1);
            let delta_in_1_rolled_a = roll_vector(delta_in_1_a.clone(), switches.len(), 1);

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

            let combined_auth_shares_a = VectorInput::<F>::run(
                net,
                state.inner_mut(),
                (permuter_id, Some(combined_shares_a), None),
            );

            // Perform K auth check
            // Permuter assists with performing K auth check
            // Permuter sends Tau vector to Sender, observe that alterting Tau will cause the K auth check to fail

            // E.g. uncomment these lines will fail auth check
            // let mut tau_vector = tau_vector.clone();
            // tau_vector[0] = tau_vector[0] + F::one();

            net.send_to_party(1 - permuter_id, &tau_vector);

            let k_auth_shares = VectorMul::<F>::run(
                net,
                state.inner_mut(),
                (
                    combined_auth_shares_a.clone(),
                    vec![k_a; combined_auth_shares_a.len()],
                ),
            );
            let gamma_auth_shares = VectorAdd::<F>::run(
                net,
                state.inner_mut(),
                (output_wires_coins_a_mac, k_auth_shares),
            );
            VectorReveal::<F>::run(net, state, gamma_auth_shares);

            // End K auth check

            let neg_output_wires_coins_a =
                VectorNeg::<F>::run(net, state.inner_mut(), output_wires_coins_a);
            let output_shares_a = roll_vector(
                VectorAdd::<F>::run(
                    net,
                    state.inner_mut(),
                    (neg_output_wires_coins_a, combined_auth_shares_a),
                ),
                n,
                1,
            );

            output_shares_a[0].clone()
        } else {
            let combined_auth_shares_a =
                VectorInput::<F>::run(net, state.inner_mut(), (permuter_id, None, Some(n)));

            // Perform K auth check
            // Sender verifies K auth check
            let combined_tau_vector = net.recv_from_party::<Vec<F>>(permuter_id);
            let k_auth_shares = VectorMul::<F>::run(
                net,
                state.inner_mut(),
                (
                    combined_auth_shares_a.clone(),
                    vec![k_a; combined_auth_shares_a.len()],
                ),
            );
            let gamma_auth_shares = VectorAdd::<F>::run(
                net,
                state.inner_mut(),
                (output_wires_coins_a_mac, k_auth_shares),
            );
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

            let neg_output_wires_coins_a =
                VectorNeg::<F>::run(net, state.inner_mut(), output_wires_coins_a);
            let output_shares_a = roll_vector(
                VectorAdd::<F>::run(
                    net,
                    state.inner_mut(),
                    (neg_output_wires_coins_a, combined_auth_shares_a),
                ),
                n,
                1,
            );

            output_shares_a[0].clone()
        };

        let total_time = start_time.elapsed();
        let online_time = total_time - offline_time;
        let online_bandwidth = (
            net.stats().bytes_sent - offline_bandwidth.0 - start_bytes_sent,
            net.stats().bytes_recv - offline_bandwidth.1 - start_bytes_recv,
        );

        if let Some(callback) = timing_callback {
            callback(
                offline_time,
                online_time,
                offline_bandwidth,
                online_bandwidth,
            );
        }

        output
    }

    /// Generate Mohassel et. al (2014) maliciously secure inverse shuffle for auth inputs
    fn perm_network_inverse_shuffle_helper(
        net: &mut Net,
        state: &mut ArithPermCircState<F>,
        shuffle: Option<ShuffleVecType>,
        auth_shares: Vec<AuthShare<F>>,
    ) -> Vec<AuthShare<F>> {
        PermNetworkShuffle::perm_network_inverse_shuffle_helper_with_timing(
            net,
            state,
            shuffle,
            auth_shares,
            None,
        )
    }

    /// Generate Mohassel et. al (2014) maliciously secure inverse shuffle for auth inputs with timing
    fn perm_network_inverse_shuffle_helper_with_timing(
        net: &mut Net,
        state: &mut ArithPermCircState<F>,
        shuffle: Option<ShuffleVecType>,
        auth_shares: Vec<AuthShare<F>>,
        timing_callback: Option<
            &mut dyn FnMut(
                std::time::Duration,
                std::time::Duration,
                (usize, usize),
                (usize, usize),
            ),
        >,
    ) -> Vec<AuthShare<F>> {
        let permuter_id = if shuffle.is_some() {
            net.party_id()
        } else {
            1 - net.party_id()
        };

        let n = auth_shares.len();

        let start_time = Instant::now();
        let start_bytes_recv = net.stats().bytes_recv;
        let start_bytes_sent = net.stats().bytes_sent;

        let inputted_switch_bits = if net.party_id() == permuter_id {
            let shuffle: ShuffleVecType = shuffle.clone().unwrap();

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
            let cfg = Config::for_permuting::<usize>((0..n).collect::<Vec<usize>>());
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

        // Step 3: create the perm network circuit
        let input_wires = (0..n).collect::<Vec<usize>>();
        let mut switches_to_return = Vec::new();
        let mut global_index = n;
        let output_wires = get_indexed_switches(
            input_wires.clone(),
            &mut global_index,
            &mut switches_to_return,
        );
        let coins_to_take = max(output_wires.clone()).unwrap() + 1;
        let coins_a = state.inner_mut().take_auth_coins(coins_to_take);
        let a_coins = roll_vector(coins_a, coins_to_take, 1);

        let coins_mac_a = state.inner_mut().take_auth_coins(coins_to_take);
        let a_coins_mac = roll_vector(coins_mac_a, coins_to_take, 1);

        let k_a = state.inner_mut().take_auth_coins(1)[0];

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

        let vector_sub_out_0_first_term_a = VectorSub::<F>::run(
            net,
            state.inner_mut(),
            (
                switch_vector_in_0_coins_a.clone(),
                switch_vector_out_0_coins_a.clone(),
            ),
        );
        let vector_sub_out_0_first_term_mac_a = VectorSub::<F>::run(
            net,
            state.inner_mut(),
            (
                switch_vector_in_0_coins_mac_a.clone(),
                switch_vector_out_0_coins_mac_a.clone(),
            ),
        );
        let s_out_0_first_term_a = VectorMul::<F>::run(
            net,
            state.inner_mut(),
            (
                dupe_vector(one_minus_bits.clone(), 1),
                vector_sub_out_0_first_term_a,
            ),
        );
        let delta_out_0_first_term_a = VectorMul::<F>::run(
            net,
            state.inner_mut(),
            (
                dupe_vector(one_minus_bits.clone(), 1),
                vector_sub_out_0_first_term_mac_a,
            ),
        );

        let vector_sub_out_0_second_term_a = VectorSub::<F>::run(
            net,
            state.inner_mut(),
            (
                switch_vector_in_1_coins_a.clone(),
                switch_vector_out_0_coins_a.clone(),
            ),
        );
        let vector_sub_out_0_second_term_mac_a = VectorSub::<F>::run(
            net,
            state.inner_mut(),
            (
                switch_vector_in_1_coins_mac_a.clone(),
                switch_vector_out_0_coins_mac_a.clone(),
            ),
        );

        let s_out_0_second_term_a = VectorMul::<F>::run(
            net,
            state.inner_mut(),
            (
                dupe_vector(inputted_switch_bits.clone(), 1),
                vector_sub_out_0_second_term_a,
            ),
        );
        let delta_out_0_second_term_a = VectorMul::<F>::run(
            net,
            state.inner_mut(),
            (
                dupe_vector(inputted_switch_bits.clone(), 1),
                vector_sub_out_0_second_term_mac_a,
            ),
        );

        let vector_add_out_0 = VectorAdd::<F>::run(
            net,
            state.inner_mut(),
            (s_out_0_first_term_a, s_out_0_second_term_a),
        );
        let s_out_0_a = VectorReveal::<F>::run(net, state, vector_add_out_0);

        let delta_out_0_third_term_a = VectorScaleByVector::<F>::run(
            net,
            state.inner_mut(),
            (vec![k_a; s_out_0_a.len()], s_out_0_a.clone()),
        );

        let delta_out_0_a_pt1 = VectorAdd::<F>::run(
            net,
            state.inner_mut(),
            (delta_out_0_first_term_a, delta_out_0_second_term_a),
        );

        let vector_add_delta_out_0_a = VectorAdd::<F>::run(
            net,
            state.inner_mut(),
            (delta_out_0_third_term_a, delta_out_0_a_pt1),
        );
        let delta_out_0_a = VectorReveal::<F>::run(net, state, vector_add_delta_out_0_a);

        let vector_sub_out_1_first_term_a = VectorSub::<F>::run(
            net,
            state.inner_mut(),
            (
                switch_vector_in_1_coins_a.clone(),
                switch_vector_out_1_coins_a.clone(),
            ),
        );
        let vector_sub_out_1_first_term_mac_a = VectorSub::<F>::run(
            net,
            state.inner_mut(),
            (
                switch_vector_in_1_coins_mac_a.clone(),
                switch_vector_out_1_coins_mac_a.clone(),
            ),
        );
        let s_out_1_first_term_a = VectorMul::<F>::run(
            net,
            state.inner_mut(),
            (
                dupe_vector(one_minus_bits.clone(), 1),
                vector_sub_out_1_first_term_a,
            ),
        );
        let delta_out_1_first_term_a = VectorMul::<F>::run(
            net,
            state.inner_mut(),
            (
                dupe_vector(one_minus_bits.clone(), 1),
                vector_sub_out_1_first_term_mac_a,
            ),
        );

        let vector_sub_out_1_second_term_a = VectorSub::<F>::run(
            net,
            state.inner_mut(),
            (
                switch_vector_in_0_coins_a.clone(),
                switch_vector_out_1_coins_a.clone(),
            ),
        );
        let vector_sub_out_1_second_term_mac_a = VectorSub::<F>::run(
            net,
            state.inner_mut(),
            (
                switch_vector_in_0_coins_mac_a.clone(),
                switch_vector_out_1_coins_mac_a.clone(),
            ),
        );
        let s_out_1_second_term_a = VectorMul::<F>::run(
            net,
            state.inner_mut(),
            (
                dupe_vector(inputted_switch_bits.clone(), 1),
                vector_sub_out_1_second_term_a,
            ),
        );
        let delta_out_1_second_term_a = VectorMul::<F>::run(
            net,
            state.inner_mut(),
            (
                dupe_vector(inputted_switch_bits.clone(), 1),
                vector_sub_out_1_second_term_mac_a,
            ),
        );
        let vector_add_out_1 = VectorAdd::<F>::run(
            net,
            state.inner_mut(),
            (s_out_1_first_term_a, s_out_1_second_term_a),
        );
        let s_out_1_a = VectorReveal::<F>::run(net, state, vector_add_out_1);

        let delta_out_1_third_term_a = VectorScaleByVector::<F>::run(
            net,
            state.inner_mut(),
            (vec![k_a; s_out_1_a.len()], s_out_1_a.clone()),
        );

        let delta_out_1_a_pt1 = VectorAdd::<F>::run(
            net,
            state.inner_mut(),
            (delta_out_1_first_term_a, delta_out_1_second_term_a),
        );

        let vector_add_delta_out_1_a = VectorAdd::<F>::run(
            net,
            state.inner_mut(),
            (delta_out_1_third_term_a, delta_out_1_a_pt1),
        );
        let delta_out_1_a = VectorReveal::<F>::run(net, state, vector_add_delta_out_1_a);

        let offline_time = start_time.elapsed();
        let offline_bandwidth = (
            net.stats().bytes_sent - start_bytes_sent,
            net.stats().bytes_recv - start_bytes_recv,
        );

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

        let vector_add_t_a = VectorAdd::<F>::run(
            net,
            state.inner_mut(),
            (auth_shares.clone(), output_wires_coins_a.clone()),
        );
        let t_vector_a = VectorReveal::<F>::run(net, state, vector_add_t_a);

        let kappa_t_a = VectorScaleByVector::<F>::run(
            net,
            state.inner_mut(),
            (vec![k_a; t_vector_a.len()], t_vector_a.clone()),
        );
        let vector_add_tau_a = VectorAdd::<F>::run(
            net,
            state.inner_mut(),
            (kappa_t_a, output_wires_coins_a_mac),
        );
        let tau_vector_a = VectorReveal::<F>::run(net, state, vector_add_tau_a);

        let output = if net.party_id() == permuter_id {
            let shuffle: ShuffleVecType = shuffle.as_ref().unwrap().clone();

            let cfg = Config::for_permuting::<usize>(shuffle);
            let switches = cfg.switches();

            let t_vector_rolled_a = roll_vector(t_vector_a.clone(), n, 1);
            let tau_vector_rolled_a = roll_vector(tau_vector_a.clone(), n, 1);
            let s_out_0_rolled_a = roll_vector(s_out_0_a.clone(), switches.len(), 1);
            let delta_out_0_rolled_a = roll_vector(delta_out_0_a.clone(), switches.len(), 1);
            let s_out_1_rolled_a = roll_vector(s_out_1_a.clone(), switches.len(), 1);
            let delta_out_1_rolled_a = roll_vector(delta_out_1_a.clone(), switches.len(), 1);

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

            let combined_auth_shares_a = VectorInput::<F>::run(
                net,
                state.inner_mut(),
                (permuter_id, Some(combined_shares_a), None),
            );

            // Perform K auth check
            // Permuter assists with performing K auth check
            // Permuter sends Tau vector to Sender, observe that alterting Tau will cause the K auth check to fail

            // E.g. uncomment these lines will fail auth check
            // let mut tau_vector = tau_vector.clone();
            // tau_vector[0] = tau_vector[0] + F::one();

            net.send_to_party(1 - permuter_id, &tau_vector);

            let k_auth_shares = VectorMul::<F>::run(
                net,
                state.inner_mut(),
                (
                    combined_auth_shares_a.clone(),
                    vec![k_a; combined_auth_shares_a.len()],
                ),
            );
            let gamma_auth_shares = VectorAdd::<F>::run(
                net,
                state.inner_mut(),
                (input_wires_coins_a_mac, k_auth_shares),
            );
            VectorReveal::<F>::run(net, state, gamma_auth_shares);

            // End K auth check

            let vector_neg_input_wires_coins_a =
                VectorNeg::<F>::run(net, state.inner_mut(), input_wires_coins_a);
            let output_shares_a = roll_vector(
                VectorAdd::<F>::run(
                    net,
                    state.inner_mut(),
                    (vector_neg_input_wires_coins_a, combined_auth_shares_a),
                ),
                n,
                1,
            );

            output_shares_a[0].clone()
        } else {
            let combined_auth_shares_a =
                VectorInput::<F>::run(net, state.inner_mut(), (permuter_id, None, Some(n)));

            // Perform K auth check
            // Sender verifies K auth check
            let combined_tau_vector = net.recv_from_party::<Vec<F>>(permuter_id);
            let k_auth_shares = VectorMul::<F>::run(
                net,
                state.inner_mut(),
                (
                    combined_auth_shares_a.clone(),
                    vec![k_a; combined_auth_shares_a.len()],
                ),
            );
            let gamma_auth_shares = VectorAdd::<F>::run(
                net,
                state.inner_mut(),
                (input_wires_coins_a_mac, k_auth_shares),
            );
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
                VectorNeg::<F>::run(net, state.inner_mut(), input_wires_coins_a);
            let output_shares_a = roll_vector(
                VectorAdd::<F>::run(
                    net,
                    state.inner_mut(),
                    (vector_neg_input_wires_coins_a, combined_auth_shares_a),
                ),
                n,
                1,
            );

            output_shares_a[0].clone()
        };

        let total_time = start_time.elapsed();
        let online_time = total_time - offline_time;
        let online_bandwidth = (
            net.stats().bytes_sent - offline_bandwidth.0 - start_bytes_sent,
            net.stats().bytes_recv - offline_bandwidth.1 - start_bytes_recv,
        );

        if let Some(callback) = timing_callback {
            callback(
                offline_time,
                online_time,
                offline_bandwidth,
                online_bandwidth,
            );
        }

        output
    }

    /// Run the shuffle operation with optional timing callback
    pub fn run_with_timing<
        C: FnMut(std::time::Duration, std::time::Duration, (usize, usize), (usize, usize)),
    >(
        net: &mut Net,
        state: &mut ArithPermCircState<F>,
        input: (Option<ShuffleVecType>, Vec<AuthShare<F>>, bool),
        mut timing_callback: &mut C,
    ) -> Vec<AuthShare<F>> {
        let (shuffle, input_auth_shares, with_inverse) = input;

        if with_inverse {
            PermNetworkShuffle::perm_network_inverse_shuffle_helper_with_timing(
                net,
                state,
                shuffle,
                input_auth_shares,
                Some(&mut timing_callback),
            )
        } else {
            PermNetworkShuffle::perm_network_shuffle_helper_with_timing(
                net,
                state,
                shuffle,
                input_auth_shares,
                Some(&mut timing_callback),
            )
        }
    }
}

impl<F: Field> ArithPermCircOp<F> for PermNetworkShuffle<F> {
    type In = (
        Option<ShuffleVecType>, // shuffle
        Vec<AuthShare<F>>,      // input auth shares
        bool,                   // with inverse
    );
    type Out = Vec<AuthShare<F>>;

    fn run(net: &mut Net, state: &mut ArithPermCircState<F>, input: Self::In) -> Self::Out {
        let (shuffle, input_auth_shares, with_inverse) = input;

        let output_auth_shares = if with_inverse {
            &PermNetworkShuffle::perm_network_inverse_shuffle_helper(
                net,
                state,
                shuffle,
                input_auth_shares,
            )
        } else {
            &PermNetworkShuffle::perm_network_shuffle_helper(net, state, shuffle, input_auth_shares)
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
    fn test_perm_network_shuffle() {
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

                let party0_regular_shuffle_output = PermNetworkShuffle::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    (
                        Some(shuffle_input.clone()),
                        party0_auth_shares.clone(),
                        false,
                    ),
                );

                let party0_inverse_shuffle_output = PermNetworkShuffle::<Fr>::run(
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

                let party1_regular_shuffle_output = PermNetworkShuffle::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    (None, party1_auth_shares.clone(), false),
                );

                let party1_inverse_shuffle_output = PermNetworkShuffle::<Fr>::run(
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
