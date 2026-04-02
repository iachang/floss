use ark_ff::Field;

use crate::{
    arithcircop::{
        ArithCircOp, vector_add::VectorAdd, vector_input::VectorInput, vector_mul::VectorMul,
        vector_neg::VectorNeg, vector_shift::VectorShift, vector_sub::VectorSub,
    },
    arithpermcircop::{
        ArithPermCircOp, ArithPermCircState, apply_perm::ApplyPerm, unapply_perm::UnapplyPerm,
    },
    net::Net,
    primitives::auth::AuthShare,
    utils::vector_utils::transpose_vector,
};

/// Generate the 0-indexed inverse permutation (vector of destinations) to stable sort a vector of bits.
pub fn generate_bit_permutation<F: Field>(
    net: &mut Net,
    state: &mut ArithPermCircState<F>,
    input: &Vec<AuthShare<F>>,
) -> Vec<AuthShare<F>> {
    // Input: secret share of a single bit position of all inputs
    let negated_input = VectorNeg::<F>::run(net, state.inner_mut(), input.clone());
    let zero_track_shares =
        VectorShift::<F>::run(net, state.inner_mut(), (negated_input, F::one())); // need to negate the authShare, and then shift by 1
    let one_track_shares = input;

    let mut s_prefix_sum = VectorInput::<F>::run(
        net,
        state.inner_mut(),
        (0, Some(vec![F::one().neg()]), Some(1)),
    )[0];
    let mut s_zero_shares = vec![];
    let mut s_one_shares = vec![];

    for i in 0..input.len() {
        s_prefix_sum = s_prefix_sum + zero_track_shares[i];
        s_zero_shares.push(s_prefix_sum);
    }

    for i in 0..input.len() {
        s_prefix_sum = s_prefix_sum + one_track_shares[i];
        s_one_shares.push(s_prefix_sum);
    }

    let sub_shares = VectorSub::<F>::run(
        net,
        state.inner_mut(),
        (s_one_shares, s_zero_shares.clone()),
    );

    let t_shares = VectorMul::<F>::run(net, state.inner_mut(), (input.clone(), sub_shares));

    let sorted_positions = VectorAdd::<F>::run(net, state.inner_mut(), (s_zero_shares, t_shares));
    sorted_positions
}

/// Sort(vec[ vec (bit decomp of Field)]]_i) -> vec[ sorted vec (bit decomp of Field)]
pub struct Sort<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> Sort<F> {
    /// Create a new ArithCircOp instance
    pub fn new() -> Self {
        Sort {
            _phantom: std::marker::PhantomData,
        }
    }

    /// Run the sort operation with perm network with timing callback
    pub fn run_with_perm_network_timing(
        net: &mut Net,
        state: &mut ArithPermCircState<F>,
        input: Vec<Vec<AuthShare<F>>>,
        mut timing_callback: &mut dyn FnMut(
            std::time::Duration,
            std::time::Duration,
            (usize, usize),
            (usize, usize),
        ),
    ) -> Vec<AuthShare<F>> {
        let input_bits = input;
        let num_bits = input_bits[0].len();

        let input_first_bit = grab_ith_bit(&input_bits, 0);

        let rho_0 = generate_bit_permutation(net, state, &input_first_bit);
        let mut sigma = vec![];
        sigma.push(rho_0.clone());

        for j in 1..num_bits {
            let input_j_bit = grab_ith_bit(&input_bits, j);
            // Unapply the inverse permutation from generate_bit_permutation to correctly sort the bits
            let k_prime_j = UnapplyPerm::run_with_perm_network_timing(
                net,
                state,
                (
                    "random_shuffle_A_p0_".to_string() + &(j - 1).to_string(),
                    "random_shuffle_A_p1_".to_string() + &(j - 1).to_string(),
                    sigma[j - 1].clone(),
                    input_j_bit.clone(),
                ),
                &mut timing_callback,
            );

            let rho_j = generate_bit_permutation(net, state, &k_prime_j);

            // Compose the previous bit inverse permutations with the current bit inverse permutation
            let sigma_j = ApplyPerm::run_with_perm_network_timing(
                net,
                state,
                (
                    "random_shuffle_B_p0_".to_string() + &(j - 1).to_string(),
                    "random_shuffle_B_p1_".to_string() + &(j - 1).to_string(),
                    sigma[j - 1].clone(),
                    rho_j.clone(),
                ),
                &mut timing_callback,
            );
            sigma.push(sigma_j);
        }

        let final_sort_inverse_permutation = sigma[num_bits - 1].clone();

        final_sort_inverse_permutation
    }

    /// Sort run with floss
    pub fn run_with_floss_timing(
        net: &mut Net,
        state: &mut ArithPermCircState<F>,
        input: Vec<Vec<AuthShare<F>>>,
        timing_callback: &mut dyn FnMut(std::time::Duration),
    ) -> Vec<AuthShare<F>> {
        let input_bits = input;
        let num_bits = input_bits[0].len();

        let input_first_bit = grab_ith_bit(&input_bits, 0);

        let rho_0 = generate_bit_permutation(net, state, &input_first_bit);
        let mut sigma = vec![];
        sigma.push(rho_0.clone());

        for j in 1..num_bits {
            let input_j_bit = grab_ith_bit(&input_bits, j);
            // Unapply the inverse permutation from generate_bit_permutation to correctly sort the bits
            let k_prime_j = UnapplyPerm::run_with_floss_timing(
                net,
                state,
                (
                    "random_shuffle_A_p0_".to_string() + &(j - 1).to_string(),
                    "random_shuffle_A_p1_".to_string() + &(j - 1).to_string(),
                    sigma[j - 1].clone(),
                    input_j_bit.clone(),
                ),
                timing_callback,
            );

            let rho_j = generate_bit_permutation(net, state, &k_prime_j);

            // Compose the previous bit inverse permutations with the current bit inverse permutation
            let sigma_j = ApplyPerm::run_with_floss_timing(
                net,
                state,
                (
                    "random_shuffle_B_p0_".to_string() + &(j - 1).to_string(),
                    "random_shuffle_B_p1_".to_string() + &(j - 1).to_string(),
                    sigma[j - 1].clone(),
                    rho_j.clone(),
                ),
                timing_callback,
            );
            sigma.push(sigma_j);
        }

        let final_sort_inverse_permutation = sigma[num_bits - 1].clone();

        final_sort_inverse_permutation
    }

    /// Sort run with floss
    pub fn run_with_simple_perm_network_timing(
        net: &mut Net,
        state: &mut ArithPermCircState<F>,
        input: Vec<Vec<AuthShare<F>>>,
        timing_callback: &mut dyn FnMut(std::time::Duration),
    ) -> Vec<AuthShare<F>> {
        let input_bits = input;
        let num_bits = input_bits[0].len();

        let input_first_bit = grab_ith_bit(&input_bits, 0);

        let rho_0 = generate_bit_permutation(net, state, &input_first_bit);
        let mut sigma = vec![];
        sigma.push(rho_0.clone());

        for j in 1..num_bits {
            let input_j_bit = grab_ith_bit(&input_bits, j);
            // Unapply the inverse permutation from generate_bit_permutation to correctly sort the bits
            let k_prime_j = UnapplyPerm::run_with_simple_perm_network_timing(
                net,
                state,
                (sigma[j - 1].clone(), input_j_bit.clone()),
                timing_callback,
            );

            let rho_j = generate_bit_permutation(net, state, &k_prime_j);

            // Compose the previous bit inverse permutations with the current bit inverse permutation
            let sigma_j = ApplyPerm::run_with_simple_perm_network_timing(
                net,
                state,
                (sigma[j - 1].clone(), rho_j.clone()),
                timing_callback,
            );
            sigma.push(sigma_j);
        }

        let final_sort_inverse_permutation = sigma[num_bits - 1].clone();

        final_sort_inverse_permutation
    }
}

fn grab_ith_bit<F: Field>(input: &Vec<Vec<AuthShare<F>>>, i: usize) -> Vec<AuthShare<F>> {
    input
        .iter()
        .map(|bits| bits[i].clone())
        .collect::<Vec<AuthShare<F>>>()
}

impl<F: Field> ArithPermCircOp<F> for Sort<F> {
    type In = (Vec<Vec<AuthShare<F>>>, bool); // inputs as shared bit vectors (LSB at starting index 0), with_perm_network
    // type Out = Vec<AuthShare<F>>; // outputs the sorted input shares
    type Out = Vec<Vec<AuthShare<F>>>; // outputs the bits reconstructed

    // fn run(&self, net: &mut Net, state: &mut ArithPermCircState<F>, input: Self::In) -> Self::Out {
    //     let (key_share, input_bits) = input;
    //     let num_bits = input_bits[0].len();

    //     let input_first_bit = grab_ith_bit(&input_bits, 0);

    //     let rho_0 = generate_bit_permutation(net, state, key_share.0, &input_first_bit);
    //     let mut sigma = vec![];
    //     sigma.push(rho_0);

    //     for j in 1..num_bits {
    //         let input_j_bit = grab_ith_bit(&input_bits, j);
    //         // Unapply the inverse permutation from generate_bit_permutation to correctly sort the bits
    //         let k_prime_j = UnapplyPerm::new().run(
    //             net,
    //             state,
    //             (
    //                 "random_shuffle_A_p0_".to_string() + &j.to_string(),
    //                 "random_shuffle_A_p1_".to_string() + &j.to_string(),
    //                 key_share,
    //                 sigma[j - 1].clone(),
    //                 input_j_bit,
    //             ),
    //         );

    //         let rho_j = generate_bit_permutation(net, state, key_share.0, &k_prime_j);

    //         // Compose the previous bit inverse permutations with the current bit inverse permutation
    //         let sigma_j = ApplyPerm::new().run(
    //             net,
    //             state,
    //             (
    //                 "random_shuffle_B_p0_".to_string() + &j.to_string(),
    //                 "random_shuffle_B_p1_".to_string() + &j.to_string(),
    //                 key_share,
    //                 sigma[j - 1].clone(),
    //                 rho_j.clone(),
    //             ),
    //         );
    //         sigma.push(sigma_j);
    //     }

    //     let input_shares = input_bits
    //         .iter()
    //         .map(|bits| {
    //             BitsToFieldReconstruct::<F>::new().run(
    //                 net,
    //                 state.inner_mut(),
    //                 (key_share.0, bits.clone()),
    //             )
    //         })
    //         .collect::<Vec<AuthShare<F>>>();

    //     // Unapplying the final composed inverse permutation will output the sorted input shares
    //     let final_sort_inverse_permutation = sigma[num_bits - 1].clone();
    //     UnapplyPerm::new().run(
    //         net,
    //         state,
    //         (
    //             "random_shuffle_A_p0_".to_string() + &(num_bits).to_string(),
    //             "random_shuffle_A_p1_".to_string() + &(num_bits).to_string(),
    //             key_share,
    //             final_sort_inverse_permutation,
    //             input_shares,
    //         ),
    //     )
    // }

    fn run(net: &mut Net, state: &mut ArithPermCircState<F>, input: Self::In) -> Self::Out {
        let (input_bits, with_perm_network) = input;
        let num_bits = input_bits[0].len();

        let input_first_bit = grab_ith_bit(&input_bits, 0);

        let rho_0 = generate_bit_permutation(net, state, &input_first_bit);
        let mut sigma = vec![];
        sigma.push(rho_0.clone());

        for j in 1..num_bits {
            let input_j_bit = grab_ith_bit(&input_bits, j);
            // Unapply the inverse permutation from generate_bit_permutation to correctly sort the bits
            let k_prime_j = UnapplyPerm::run(
                net,
                state,
                (
                    "random_shuffle_A_p0_".to_string() + &(j - 1).to_string(),
                    "random_shuffle_A_p1_".to_string() + &(j - 1).to_string(),
                    sigma[j - 1].clone(),
                    input_j_bit.clone(),
                    with_perm_network,
                ),
            );

            let rho_j = generate_bit_permutation(net, state, &k_prime_j);

            // Compose the previous bit inverse permutations with the current bit inverse permutation
            let sigma_j = ApplyPerm::run(
                net,
                state,
                (
                    "random_shuffle_B_p0_".to_string() + &(j - 1).to_string(),
                    "random_shuffle_B_p1_".to_string() + &(j - 1).to_string(),
                    sigma[j - 1].clone(),
                    rho_j.clone(),
                    with_perm_network,
                ),
            );
            sigma.push(sigma_j);
        }

        let final_sort_inverse_permutation = sigma[num_bits - 1].clone();

        let sorted_bits: Vec<Vec<AuthShare<F>>> = transpose_vector(input_bits)
            .iter()
            .enumerate()
            .map(|(j, bits_for_col)| {
                UnapplyPerm::run(
                    net,
                    state,
                    (
                        "random_shuffle_A_p0_".to_string() + &(num_bits + j).to_string(),
                        "random_shuffle_A_p1_".to_string() + &(num_bits + j).to_string(),
                        final_sort_inverse_permutation.clone(),
                        bits_for_col.clone(),
                        with_perm_network,
                    ),
                )
            })
            .collect::<Vec<Vec<AuthShare<F>>>>();

        transpose_vector(sorted_bits)
    }
}

#[cfg(test)]
mod test {
    use rand::Rng;

    use crate::{
        arithcircop::{
            ArithCircOp, bits_to_field::BitsToFieldReconstruct, vector_input::VectorInput,
            vector_reveal::VectorReveal,
        },
        arithcircprep::{ArithCircPrep, dummy::DummyArithCircPrep},
        arithpermcircprep::{ArithPermCircPrep, ShuffleTupleInput, dummy::DummyArithPermCircPrep},
        bench::Mersenne64Fq,
        utils::{
            conversion_utils::{field_to_bits, get_field_bits},
            rng_utils::{
                get_random_permutation_usize, get_random_vector, unshuffle_vector_testing,
            },
        },
    };

    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use tempfile::NamedTempFile;
    type Fr = crate::bench::Mersenne64Fq;
    use ark_std::{One, Zero};

    #[test]
    fn test_generate_bit_permutation() {
        // to be inputted
        let keys = vec![Fr::zero(), Fr::one(), Fr::zero(), Fr::zero(), Fr::one()];
        let keys_clone = keys.clone();
        let n = keys.len();

        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        // Shared state to collect outputs
        let outputs = Arc::new(Mutex::new(Vec::<Vec<Fr>>::new()));

        rayon::scope(|s| {
            let outputs_clone = outputs.clone();
            // party 0
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 0);

                let mut state =
                    DummyArithCircPrep::<Fr>::new().run(&mut net, 2 * 5, 2 * 5, 0, 2 * 5, 0);

                let party0_key_shares =
                    VectorInput::<Fr>::run(&mut net, &mut state, (0, Some(keys), None));

                let mut perm_state =
                    DummyArithPermCircPrep::<Fr>::new().run(&mut net, &mut state, vec![]);

                let bit_permutation =
                    generate_bit_permutation(&mut net, &mut perm_state, &party0_key_shares);

                let reconstructed_bit_permutation = VectorReveal::<Fr>::run(
                    &mut net,
                    &mut perm_state.inner_mut(),
                    bit_permutation.clone(),
                );

                // Store party 0's results
                outputs_clone
                    .lock()
                    .unwrap()
                    .push(reconstructed_bit_permutation.clone());
            });

            let outputs_clone = outputs.clone();
            // party 1
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);

                let mut state =
                    DummyArithCircPrep::<Fr>::new().run(&mut net, 2 * 5, 2 * 5, 0, 2 * 5, 0);

                let party1_key_shares =
                    VectorInput::<Fr>::run(&mut net, &mut state, (0, None, Some(n)));

                let mut perm_state =
                    DummyArithPermCircPrep::<Fr>::new().run(&mut net, &mut state, vec![]);

                let bit_permutation =
                    generate_bit_permutation(&mut net, &mut perm_state, &party1_key_shares);

                let reconstructed_bit_permutation = VectorReveal::<Fr>::run(
                    &mut net,
                    &mut perm_state.inner_mut(),
                    bit_permutation.clone(),
                );

                // Store party 0's results
                outputs_clone
                    .lock()
                    .unwrap()
                    .push(reconstructed_bit_permutation.clone());
            });
        });

        let combined_outputs = outputs.lock().unwrap();

        // Verify the results
        if combined_outputs.len() == 2 {
            let reconstructed_bit_permutation = combined_outputs[0].clone();

            assert_eq!(
                reconstructed_bit_permutation,
                vec![
                    Fr::from(0),
                    Fr::from(3),
                    Fr::from(1),
                    Fr::from(2),
                    Fr::from(4),
                ]
            );

            assert_eq!(
                unshuffle_vector_testing(&reconstructed_bit_permutation, &keys_clone),
                vec![
                    Fr::from(0),
                    Fr::from(0),
                    Fr::from(0),
                    Fr::from(1),
                    Fr::from(1)
                ]
            );
        }
    }

    #[test]
    fn test_sort() {
        let n = 25;
        let num_bits = get_field_bits::<Fr>();

        // to be inputted
        let random_shuffles_a_p0 = (0..2 * num_bits + 1)
            .map(|_| get_random_permutation_usize(n))
            .collect::<Vec<Vec<usize>>>();
        let random_shuffles_b_p0 = (0..2 * num_bits + 1)
            .map(|_| get_random_permutation_usize(n))
            .collect::<Vec<Vec<usize>>>();
        let random_shuffles_a_p1 = (0..2 * num_bits + 1)
            .map(|_| get_random_permutation_usize(n))
            .collect::<Vec<Vec<usize>>>();
        let random_shuffles_b_p1 = (0..2 * num_bits + 1)
            .map(|_| get_random_permutation_usize(n))
            .collect::<Vec<Vec<usize>>>();

        let random_input = get_random_vector::<Fr>(12345684129, n);
        let random_input_clone: Vec<Mersenne64Fq> = random_input.clone();
        let random_input_clone_2: Vec<Mersenne64Fq> = random_input.clone();

        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        // Shared state to collect outputs
        let outputs = Arc::new(Mutex::new(Vec::new()));

        rayon::scope(|s| {
            let outputs_clone = outputs.clone();

            // party 0
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 0);

                let mut state = DummyArithCircPrep::<Fr>::new().run(
                    &mut net,
                    num_bits * 100 * n + 2,
                    num_bits * 100 * n + 2,
                    0,
                    num_bits * 100 * n,
                    0,
                );

                // Generate arithmetic permutation circuit state with shuffle tuples
                let shuffle_tuples_a_p0 = (0..2 * num_bits + 1)
                    .map(|j| ShuffleTupleInput {
                        shuffle_id: "random_shuffle_A_p0_".to_string() + &j.to_string(),
                        shuffle: Some(random_shuffles_a_p0[j].clone()),
                        n: n,
                        num_shuffle_tuples: 2,
                        with_inverse: true,
                    })
                    .collect::<Vec<ShuffleTupleInput>>();
                let shuffle_tuples_b_p0 = (0..2 * num_bits + 1)
                    .map(|j| ShuffleTupleInput {
                        shuffle_id: "random_shuffle_B_p0_".to_string() + &j.to_string(),
                        shuffle: Some(random_shuffles_b_p0[j].clone()),
                        n: n,
                        num_shuffle_tuples: 2,
                        with_inverse: true,
                    })
                    .collect::<Vec<ShuffleTupleInput>>();
                let shuffle_tuples_a_p1 = (0..2 * num_bits + 1)
                    .map(|j| ShuffleTupleInput {
                        shuffle_id: "random_shuffle_A_p1_".to_string() + &j.to_string(),
                        shuffle: None,
                        n: n,
                        num_shuffle_tuples: 2,
                        with_inverse: true,
                    })
                    .collect::<Vec<ShuffleTupleInput>>();
                let shuffle_tuples_b_p1 = (0..2 * num_bits + 1)
                    .map(|j| ShuffleTupleInput {
                        shuffle_id: "random_shuffle_B_p1_".to_string() + &j.to_string(),
                        shuffle: None,
                        n: n,
                        num_shuffle_tuples: 2,
                        with_inverse: true,
                    })
                    .collect::<Vec<ShuffleTupleInput>>();

                let shuffle_tuples = shuffle_tuples_a_p0
                    .into_iter()
                    .chain(shuffle_tuples_b_p0.into_iter())
                    .chain(shuffle_tuples_a_p1.into_iter())
                    .chain(shuffle_tuples_b_p1.into_iter())
                    .collect::<Vec<ShuffleTupleInput>>();

                let mut arith_perm_circ_prep = DummyArithPermCircPrep::<Fr>::new();
                let mut arith_perm_circ_state =
                    arith_perm_circ_prep.run(&mut net, &mut state, shuffle_tuples);

                let input_bits = random_input_clone
                    .iter()
                    .map(|share| field_to_bits::<Fr>(*share, num_bits))
                    .collect::<Vec<Vec<Fr>>>();

                let input_bits_p0 = (0..input_bits.len())
                    .map(|i| {
                        VectorInput::<Fr>::run(
                            &mut net,
                            &mut arith_perm_circ_state.inner_mut(),
                            (0, Some(input_bits[i].clone()), None),
                        )
                    })
                    .collect::<Vec<Vec<AuthShare<Fr>>>>();

                let sort_output =
                    Sort::run(&mut net, &mut arith_perm_circ_state, (input_bits_p0, false));

                // outputs_clone.lock().unwrap().push(sort_output);

                let party0_apply_perm_output = sort_output
                    .iter()
                    .map(|bits| {
                        BitsToFieldReconstruct::<Fr>::run(
                            &mut net,
                            &mut arith_perm_circ_state.inner_mut(),
                            bits.clone(),
                        )
                    })
                    .collect::<Vec<AuthShare<Fr>>>();

                let apply_perm_output =
                    <crate::arithpermcircop::vector_reveal::VectorReveal<Fr> as ArithPermCircOp<
                        Fr,
                    >>::run(
                        &mut net,
                        &mut arith_perm_circ_state,
                        party0_apply_perm_output.clone(),
                    );

                outputs_clone.lock().unwrap().push(apply_perm_output);
            });

            let outputs_clone = outputs.clone();
            // party 1
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);

                dbg!("start circ prep");
                let mut state = DummyArithCircPrep::<Fr>::new().run(
                    &mut net,
                    num_bits * 100 * n + 2,
                    num_bits * 100 * n + 2,
                    0,
                    num_bits * 100 * n,
                    0,
                );
                // Generate arithmetic permutation circuit state with shuffle tuples
                let shuffle_tuples_a_p0 = (0..2 * num_bits + 1)
                    .map(|j| ShuffleTupleInput {
                        shuffle_id: "random_shuffle_A_p0_".to_string() + &j.to_string(),
                        shuffle: None,
                        n: n,
                        num_shuffle_tuples: 2,
                        with_inverse: true,
                    })
                    .collect::<Vec<ShuffleTupleInput>>();
                let shuffle_tuples_b_p0 = (0..2 * num_bits + 1)
                    .map(|j| ShuffleTupleInput {
                        shuffle_id: "random_shuffle_B_p0_".to_string() + &j.to_string(),
                        shuffle: None,
                        n: n,
                        num_shuffle_tuples: 2,
                        with_inverse: true,
                    })
                    .collect::<Vec<ShuffleTupleInput>>();
                let shuffle_tuples_a_p1 = (0..2 * num_bits + 1)
                    .map(|j| ShuffleTupleInput {
                        shuffle_id: "random_shuffle_A_p1_".to_string() + &j.to_string(),
                        shuffle: Some(random_shuffles_a_p1[j].clone()),
                        n: n,
                        num_shuffle_tuples: 2,
                        with_inverse: true,
                    })
                    .collect::<Vec<ShuffleTupleInput>>();
                let shuffle_tuples_b_p1 = (0..2 * num_bits + 1)
                    .map(|j| ShuffleTupleInput {
                        shuffle_id: "random_shuffle_B_p1_".to_string() + &j.to_string(),
                        shuffle: Some(random_shuffles_b_p1[j].clone()),
                        n: n,
                        num_shuffle_tuples: 2,
                        with_inverse: true,
                    })
                    .collect::<Vec<ShuffleTupleInput>>();

                let shuffle_tuples = shuffle_tuples_a_p0
                    .into_iter()
                    .chain(shuffle_tuples_b_p0.into_iter())
                    .chain(shuffle_tuples_a_p1.into_iter())
                    .chain(shuffle_tuples_b_p1.into_iter())
                    .collect::<Vec<ShuffleTupleInput>>();

                let mut arith_perm_circ_prep = DummyArithPermCircPrep::<Fr>::new();
                dbg!("start shuffle tuple prep");
                let mut arith_perm_circ_state =
                    arith_perm_circ_prep.run(&mut net, &mut state, shuffle_tuples);

                dbg!("end shuffle tuple prep");

                dbg!("start input bits prep");
                let input_bits_p1 = (0..n)
                    .map(|_| {
                        VectorInput::<Fr>::run(
                            &mut net,
                            &mut arith_perm_circ_state.inner_mut(),
                            (0, None, Some(num_bits)),
                        )
                    })
                    .collect::<Vec<Vec<AuthShare<Fr>>>>();
                dbg!("end input bits prep");

                dbg!("start sort");
                let sort_output =
                    Sort::run(&mut net, &mut arith_perm_circ_state, (input_bits_p1, false));
                dbg!("end sort");

                // outputs_clone.lock().unwrap().push(sort_output);

                let party1_apply_perm_output = sort_output
                    .iter()
                    .map(|bits| {
                        BitsToFieldReconstruct::<Fr>::run(
                            &mut net,
                            &mut arith_perm_circ_state.inner_mut(),
                            bits.clone(),
                        )
                    })
                    .collect::<Vec<AuthShare<Fr>>>();

                let apply_perm_output =
                    <crate::arithpermcircop::vector_reveal::VectorReveal<Fr> as ArithPermCircOp<
                        Fr,
                    >>::run(
                        &mut net,
                        &mut arith_perm_circ_state,
                        party1_apply_perm_output.clone(),
                    );

                outputs_clone.lock().unwrap().push(apply_perm_output);
            });
        });

        let combined_outputs = outputs.lock().unwrap();

        // Verify the results
        if combined_outputs.len() == 2 {
            let apply_perm_output = combined_outputs[0].clone();
            let mut sorted_random_input = random_input_clone_2.clone();
            sorted_random_input.sort_by(|a, b| a.cmp(b));
            assert_eq!(apply_perm_output, sorted_random_input);
        }
    }

    #[test]
    fn test_sort_with_perm_network() {
        let n = 25;
        let num_bits = get_field_bits::<Fr>();

        let random_input = get_random_vector::<Fr>(12345684129, n);
        let random_input_clone: Vec<Mersenne64Fq> = random_input.clone();
        let random_input_clone_2: Vec<Mersenne64Fq> = random_input.clone();

        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        // Shared state to collect outputs
        let outputs = Arc::new(Mutex::new(Vec::new()));

        rayon::scope(|s| {
            let outputs_clone = outputs.clone();

            // party 0
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 0);

                let mut state = DummyArithCircPrep::<Fr>::new().run(
                    &mut net,
                    num_bits * 160 * n + 2,
                    num_bits * 350 * n + 2,
                    num_bits * 160 * n,
                    num_bits * 450 * n,
                    0,
                );

                let mut arith_perm_circ_prep = DummyArithPermCircPrep::<Fr>::new();
                let mut arith_perm_circ_state =
                    arith_perm_circ_prep.run(&mut net, &mut state, vec![]);

                let input_bits = random_input_clone
                    .iter()
                    .map(|share| field_to_bits::<Fr>(*share, num_bits))
                    .collect::<Vec<Vec<Fr>>>();

                let input_bits_p0 = (0..input_bits.len())
                    .map(|i| {
                        VectorInput::<Fr>::run(
                            &mut net,
                            &mut arith_perm_circ_state.inner_mut(),
                            (0, Some(input_bits[i].clone()), None),
                        )
                    })
                    .collect::<Vec<Vec<AuthShare<Fr>>>>();

                let sort_output =
                    Sort::run(&mut net, &mut arith_perm_circ_state, (input_bits_p0, true));

                // outputs_clone.lock().unwrap().push(sort_output);

                let party0_apply_perm_output = sort_output
                    .iter()
                    .map(|bits| {
                        BitsToFieldReconstruct::<Fr>::run(
                            &mut net,
                            &mut arith_perm_circ_state.inner_mut(),
                            bits.clone(),
                        )
                    })
                    .collect::<Vec<AuthShare<Fr>>>();

                let apply_perm_output =
                    <crate::arithpermcircop::vector_reveal::VectorReveal<Fr> as ArithPermCircOp<
                        Fr,
                    >>::run(
                        &mut net,
                        &mut arith_perm_circ_state,
                        party0_apply_perm_output.clone(),
                    );

                outputs_clone.lock().unwrap().push(apply_perm_output);
            });

            let outputs_clone = outputs.clone();
            // party 1
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);

                dbg!("start circ prep");
                let mut state = DummyArithCircPrep::<Fr>::new().run(
                    &mut net,
                    num_bits * 160 * n + 2,
                    num_bits * 350 * n + 2,
                    num_bits * 160 * n,
                    num_bits * 450 * n,
                    0,
                );

                let mut arith_perm_circ_prep = DummyArithPermCircPrep::<Fr>::new();
                dbg!("start shuffle tuple prep");
                let mut arith_perm_circ_state =
                    arith_perm_circ_prep.run(&mut net, &mut state, vec![]);

                dbg!("end shuffle tuple prep");

                dbg!("start input bits prep");
                let input_bits_p1 = (0..n)
                    .map(|_| {
                        VectorInput::<Fr>::run(
                            &mut net,
                            &mut arith_perm_circ_state.inner_mut(),
                            (0, None, Some(num_bits)),
                        )
                    })
                    .collect::<Vec<Vec<AuthShare<Fr>>>>();
                dbg!("end input bits prep");

                dbg!("start sort");
                let sort_output =
                    Sort::run(&mut net, &mut arith_perm_circ_state, (input_bits_p1, true));
                dbg!("end sort");

                // outputs_clone.lock().unwrap().push(sort_output);

                let party1_apply_perm_output = sort_output
                    .iter()
                    .map(|bits| {
                        BitsToFieldReconstruct::<Fr>::run(
                            &mut net,
                            &mut arith_perm_circ_state.inner_mut(),
                            bits.clone(),
                        )
                    })
                    .collect::<Vec<AuthShare<Fr>>>();

                let apply_perm_output =
                    <crate::arithpermcircop::vector_reveal::VectorReveal<Fr> as ArithPermCircOp<
                        Fr,
                    >>::run(
                        &mut net,
                        &mut arith_perm_circ_state,
                        party1_apply_perm_output.clone(),
                    );

                outputs_clone.lock().unwrap().push(apply_perm_output);
            });
        });

        let combined_outputs = outputs.lock().unwrap();

        // Verify the results
        if combined_outputs.len() == 2 {
            let apply_perm_output = combined_outputs[0].clone();
            let mut sorted_random_input = random_input_clone_2.clone();
            sorted_random_input.sort_by(|a, b| a.cmp(b));
            assert_eq!(apply_perm_output, sorted_random_input);
        }
    }

    #[test]
    fn test_sort_with_simple_perm_network() {
        let n = 25;
        let num_bits = get_field_bits::<Fr>();

        let random_input = get_random_vector::<Fr>(12345684129, n);
        let random_input_clone: Vec<Mersenne64Fq> = random_input.clone();
        let random_input_clone_2: Vec<Mersenne64Fq> = random_input.clone();

        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        // Shared state to collect outputs
        let outputs = Arc::new(Mutex::new(Vec::new()));

        rayon::scope(|s| {
            let outputs_clone = outputs.clone();

            // party 0
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 0);

                let mut state = DummyArithCircPrep::<Fr>::new().run(
                    &mut net,
                    num_bits * 160 * n + 2,
                    num_bits * 350 * n + 2,
                    num_bits * 160 * n,
                    num_bits * 450 * n,
                    0,
                );

                let mut arith_perm_circ_prep = DummyArithPermCircPrep::<Fr>::new();
                let mut arith_perm_circ_state =
                    arith_perm_circ_prep.run(&mut net, &mut state, vec![]);

                let input_bits = random_input_clone
                    .iter()
                    .map(|share| field_to_bits::<Fr>(*share, num_bits))
                    .collect::<Vec<Vec<Fr>>>();

                let input_bits_p0 = (0..input_bits.len())
                    .map(|i| {
                        VectorInput::<Fr>::run(
                            &mut net,
                            &mut arith_perm_circ_state.inner_mut(),
                            (0, Some(input_bits[i].clone()), None),
                        )
                    })
                    .collect::<Vec<Vec<AuthShare<Fr>>>>();

                let mut shuffle_time_duration_sort = std::time::Duration::ZERO;
                let sort_output = Sort::run_with_simple_perm_network_timing(
                    &mut net,
                    &mut arith_perm_circ_state,
                    input_bits_p0,
                    &mut |shuffle_time| {
                        shuffle_time_duration_sort += shuffle_time;
                    },
                );

                // outputs_clone.lock().unwrap().push(sort_output);

                let apply_perm_output =
                    <crate::arithpermcircop::vector_reveal::VectorReveal<Fr> as ArithPermCircOp<
                        Fr,
                    >>::run(
                        &mut net, &mut arith_perm_circ_state, sort_output.clone()
                    );

                outputs_clone.lock().unwrap().push(apply_perm_output);
            });

            let outputs_clone = outputs.clone();
            // party 1
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);

                dbg!("start circ prep");
                let mut state = DummyArithCircPrep::<Fr>::new().run(
                    &mut net,
                    num_bits * 160 * n + 2,
                    num_bits * 350 * n + 2,
                    num_bits * 160 * n,
                    num_bits * 450 * n,
                    0,
                );

                let mut arith_perm_circ_prep = DummyArithPermCircPrep::<Fr>::new();
                dbg!("start shuffle tuple prep");
                let mut arith_perm_circ_state =
                    arith_perm_circ_prep.run(&mut net, &mut state, vec![]);

                dbg!("end shuffle tuple prep");

                dbg!("start input bits prep");
                let input_bits_p1 = (0..n)
                    .map(|_| {
                        VectorInput::<Fr>::run(
                            &mut net,
                            &mut arith_perm_circ_state.inner_mut(),
                            (0, None, Some(num_bits)),
                        )
                    })
                    .collect::<Vec<Vec<AuthShare<Fr>>>>();
                dbg!("end input bits prep");

                dbg!("start sort");
                let mut shuffle_time_duration_sort = std::time::Duration::ZERO;
                let sort_output = Sort::run_with_simple_perm_network_timing(
                    &mut net,
                    &mut arith_perm_circ_state,
                    input_bits_p1,
                    &mut |shuffle_time| {
                        shuffle_time_duration_sort += shuffle_time;
                    },
                );
                dbg!("end sort", shuffle_time_duration_sort);

                // outputs_clone.lock().unwrap().push(sort_output);

                let apply_perm_output =
                    <crate::arithpermcircop::vector_reveal::VectorReveal<Fr> as ArithPermCircOp<
                        Fr,
                    >>::run(
                        &mut net, &mut arith_perm_circ_state, sort_output.clone()
                    );

                outputs_clone.lock().unwrap().push(apply_perm_output);
            });
        });

        let combined_outputs = outputs.lock().unwrap();

        // Verify the results
        if combined_outputs.len() == 2 {
            let apply_perm_output = combined_outputs[0].clone();
            let mut sorted_random_input = random_input_clone_2.clone();
            sorted_random_input.sort_by(|a, b| a.cmp(b));
            let unshuffle_output =
                unshuffle_vector_testing(&apply_perm_output, &random_input_clone_2);
            assert_eq!(unshuffle_output, sorted_random_input);
        }
    }
}
