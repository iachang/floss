use ark_ff::Field;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

use crate::{
    arithcircop::{ArithCircOp, ArithCircState, vector_shift_by_vector::VectorShiftByVector},
    net::Net,
    primitives::auth::AuthShare,
    utils::vector_utils::{elementwise_ref, reduce_columns_parallel},
};

/// Arithmetic circuit operations, vanilla SPDZ.
pub struct VectorInput<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> VectorInput<F> {
    /// Create a new ArithCircOp instance
    pub fn new() -> Self {
        VectorInput {
            _phantom: std::marker::PhantomData,
        }
    }
}

/// Take multiple inputs from `party` in parallel.
///
/// Consumes `values.len()` random coins.
/// When `values` is None (for non-input parties), the length must be provided as `n`.
impl<F: Field> ArithCircOp<F> for VectorInput<F> {
    type In = (usize, Option<Vec<F>>, Option<usize>); // inputting party id, values, number of values
    type Out = Vec<AuthShare<F>>;

    fn run(net: &mut Net, state: &mut ArithCircState<F>, input: Self::In) -> Self::Out {
        let inputting_party = input.0;
        let values = input.1;
        let n = input.2;

        let checked_n = values.as_ref().map(|v| v.len()).or(n).unwrap_or_else(|| {
            panic!("vector_input requires either Some(values) or Some(n) for non-input parties");
        });
        if checked_n == 0 {
            return vec![];
        }

        // Take coins for all inputs
        let mask_shares: Vec<AuthShare<F>> = state.take_auth_coins(checked_n);

        // Collect all mask values to send to the party
        let mask_values: Vec<F> = mask_shares.par_iter().map(|share| share.value).collect();

        // Send all mask values to the party and get the sum
        let masks = net.all_send_vector_to_party(inputting_party, &mask_values);

        // Sum all of the parties' values
        let mask_sums = masks
            .as_ref()
            .map(|m| reduce_columns_parallel(m, || F::zero(), |a, b| a + b));

        // Calculate shifts for all values
        let shifts = net.all_recv_vector_from_party(
            inputting_party,
            mask_sums.map(|mask_sums| {
                vec![elementwise_ref(&values.unwrap(), &mask_sums, |a, b| a - b); net.n_parties()]
            }),
        );

        // Apply shifts to all mask shares using vectorized operation
        let result = VectorShiftByVector::<F>::run(net, state, (mask_shares, shifts));
        result
    }
}

#[cfg(test)]
mod test {
    use ark_ff::UniformRand;
    use rand::Rng;

    use crate::{
        arithcircprep::{ArithCircPrep, dummy::DummyArithCircPrep},
        utils::rng_utils::get_random_rng,
    };

    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;
    type Fr = crate::bench::Mersenne128Fq;

    #[test]
    fn test_input_dim1() {
        let value = Fr::rand(&mut get_random_rng());

        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        let mut output = AuthShare {
            value: Fr::from(0),
            mac: Fr::from(0),
        };

        let input_party = 0;
        let output_shared = std::sync::Arc::new(std::sync::Mutex::new(output));

        let mac_shares = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Fr>::new()));
        rayon::scope(|s| {
            // party 0
            let output_party0 = output_shared.clone();
            let mac_shares_party0 = mac_shares.clone();
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 0);
                let mut state = DummyArithCircPrep::<Fr>::new().run(&mut net, 0, 1, 0, 0, 0);
                mac_shares_party0.lock().unwrap().push(state.key_share());
                let output_temp_p0 = VectorInput::<Fr>::run(
                    &mut net,
                    &mut state,
                    (input_party, Some(vec![value]), Some(1)),
                );
                {
                    let mut output_guard = output_party0.lock().unwrap();
                    *output_guard = *output_guard + output_temp_p0[0];
                }
            });
            // party 1
            let output_party1 = output_shared.clone();
            let mac_shares_party1 = mac_shares.clone();
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);
                let mut state = DummyArithCircPrep::<Fr>::new().run(&mut net, 0, 1, 0, 0, 0);
                mac_shares_party1.lock().unwrap().push(state.key_share());
                let output_temp_p1 =
                    VectorInput::<Fr>::run(&mut net, &mut state, (input_party, None, Some(1)));
                {
                    let mut output_guard = output_party1.lock().unwrap();
                    *output_guard = *output_guard + output_temp_p1[0];
                }
            });
        });
        output = *output_shared.lock().unwrap();
        let mac = mac_shares.lock().unwrap().iter().sum::<Fr>();
        let expected = value;
        assert_eq!(output.value, expected);
        assert_eq!(output.mac, expected * mac);
    }

    #[test]
    fn test_vector_input_consistency() {
        let n = 3; // Number of inputs to test

        // Generate test values for party 0
        let test_values = vec![
            Fr::rand(&mut get_random_rng()),
            Fr::rand(&mut get_random_rng()),
            Fr::rand(&mut get_random_rng()),
        ];

        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        let outputs = std::sync::Arc::new(std::sync::Mutex::new(Vec::<(
            Vec<AuthShare<Fr>>,
            Vec<AuthShare<Fr>>,
        )>::new()));

        let mac_shares = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Fr>::new()));

        rayon::scope(|s| {
            // party 0 (input party)
            let outputs_party0 = outputs.clone();
            let test_values_party0 = test_values.clone();
            let mac_shares_party0 = mac_shares.clone();
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 0);
                let mut state = DummyArithCircPrep::<Fr>::new().run(&mut net, 0, 2 * n, 0, 0, 0);

                // Test individual inputs - we'll use vector_input with single elements
                let individual_results: Vec<AuthShare<Fr>> = test_values_party0
                    .iter()
                    .map(|&value| {
                        VectorInput::<Fr>::run(
                            &mut net,
                            &mut state,
                            (0, Some(vec![value]), Some(1)),
                        )[0]
                    })
                    .collect();

                // Test vector_input

                mac_shares_party0.lock().unwrap().push(state.key_share());
                let vector_results = VectorInput::<Fr>::run(
                    &mut net,
                    &mut state,
                    (0, Some(test_values_party0), None),
                );

                // Both should produce the same number of results
                assert_eq!(individual_results.len(), vector_results.len());
                assert_eq!(individual_results.len(), n);

                outputs_party0
                    .lock()
                    .unwrap()
                    .push((individual_results, vector_results));
            });
            // party 1 (non-input party)
            let outputs_party1 = outputs.clone();
            let mac_shares_party1 = mac_shares.clone();
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);
                let mut state = DummyArithCircPrep::<Fr>::new().run(&mut net, 0, 2 * n, 0, 0, 0);

                mac_shares_party1.lock().unwrap().push(state.key_share());

                // Test individual inputs (should receive None for values)
                let individual_results: Vec<AuthShare<Fr>> = (0..n)
                    .map(|_| VectorInput::<Fr>::run(&mut net, &mut state, (0, None, Some(1)))[0])
                    .collect();

                // Test vector_input (should receive None for values)
                let vector_results =
                    VectorInput::<Fr>::run(&mut net, &mut state, (0, None, Some(n)));

                // Both should produce the same number of results
                assert_eq!(individual_results.len(), vector_results.len());
                assert_eq!(individual_results.len(), n);

                outputs_party1
                    .lock()
                    .unwrap()
                    .push((individual_results, vector_results));
            });
        });

        let combined_outputs = outputs.lock().unwrap();
        let mac = mac_shares.lock().unwrap().iter().sum::<Fr>();
        // Verify that both parties got the same results
        if combined_outputs.len() == 2 {
            let (party0_individual, party0_vector) = &combined_outputs[0];
            let (party1_individual, party1_vector) = &combined_outputs[1];

            // Verify that both individual and vector results produce the same global values
            for i in 0..n {
                // Check individual results
                let global_value_individual =
                    party0_individual[i].value + party1_individual[i].value;
                let global_mac_individual = party0_individual[i].mac + party1_individual[i].mac;

                // Check vector results
                let global_value_vector = party0_vector[i].value + party1_vector[i].value;
                let global_mac_vector = party0_vector[i].mac + party1_vector[i].mac;

                let expected_value = test_values[i];
                let expected_mac = mac * expected_value;

                // Both approaches should produce the same global values
                assert_eq!(global_value_individual, expected_value);
                assert_eq!(global_mac_individual, expected_mac);
                assert_eq!(global_value_vector, expected_value);
                assert_eq!(global_mac_vector, expected_mac);

                // Individual and vector results should be identical
                assert_eq!(global_value_individual, global_value_vector);
                assert_eq!(global_mac_individual, global_mac_vector);
            }
        }
    }
}
