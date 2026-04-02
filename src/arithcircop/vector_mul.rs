use ark_ff::Field;

use crate::{
    arithcircop::{
        ArithCircOp, ArithCircState, vector_add::VectorAdd, vector_reveal::VectorReveal,
        vector_scale_by_vector::VectorScaleByVector, vector_shift_by_vector::VectorShiftByVector,
        vector_sub::VectorSub,
    },
    net::Net,
    primitives::auth::AuthShare,
    utils::vector_utils::elementwise_ref,
};

/// Arithmetic circuit operations, vanilla SPDZ.
pub struct VectorMul<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> VectorMul<F> {
    /// Create a new ArithCircOp instance
    pub fn new() -> Self {
        VectorMul {
            _phantom: std::marker::PhantomData,
        }
    }
}

/// Take multiple inputs from `party` in parallel.
///
/// Consumes `values.len()` random coins.
/// When `values` is None (for non-input parties), the length must be provided as `n`.
impl<F: Field> ArithCircOp<F> for VectorMul<F> {
    type In = (Vec<AuthShare<F>>, Vec<AuthShare<F>>); // a, b
    type Out = Vec<AuthShare<F>>;

    fn run(net: &mut Net, state: &mut ArithCircState<F>, input: Self::In) -> Self::Out {
        let a = input.0;
        let b = input.1;

        assert_eq!(a.len(), b.len(), "length mismatch");
        let n = a.len();
        let triples = state.take_triples(n);
        let x: Vec<_> = triples.iter().map(|(x, _, _)| x.clone()).collect();
        let y: Vec<_> = triples.iter().map(|(_, y, _)| y.clone()).collect();
        let z: Vec<_> = triples.iter().map(|(_, _, z)| z.clone()).collect();
        // output: z - open(a + x)y - open(b + y)x + open(a + x)open(b + y)
        //         = xy - ay - xy - bx - yx + ab + ay + xb + xy
        //         = ab
        let a_plus_x_vec = VectorAdd::<F>::run(net, state, (a, x.clone()));
        let a_plus_x = VectorReveal::<F>::run(net, state, a_plus_x_vec);
        let b_plus_y_vec = VectorAdd::<F>::run(net, state, (b, y.clone()));
        let b_plus_y = VectorReveal::<F>::run(net, state, b_plus_y_vec);

        let y_scaled = VectorScaleByVector::<F>::run(net, state, (y, a_plus_x.clone()));
        let x_scaled = VectorScaleByVector::<F>::run(net, state, (x, b_plus_y.clone()));
        let scaled_sum = VectorAdd::<F>::run(net, state, (y_scaled, x_scaled));
        let z_minus_scaled = VectorSub::<F>::run(net, state, (z, scaled_sum));

        let a_plus_x_times_b_plus_y: Vec<F> = elementwise_ref(&a_plus_x, &b_plus_y, |a, b| a * b);

        VectorShiftByVector::<F>::run(net, state, (z_minus_scaled, a_plus_x_times_b_plus_y))
    }
}

#[cfg(test)]
mod test {
    use rand::Rng;

    use crate::{
        arithcircprep::{ArithCircPrep, dummy::DummyArithCircPrep},
        utils::testing_utils::generate_random_auth_shares,
    };

    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;
    type Fr = crate::bench::Mersenne128Fq;

    #[test]
    fn test_vector_mul() {
        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        // Modify the shared output to include the input vectors
        let outputs = std::sync::Arc::new(std::sync::Mutex::new(Vec::<(
            Vec<AuthShare<Fr>>,
            Vec<AuthShare<Fr>>,
            Vec<AuthShare<Fr>>,
        )>::new()));

        let n = 10;
        let mac_shares = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Fr>::new()));
        rayon::scope(|s| {
            // party 0
            let outputs_party0 = outputs.clone();
            let mac_shares_party0 = mac_shares.clone();
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 0);

                let mut state =
                    DummyArithCircPrep::<Fr>::new().run(&mut net, 2 * n, 4 * n, 0, n, 0);

                mac_shares_party0.lock().unwrap().push(state.key_share());

                let v1_party0 = generate_random_auth_shares(&mut state, n);
                let v2_party0 = generate_random_auth_shares(&mut state, n);

                let output = VectorMul::<Fr>::run(
                    &mut net,
                    &mut state,
                    (v1_party0.clone(), v2_party0.clone()),
                );

                // Store input vectors and output together
                outputs_party0
                    .lock()
                    .unwrap()
                    .push((v1_party0, v2_party0, output));
            });
            // party 1
            let outputs_party1 = outputs.clone();
            let mac_shares_party1 = mac_shares.clone();
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);
                let mut state =
                    DummyArithCircPrep::<Fr>::new().run(&mut net, 2 * n, 4 * n, 0, n, 0);

                mac_shares_party1.lock().unwrap().push(state.key_share());

                let v1_party1 = generate_random_auth_shares(&mut state, n);
                let v2_party1 = generate_random_auth_shares(&mut state, n);

                let output = VectorMul::<Fr>::run(
                    &mut net,
                    &mut state,
                    (v1_party1.clone(), v2_party1.clone()),
                );

                outputs_party1
                    .lock()
                    .unwrap()
                    .push((v1_party1, v2_party1, output));
            });
        });

        // In verification section, access the stored vectors:
        let mac = mac_shares.lock().unwrap().iter().sum::<Fr>();
        let combined_outputs = outputs.lock().unwrap();
        if combined_outputs.len() == 2 {
            let (v1_party0, v2_party0, party0_output) = &combined_outputs[0];
            let (v1_party1, v2_party1, party1_output) = &combined_outputs[1];

            // Reconstruct global values by adding corresponding shares
            if party0_output.len() == party1_output.len() {
                for (i, (share0, share1)) in
                    party0_output.iter().zip(party1_output.iter()).enumerate()
                {
                    let global_value = share0.value + share1.value;
                    let global_mac = share0.mac + share1.mac;

                    // Verify multiplicative relationship:
                    // (v1_party0[i].value + v1_party1[i].value) * (v2_party0[i].value + v2_party1[i].value)
                    // = party0_output[i].value + party1_output[i].value
                    let v1_global = v1_party0[i].value + v1_party1[i].value;
                    let v2_global = v2_party0[i].value + v2_party1[i].value;
                    let expected_value = v1_global * v2_global;

                    // Verify authentication property:
                    // (mac_party0 + mac_party1) * (party0_output[i].value + party1_output[i].value)
                    // = party0_output[i].mac + party1_output[i].mac
                    let expected_mac = mac * global_value;

                    assert_eq!(global_value, expected_value);
                    assert_eq!(global_mac, expected_mac);
                }
            }
        }
    }

    #[test]
    fn test_vector_mul_consistency() {
        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        let outputs = std::sync::Arc::new(std::sync::Mutex::new(Vec::<(
            Vec<AuthShare<Fr>>,
            Vec<AuthShare<Fr>>,
            Vec<AuthShare<Fr>>,
            Vec<AuthShare<Fr>>,
        )>::new()));

        let n = 10;

        let mac_shares = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Fr>::new()));
        rayon::scope(|s| {
            // party 0
            let outputs_party0 = outputs.clone();
            let mac_shares_party0 = mac_shares.clone();
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 0);
                let mut state =
                    DummyArithCircPrep::<Fr>::new().run(&mut net, 4 * n, 4 * n, 0, 2 * n + 1, 0);

                mac_shares_party0.lock().unwrap().push(state.key_share());

                let v1_party0 = generate_random_auth_shares(&mut state, n);
                let v2_party0 = generate_random_auth_shares(&mut state, n);

                // Test individual muls - we'll use vector_mul with single elements
                let individual_results: Vec<AuthShare<Fr>> = v1_party0
                    .iter()
                    .zip(v2_party0.iter())
                    .map(|(a, b)| {
                        let a_vec = vec![*a];
                        let b_vec = vec![*b];
                        VectorMul::<Fr>::run(&mut net, &mut state, (a_vec, b_vec))[0]
                    })
                    .collect();

                // Test vector_mul
                let vector_results = VectorMul::<Fr>::run(
                    &mut net,
                    &mut state,
                    (v1_party0.clone(), v2_party0.clone()),
                );

                // Both should produce the same number of results
                assert_eq!(individual_results.len(), vector_results.len());

                outputs_party0.lock().unwrap().push((
                    v1_party0,
                    v2_party0,
                    individual_results,
                    vector_results,
                ));
            });
            // party 1
            let outputs_party1 = outputs.clone();
            let mac_shares_party1 = mac_shares.clone();
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);
                let mut state =
                    DummyArithCircPrep::<Fr>::new().run(&mut net, 4 * n, 4 * n, 0, 2 * n + 1, 0);

                mac_shares_party1.lock().unwrap().push(state.key_share());

                let v1_party1 = generate_random_auth_shares(&mut state, n);
                let v2_party1 = generate_random_auth_shares(&mut state, n);

                // Test individual muls - we'll use vector_mul with single elements
                let individual_results: Vec<AuthShare<Fr>> = v1_party1
                    .iter()
                    .zip(v2_party1.iter())
                    .map(|(a, b)| {
                        let a_vec = vec![*a];
                        let b_vec = vec![*b];
                        VectorMul::<Fr>::run(&mut net, &mut state, (a_vec, b_vec))[0]
                    })
                    .collect();

                // Test vector_mul
                let vector_results = VectorMul::<Fr>::run(
                    &mut net,
                    &mut state,
                    (v1_party1.clone(), v2_party1.clone()),
                );

                // Both should produce the same number of results
                assert_eq!(individual_results.len(), vector_results.len());

                outputs_party1.lock().unwrap().push((
                    v1_party1,
                    v2_party1,
                    individual_results,
                    vector_results,
                ));
            });
        });

        let combined_outputs = outputs.lock().unwrap();
        let mac = mac_shares.lock().unwrap().iter().sum::<Fr>();
        // Verify that both parties got the same results
        if combined_outputs.len() == 2 {
            let (v1_party0, v2_party0, party0_individual, party0_vector) = &combined_outputs[0];
            let (v1_party1, v2_party1, party1_individual, party1_vector) = &combined_outputs[1];

            // Verify that both individual and vector results produce the same global values
            for i in 0..3 {
                // Check individual results
                let global_value_individual =
                    party0_individual[i].value + party1_individual[i].value;
                let global_mac_individual = party0_individual[i].mac + party1_individual[i].mac;

                // Check vector results
                let global_value_vector = party0_vector[i].value + party1_vector[i].value;
                let global_mac_vector = party0_vector[i].mac + party1_vector[i].mac;

                let v1_global = v1_party0[i].value + v1_party1[i].value;
                let v2_global = v2_party0[i].value + v2_party1[i].value;
                let expected_value = v1_global * v2_global;
                let expected_mac = mac * expected_value;

                // Both approaches should produce the same global values
                assert_eq!(global_value_individual, expected_value);
                assert_eq!(global_mac_individual, expected_mac);
                assert_eq!(global_value_vector, expected_value);
                assert_eq!(global_mac_vector, expected_mac);
            }
        }
    }
}
