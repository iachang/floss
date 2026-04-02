use std::collections::VecDeque;

use ark_ff::Field;

use crate::arithcircop::unauth_mul::UnauthMul;
use crate::arithcircop::vector_scale::VectorScale;
use crate::arithcircop::{ArithCircOp, ArithCircState};
use crate::net::Net;
use crate::primitives::auth::AuthShare;
/// Inverts a vector of shares using montgomery batching.
pub struct VectorInvert<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> VectorInvert<F> {
    /// Create a new ArithCircOp instance
    pub fn new() -> Self {
        VectorInvert {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<F: Field> ArithCircOp<F> for VectorInvert<F> {
    type In = Vec<AuthShare<F>>;
    type Out = Vec<AuthShare<F>>;

    fn run(net: &mut Net, state: &mut ArithCircState<F>, input: Self::In) -> Self::Out {
        let a = input;
        let (r, _r_inv) = state.take_inversions(1)[0];
        let mut p = vec![a[0]];
        for i in 1..a.len() {
            let p_i = UnauthMul::<F>::run(net, state, (a[i].value, p[i - 1].value));
            let p_i_mac = UnauthMul::<F>::run(net, state, (a[i].mac, p[i - 1].mac));
            p.push(AuthShare {
                value: p_i,
                mac: p_i_mac,
            });
        }

        let mask = UnauthMul::<F>::run(net, state, (r.value, p[a.len() - 1].value));
        let mask_mac = UnauthMul::<F>::run(net, state, (r.mac, p[a.len() - 1].mac));
        let mask_value_shares = net.atomic_broadcast(&mask);
        let mask_value: F = mask_value_shares.iter().sum();
        let mask_mac_shares = net.atomic_broadcast(&mask_mac);
        let mask_mac: F = mask_mac_shares.iter().sum();

        if mask_value == F::zero() {
            assert!(false, "mask value is zero, no inversion with a zero input");
        }
        if mask_mac == F::zero() {
            assert!(false, "mask mac is zero, no inversion with a zero input");
        }

        let mask_value_inv = mask_value.inverse().unwrap();
        let mask_mac_inv = mask_mac.inverse().unwrap();

        let mut sweeping_inv_value =
            VectorScale::<F>::run(net, state, (vec![r], mask_value_inv))[0].value;
        let mut sweeping_inv_mac =
            VectorScale::<F>::run(net, state, (vec![r], mask_mac_inv))[0].mac;
        let mut invs = VecDeque::new();
        for i in (1..a.len()).rev() {
            let inv_i = UnauthMul::<F>::run(net, state, (p[i - 1].value, sweeping_inv_value));
            let inv_i_mac = UnauthMul::<F>::run(net, state, (sweeping_inv_mac, p[i - 1].mac));

            sweeping_inv_value = UnauthMul::<F>::run(net, state, (sweeping_inv_value, a[i].value));
            sweeping_inv_mac = UnauthMul::<F>::run(net, state, (sweeping_inv_mac, a[i].mac));

            invs.push_front(AuthShare {
                value: inv_i,
                mac: inv_i_mac,
            });
        }
        invs.push_front(AuthShare {
            value: sweeping_inv_value,
            mac: sweeping_inv_mac,
        });
        invs.into_iter().collect()
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
    use std::{
        io::Write,
        sync::{Arc, Mutex},
    };
    use tempfile::NamedTempFile;
    type Fr = crate::bench::Mersenne128Fq;

    #[test]
    fn test_vector_invert() {
        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        // Shared state to collect outputs
        let outputs = Arc::new(Mutex::new(Vec::new()));

        let n = 10;

        rayon::scope(|s| {
            // party 0
            let outputs_party0 = outputs.clone();
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 0);
                let mut state = DummyArithCircPrep::<Fr>::new().run(&mut net, 0, n, 8 * n, 0, 1);

                let party0_auth_shares = generate_random_auth_shares(&mut state, n);

                // Test individual muls - we'll use vector_mul with single elements
                let individual_results: Vec<AuthShare<Fr>> =
                    VectorInvert::<Fr>::run(&mut net, &mut state, party0_auth_shares.clone());

                outputs_party0
                    .lock()
                    .unwrap()
                    .push((party0_auth_shares, individual_results));
            });
            // party 1
            let outputs_party1 = outputs.clone();
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);
                let mut state = DummyArithCircPrep::<Fr>::new().run(&mut net, 0, n, 8 * n, 0, 1);

                let party1_auth_shares = generate_random_auth_shares(&mut state, n);

                // Test individual muls - we'll use vector_mul with single elements
                let individual_results: Vec<AuthShare<Fr>> =
                    VectorInvert::<Fr>::run(&mut net, &mut state, party1_auth_shares.clone());

                outputs_party1
                    .lock()
                    .unwrap()
                    .push((party1_auth_shares, individual_results));
            });
        });

        let combined_outputs = outputs.lock().unwrap();

        // Verify that both parties got the same results
        if combined_outputs.len() == 2 {
            let (party0_auth_shares, party0_output) = &combined_outputs[0];
            let (party1_auth_shares, party1_output) = &combined_outputs[1];

            // Verify that both individual and vector results produce the same global values
            for i in 0..n {
                // Check output results
                let global_value_output = party0_output[i].value + party1_output[i].value;
                let global_mac_output = party0_output[i].mac + party1_output[i].mac;

                // Check input results
                let global_value_input = party0_auth_shares[i].value + party1_auth_shares[i].value;
                let global_mac_input = party0_auth_shares[i].mac + party1_auth_shares[i].mac;

                let expected_value = global_value_input.inverse().unwrap();
                let expected_mac = global_mac_input.inverse().unwrap();

                // Check that the output is the inverse of the input
                assert_eq!(global_value_output, expected_value);
                assert_eq!(global_mac_output, expected_mac);
                assert_eq!(global_value_input * global_value_output, Fr::ONE);
                assert_eq!(global_mac_input * global_mac_output, Fr::ONE);
            }
        }
    }
}
