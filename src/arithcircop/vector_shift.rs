use ark_ff::Field;

use crate::{
    arithcircop::{ArithCircOp, ArithCircState, vector_shift_by_vector::VectorShiftByVector},
    net::Net,
    primitives::auth::AuthShare,
};

/// Shifts a vector of shares by a constant.
pub struct VectorShift<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> VectorShift<F> {
    /// Create a new ArithCircOp instance
    pub fn new() -> Self {
        VectorShift {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<F: Field> ArithCircOp<F> for VectorShift<F> {
    type In = (Vec<AuthShare<F>>, F);
    type Out = Vec<AuthShare<F>>;

    fn run(net: &mut Net, state: &mut ArithCircState<F>, input: Self::In) -> Self::Out {
        let (shares, offset) = input;
        VectorShiftByVector::<F>::run(net, state, (shares.clone(), vec![offset; shares.len()]))
    }
}

#[cfg(test)]
mod test {
    use ark_ff::UniformRand;
    use rand::Rng;

    use crate::{
        arithcircprep::{ArithCircPrep, dummy::DummyArithCircPrep},
        utils::{rng_utils::get_random_rng, testing_utils::generate_random_auth_shares},
    };

    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;
    type Fr = crate::bench::Mersenne128Fq;

    #[test]
    fn test_vector_shift() {
        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        // Shared output to include input vectors and output
        let outputs = std::sync::Arc::new(std::sync::Mutex::new(Vec::<(
            Vec<AuthShare<Fr>>,
            Vec<AuthShare<Fr>>,
        )>::new()));

        let n = 10;
        let offset = Fr::rand(&mut get_random_rng());
        let mac_shares = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Fr>::new()));
        rayon::scope(|s| {
            // party 0
            let outputs_party0 = outputs.clone();
            let mac_shares_party0 = mac_shares.clone();
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 0);

                let mut state = DummyArithCircPrep::<Fr>::new().run(&mut net, 0, n, 0, 0, 0);
                let v_party0 = generate_random_auth_shares(&mut state, n);
                let output =
                    VectorShift::<Fr>::run(&mut net, &mut state, (v_party0.clone(), offset));

                mac_shares_party0.lock().unwrap().push(state.key_share());
                outputs_party0.lock().unwrap().push((v_party0, output));
            });
            // party 1
            let outputs_party1 = outputs.clone();
            let mac_shares_party1 = mac_shares.clone();
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);

                let mut state = DummyArithCircPrep::<Fr>::new().run(&mut net, 0, n, 0, 0, 0);
                let v_party1 = generate_random_auth_shares(&mut state, n);
                let output =
                    VectorShift::<Fr>::run(&mut net, &mut state, (v_party1.clone(), offset));

                mac_shares_party1.lock().unwrap().push(state.key_share());
                outputs_party1.lock().unwrap().push((v_party1, output));
            });
        });

        let mac = mac_shares.lock().unwrap().iter().sum::<Fr>();
        let combined_outputs = outputs.lock().unwrap();
        if combined_outputs.len() == 2 {
            let (v_party0, party0_output) = &combined_outputs[0];
            let (v_party1, party1_output) = &combined_outputs[1];

            // Verify that both parties generated the same number of shares
            assert_eq!(party0_output.len(), party1_output.len());
            assert_eq!(v_party0.len(), v_party1.len());

            // Verify each element
            for (i, (share0, share1)) in party0_output.iter().zip(party1_output.iter()).enumerate()
            {
                let global_value = share0.value + share1.value;
                let global_mac = share0.mac + share1.mac;

                // Verify shift relationship:
                // (v_party0[i].value + v_party1[i].value) + offset = party0_output[i].value + party1_output[i].value
                let v_global = v_party0[i].value + v_party1[i].value;
                let expected_value = v_global + offset;

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
