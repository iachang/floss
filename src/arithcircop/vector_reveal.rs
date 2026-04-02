use ark_ff::Field;

use crate::{
    arithcircop::{ArithCircOp, ArithCircState, opened_auth_check::OpenedAuthCheck},
    net::Net,
    primitives::auth::AuthShare,
    utils::vector_utils::reduce_columns_parallel,
};
use rayon::prelude::*;
/// Reveal the data in `share` to all parties.
/// (Checks that the MACs are correct.)
pub struct VectorReveal<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> VectorReveal<F> {
    /// Create a new ArithCircOp instance
    pub fn new() -> Self {
        VectorReveal {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<F: Field> ArithCircOp<F> for VectorReveal<F> {
    type In = Vec<AuthShare<F>>;
    type Out = Vec<F>;

    fn run(net: &mut Net, state: &mut ArithCircState<F>, input: Self::In) -> Self::Out {
        let shares = input;
        let vals: Vec<Vec<F>> =
            net.atomic_broadcast_vector(&shares.iter().map(|s| s.value).collect());
        let x: Vec<F> = reduce_columns_parallel(&vals, || F::zero(), |a, b| a + b);
        state.add_to_check_auth_shares(
            x.par_iter()
                .zip(shares.par_iter())
                .map(|(x, s)| (*x, s.mac))
                .collect::<Vec<(F, F)>>(),
        );

        // Perform an auth check over opened input.
        let to_check_auth_shares = state.drain_to_check_auth_shares();
        let (opened_values, auth_shares): (Vec<F>, Vec<F>) = to_check_auth_shares
            .iter()
            .map(|(opened_value, auth_share)| (*opened_value, *auth_share))
            .unzip();
        OpenedAuthCheck::<F>::run(net, state, (opened_values, auth_shares));

        x
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
    fn test_vector_reveal() {
        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        let n = 10;

        let outputs = std::sync::Arc::new(std::sync::Mutex::new(Vec::<(
            Vec<AuthShare<Fr>>,
            Vec<Fr>,
        )>::new()));

        rayon::scope(|s| {
            // party 0
            let outputs_party0 = outputs.clone();
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 0);
                let mut state = DummyArithCircPrep::<Fr>::new().run(&mut net, n, n, 0, 0, 0);

                let v_party0 = generate_random_auth_shares(&mut state, n);

                // Test batch reveal
                let batch_results = VectorReveal::<Fr>::run(&mut net, &mut state, v_party0.clone());

                // Store the results for verification
                outputs_party0
                    .lock()
                    .unwrap()
                    .push((v_party0, batch_results));
            });
            // party 1
            let outputs_party1 = outputs.clone();
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);
                let mut state = DummyArithCircPrep::<Fr>::new().run(&mut net, n, n, 0, 0, 0);

                let v_party1 = generate_random_auth_shares(&mut state, n);

                // Test batch reveal
                let batch_results = VectorReveal::<Fr>::run(&mut net, &mut state, v_party1.clone());

                // Store the results for verification
                outputs_party1
                    .lock()
                    .unwrap()
                    .push((v_party1, batch_results));
            });
        });

        let combined_outputs = outputs.lock().unwrap();

        // Verify that both parties got the same results
        if combined_outputs.len() == 2 {
            let (v_party0, party0_output) = &combined_outputs[0];
            let (v_party1, party1_output) = &combined_outputs[1];
            assert_eq!(party0_output, party1_output);

            // Verify that the results match the original global values
            for i in 0..n {
                let global_value = v_party0[i].value + v_party1[i].value;
                assert_eq!(party0_output[i], global_value);
            }
        }
    }
}
