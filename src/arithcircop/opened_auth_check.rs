use ark_ff::Field;

use crate::{
    arithcircop::{ArithCircOp, ArithCircState},
    net::Net,
    utils::rng_utils::get_random_rng,
};
use rayon::prelude::*;

/// Perform an auth check over opened input.
pub struct OpenedAuthCheck<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> OpenedAuthCheck<F> {
    /// Create a new OpenedAuthCheck instance
    pub fn new() -> Self {
        OpenedAuthCheck {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<F: Field> ArithCircOp<F> for OpenedAuthCheck<F> {
    type In = (Vec<F>, Vec<F>); // key share, opened values, auth shares to check
    type Out = bool;

    fn run(net: &mut Net, state: &mut ArithCircState<F>, input: Self::In) -> Self::Out {
        let (opened_values, auth_shares) = input;

        // Step 1: Parse input
        let n = auth_shares.len();

        // Step 2: Generate challenges
        let challenge_share: F = F::rand(&mut get_random_rng());
        let challenge: F = net.atomic_broadcast(&challenge_share).iter().sum();

        // Step 3: Reduce to compute shares of t and shares of at
        let challenge_powers: Vec<F> = {
            let mut powers = Vec::with_capacity(n);
            let mut power = challenge;
            powers.push(power);
            for _ in 1..n {
                power = power * challenge;
                powers.push(power);
            }
            powers
        };

        let (t, at_share): (F, F) = (0..n)
            .into_par_iter()
            .map(|i| {
                let power = challenge_powers[i];
                (power * opened_values[i], power * auth_shares[i])
            })
            .reduce(
                || (F::zero(), F::zero()),
                |(a1, a2), (b1, b2)| (a1 + b1, a2 + b2),
            );

        // Step 4: Locally compute z share
        let z_share: F = at_share - t * state.key_share();

        // Step 5: Exchange commitments to shares of z and open to compute z
        let z: F = net.atomic_broadcast(&z_share).iter().sum();

        // Step 6: Succeed if z = 0. Else fail.
        assert!(z.is_zero());

        true
    }
}

#[cfg(test)]
mod test {
    use rand::Rng;

    use crate::{
        arithcircop::{ArithCircOp, opened_auth_check::OpenedAuthCheck},
        arithcircprep::{ArithCircPrep, dummy::DummyArithCircPrep},
        net::Net,
        utils::testing_utils::generate_random_auth_shares,
        utils::vector_utils::reduce_columns_parallel,
    };

    use std::io::Write;
    use tempfile::NamedTempFile;
    type Fr = crate::bench::Mersenne128Fq;

    #[test]
    fn test_opened_auth_check() {
        let n = 25;

        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        rayon::scope(|s| {
            // party 0
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 0);

                let mut state = DummyArithCircPrep::<Fr>::new().run(&mut net, 1, n, 0, 0, 0);
                let party0_auth_shares = generate_random_auth_shares(&mut state, n);

                let opened_values_shares = net
                    .atomic_broadcast_vector(&party0_auth_shares.iter().map(|s| s.value).collect());
                let opened_values: Vec<Fr> =
                    reduce_columns_parallel(&opened_values_shares, || Fr::from(0), |a, b| a + b);

                OpenedAuthCheck::<Fr>::run(
                    &mut net,
                    &mut state,
                    (
                        opened_values,
                        party0_auth_shares.iter().map(|s| s.mac).collect(),
                    ),
                );
            });
            // party 1
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);

                let mut state = DummyArithCircPrep::<Fr>::new().run(&mut net, 1, n, 0, 0, 0);

                let party1_auth_shares = generate_random_auth_shares(&mut state, n);

                let opened_values_shares = net
                    .atomic_broadcast_vector(&party1_auth_shares.iter().map(|s| s.value).collect());
                let opened_values: Vec<Fr> =
                    reduce_columns_parallel(&opened_values_shares, || Fr::from(0), |a, b| a + b);

                OpenedAuthCheck::<Fr>::run(
                    &mut net,
                    &mut state,
                    (
                        opened_values,
                        party1_auth_shares.iter().map(|s| s.mac).collect(),
                    ),
                );
            });
        });
    }

    #[test]
    fn test_opened_auth_check_fail() {
        let n = 25;

        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        writeln!(f, "127.0.0.1:{}", port + 1).unwrap();
        let filename = f.path().to_str().unwrap();

        let result = std::panic::catch_unwind(|| {
            rayon::scope(|s| {
                // party 0
                s.spawn(move |_| {
                    let mut net = Net::init_from_file(filename, 0);
                    let mut state = DummyArithCircPrep::<Fr>::new().run(&mut net, 1, n, 0, 0, 0);

                    let mut party0_auth_shares = generate_random_auth_shares(&mut state, n);
                    party0_auth_shares[0].value = party0_auth_shares[0].value + Fr::from(1);

                    let opened_values_shares = net.atomic_broadcast_vector(
                        &party0_auth_shares.iter().map(|s| s.value).collect(),
                    );
                    let opened_values: Vec<Fr> = reduce_columns_parallel(
                        &opened_values_shares,
                        || Fr::from(0),
                        |a, b| a + b,
                    );

                    OpenedAuthCheck::<Fr>::run(
                        &mut net,
                        &mut state,
                        (
                            opened_values,
                            party0_auth_shares.iter().map(|s| s.mac).collect(),
                        ),
                    );
                });
                // party 1
                s.spawn(move |_| {
                    let mut net = Net::init_from_file(filename, 1);
                    let mut state = DummyArithCircPrep::<Fr>::new().run(&mut net, 1, n, 0, 0, 0);

                    let party1_auth_shares = generate_random_auth_shares(&mut state, n);

                    let opened_values_shares = net.atomic_broadcast_vector(
                        &party1_auth_shares.iter().map(|s| s.value).collect(),
                    );
                    let opened_values: Vec<Fr> = reduce_columns_parallel(
                        &opened_values_shares,
                        || Fr::from(0),
                        |a, b| a + b,
                    );

                    OpenedAuthCheck::<Fr>::run(
                        &mut net,
                        &mut state,
                        (
                            opened_values,
                            party1_auth_shares.iter().map(|s| s.mac).collect(),
                        ),
                    );
                });
            });
        });
        assert!(result.is_err());
    }
}
