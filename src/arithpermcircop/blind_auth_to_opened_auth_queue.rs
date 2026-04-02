use crate::{
    arithcircop::{ArithCircOp, opened_auth_queue::OpenedAuthQueue},
    arithpermcircop::{ArithPermCircOp, ArithPermCircState},
    net::Net,
    primitives::auth::AuthShare,
    utils::rng_utils::get_random_rng,
};
use ark_ff::Field;
use rayon::prelude::*;
/// Queues blinded auth shares for the opened auth check operation upon Reveal
pub struct BlindAuthToOpenedAuthQueue<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> BlindAuthToOpenedAuthQueue<F> {
    /// Create a new OpenedAuthCheck instance
    pub fn new() -> Self {
        BlindAuthToOpenedAuthQueue {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<F: Field> ArithPermCircOp<F> for BlindAuthToOpenedAuthQueue<F> {
    type In = Vec<AuthShare<F>>; // auth shares to check
    type Out = ();

    fn run(net: &mut Net, state: &mut ArithPermCircState<F>, input: Self::In) -> Self::Out {
        let mut auth_shares = input;

        let key_share = state.key_share();

        // Step 1: Parse input and generate coins andchallenges
        auth_shares.push(AuthShare {
            value: key_share.1,
            mac: key_share.2,
        });
        let n = auth_shares.len();

        // Step 2: Generate coin and challenge
        let coin: AuthShare<F> = state.inner_mut().take_auth_coins(1)[0];
        let challenge_share: F = F::rand(&mut get_random_rng());
        let challenge: F = net.atomic_broadcast(&challenge_share).iter().sum();

        // Step 3: Compute shares of t and shares of at
        // Pre-compute challenge powers once

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

        let (t_sum, at_sum): (F, F) = (0..n)
            .into_par_iter()
            .map(|i| {
                (
                    challenge_powers[i] * auth_shares[i].value,
                    challenge_powers[i] * auth_shares[i].mac,
                )
            })
            .reduce(
                || (F::zero(), F::zero()),
                |(a1, a2), (b1, b2)| (a1 + b1, a2 + b2),
            );

        let t_share = t_sum + coin.value * F::from(n as u64);
        let at_share = at_sum + coin.mac * F::from(n as u64);

        // Step 4: Broadcast shares of t to compute t
        let opened_t: F = net.atomic_broadcast(&t_share).iter().sum();

        // Step 5: Queue for opened auth check on the blinded secret shared inputs
        let result =
            OpenedAuthQueue::<F>::run(net, state.inner_mut(), (vec![opened_t], vec![at_share]));
        result
    }
}

#[cfg(test)]
mod test {
    use rand::Rng;

    use crate::{
        arithcircop::{ArithCircOp, opened_auth_check::OpenedAuthCheck},
        arithcircprep::{ArithCircPrep, dummy::DummyArithCircPrep},
        arithpermcircop::{
            ArithPermCircOp, blind_auth_to_opened_auth_queue::BlindAuthToOpenedAuthQueue,
        },
        arithpermcircprep::{ArithPermCircPrep, dummy::DummyArithPermCircPrep},
        net::Net,
        utils::testing_utils::generate_random_auth_shares,
    };

    use std::io::Write;
    use tempfile::NamedTempFile;
    type Fr = crate::bench::Mersenne128Fq;

    #[test]
    fn test_blind_auth_check() {
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

                let mut state = DummyArithCircPrep::<Fr>::new().run(&mut net, 5, n + 2, 0, 0, 0);

                let party0_auth_shares = generate_random_auth_shares(&mut state, n);

                let mut arith_perm_circ_state =
                    DummyArithPermCircPrep::<Fr>::new().run(&mut net, &mut state, vec![]);

                BlindAuthToOpenedAuthQueue::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    party0_auth_shares.clone(),
                );

                // Flushing the auth share check queue should pass
                let to_check_auth_shares = arith_perm_circ_state
                    .inner_mut()
                    .drain_to_check_auth_shares();
                let (opened_values, auth_shares) = (
                    to_check_auth_shares
                        .iter()
                        .map(|(opened_value, _)| *opened_value)
                        .collect(),
                    to_check_auth_shares
                        .iter()
                        .map(|(_, auth_share)| *auth_share)
                        .collect(),
                );
                OpenedAuthCheck::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state.inner_mut(),
                    (opened_values, auth_shares),
                );
            });
            // party 1
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);

                let mut state = DummyArithCircPrep::<Fr>::new().run(&mut net, 5, n + 2, 0, 0, 0);

                let party1_auth_shares = generate_random_auth_shares(&mut state, n);

                let mut arith_perm_circ_state =
                    DummyArithPermCircPrep::<Fr>::new().run(&mut net, &mut state, vec![]);
                BlindAuthToOpenedAuthQueue::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    party1_auth_shares.clone(),
                );

                // Flushing the auth share check queue should pass
                let to_check_auth_shares = arith_perm_circ_state
                    .inner_mut()
                    .drain_to_check_auth_shares();
                let (opened_values, auth_shares) = (
                    to_check_auth_shares
                        .iter()
                        .map(|(opened_value, _)| *opened_value)
                        .collect(),
                    to_check_auth_shares
                        .iter()
                        .map(|(_, auth_share)| *auth_share)
                        .collect(),
                );
                OpenedAuthCheck::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state.inner_mut(),
                    (opened_values, auth_shares),
                );
            });
        });
    }

    #[test]
    fn test_blind_auth_check_fail() {
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

                    let mut state =
                        DummyArithCircPrep::<Fr>::new().run(&mut net, 2, n + 2, 0, 0, 0);

                    let mut party0_auth_shares = generate_random_auth_shares(&mut state, n);
                    party0_auth_shares[0].value = party0_auth_shares[0].value + Fr::from(1);

                    let mut arith_perm_circ_state =
                        DummyArithPermCircPrep::<Fr>::new().run(&mut net, &mut state, vec![]);

                    BlindAuthToOpenedAuthQueue::<Fr>::run(
                        &mut net,
                        &mut arith_perm_circ_state,
                        party0_auth_shares.clone(),
                    );

                    // Flushing the auth share check queue should fail
                    let to_check_auth_shares = arith_perm_circ_state
                        .inner_mut()
                        .drain_to_check_auth_shares();
                    let (opened_values, auth_shares) = (
                        to_check_auth_shares
                            .iter()
                            .map(|(opened_value, _)| *opened_value)
                            .collect(),
                        to_check_auth_shares
                            .iter()
                            .map(|(_, auth_share)| *auth_share)
                            .collect(),
                    );
                    OpenedAuthCheck::<Fr>::run(
                        &mut net,
                        &mut arith_perm_circ_state.inner_mut(),
                        (opened_values, auth_shares),
                    );
                });
                // party 1
                s.spawn(move |_| {
                    let mut net = Net::init_from_file(filename, 1);

                    let mut state =
                        DummyArithCircPrep::<Fr>::new().run(&mut net, 2, n + 2, 0, 0, 0);

                    let party1_auth_shares = generate_random_auth_shares(&mut state, n);

                    let mut arith_perm_circ_state =
                        DummyArithPermCircPrep::<Fr>::new().run(&mut net, &mut state, vec![]);

                    BlindAuthToOpenedAuthQueue::<Fr>::run(
                        &mut net,
                        &mut arith_perm_circ_state,
                        party1_auth_shares.clone(),
                    );

                    // Flushing the auth share check queue should fail
                    let to_check_auth_shares = arith_perm_circ_state
                        .inner_mut()
                        .drain_to_check_auth_shares();
                    let (opened_values, auth_shares) = (
                        to_check_auth_shares
                            .iter()
                            .map(|(opened_value, _)| *opened_value)
                            .collect(),
                        to_check_auth_shares
                            .iter()
                            .map(|(_, auth_share)| *auth_share)
                            .collect(),
                    );
                    OpenedAuthCheck::<Fr>::run(
                        &mut net,
                        &mut arith_perm_circ_state.inner_mut(),
                        (opened_values, auth_shares),
                    );
                });
            });
        });
        assert!(result.is_err());
    }
}
