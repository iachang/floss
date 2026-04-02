use ark_ff::Field;

use crate::{
    arithcircop::ArithCircOp,
    arithcircop::opened_auth_check::OpenedAuthCheck,
    arithpermcircop::{
        ArithPermCircOp, ArithPermCircState,
        blind_auth_to_opened_auth_queue::BlindAuthToOpenedAuthQueue,
    },
    net::Net,
};

/// Clears all blind auth checks and combines them into an opened auth check, then clears and checks all remaining auth checks
pub struct ExecBlindAuthCheck<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> ExecBlindAuthCheck<F> {
    /// Create a new ExecBlindAuthCheck instance
    pub fn new() -> Self {
        ExecBlindAuthCheck {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<F: Field> ArithPermCircOp<F> for ExecBlindAuthCheck<F> {
    type In = (); // key share
    type Out = bool;

    fn run(net: &mut Net, state: &mut ArithPermCircState<F>, _input: Self::In) -> Self::Out {
        // Clear all blind auth checks into opened auth queue.
        let to_check_blind_auth_shares = state.drain_to_check_blind_auth_shares();
        BlindAuthToOpenedAuthQueue::<F>::run(net, state, to_check_blind_auth_shares);
        // Perform an auth check over opened input.
        let to_check_auth_shares = state.inner_mut().drain_to_check_auth_shares();
        let (opened_values, auth_shares): (Vec<F>, Vec<F>) = to_check_auth_shares
            .iter()
            .map(|(opened_value, auth_share)| (*opened_value, *auth_share))
            .unzip();
        let result =
            OpenedAuthCheck::<F>::run(net, state.inner_mut(), (opened_values, auth_shares));

        result
    }
}

#[cfg(test)]
mod test {
    use rand::Rng;

    use crate::{
        arithcircprep::{ArithCircPrep, dummy::DummyArithCircPrep},
        arithpermcircop::{
            ArithPermCircOp, blind_auth_queue::BlindAuthQueue,
            exec_blind_auth_check::ExecBlindAuthCheck,
        },
        arithpermcircprep::{ArithPermCircPrep, dummy::DummyArithPermCircPrep},
        net::Net,
        utils::testing_utils::generate_random_auth_shares,
    };

    use std::io::Write;
    use tempfile::NamedTempFile;
    type Fr = crate::bench::Mersenne128Fq;

    #[test]
    fn test_exec_blind_auth_check() {
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

                BlindAuthQueue::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    party0_auth_shares.clone(),
                );
                ExecBlindAuthCheck::<Fr>::run(&mut net, &mut arith_perm_circ_state, ());
            });
            // party 1
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);

                let mut state = DummyArithCircPrep::<Fr>::new().run(&mut net, 5, n + 2, 0, 0, 0);

                let party1_auth_shares = generate_random_auth_shares(&mut state, n);

                let mut arith_perm_circ_state =
                    DummyArithPermCircPrep::<Fr>::new().run(&mut net, &mut state, vec![]);
                BlindAuthQueue::<Fr>::run(
                    &mut net,
                    &mut arith_perm_circ_state,
                    party1_auth_shares.clone(),
                );
                ExecBlindAuthCheck::<Fr>::run(&mut net, &mut arith_perm_circ_state, ());
            });
        });
    }

    #[test]
    fn test_exec_blind_auth_check_fail() {
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

                    BlindAuthQueue::<Fr>::run(
                        &mut net,
                        &mut arith_perm_circ_state,
                        party0_auth_shares.clone(),
                    );
                    ExecBlindAuthCheck::<Fr>::run(&mut net, &mut arith_perm_circ_state, ());
                });
                // party 1
                s.spawn(move |_| {
                    let mut net = Net::init_from_file(filename, 1);

                    let mut state =
                        DummyArithCircPrep::<Fr>::new().run(&mut net, 2, n + 2, 0, 0, 0);

                    let party1_auth_shares = generate_random_auth_shares(&mut state, n);

                    let mut arith_perm_circ_state =
                        DummyArithPermCircPrep::<Fr>::new().run(&mut net, &mut state, vec![]);

                    BlindAuthQueue::<Fr>::run(
                        &mut net,
                        &mut arith_perm_circ_state,
                        party1_auth_shares.clone(),
                    );
                    ExecBlindAuthCheck::<Fr>::run(&mut net, &mut arith_perm_circ_state, ());
                });
            });
        });
        assert!(result.is_err());
    }
}
