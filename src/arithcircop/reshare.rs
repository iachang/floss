use ark_ff::Field;

use crate::{
    arithcircop::{ArithCircOp, ArithCircState},
    net::Net,
    primitives::auth::AuthShare,
};

/// Reshare an authenticated share.
pub struct Reshare<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> Reshare<F> {
    /// Create a new Reshare instance
    pub fn new() -> Self {
        Reshare {
            _phantom: std::marker::PhantomData,
        }
    }
}

/// Reshares an authenticated input `input` from `party`.
/// Consumes a random coin.
impl<F: Field> ArithCircOp<F> for Reshare<F> {
    type In = (usize, Option<AuthShare<F>>);
    type Out = AuthShare<F>;

    fn run(net: &mut Net, state: &mut ArithCircState<F>, input: Self::In) -> Self::Out {
        let (inputting_party, input) = input;

        let mask_share = state.take_auth_coins(1)[0];
        let mask = net
            .all_send_to_party(inputting_party, &mask_share)
            .map(|shares| shares.into_iter().sum::<AuthShare<F>>());

        let shift = net.all_recv_from_party(
            inputting_party,
            mask.map(|m| vec![input.unwrap() - m; net.n_parties()]),
        );

        if net.am_king() {
            mask_share + shift
        } else {
            mask_share
        }
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
    fn test_reshare() {
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

        let sharing_party = 0;
        let output_shared = std::sync::Arc::new(std::sync::Mutex::new(output));

        rayon::scope(|s| {
            // party 0
            let output_party0 = output_shared.clone();
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 0);
                let mut state = DummyArithCircPrep::<Fr>::new().run(&mut net, 0, 1, 0, 0, 0);
                let output_temp_p0 = Reshare::<Fr>::run(
                    &mut net,
                    &mut state,
                    (
                        sharing_party,
                        Some(AuthShare {
                            value: value,
                            mac: state.key_share() * value,
                        }),
                    ),
                );
                {
                    let mut output_guard = output_party0.lock().unwrap();
                    *output_guard = *output_guard + output_temp_p0;
                }
            });
            // party 1
            let output_party1 = output_shared.clone();
            s.spawn(move |_| {
                let mut net = Net::init_from_file(filename, 1);
                let mut state = DummyArithCircPrep::<Fr>::new().run(&mut net, 0, 1, 0, 0, 0);
                let output_temp_p1 =
                    Reshare::<Fr>::run(&mut net, &mut state, (sharing_party, None));
                {
                    let mut output_guard = output_party1.lock().unwrap();
                    *output_guard = *output_guard + output_temp_p1;
                }
            });
        });
        output = *output_shared.lock().unwrap();

        let expected = AuthShare {
            value: value,
            mac: mac_share,
        };
        assert_eq!(output, expected);
    }
}
