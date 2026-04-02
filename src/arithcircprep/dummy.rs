use crate::arithcircop::ArithCircState;
use crate::arithcircprep::ArithCircPrep;
use crate::net::Net;
use crate::primitives::auth::AuthShare;
use crate::utils::rng_utils::get_random_rng;
use crate::utils::vector_utils::{elementwise_ref, reduce_columns_parallel};
use ark_ff::Field;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

/// Dummy implementation of preprocessing for testing purposes
pub struct DummyArithCircPrep<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> DummyArithCircPrep<F> {
    /// Create a new dummy preprocessing instance
    pub fn new() -> Self {
        DummyArithCircPrep {
            _phantom: std::marker::PhantomData,
        }
    }
    ///  Generates n random coins.
    fn generate_coins(&mut self, _net: &mut Net, n: usize) -> Vec<F> {
        let coins: Vec<F> = (0..n)
            .into_par_iter()
            .map(|_| F::rand(&mut get_random_rng()))
            .collect();
        coins
    }

    fn generate_auth_coins(
        &mut self,
        _net: &mut Net,
        _key_share: F,
        n: usize,
    ) -> Vec<AuthShare<F>> {
        let auth_coins: Vec<AuthShare<F>> = (0..n)
            .into_par_iter()
            .map(|_i| AuthShare {
                value: F::from(0),
                mac: F::from(0),
            })
            .collect();
        auth_coins
    }

    // TODO: uncomment and re-add to preprocess_for for auth_coins if tests break here
    fn generate_shared_auth_values(
        &mut self,
        net: &mut Net,
        key_share: F,
        n: usize,
    ) -> Vec<AuthShare<F>> {
        let key_shares: Vec<F> = net.atomic_broadcast(&key_share);
        let key: F = key_shares.iter().sum();
        let coins = self.generate_coins(net, n);
        let auth_coins: Vec<AuthShare<F>> = coins
            .iter()
            .map(|c| AuthShare {
                value: *c,
                mac: key * c,
            })
            .collect();
        auth_coins
    }

    fn generate_unauth_triples(&mut self, net: &mut Net, n: usize) -> Vec<(F, F, F)> {
        let a_share_vector: Vec<F> = self.generate_coins(net, n);
        let b_share_vector: Vec<F> = self.generate_coins(net, n);

        let a_shares: Vec<Vec<F>> = net.atomic_broadcast_vector(&a_share_vector);
        let b_shares: Vec<Vec<F>> = net.atomic_broadcast_vector(&b_share_vector);

        let a: Vec<F> = reduce_columns_parallel(&a_shares, || F::zero(), |a, b| a + b);
        let b: Vec<F> = reduce_columns_parallel(&b_shares, || F::zero(), |a, b| a + b);
        let c: Vec<F> = elementwise_ref(&a, &b, |a, b| a * b);

        let mask_shares: Vec<F> = if net.am_king() {
            vec![F::ZERO; n]
        } else {
            self.generate_coins(net, n)
        };

        let mask = net.all_send_vector_to_party(0, &mask_shares);
        let mask_sums: Vec<F> = mask
            .as_ref()
            .map(|m| reduce_columns_parallel(m, || F::zero(), |a, b| a + b))
            .unwrap_or_else(|| vec![F::ZERO; n]);
        let king_shares = elementwise_ref(&c, &mask_sums, |a, b| a - b);

        // Combine into tuples: (a_share, b_share, c_share)
        if net.am_king() {
            (0..n)
                .into_par_iter()
                .map(|i| (a_share_vector[i], b_share_vector[i], king_shares[i]))
                .collect()
        } else {
            (0..n)
                .into_par_iter()
                .map(|i| (a_share_vector[i], b_share_vector[i], mask_shares[i]))
                .collect()
        }
    }

    fn generate_auth_triples(
        &mut self,
        _net: &mut Net,
        _key_share: F,
        n: usize,
    ) -> Vec<(AuthShare<F>, AuthShare<F>, AuthShare<F>)> {
        let auth_triples: Vec<(AuthShare<F>, AuthShare<F>, AuthShare<F>)> = (0..n)
            .into_par_iter()
            .map(|_| {
                (
                    AuthShare {
                        value: F::from(0),
                        mac: F::from(0),
                    },
                    AuthShare {
                        value: F::from(0),
                        mac: F::from(0),
                    },
                    AuthShare {
                        value: F::from(0),
                        mac: F::from(0),
                    },
                )
            })
            .collect();
        dbg!("finished auth triples");
        auth_triples
    }

    fn generate_inversions(
        &mut self,
        net: &mut Net,
        key_share: F,
        n: usize,
    ) -> Vec<(AuthShare<F>, AuthShare<F>)> {
        let auth_coins = self.generate_shared_auth_values(net, key_share, n);
        let inversions: Vec<(AuthShare<F>, AuthShare<F>)> = auth_coins
            .iter()
            .map(|c| {
                (
                    AuthShare {
                        value: c.value,
                        mac: c.mac,
                    },
                    AuthShare {
                        value: c.value.inverse().unwrap(),
                        mac: c.mac.inverse().unwrap(),
                    },
                )
            })
            .collect();
        inversions
    }
}
impl<F: Field> ArithCircPrep<F> for DummyArithCircPrep<F> {
    fn run(
        &mut self,
        net: &mut Net,
        _n_unauth_coins: usize,
        n_auth_coins: usize,
        n_unauth_triples: usize,
        n_auth_triples: usize,
        n_inversions: usize,
    ) -> ArithCircState<F> {
        let mut state = ArithCircState::new(F::rand(&mut get_random_rng()));
        state.add_triples(self.generate_auth_triples(net, state.key_share(), n_auth_triples));
        state.add_auth_coins(self.generate_auth_coins(net, state.key_share(), n_auth_coins));
        state.add_unauth_triples(self.generate_unauth_triples(net, n_unauth_triples));
        state.add_inversions(self.generate_inversions(net, state.key_share(), n_inversions));
        state
    }
}
