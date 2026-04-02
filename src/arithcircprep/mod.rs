use crate::arithcircop::ArithCircState;
use crate::net::Net;
use ark_ff::Field;

/// Trait for general arithmetic circuit preprocessing schemes.
pub trait ArithCircPrep<F: Field> {
    /// Preprocesses a given number of auth coins, unauth triples, and auth triples for some key.
    /// Returns the preprocessing outputs.
    fn run(
        &mut self,
        net: &mut Net,
        n_unauth_coins: usize,
        n_auth_coins: usize,
        n_unauth_triples: usize,
        n_auth_triples: usize,
        n_inversions: usize,
    ) -> ArithCircState<F>;
}

/// Dummy implementation of preprocessing for testing purposes
pub mod dummy;

/// Real SPDZ preprocessing
pub mod spdz;
