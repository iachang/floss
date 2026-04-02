use ark_ff::Field;

use crate::{net::Net, primitives::auth::AuthShare};

/// Vector add operation
pub mod vector_add;

/// Vector subtract operation
pub mod vector_sub;

/// Vector negate operation
pub mod vector_neg;

/// Vector multiplicative inverse operation
pub mod vector_invert;

/// Input vector of values operation
pub mod vector_input;

/// Reshare operation
// pub mod reshare;
/// Reveal a vector of auth shares
pub mod vector_reveal;

/// Opened Auth Check operation
pub mod opened_auth_check;

/// Opened Auth Queue operation
pub mod opened_auth_queue;

/// Unauthenticated multiplication operation
pub mod unauth_mul;

/// Vector multiplication operation
pub mod vector_mul;

/// Vector scale operation
pub mod vector_scale;

/// Vector scale by vector operation
pub mod vector_scale_by_vector;

/// Vector shift by vector operation
pub mod vector_shift_by_vector;

/// Vector shift operation
pub mod vector_shift;

/// Bits to field operation
pub mod bits_to_field;

/// Type for authenticated triples
pub type AuthTriple<F> = (AuthShare<F>, AuthShare<F>, AuthShare<F>);

/// Type for unauthenticated triples
pub type UnauthTriple<F> = (F, F, F);

/// Struct for Arithmetic Circuit State
#[derive(Default)]
pub struct ArithCircState<F: Field> {
    key_share: F,
    auth_coins: Vec<AuthShare<F>>,
    triples: Vec<AuthTriple<F>>,
    unauth_triples: Vec<UnauthTriple<F>>,
    inversions: Vec<(AuthShare<F>, AuthShare<F>)>,
    to_check_auth_shares: Vec<(F, F)>, // (opened values, auth shares)
    triples_used: usize,
    coins_used: usize,
}

impl<F: Field> ArithCircState<F> {
    /// Create a new ArithCircState with the given key share
    pub fn new(key_share: F) -> Self {
        ArithCircState {
            key_share,
            auth_coins: Vec::new(),
            triples_used: 0,
            coins_used: 0,
            triples: Vec::new(),
            unauth_triples: Vec::new(),
            inversions: Vec::new(),
            to_check_auth_shares: Vec::new(),
        }
    }

    /// Change the key share for testing purposes.
    pub fn set_key_share(&mut self, key_share: F) {
        self.key_share = key_share;
    }

    /// Get the key share
    pub fn key_share(&self) -> F {
        self.key_share
    }

    /// Count number of triples used
    pub fn count_triples_used(&self) -> usize {
        self.triples_used
    }

    /// Count number of coins used
    pub fn count_coins(&self) -> usize {
        self.coins_used
    }

    /// Count number of unauthenticated triples used
    pub fn count_unauth_triples(&self) -> usize {
        self.unauth_triples.len()
    }

    /// Add authenticated coins to the state.
    pub fn add_auth_coins(&mut self, coins: impl IntoIterator<Item = AuthShare<F>>) {
        self.auth_coins.extend(coins);
    }

    /// Take n authenticated coins from the state.
    pub fn take_auth_coins(&mut self, n: usize) -> Vec<AuthShare<F>> {
        self.coins_used += n;
        (0..n)
            .map(|_| self.auth_coins.pop().expect("No auth coin left"))
            .collect()
    }

    /// Add authenticated triples to the state.
    pub fn add_triples(
        &mut self,
        triples: impl IntoIterator<Item = (AuthShare<F>, AuthShare<F>, AuthShare<F>)>,
    ) {
        self.triples.extend(triples);
    }

    /// Take n authenticated triples from the state.
    pub fn take_triples(&mut self, n: usize) -> Vec<(AuthShare<F>, AuthShare<F>, AuthShare<F>)> {
        self.triples_used += n;
        (0..n)
            .map(|_| self.triples.pop().expect("No auth triple left"))
            .collect()
    }

    /// Add unauthenticated triples to the state.
    pub fn add_unauth_triples(&mut self, triples: impl IntoIterator<Item = (F, F, F)>) {
        self.unauth_triples.extend(triples);
    }

    /// Take n unauthenticated triples from the state.
    pub fn take_unauth_triples(&mut self, n: usize) -> Vec<(F, F, F)> {
        (0..n)
            .map(|_| self.unauth_triples.pop().expect("No unauth triple left"))
            .collect()
    }

    /// Add inversion pairs to the state.
    pub fn add_inversions(
        &mut self,
        inversions: impl IntoIterator<Item = (AuthShare<F>, AuthShare<F>)>,
    ) {
        self.inversions.extend(inversions);
    }

    /// Take n inversion pairs from the state.
    pub fn take_inversions(&mut self, n: usize) -> Vec<(AuthShare<F>, AuthShare<F>)> {
        (0..n)
            .map(|_| self.inversions.pop().expect("No inversion left"))
            .collect()
    }

    /// Add an authenticated share to the list of shares to check.
    pub fn push_to_check_auth_share(&mut self, to_check_opened_auth: (F, F)) {
        self.to_check_auth_shares.push(to_check_opened_auth);
    }

    /// Add authenticated shares to the list of shares to check.
    pub fn add_to_check_auth_shares(
        &mut self,
        to_check_opened_auths: impl IntoIterator<Item = (F, F)>,
    ) {
        self.to_check_auth_shares.extend(to_check_opened_auths);
    }

    /// Take all opened auth sharesfrom the list of shares to check.
    pub fn drain_to_check_auth_shares(&mut self) -> Vec<(F, F)> {
        self.to_check_auth_shares.drain(..).collect()
    }
}

/// Trait for operations on arithmetic circuits
pub trait ArithCircOp<F: Field> {
    /// The input type for the operation    .
    type In;
    /// The output type for the operation.
    type Out;

    /// Run the operation.
    fn run(net: &mut Net, state: &mut ArithCircState<F>, input: Self::In) -> Self::Out;
}
