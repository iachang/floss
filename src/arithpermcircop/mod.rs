use ark_ff::Field;
use std::collections::{HashMap, VecDeque};

use crate::{
    arithcircop::ArithCircState,
    net::Net,
    primitives::auth::{AuthShare, KAuthShare},
};

/// ApplyPerm operation
pub mod apply_perm;

/// UnapplyPerm operation
pub mod unapply_perm;

/// Shuffle operation
pub mod shuffle;
/// Sort operation (Asharov et. al)
pub mod sort;

/// Queues blinded auth shares for blind auth check operation
pub mod blind_auth_queue;
/// Queues blind auth checks for opened auth check operation
pub mod blind_auth_to_opened_auth_queue;

/// Executes the blind auth check operation
pub mod exec_blind_auth_check;

/// Reveal the data in `share` to all parties.
/// Checks that the MACs are correct and drains the blind auth checks.
pub mod vector_reveal;

/// Permutation network shuffle operation
pub mod perm_network_shuffle;

/// Simple log(n) round implementation of permutation network shuffle
pub mod simple_perm_net_shuffle;

/// Struct for a shuffle tuple
#[derive(Clone)]
pub struct ShuffleTuple<F: Field> {
    /// The shuffle permutation
    pub shuffle: Option<ShuffleVecType>, // Some for permuter
    /// The tuples for the first party
    pub tuples_a: Vec<KAuthShare<F>>, // K is Some for permuter
    /// The tuples for the second party
    pub tuples_b: Vec<KAuthShare<F>>, // K is Some for permuter
    /// The input for the first party
    pub a: Option<Vec<F>>, // Some for non-permuter
    /// The input for the second party
    pub b: Option<Vec<F>>, // Some for non-permuter
}

/// Struct for a shuffle tuple
#[derive(Clone)]
pub struct ShuffleTupleTest<F: Field> {
    /// The shuffle permutation
    pub shuffle: Option<ShuffleVecType>, // Some for permuter
    /// The tuples for the first party
    pub tuples_a: Vec<AuthShare<F>>, // K is Some for permuter
    /// The tuples for the second party
    pub tuples_b: Vec<AuthShare<F>>, // K is Some for permuter
    /// The input for the first party
    pub a: Option<Vec<F>>, // Some for non-permuter
    /// The input for the second party
    pub b: Option<Vec<F>>, // Some for non-permuter
}

/// Struct for Arithmetic Circuit State
#[derive(Default)]
pub struct ArithPermCircState<F: Field> {
    inner: ArithCircState<F>,
    key_share: (F, F, F),
    to_check_blind_auth_shares: Vec<AuthShare<F>>, // (opened values, auth shares)
    shuffle_tuples: HashMap<String, VecDeque<ShuffleTuple<F>>>, // Shuffle tuples for each shuffle id
}

/// Type for the shuffle vector
pub type ShuffleVecType = Vec<usize>;

impl<F: Field> ArithPermCircState<F> {
    /// Create a new ArithPermCircState with the given inner ArithCircState
    pub fn new(inner: ArithCircState<F>, key_share: (F, F, F)) -> Self {
        ArithPermCircState {
            inner,
            key_share,
            to_check_blind_auth_shares: Vec::new(),
            shuffle_tuples: HashMap::new(),
        }
    }

    /// Get the key share
    pub fn key_share(&self) -> (F, F, F) {
        self.key_share
    }

    /// Get mutable access to the inner ArithCircState
    pub fn inner_mut(&mut self) -> &mut ArithCircState<F> {
        &mut self.inner
    }

    /// Push shuffle tuples to the list of shuffle tuples.
    pub fn push_shuffle_tuples(
        &mut self,
        shuffle_id: String,
        shuffle: Option<ShuffleVecType>,
        shuffle_tuples_a: Vec<KAuthShare<F>>,
        shuffle_tuples_b: Vec<KAuthShare<F>>,
        a: Option<Vec<F>>,
        b: Option<Vec<F>>,
    ) {
        self.shuffle_tuples
            .entry(shuffle_id)
            .or_insert_with(|| VecDeque::new())
            .push_back(ShuffleTuple {
                shuffle,
                tuples_a: shuffle_tuples_a,
                tuples_b: shuffle_tuples_b,
                a,
                b,
            });
    }

    /// Push multiple shuffle tuples to the list of shuffle tuples.
    pub fn push_multiple_shuffle_tuples(
        &mut self,
        shuffle_id: String,
        shuffle_tuples: Vec<ShuffleTuple<F>>,
    ) {
        self.shuffle_tuples
            .entry(shuffle_id)
            .or_insert_with(|| VecDeque::new())
            .extend(shuffle_tuples);
    }

    /// Pop a shuffle tuple from the list of shuffle tuples.
    pub fn pop_shuffle_tuple(&mut self, shuffle_id: String) -> ShuffleTuple<F> {
        let queue = self.shuffle_tuples.get_mut(&shuffle_id).expect(&format!(
            "No shuffle tuple {} created with this id",
            shuffle_id
        ));
        queue
            .pop_front()
            .expect(&format!("No shuffle tuple {} left", shuffle_id))
    }

    /// Take n shuffle tuples from the list of shuffle tuples.
    pub fn take_shuffle_tuples(&mut self, shuffle_id: String, n: usize) -> Vec<ShuffleTuple<F>> {
        let queue = self.shuffle_tuples.get_mut(&shuffle_id).expect(&format!(
            "No shuffle tuple {} created with this id",
            shuffle_id
        ));

        (0..n)
            .map(|_| {
                queue
                    .pop_front()
                    .expect(&format!("No shuffle tuple {} left", shuffle_id))
            })
            .collect()
    }

    /// Add an authenticated share to the list of shares to check.
    pub fn push_to_check_blind_auth_share(&mut self, to_check_blind_auth_share: AuthShare<F>) {
        self.to_check_blind_auth_shares
            .push(to_check_blind_auth_share);
    }

    /// Add authenticated shares to the list of shares to check.
    pub fn add_to_check_blind_auth_shares(
        &mut self,
        to_check_blind_auth_shares: impl IntoIterator<Item = AuthShare<F>>,
    ) {
        self.to_check_blind_auth_shares
            .extend(to_check_blind_auth_shares);
    }

    /// Take all opened auth sharesfrom the list of shares to check.
    pub fn drain_to_check_blind_auth_shares(&mut self) -> Vec<AuthShare<F>> {
        self.to_check_blind_auth_shares.drain(..).collect()
    }
}

/// Trait for operations on arithmetic circuits
pub trait ArithPermCircOp<F: Field> {
    /// The input type for the operation    .
    type In;
    /// The output type for the operation.
    type Out;

    /// Run the operation.
    fn run(net: &mut Net, state: &mut ArithPermCircState<F>, input: Self::In) -> Self::Out;
}
