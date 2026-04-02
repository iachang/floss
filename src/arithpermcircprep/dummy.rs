use ark_ff::Field;

use crate::arithcircop::vector_input::VectorInput;
use crate::arithcircop::{ArithCircOp, ArithCircState};
use crate::arithpermcircop::{ArithPermCircState, ShuffleTuple, ShuffleVecType};
use crate::arithpermcircprep::{
    ArithPermCircPrep, ShuffleTupleInput, apply_k_to_shuffle_and_inverse_shuffle_tuples,
};
use crate::net::Net;
use crate::primitives::auth::AuthShare;
use crate::utils::rng_utils::{
    get_inverse_permutation_usize_option, get_random_rng, local_shuffle_vector,
    local_unshuffle_vector,
};
use crate::utils::testing_utils::generate_random_vector;

/// Dummy implementation of preprocessing for testing purposes
pub struct DummyArithPermCircPrep<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> DummyArithPermCircPrep<F> {
    /// Create a new dummy preprocessing instance
    pub fn new() -> Self {
        DummyArithPermCircPrep {
            _phantom: std::marker::PhantomData,
        }
    }

    /// Shuffle a vector given a shuffle
    pub fn shuffle_vector(&mut self, shuffle: &Option<ShuffleVecType>, vec: &mut Vec<F>) -> Vec<F> {
        let shuffle = shuffle.as_ref().unwrap();
        assert!(shuffle.len() == vec.len());
        local_shuffle_vector(shuffle, vec)
    }

    /// Unshuffle a vector given a shuffle
    pub fn unshuffle_vector(
        &mut self,
        shuffle: &Option<ShuffleVecType>,
        vec: &mut Vec<F>,
    ) -> Vec<F> {
        let shuffle = shuffle.as_ref().unwrap();
        assert!(shuffle.len() == vec.len());
        local_unshuffle_vector(shuffle, vec)
    }

    /// Generate shuffle tuples for a given shuffle tuple input
    pub fn generate_shuffle_tuples(
        &mut self,
        net: &mut Net,
        state: &mut ArithPermCircState<F>,
        shuffle_tuple: &ShuffleTupleInput,
    ) {
        let (shuffle_id, shuffle, n, num_shuffle_tuples) = (
            shuffle_tuple.shuffle_id.clone(),
            shuffle_tuple.shuffle.clone(),
            shuffle_tuple.n,
            shuffle_tuple.num_shuffle_tuples,
        );

        let permuter_id = if shuffle.is_some() {
            net.party_id()
        } else {
            1 - net.party_id()
        };

        let a_vectors: Vec<Vec<F>> = (0..num_shuffle_tuples)
            .map(|_| generate_random_vector(n))
            .collect();
        let b_vectors: Vec<Vec<F>> = (0..num_shuffle_tuples)
            .map(|_| generate_random_vector(n))
            .collect();
        let k_vals = if permuter_id == net.party_id() {
            Some(generate_random_vector(num_shuffle_tuples))
        } else {
            None
        };

        let shuffle_broadcasted = if net.party_id() == permuter_id {
            net.send_to_party(1 - permuter_id, &shuffle.clone().unwrap());
            shuffle.clone()
        } else {
            Some(net.recv_from_party::<Vec<usize>>(permuter_id))
        };

        let pa_vectors: Option<Vec<F>> = if 1 - net.party_id() == permuter_id {
            Some(
                a_vectors
                    .iter()
                    .map(|v| self.shuffle_vector(&shuffle_broadcasted, &mut v.clone()))
                    .flatten()
                    .collect::<Vec<F>>(),
            )
        } else {
            None
        };

        let pb_vectors: Option<Vec<F>> = if 1 - permuter_id == net.party_id() {
            Some(
                b_vectors
                    .iter()
                    .map(|v| self.shuffle_vector(&shuffle_broadcasted, &mut v.clone()))
                    .flatten()
                    .collect::<Vec<F>>(),
            )
        } else {
            None
        };

        let pa_inverse_vectors: Option<Vec<F>> = if 1 - permuter_id == net.party_id() {
            Some(
                a_vectors
                    .iter()
                    .map(|v| self.unshuffle_vector(&shuffle_broadcasted, &mut v.clone()))
                    .flatten()
                    .collect::<Vec<F>>(),
            )
        } else {
            None
        };
        let pb_inverse_vectors: Option<Vec<F>> = if 1 - permuter_id == net.party_id() {
            Some(
                b_vectors
                    .iter()
                    .map(|v| self.unshuffle_vector(&shuffle_broadcasted, &mut v.clone()))
                    .flatten()
                    .collect::<Vec<F>>(),
            )
        } else {
            None
        };

        let flattened_pa_share = VectorInput::<F>::run(
            net,
            state.inner_mut(),
            (1 - permuter_id, pa_vectors, Some(n * num_shuffle_tuples)),
        );
        let flattened_pb_share = VectorInput::<F>::run(
            net,
            state.inner_mut(),
            (1 - permuter_id, pb_vectors, Some(n * num_shuffle_tuples)),
        );

        let flattened_pa_share_inverse = VectorInput::<F>::run(
            net,
            state.inner_mut(),
            (
                1 - permuter_id,
                pa_inverse_vectors,
                Some(n * num_shuffle_tuples),
            ),
        );
        let flattened_pb_share_inverse = VectorInput::<F>::run(
            net,
            state.inner_mut(),
            (
                1 - permuter_id,
                pb_inverse_vectors,
                Some(n * num_shuffle_tuples),
            ),
        );

        let pa_share: Vec<Vec<AuthShare<F>>> = flattened_pa_share
            .chunks_exact(n)
            .map(|chunk| chunk.to_vec())
            .collect();
        let pb_share: Vec<Vec<AuthShare<F>>> = flattened_pb_share
            .chunks_exact(n)
            .map(|chunk| chunk.to_vec())
            .collect();
        let pa_share_inverse: Vec<Vec<AuthShare<F>>> = flattened_pa_share_inverse
            .chunks_exact(n)
            .map(|chunk| chunk.to_vec())
            .collect();
        let pb_share_inverse: Vec<Vec<AuthShare<F>>> = flattened_pb_share_inverse
            .chunks_exact(n)
            .map(|chunk| chunk.to_vec())
            .collect();

        let (shuffle_tuples_a, inverse_shuffle_tuples_a) =
            apply_k_to_shuffle_and_inverse_shuffle_tuples(
                permuter_id,
                pa_share.clone(),
                pa_share_inverse.clone(),
                state,
                net,
                k_vals.clone(),
            );
        let (shuffle_tuples_b, inverse_shuffle_tuples_b) =
            apply_k_to_shuffle_and_inverse_shuffle_tuples(
                permuter_id,
                pb_share.clone(),
                pb_share_inverse.clone(),
                state,
                net,
                k_vals,
            );
        state.push_multiple_shuffle_tuples(
            shuffle_id.clone(),
            shuffle_tuples_a
                .into_iter()
                .zip(shuffle_tuples_b.into_iter())
                .enumerate()
                .map(|(i, (st_a, st_b))| ShuffleTuple {
                    shuffle: shuffle.clone(),
                    tuples_a: st_a,
                    tuples_b: st_b,
                    a: if (1 - permuter_id) == net.party_id() {
                        Some(a_vectors[i].clone())
                    } else {
                        None
                    },
                    b: if (1 - permuter_id) == net.party_id() {
                        Some(b_vectors[i].clone())
                    } else {
                        None
                    },
                })
                .collect(),
        );
        state.push_multiple_shuffle_tuples(
            shuffle_id.clone() + "_inverse",
            inverse_shuffle_tuples_a
                .into_iter()
                .zip(inverse_shuffle_tuples_b.into_iter())
                .enumerate()
                .map(|(i, (inverse_st_a, inverse_st_b))| ShuffleTuple {
                    shuffle: get_inverse_permutation_usize_option(&shuffle.clone()),
                    tuples_a: inverse_st_a,
                    tuples_b: inverse_st_b,
                    a: if (1 - permuter_id) == net.party_id() {
                        Some(a_vectors[i].clone())
                    } else {
                        None
                    },
                    b: if (1 - permuter_id) == net.party_id() {
                        Some(b_vectors[i].clone())
                    } else {
                        None
                    },
                })
                .collect(),
        );
    }
}

impl<F: Field> ArithPermCircPrep<F> for DummyArithPermCircPrep<F> {
    fn run(
        &mut self,
        net: &mut Net,
        arith_circ_state: &mut ArithCircState<F>,
        shuffle_tuples: Vec<ShuffleTupleInput>,
    ) -> ArithPermCircState<F> {
        let shared_beta_alphabeta_share: AuthShare<F> = if net.am_king() {
            VectorInput::<F>::run(
                net,
                arith_circ_state,
                (0, Some(vec![F::rand(&mut get_random_rng())]), Some(1)),
            )[0]
        } else {
            VectorInput::<F>::run(net, arith_circ_state, (0, None, Some(1)))[0]
        };

        let alpha_share = arith_circ_state.key_share();
        let beta_share = shared_beta_alphabeta_share.value;
        let alpha_beta_share = shared_beta_alphabeta_share.mac;

        let inner = std::mem::take(arith_circ_state);

        // Create dummy key sharing
        let mut state = ArithPermCircState::new(inner, (alpha_share, beta_share, alpha_beta_share));

        shuffle_tuples
            .into_iter()
            .for_each(|st| self.generate_shuffle_tuples(net, &mut state, &st));

        state
    }
}
