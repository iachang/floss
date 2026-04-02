use ark_ff::Field;

use crate::{
    arithcircop::{ArithCircOp, opened_auth_queue::OpenedAuthQueue},
    arithpermcircop::{
        ArithPermCircOp, ArithPermCircState, exec_blind_auth_check::ExecBlindAuthCheck,
    },
    net::Net,
    primitives::auth::AuthShare,
    utils::vector_utils::reduce_columns_parallel,
};

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

impl<F: Field> ArithPermCircOp<F> for VectorReveal<F> {
    type In = Vec<AuthShare<F>>;
    type Out = Vec<F>;

    fn run(net: &mut Net, state: &mut ArithPermCircState<F>, input: Self::In) -> Self::Out {
        let shares = input;
        let vals: Vec<Vec<F>> =
            net.atomic_broadcast_vector(&shares.iter().map(|s: &AuthShare<F>| s.value).collect());
        let x: Vec<F> = reduce_columns_parallel(&vals, || F::zero(), |a, b| a + b);

        // Queue revealed vector first into the opened auth queue.
        let (opened_values, auth_shares): (Vec<F>, Vec<F>) = x
            .iter()
            .zip(shares.iter())
            .map(|(x, s)| (*x, s.mac))
            .unzip();
        OpenedAuthQueue::<F>::run(net, state.inner_mut(), (opened_values, auth_shares));

        // Perform an opened auth check over opened input.
        ExecBlindAuthCheck::<F>::run(net, state, ());

        x
    }
}
