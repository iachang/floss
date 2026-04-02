use ark_ff::Field;

use crate::{
    arithpermcircop::{ArithPermCircOp, ArithPermCircState},
    net::Net,
    primitives::auth::AuthShare,
};

/// Queues blinded auth shares for the blind auth check operation upon Reveal
pub struct BlindAuthQueue<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> BlindAuthQueue<F> {
    /// Create a new OpenedAuthCheck instance
    pub fn new() -> Self {
        BlindAuthQueue {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<F: Field> ArithPermCircOp<F> for BlindAuthQueue<F> {
    type In = Vec<AuthShare<F>>; // auth shares to check
    type Out = ();

    fn run(_net: &mut Net, state: &mut ArithPermCircState<F>, input: Self::In) -> Self::Out {
        let auth_shares = input;

        state.add_to_check_blind_auth_shares(auth_shares.iter().cloned());
    }
}
