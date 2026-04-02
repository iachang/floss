use ark_ff::Field;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

use crate::{
    arithcircop::{ArithCircOp, ArithCircState},
    net::Net,
};

/// Queues opened auth shares for the opened auth check operation upon Reveal
pub struct OpenedAuthQueue<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> OpenedAuthQueue<F> {
    /// Create a new OpenedAuthCheck instance
    pub fn new() -> Self {
        OpenedAuthQueue {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<F: Field> ArithCircOp<F> for OpenedAuthQueue<F> {
    type In = (Vec<F>, Vec<F>); //  opened values, auth shares
    type Out = ();

    fn run(_net: &mut Net, state: &mut ArithCircState<F>, input: Self::In) -> Self::Out {
        let (opened_values, auth_shares) = input;

        state.add_to_check_auth_shares(
            opened_values
                .par_iter()
                .zip(auth_shares.par_iter())
                .map(|(opened_value, auth_share)| (*opened_value, *auth_share))
                .collect::<Vec<(F, F)>>(),
        );
    }
}
