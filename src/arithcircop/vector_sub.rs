use ark_ff::Field;

use crate::{
    arithcircop::{ArithCircOp, ArithCircState},
    net::Net,
    primitives::auth::AuthShare,
    utils::vector_utils::elementwise_ref,
};

/// Shifts a vector of shares by a vector of constants.
pub struct VectorSub<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> VectorSub<F> {
    /// Create a new ArithCircOp instance
    pub fn new() -> Self {
        VectorSub {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<F: Field> ArithCircOp<F> for VectorSub<F> {
    type In = (Vec<AuthShare<F>>, Vec<AuthShare<F>>);
    type Out = Vec<AuthShare<F>>;

    fn run(_net: &mut Net, _state: &mut ArithCircState<F>, input: Self::In) -> Self::Out {
        let (a, b) = input;
        elementwise_ref(&a, &b, |x, y| x - y)
    }
}
