use ark_ff::Field;

use crate::{
    arithcircop::{ArithCircOp, ArithCircState},
    net::Net,
};

/// Multiply two secret-share values.
pub struct UnauthMul<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> UnauthMul<F> {
    /// Create a new ArithCircOp instance
    pub fn new() -> Self {
        UnauthMul {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<F: Field> ArithCircOp<F> for UnauthMul<F> {
    type In = (F, F);
    type Out = F;

    fn run(net: &mut Net, state: &mut ArithCircState<F>, input: Self::In) -> Self::Out {
        let (a, b) = input;
        let (x, y, z) = state.take_unauth_triples(1)[0];
        let a_minus_x: F = net.atomic_broadcast(&(a - x)).iter().sum();
        let b_minus_y: F = net.atomic_broadcast(&(b - y)).iter().sum();

        let t = if net.am_king() {
            a_minus_x * b_minus_y
        } else {
            F::zero()
        };
        z + a_minus_x * y + b_minus_y * x + t
    }
}
