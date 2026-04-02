use ark_ff::Field;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

use crate::{
    arithcircop::{ArithCircOp, ArithCircState},
    net::Net,
    primitives::auth::AuthShare,
};

/// Multiplies a vector of shares by a constant.
pub struct VectorScale<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> VectorScale<F> {
    /// Create a new ArithCircOp instance
    pub fn new() -> Self {
        VectorScale {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<F: Field> ArithCircOp<F> for VectorScale<F> {
    type In = (Vec<AuthShare<F>>, F);
    type Out = Vec<AuthShare<F>>;

    fn run(_net: &mut Net, _state: &mut ArithCircState<F>, input: Self::In) -> Self::Out {
        let (shares, offset) = input;
        shares.par_iter().map(|x| *x * offset).collect()
    }
}
