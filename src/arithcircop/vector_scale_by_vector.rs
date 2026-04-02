use ark_ff::Field;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

use crate::{
    arithcircop::{ArithCircOp, ArithCircState},
    net::Net,
    primitives::auth::AuthShare,
};

/// Multiplies a vector of shares by a constant.
pub struct VectorScaleByVector<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> VectorScaleByVector<F> {
    /// Create a new ArithCircOp instance
    pub fn new() -> Self {
        VectorScaleByVector {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<F: Field> ArithCircOp<F> for VectorScaleByVector<F> {
    type In = (Vec<AuthShare<F>>, Vec<F>);
    type Out = Vec<AuthShare<F>>;

    fn run(_net: &mut Net, _state: &mut ArithCircState<F>, input: Self::In) -> Self::Out {
        let (shares, offsets) = input;
        shares
            .par_iter()
            .zip(offsets.par_iter())
            .map(|(x, offset)| *x * *offset)
            .collect()
    }
}
