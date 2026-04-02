use ark_ff::Field;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

use crate::{
    arithcircop::{ArithCircOp, ArithCircState},
    net::Net,
    primitives::auth::AuthShare,
};

/// Shifts a vector of shares by a vector of constants.
pub struct VectorShiftByVector<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> VectorShiftByVector<F> {
    /// Create a new ArithCircOp instance
    pub fn new() -> Self {
        VectorShiftByVector {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<F: Field> ArithCircOp<F> for VectorShiftByVector<F> {
    type In = (Vec<AuthShare<F>>, Vec<F>);
    type Out = Vec<AuthShare<F>>;

    fn run(net: &mut Net, state: &mut ArithCircState<F>, input: Self::In) -> Self::Out {
        let (shares, offsets) = input;
        if net.am_king() {
            shares
                .par_iter()
                .zip(offsets.par_iter())
                .map(|(x, offset)| AuthShare {
                    value: x.value + offset,
                    mac: x.mac + state.key_share() * offset,
                })
                .collect()
        } else {
            shares
                .par_iter()
                .zip(offsets.par_iter())
                .map(|(x, offset)| AuthShare {
                    value: x.value,
                    mac: x.mac + state.key_share() * offset,
                })
                .collect()
        }
    }
}
