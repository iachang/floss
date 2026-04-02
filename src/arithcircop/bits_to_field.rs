use ark_ff::Field;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};

use crate::{
    arithcircop::{
        ArithCircOp, ArithCircState, vector_mul::VectorMul, vector_neg::VectorNeg,
        vector_reveal::VectorReveal, vector_shift::VectorShift,
    },
    net::Net,
    primitives::auth::AuthShare,
};

/// Arithmetic circuit operations, vanilla SPDZ.
pub struct BitsToFieldReconstruct<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> BitsToFieldReconstruct<F> {
    /// Create a new ArithCircOp instance
    pub fn new() -> Self {
        BitsToFieldReconstruct {
            _phantom: std::marker::PhantomData,
        }
    }
}

/// Checks that the bits are correct and constructs the field share.
impl<F: Field> ArithCircOp<F> for BitsToFieldReconstruct<F> {
    type In = Vec<AuthShare<F>>;
    type Out = AuthShare<F>;

    fn run(net: &mut Net, state: &mut ArithCircState<F>, input: Self::In) -> Self::Out {
        let bits = input;
        let neg_bits = VectorNeg::<F>::run(net, state, bits.clone());
        let one_minus_bits = VectorShift::<F>::run(net, state, (neg_bits, F::one()));
        let eq = VectorMul::<F>::run(net, state, (bits.clone(), one_minus_bits));
        let z = VectorReveal::<F>::run(net, state, eq);

        assert!(z.iter().all(|z| z.is_zero()), "Vector Bit Check failed");

        bits.par_iter()
            .enumerate()
            .map(|(i, bit)| *bit * F::pow(&F::from(2), &[i as u64]))
            .reduce(
                || AuthShare {
                    value: F::zero(),
                    mac: F::zero(),
                },
                |a, b| a + b,
            )
    }
}
