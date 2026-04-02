use ark_ff::Field;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

use crate::{
    arithcircop::{ArithCircOp, ArithCircState},
    net::Net,
    primitives::auth::AuthShare,
};

/// Shifts a vector of shares by a vector of constants.
pub struct VectorNeg<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> VectorNeg<F> {
    /// Create a new ArithCircOp instance
    pub fn new() -> Self {
        VectorNeg {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<F: Field> ArithCircOp<F> for VectorNeg<F> {
    type In = Vec<AuthShare<F>>;
    type Out = Vec<AuthShare<F>>;

    fn run(_net: &mut Net, _state: &mut ArithCircState<F>, input: Self::In) -> Self::Out {
        let a = input;
        a.par_iter().map(|x| *x * F::one().neg()).collect()
    }
}

#[cfg(test)]
mod test {
    use crate::{
        arithcircop::vector_add::VectorAdd,
        arithcircprep::{ArithCircPrep, dummy::DummyArithCircPrep},
        utils::rng_utils::get_random_rng,
    };
    use ark_ff::UniformRand;
    use rand::Rng;
    use std::io::Write;
    use tempfile::NamedTempFile;

    use ark_std::Zero;

    use super::*;
    type Fr = crate::bench::Mersenne128Fq;

    #[test]
    fn test_vector_neg() {
        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        let filename = f.path().to_str().unwrap();
        let mut net = Net::init_from_file(filename, 0);

        let mut state = DummyArithCircPrep::<Fr>::new().run(&mut net, 0, 0, 0, 0, 0);
        let a = vec![AuthShare {
            value: Fr::rand(&mut get_random_rng()),
            mac: Fr::rand(&mut get_random_rng()),
        }];
        let neg_a = VectorNeg::<Fr>::run(&mut net, &mut state, a.clone());
        let output = VectorAdd::<Fr>::run(&mut net, &mut state, (a, neg_a));
        assert_eq!(
            output,
            vec![AuthShare {
                value: Fr::zero(),
                mac: Fr::zero(),
            }]
        );
    }
}
