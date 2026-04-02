use ark_ff::Field;

use crate::{
    arithcircop::{ArithCircOp, ArithCircState},
    net::Net,
    primitives::auth::AuthShare,
    utils::vector_utils::elementwise_ref,
};

/// Shifts a vector of shares by a vector of constants.
pub struct VectorAdd<F: Field> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> VectorAdd<F> {
    /// Create a new ArithCircOp instance
    pub fn new() -> Self {
        VectorAdd {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<F: Field> ArithCircOp<F> for VectorAdd<F> {
    type In = (Vec<AuthShare<F>>, Vec<AuthShare<F>>);
    type Out = Vec<AuthShare<F>>;

    fn run(_net: &mut Net, _state: &mut ArithCircState<F>, input: Self::In) -> Self::Out {
        let (a, b) = input;
        elementwise_ref(&a, &b, |x, y| x + y)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_ff::UniformRand;
    use rand::Rng;
    use std::io::Write;
    use tempfile::NamedTempFile;
    type Fr = crate::bench::Mersenne128Fq;

    use crate::{
        arithcircprep::{ArithCircPrep, dummy::DummyArithCircPrep},
        utils::rng_utils::get_random_rng,
    };

    #[test]
    fn test_vector_add() {
        let v1 = vec![
            AuthShare {
                value: Fr::rand(&mut get_random_rng()),
                mac: Fr::rand(&mut get_random_rng()),
            },
            AuthShare {
                value: Fr::rand(&mut get_random_rng()),
                mac: Fr::rand(&mut get_random_rng()),
            },
        ];
        let v2 = vec![
            AuthShare {
                value: Fr::rand(&mut get_random_rng()),
                mac: Fr::rand(&mut get_random_rng()),
            },
            AuthShare {
                value: Fr::rand(&mut get_random_rng()),
                mac: Fr::rand(&mut get_random_rng()),
            },
        ];

        let mut f = NamedTempFile::new().unwrap();
        let port = 8000 + rand::rng().random_range(0..2000);
        writeln!(f, "127.0.0.1:{}", port).unwrap();
        let filename = f.path().to_str().unwrap();
        let mut net = Net::init_from_file(filename, 0);

        let mut state = DummyArithCircPrep::<Fr>::new().run(&mut net, 0, 0, 0, 0, 0);
        let expected_output = elementwise_ref(&v1, &v2, |a, b| a + b);

        let output = VectorAdd::<Fr>::run(&mut net, &mut state, (v1, v2));
        assert_eq!(output, expected_output);
    }
}
