use ark_ff::Field;

use crate::{
    arithcircop::ArithCircState, primitives::auth::AuthShare, utils::rng_utils::get_random_rng,
};

/// Generates a vector of random elements of type F
pub fn generate_random_vector<F: Field>(n: usize) -> Vec<F> {
    let mut rng = get_random_rng();
    (0..n).map(|_| F::rand(&mut rng)).collect()
}

/// Generates a vector of random authenticated shares, given the key
pub fn generate_random_auth_shares<F: Field>(
    state: &mut ArithCircState<F>,
    n: usize,
) -> Vec<AuthShare<F>> {
    state.take_auth_coins(n)
}
