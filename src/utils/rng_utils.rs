use ark_ff::Field;
use ark_std::rand::Rng;
use ark_std::rand::prelude::SliceRandom;
use ark_std::rand::{SeedableRng, rngs::StdRng};
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::arithpermcircop::ShuffleVecType;

/// Get a random RNG seeded by time
pub fn get_random_rng() -> StdRng {
    let time_seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    StdRng::from_seed([time_seed as u8; 32])
}

/// Get a pseduo-random RNG seeded by a given seed
pub fn get_seeded_rng(seed: u64) -> StdRng {
    StdRng::from_seed([seed as u8; 32])
}

/// Get a random field element
pub fn get_random_field<F: Field>() -> F {
    let mut rng = get_random_rng();
    F::rand(&mut rng)
}

/// Get a vector of random elements of type F, seeded by a given seed to ensure consistency
pub fn get_random_vector<F: Field>(seed: u64, n: usize) -> Vec<F> {
    let mut rng = get_seeded_rng(seed);
    (0..n).map(|_| F::rand(&mut rng)).collect()
}

/// Get a vector of random elements of type F,bounded by range, seeded by a given seed to ensure consistency
pub fn get_random_vector_bounded<F: Field>(seed: u64, low: u64, high: u64, n: usize) -> Vec<F> {
    let mut rng = get_seeded_rng(seed);
    (0..n).map(|_| F::from(rng.gen_range(low..high))).collect()
}

/// Get a vector of random elements of type usize,bounded by range, seeded by a given seed to ensure consistency
pub fn get_random_vector_bounded_usize(seed: u64, low: usize, high: usize, n: usize) -> Vec<usize> {
    let mut rng = get_seeded_rng(seed);
    (0..n).map(|_| rng.gen_range(low..high)).collect()
}

/// Get a random permutation of length n
pub fn get_random_permutation<F: Field>(n: usize) -> Vec<F> {
    let mut rng = get_random_rng();
    let mut out = (0..n).map(|i| F::from(i as u64)).collect::<Vec<F>>();
    out.shuffle(&mut rng);
    out
}

/// Get a random permutation of length n
pub fn get_random_permutation_usize(n: usize) -> Vec<usize> {
    let mut rng = get_random_rng();
    let mut out = (0..n).map(|i| i as usize).collect::<Vec<usize>>();
    out.shuffle(&mut rng);
    out
}

/// Get the inverse shuffle of a given shuffle
pub fn get_inverse_permutation<F: Field>(permutation: &Vec<F>) -> Vec<F> {
    unshuffle_vector_testing(
        permutation,
        &(0..permutation.len())
            .map(|i| F::from(i as u64))
            .collect::<Vec<F>>(),
    )
}

/// Get the inverse permutation of a given permutation
pub fn get_inverse_permutation_usize(permutation: &ShuffleVecType) -> ShuffleVecType {
    local_unshuffle_vector(permutation, &(0..permutation.len()).collect::<Vec<usize>>())
}

/// Get the inverse permutation of a given permutation
pub fn get_inverse_permutation_option<F: Field>(permutation: &Option<Vec<F>>) -> Option<Vec<F>> {
    if permutation.is_none() {
        return None;
    }
    Some(get_inverse_permutation(&permutation.as_ref().unwrap()))
}

/// Get the inverse permutation of a given permutation
pub fn get_inverse_permutation_usize_option(
    permutation: &Option<ShuffleVecType>,
) -> Option<ShuffleVecType> {
    if permutation.is_none() {
        return None;
    }
    Some(get_inverse_permutation_usize(
        &permutation.as_ref().unwrap(),
    ))
}
/// Shuffle a vector using a permutation for testing
pub fn shuffle_vector_testing<F: Field, T: Clone>(shuffle: &Vec<F>, vec: &Vec<T>) -> Vec<T> {
    assert!(shuffle.len() == vec.len());
    let mut shuffled_vec = vec.clone();
    for i in 0..shuffle.len() {
        shuffled_vec[i] = vec[shuffle[i].to_string().parse::<usize>().unwrap()].clone();
    }
    shuffled_vec
}

/// Shuffle a vector using a permutation
pub fn local_shuffle_vector<T: Clone>(shuffle: &ShuffleVecType, vec: &Vec<T>) -> Vec<T>
where
    T: Send + Sync,
{
    assert_eq!(vec.len(), shuffle.len());
    shuffle.par_iter().map(|&idx| vec[idx].clone()).collect()
}

/// Unshuffle a vector using a permutation for testing
pub fn unshuffle_vector_testing<F: Field, T: Clone>(shuffle: &Vec<F>, vec: &Vec<T>) -> Vec<T> {
    assert!(shuffle.len() == vec.len());
    let mut unshuffled_vec = vec.clone();
    for i in 0..shuffle.len() {
        unshuffled_vec[shuffle[i].to_string().parse::<usize>().unwrap()] = vec[i].clone();
    }
    unshuffled_vec
}

/// Unshuffle a vector using a permutation
pub fn local_unshuffle_vector<T: Clone + Send + Sync>(
    shuffle: &ShuffleVecType,
    vec: &Vec<T>,
) -> Vec<T> {
    assert_eq!(vec.len(), shuffle.len());
    let result: Mutex<Vec<Option<T>>> = Mutex::new(vec![None; shuffle.len()]);

    shuffle.par_iter().enumerate().for_each(|(i, &target_idx)| {
        let mut res = result.lock().unwrap();
        res[target_idx] = Some(vec[i].clone());
    });

    result
        .into_inner()
        .unwrap()
        .into_iter()
        .map(|opt| opt.unwrap())
        .collect()
}
