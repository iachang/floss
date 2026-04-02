use ark_ff::Field;
use rayon::iter::{IntoParallelIterator, IntoParallelRefIterator, ParallelIterator};

/// Helper function to return a new vector with binary op applied elementwise to two slices
pub fn elementwise_ref<T: Copy + Send + Sync, F: Fn(T, T) -> T + Send + Sync>(
    v1: &[T],
    v2: &[T],
    op: F,
) -> Vec<T> {
    assert_eq!(v1.len(), v2.len(), "length mismatch");
    (0..v1.len())
        .into_par_iter()
        .map(|i| op(v1[i], v2[i]))
        .collect()
}

/// Helper function to return a new vector with binary op applied elementwise to a slice and a scalar
pub fn elementwise_ref_scalar<T: Copy + Send + Sync, F: Fn(T, T) -> T + Send + Sync>(
    v1: &[T],
    v2: T,
    op: F,
) -> Vec<T> {
    v1.par_iter().map(|x| op(*x, v2)).collect()
}

/// Takes a Vec<Vec<T>> and reduces all inner Vec<T> by the operation (assuming all inner-vectors are same size)
/// For multiplication: || F::from(1), |a, b| a * b
/// For addition: || F::from(0), |a, b| a + b
pub fn reduce_columns_parallel<T, Id, Op>(data: &[Vec<T>], identity: Id, op: Op) -> Vec<T>
where
    T: Send + Sync + Copy,
    Id: Fn() -> T + Send + Sync + Copy,
    Op: Fn(T, T) -> T + Send + Sync + Copy,
{
    assert!(!data.is_empty(), "no rows");
    let cols = data[0].len();
    assert!(data.iter().all(|r| r.len() == cols), "ragged rows");

    (0..cols)
        .into_par_iter()
        .map(|i| {
            // Parallel *reduction* across rows in column i.
            data.par_iter()
                .map(|row| row[i])
                .reduce(identity, |a, b| op(a, b))
        })
        .collect()
}

/// Helper function to concatenate two vectors of elements
pub fn extend_vector<F: Field, T>(a: Vec<T>, b: Vec<T>) -> Vec<T> {
    let mut result = a;
    result.extend(b);
    result
}

/// Helper function to transpose a vector of vectors
pub fn transpose_vector<T: Clone>(v: Vec<Vec<T>>) -> Vec<Vec<T>> {
    let rows = v.len();
    let cols = v[0].len();
    (0..cols)
        .map(|col| (0..rows).map(|row| v[row][col].clone()).collect::<Vec<T>>())
        .collect()
}

/// Convert a vector of length n * dim into num_vectors of length n
pub fn roll_vector<T: Clone>(v: Vec<T>, n: usize, num_vectors: usize) -> Vec<Vec<T>> {
    (0..num_vectors)
        .map(|i| v[i * n..(i + 1) * n].to_vec())
        .collect()
}

/// Convert a vector of length n into a vector of length n * num_vectors
pub fn unroll_vector<T: Clone>(v: Vec<Vec<T>>) -> Vec<T> {
    v.into_iter().flatten().collect()
}

/// Convert a vector of length n into a vector of length n * num_vectors
pub fn dupe_vector<T: Clone>(v: Vec<T>, n: usize) -> Vec<T> {
    (0..n).flat_map(|_| v.clone()).collect()
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::primitives::auth::AuthShare;
    use rand::Rng;
    type Fr = crate::bench::Mersenne128Fq;

    #[test]
    fn test_elementwise_ref_randomized() {
        // Test with randomized integers
        let mut rng = rand::rng();

        // &mut rng makes sure we do not consume the rng
        // random_iter() just generates a stream of random values
        // setting random_iter() type to u8 ensures we do not integer overflow in our tests (since it defaults to i32)
        // take(4) grabs the first 4 (random) elements of the iterator
        // .map() casts the u8 type to u32
        let randomized_v1: Vec<u32> = (&mut rng)
            .random_iter::<u8>()
            .take(4)
            .map(|x| x as u32)
            .collect();
        assert_eq!(randomized_v1.len(), 4);
        let v2: Vec<u32> = vec![5, 6, 7, 8];

        let output: Vec<u32> = elementwise_ref(&randomized_v1, &v2, |a, b| a + b);
        assert_eq!(
            output,
            vec![
                randomized_v1[0] + v2[0],
                randomized_v1[1] + v2[1],
                randomized_v1[2] + v2[2],
                randomized_v1[3] + v2[3]
            ]
        );

        let output = elementwise_ref(&randomized_v1, &v2, |a, b| a * b);
        assert_eq!(
            output,
            vec![
                randomized_v1[0] * v2[0],
                randomized_v1[1] * v2[1],
                randomized_v1[2] * v2[2],
                randomized_v1[3] * v2[3]
            ]
        );
    }

    #[test]
    fn test_elementwise_ref_shares() {
        // Test with auth shares
        let v1 = vec![
            AuthShare {
                value: Fr::from(1),
                mac: Fr::from(0),
            },
            AuthShare {
                value: Fr::from(3),
                mac: Fr::from(4),
            },
        ];
        let v2 = vec![
            AuthShare {
                value: Fr::from(5),
                mac: Fr::from(2),
            },
            AuthShare {
                value: Fr::from(7),
                mac: Fr::from(8),
            },
        ];

        let output = elementwise_ref(&v1, &v2, |a, b| a + b);

        assert_eq!(output[0].value, Fr::from(6));
        assert_eq!(output[0].mac, Fr::from(2));
        assert_eq!(output[1].value, Fr::from(10));
        assert_eq!(output[1].mac, Fr::from(12));

        // Test with different lengths (should panic)
        let v3 = vec![AuthShare {
            value: Fr::from(1),
            mac: Fr::from(2),
        }];
        let output = std::panic::catch_unwind(|| {
            elementwise_ref(&v1, &v3, |a, b| a + b);
        });
        assert!(output.is_err());
    }

    #[test]
    fn test_roll_vector() {
        let v = vec![1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3];
        let result = roll_vector(v, 4, 3);
        assert_eq!(
            result,
            vec![vec![1, 1, 1, 1], vec![2, 2, 2, 2], vec![3, 3, 3, 3]]
        );
    }

    #[test]
    fn test_unroll_vector() {
        let v = vec![vec![1, 1, 1, 1], vec![2, 2, 2, 2], vec![3, 3, 3, 3]];
        let result = unroll_vector(v);
        assert_eq!(result, vec![1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3]);
    }

    #[test]
    fn test_dupe_vector() {
        let v = vec![1, 2, 3];
        let result = dupe_vector(v, 3);
        assert_eq!(result, vec![1, 2, 3, 1, 2, 3, 1, 2, 3]);
    }
}
