use ark_ff::Field;
use ark_serialize::CanonicalSerialize;

/// Representation of a field element as a vector of bits
pub type BitVector<F> = Vec<F>;

/// Get the number of bits needed to represent a field element
/// This uses the compressed serialization size
pub fn get_field_bits<F: Field + CanonicalSerialize>() -> usize {
    // Serialize a zero element to get the size
    let zero = F::zero();
    let mut bytes = Vec::new();
    zero.serialize_compressed(&mut bytes).unwrap();
    bytes.len() * 8
}

/// Get the number of bits needed to represent a number
pub fn get_number_bits(x: u64) -> usize {
    let mut bits = 0usize;
    let mut x = x;
    while x > 0 {
        bits += 1;
        x >>= 1;
    }
    bits
}

/// Convert a usize to its bit representation
/// Returns bits in little-endian order (LSB at index 0, MSB at highest index)
pub fn usize_to_bits<F: Field>(x: usize, num_bits: usize) -> BitVector<F> {
    let mut bits = Vec::with_capacity(num_bits);
    for i in 0..num_bits {
        bits.push(if ((x >> i) & 1) != 0 {
            F::one()
        } else {
            F::zero()
        });
    }
    bits
}

/// Convert a Field element to its bit representation
/// Returns bits in little-endian order (LSB at index 0, MSB at highest index)
pub fn field_to_bits<F: Field + CanonicalSerialize>(x: F, num_bits: usize) -> BitVector<F> {
    let mut bytes = Vec::new();
    x.serialize_compressed(&mut bytes).unwrap();

    let mut bits = Vec::with_capacity(num_bits);

    for i in 0..num_bits {
        let byte_idx = i / 8;
        let bit_idx = i % 8;

        let bit_value = if byte_idx < bytes.len() {
            ((bytes[byte_idx] >> bit_idx) & 1) != 0
        } else {
            false
        };

        bits.push(if bit_value { F::one() } else { F::zero() });
    }

    bits
}

/// Convert bits back to Field element
pub fn bits_to_field<F: Field>(bits: &Vec<F>) -> F {
    bits.iter().enumerate().fold(F::zero(), |acc, (i, &bit)| {
        acc + bit * F::pow(&F::from(2), &[i as u64])
    })
}
