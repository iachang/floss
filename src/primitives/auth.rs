use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

#[derive(Clone, Debug, PartialEq, Eq, Copy, CanonicalSerialize, CanonicalDeserialize)]
/// An authenticated share of a value
pub struct AuthShare<F: Field + CanonicalSerialize + CanonicalDeserialize> {
    /// An additive share of the value itself
    pub value: F,
    /// An additive share of the one-time MAC of the value, or alpha * mac additive share for DoubleAuthSS
    pub mac: F,
}

/// A one-sided K-authenticated share
#[derive(Clone, Debug, PartialEq, Eq, Copy, CanonicalSerialize, CanonicalDeserialize)]
pub struct KAuthShare<F: Field + CanonicalSerialize + CanonicalDeserialize> {
    /// The king should hold the entire key K
    pub k: Option<F>,
    /// The value of the share
    pub value: F,
    /// The MAC of the share
    pub mac: F,
    /// The value of the K-authenticated share
    pub kvalue: F,
    /// The MAC of the K-authenticated share
    pub kmac: F,
}

impl<F: Field> std::ops::Add<AuthShare<F>> for AuthShare<F> {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        AuthShare {
            value: self.value + other.value,
            mac: self.mac + other.mac,
        }
    }
}

impl<F: Field> std::ops::Sub<AuthShare<F>> for AuthShare<F> {
    type Output = Self;

    fn sub(self, other: Self) -> Self::Output {
        AuthShare {
            value: self.value - other.value,
            mac: self.mac - other.mac,
        }
    }
}

impl<F: Field> std::ops::Mul<F> for AuthShare<F> {
    type Output = Self;

    fn mul(self, other: F) -> Self::Output {
        AuthShare {
            value: self.value * other,
            mac: self.mac * other,
        }
    }
}

impl<F: Field> std::iter::Sum for AuthShare<F> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(
            AuthShare {
                value: F::zero(),
                mac: F::zero(),
            },
            |acc, x| acc + x,
        )
    }
}
