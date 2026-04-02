//! Our implementation of SPDZ.
#![deny(warnings)]
#![deny(missing_docs)]

pub mod net;
pub mod utils;

/// Primitives for the MPC protocol
pub mod primitives;

/// Operations on arithmetic circuits
pub mod arithcircop;
/// Operations on arithmetic permutation circuits
pub mod arithpermcircop;

/// Preprocessing for general arithmetic circuits
pub mod arithcircprep;
/// Preprocessing for arithmetic permutation circuits
pub mod arithpermcircprep;

/// Benchmarks
pub mod bench;
