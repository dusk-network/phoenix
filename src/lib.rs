#![allow(non_snake_case)]
#![warn(unused_crate_dependencies)]

/// Phoenix's Core Errors
pub mod error;
/// Macros
pub mod macros;
/// Transparent and Obfuscated Notes
pub mod note;

pub use error::Error;
pub use note::{Note, NoteType};

use dusk_plonk::bls12_381::Scalar as BlsScalar;
use dusk_plonk::jubjub::{
    AffinePoint as JubJubAffine, ExtendedPoint as JubJubExtended,
    Fr as JubJubScalar,
};
