// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Phoenix's Core library types and behaviors

#![allow(non_snake_case)]
#![deny(missing_docs)]

/// Type's Conversion module
mod convert;
/// Crossover
pub mod crossover;
/// Phoenix's Core Errors
pub mod error;
/// Fee
pub mod fee;
/// Transparent and Obfuscated Notes
pub mod note;

pub use crossover::Crossover;
pub use error::Error;
pub use fee::Fee;
pub use note::{Note, NoteType};

use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{JubJubAffine, JubJubExtended, JubJubScalar};
