// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![allow(non_snake_case)]

/// Phoenix's Core Errors
pub mod error;
/// Transparent and Obfuscated Notes
pub mod note;

pub use error::Error;
pub use note::{Note, NoteType};

use dusk_plonk::bls12_381::Scalar as BlsScalar;
use dusk_plonk::jubjub::{
    AffinePoint as JubJubAffine, ExtendedPoint as JubJubExtended,
    Fr as JubJubScalar,
};
