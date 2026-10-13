// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{JubJubAffine, JubJubExtended, JubJubScalar};

pub mod public;
pub mod secret;
pub mod view;

/// Hashes a JubJub's ExtendedPoint into a JubJub's Scalar using the JubJub's
/// hash to scalar function
///
/// Uses the legacy construction without a domain separator, which every
/// existing note key is derived with.
pub fn hash(p: &JubJubExtended) -> JubJubScalar {
    JubJubScalar::hash_to_scalar(None, &JubJubAffine::from(p).to_bytes())
}
