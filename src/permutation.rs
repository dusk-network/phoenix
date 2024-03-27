// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{JubJubAffine, JubJubExtended, JubJubScalar};

/// Hashes a JubJub's ExtendedPoint into a JubJub's Scalar using the JubJub's
/// hash to scalar function
pub fn hash(p: &JubJubExtended) -> JubJubScalar {
    dusk_jubjub::Fr::hash_to_scalar(&JubJubAffine::from(p).to_bytes())
}
