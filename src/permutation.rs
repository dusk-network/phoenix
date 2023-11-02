// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{JubJubExtended, JubJubScalar};
use dusk_poseidon::sponge::truncated;

/// Hashes a JubJub's ExtendedPoint into a JubJub's Scalar using the poseidon
/// hash function
pub fn hash(p: &JubJubExtended) -> JubJubScalar {
    truncated::hash(&p.to_hash_inputs())
}
