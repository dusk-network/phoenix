// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{JubJubAffine, JubJubExtended, JubJubScalar, dhke};

mod generator;
pub mod public;
pub mod secret;
pub mod view;

/// Hashes a JubJub's ExtendedPoint into a JubJub's Scalar using the JubJub's
/// hash to scalar function
///
/// Uses the legacy construction without a domain separator, which every
/// existing note key is derived with.
pub fn hash(p: &JubJubExtended) -> JubJubScalar {
    hash_affine(&JubJubAffine::from(p))
}

fn hash_affine(p: &JubJubAffine) -> JubJubScalar {
    JubJubScalar::hash_to_scalar(None, &p.to_bytes())
}

/// Hashes the shared secret `a · R` of the secret `a` and the `R` of a
/// stealth address, as [`hash`] does.
///
/// The shared secret is derived with [`dhke`], which clears the cofactor of
/// `R`: a small-order component of `R` does not reach the result, and an
/// identity or small-order `R` yields none. For an `R` of prime order the
/// result is `H(a · R)`.
pub(crate) fn hash_shared_secret(
    a: &JubJubScalar,
    R: &JubJubExtended,
) -> Option<JubJubScalar> {
    Option::from(dhke(a, R)).map(|aR| hash_affine(&aR))
}
