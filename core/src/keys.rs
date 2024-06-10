// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{JubJubAffine, JubJubExtended, JubJubScalar};

pub mod public;
pub mod secret;
pub mod stealth;
pub mod sync;
pub mod view;

/// Hashes a JubJub's ExtendedPoint into a JubJub's Scalar using the JubJub's
/// hash to scalar function
pub fn hash(p: &JubJubExtended) -> JubJubScalar {
    JubJubScalar::hash_to_scalar(&JubJubAffine::from(p).to_bytes())
}

/// The trait `Ownable` is required by any type that wants to prove its
/// ownership.
pub trait Ownable {
    /// Returns the associated `SyncAddress`
    fn sync_address(&self) -> sync::SyncAddress;
    /// Returns the associated `StealthAddress`
    fn stealth_address(&self) -> stealth::StealthAddress;
}

pub(crate) fn owns_unchecked(
    a: &JubJubScalar,
    owner: &impl crate::Ownable,
) -> bool {
    let sa = owner.sync_address();
    let aR = sa.R() * a;

    sa.k() == &aR
}

/// This trait grants the ability to check if a note is owned.
pub trait Ownability {
    /// Checks if:
    /// `note_pk ?= H(R · a) · G + B` for `ViewKey`
    /// `note_pk ?= (H(R · a) + b) · G` for `SecretKey`
    fn owns(&self, owner: &impl crate::Ownable) -> bool;

    /// Checks if `k_sync ?= R_sync · a`
    fn owns_unchecked(&self, owner: &impl crate::Ownable) -> bool;
}
