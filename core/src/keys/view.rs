// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::{keys::hash, SecretKey};

use dusk_bytes::{DeserializableSlice, Error, Serializable};
use dusk_jubjub::{
    JubJubAffine, JubJubExtended, JubJubScalar, GENERATOR_EXTENDED,
};
use subtle::{Choice, ConstantTimeEq};

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

/// Pair of a secret `a` and public `b·G`
///
/// The notes are encrypted against secret a, so this is used to decrypt the
/// blinding factor and value
#[derive(Clone, Copy, Debug)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct ViewKey {
    a: JubJubScalar,
    B: JubJubExtended,
}

impl ConstantTimeEq for ViewKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        // TODO - Why self.a is not checked?
        self.B.ct_eq(&other.B)
    }
}

impl PartialEq for ViewKey {
    fn eq(&self, other: &Self) -> bool {
        self.a == other.a && self.ct_eq(other).into()
    }
}

impl Eq for ViewKey {}

impl ViewKey {
    /// This method is used to construct a new `ViewKey` from the given
    /// pair of secret `a` and public `b·G`.
    pub fn new(a: JubJubScalar, B: JubJubExtended) -> Self {
        Self { a, B }
    }

    /// Gets `a`
    pub fn a(&self) -> &JubJubScalar {
        &self.a
    }

    /// Gets `B` (`b·G`)
    pub fn B(&self) -> &JubJubExtended {
        &self.B
    }

    /// Checks `note_pk = H(R · a) · G + B`
    pub fn owns(&self, owner: &impl crate::Ownable) -> bool {
        let sa = owner.stealth_address();

        let aR = sa.R() * self.a();
        let aR = hash(&aR);
        let aR = GENERATOR_EXTENDED * aR;
        let note_pk = aR + self.B();

        sa.note_pk().as_ref() == &note_pk
    }

    /// Checks `k_sync ?= R_sync · a`
    pub fn owns_unchecked(&self, owner: &impl crate::Ownable) -> bool {
        let sa = owner.sync_address();
        let aR = sa.R() * self.a();

        sa.k() == &aR
    }
}

impl From<&SecretKey> for ViewKey {
    fn from(sk: &SecretKey) -> Self {
        let B = GENERATOR_EXTENDED * sk.b();

        ViewKey::new(*sk.a(), B)
    }
}

impl Serializable<64> for ViewKey {
    type Error = Error;

    fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.a.to_bytes());
        bytes[32..].copy_from_slice(&JubJubAffine::from(&self.B).to_bytes());
        bytes
    }

    fn from_bytes(buf: &[u8; 64]) -> Result<Self, Self::Error> {
        let a = JubJubScalar::from_slice(&buf[..32])?;
        let B = JubJubExtended::from(JubJubAffine::from_slice(&buf[32..])?);

        Ok(Self { a, B })
    }
}
