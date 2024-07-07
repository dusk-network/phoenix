// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{JubJubAffine, JubJubExtended};
use jubjub_schnorr::PublicKey as NotePublicKey;

use dusk_bytes::{DeserializableSlice, Error, Serializable};

use subtle::{Choice, ConstantTimeEq};

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

/// To obfuscate the identity of the participants, we utilizes a Stealth Address
/// system.
/// A `StealthAddress` is composed by a one-time note-public-key (the actual
/// address) and a random point `R`.
#[derive(Default, Debug, Clone, Copy, Eq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct StealthAddress {
    pub(crate) R: JubJubExtended,
    pub(crate) note_pk: NotePublicKey,
}

impl StealthAddress {
    /// Create a stealth address from its internal parts
    ///
    /// A stealth address is intended to be generated as the public counterpart
    /// of a one time secret key. If the user opts to generate the
    /// stealth address from points, there is no guarantee a secret one time
    /// key counterpart will be known, and this stealth address will
    /// not provide the required arguments to generate it.
    ///
    /// For additional information, check [PublicKey::from_raw_unchecked].
    pub const fn from_raw_unchecked(
        R: JubJubExtended,
        note_pk: NotePublicKey,
    ) -> Self {
        Self { R, note_pk }
    }

    /// Gets the random point `R`
    pub const fn R(&self) -> &JubJubExtended {
        &self.R
    }

    /// Gets the `note_pk`
    pub const fn note_pk(&self) -> &NotePublicKey {
        &self.note_pk
    }
}

impl ConstantTimeEq for StealthAddress {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.note_pk().as_ref().ct_eq(other.note_pk().as_ref())
            & self.R.ct_eq(&other.R)
    }
}

impl PartialEq for StealthAddress {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Serializable<64> for StealthAddress {
    type Error = Error;
    /// Encode the `StealthAddress` to an array of 64 bytes
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[..32].copy_from_slice(&JubJubAffine::from(self.R).to_bytes());
        bytes[32..].copy_from_slice(
            &JubJubAffine::from(self.note_pk().as_ref()).to_bytes(),
        );
        bytes
    }

    /// Decode the `StealthAddress` from an array of 64 bytes
    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Error> {
        let R = JubJubExtended::from(JubJubAffine::from_slice(&bytes[..32])?);
        let note_pk =
            JubJubExtended::from(JubJubAffine::from_slice(&bytes[32..])?);
        let note_pk = NotePublicKey::from_raw_unchecked(note_pk);

        Ok(StealthAddress { R, note_pk })
    }
}
