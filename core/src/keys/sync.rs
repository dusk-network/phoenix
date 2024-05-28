// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::keys::{stealth::StealthAddress, Ownable};
use dusk_jubjub::{JubJubAffine, JubJubExtended};
use jubjub_schnorr::PublicKey as NotePublicKey;

use dusk_bytes::{DeserializableSlice, Error, Serializable};

use subtle::{Choice, ConstantTimeEq};

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

/// A `SyncAddress` allows for a fast sync of the wallet, and
/// is composed by a one-time DH point 'k' and an additional
/// random point `R`.
#[derive(Default, Debug, Clone, Copy)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct SyncAddress {
    pub(crate) R: JubJubExtended,
    pub(crate) k: JubJubExtended,
}

impl SyncAddress {
    /// Create a sync address from its internal parts
    /// For additional information, check [PublicKey::from_raw_unchecked].
    pub const fn from_raw_unchecked(
        R: JubJubExtended,
        k: JubJubExtended,
    ) -> Self {
        Self { R, k }
    }

    /// Gets the random point `R`
    pub const fn R(&self) -> &JubJubExtended {
        &self.R
    }

    /// Gets the DH `k`
    pub const fn k(&self) -> &JubJubExtended {
        &self.k
    }
}

impl ConstantTimeEq for SyncAddress {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.k().ct_eq(other.k()) & self.R.ct_eq(&other.R)
    }
}

impl PartialEq for SyncAddress {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Ownable for SyncAddress {
    fn stealth_address(&self) -> StealthAddress {
        self.into()
    }
    fn sync_address(&self) -> Self {
        *self
    }
}

impl From<&StealthAddress> for SyncAddress {
    fn from(sa: &StealthAddress) -> Self {
        SyncAddress {
            k: *sa.note_pk().as_ref(),
            R: *sa.R(),
        }
    }
}

impl Serializable<64> for SyncAddress {
    type Error = Error;
    /// Encode the `SyncAddress` to an array of 64 bytes
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[..32].copy_from_slice(&JubJubAffine::from(self.R).to_bytes());
        bytes[32..].copy_from_slice(&JubJubAffine::from(self.k()).to_bytes());
        bytes
    }

    /// Decode the `SyncAddress` from an array of 64 bytes
    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Error> {
        let R = JubJubExtended::from(JubJubAffine::from_slice(&bytes[..32])?);
        let note_pk =
            JubJubExtended::from(JubJubAffine::from_slice(&bytes[32..])?);
        let k = NotePublicKey::from_raw_unchecked(note_pk);

        Ok(SyncAddress { R, k: *k.as_ref() })
    }
}
