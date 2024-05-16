// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Fee module contains the logic related to `Crossover` structure

use dusk_bytes::{DeserializableSlice, Error as BytesError, Serializable};
use dusk_jubjub::{JubJubAffine, JubJubExtended};

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

use crate::note::ENCRYPTION_SIZE;

/// Crossover structure containing obfuscated encrypted data
#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct Crossover {
    pub(crate) value_commitment: JubJubExtended,
    pub(crate) encryption: [u8; ENCRYPTION_SIZE],
}

impl Default for Crossover {
    fn default() -> Self {
        Self {
            value_commitment: JubJubExtended::default(),
            encryption: [0; ENCRYPTION_SIZE],
        }
    }
}

impl PartialEq for Crossover {
    fn eq(&self, other: &Self) -> bool {
        self.value_commitment() == other.value_commitment()
    }
}

impl Eq for Crossover {}

impl Serializable<{ 32 + ENCRYPTION_SIZE }> for Crossover {
    type Error = BytesError;

    /// Converts a Crossover into it's byte representation
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];

        buf[..32].copy_from_slice(
            &JubJubAffine::from(&self.value_commitment).to_bytes(),
        );
        buf[32..].copy_from_slice(&self.encryption);
        buf
    }

    /// Attempts to convert a byte representation of a note into a `Note`,
    /// failing if the input is invalid
    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let value_commitment =
            JubJubExtended::from(JubJubAffine::from_slice(&bytes[..32])?);

        let mut encryption = [0u8; ENCRYPTION_SIZE];
        encryption.copy_from_slice(&bytes[32..]);

        Ok(Crossover {
            value_commitment,
            encryption,
        })
    }
}

impl Crossover {
    /// Returns the value commitment `H(value, blinding_factor)`
    pub const fn value_commitment(&self) -> &JubJubExtended {
        &self.value_commitment
    }

    /// Returns the encrypted data
    pub const fn encryption(&self) -> &[u8; ENCRYPTION_SIZE] {
        &self.encryption
    }
}
