// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Fee module contains the logic related to `Crossover` structure

use crate::{BlsScalar, JubJubExtended, JubJubScalar};

#[cfg(feature = "canon")]
use canonical::Canon;
#[cfg(feature = "canon")]
use canonical_derive::Canon;

use dusk_bytes::{DeserializableSlice, Error as BytesError, Serializable};
use dusk_jubjub::JubJubAffine;
use dusk_poseidon::cipher::PoseidonCipher;
use dusk_poseidon::sponge::hash;

/// Crossover structure containing obfuscated encrypted data
#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(feature = "canon", derive(Canon))]
pub struct Crossover {
    pub(crate) value_commitment: JubJubExtended,
    pub(crate) nonce: JubJubScalar,
    pub(crate) encrypted_data: PoseidonCipher,
}

impl PartialEq for Crossover {
    fn eq(&self, other: &Self) -> bool {
        self.hash() == other.hash()
    }
}

impl Eq for Crossover {}

impl Serializable<{ 64 + PoseidonCipher::SIZE }> for Crossover {
    type Error = BytesError;

    /// Converts a Crossover into it's byte representation
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];

        buf[..32].copy_from_slice(
            &JubJubAffine::from(&self.value_commitment).to_bytes(),
        );
        buf[32..64].copy_from_slice(&self.nonce.to_bytes());
        buf[64..].copy_from_slice(&self.encrypted_data.to_bytes());
        buf
    }

    /// Attempts to convert a byte representation of a note into a `Note`,
    /// failing if the input is invalid
    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let value_commitment =
            JubJubExtended::from(JubJubAffine::from_slice(&bytes[..32])?);
        let nonce = JubJubScalar::from_slice(&bytes[32..])?;

        let encrypted_data = PoseidonCipher::from_slice(&bytes[64..])?;

        Ok(Crossover {
            value_commitment,
            nonce,
            encrypted_data,
        })
    }
}

impl Crossover {
    /// Returns a hash represented by `H(value_commitment)`
    pub fn hash(&self) -> BlsScalar {
        let value_commitment = self.value_commitment().to_hash_inputs();

        hash(&value_commitment)
    }

    /// Returns the Nonce used for the encrypt / decrypt of data for this note
    pub fn nonce(&self) -> &JubJubScalar {
        &self.nonce
    }

    /// Returns the value commitment `H(value, blinding_factor)`
    pub fn value_commitment(&self) -> &JubJubExtended {
        &self.value_commitment
    }

    /// Returns the encrypted data
    pub fn encrypted_data(&self) -> &PoseidonCipher {
        &self.encrypted_data
    }
}
