// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Fee module contains the logic related to `Crossover` structure

use crate::{BlsScalar, JubJubExtended};

use dusk_bytes::{DeserializableSlice, Error as BytesError, Serializable};
use dusk_jubjub::JubJubAffine;
use dusk_poseidon::cipher::PoseidonCipher;
use dusk_poseidon::sponge;

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

/// Crossover structure containing obfuscated encrypted data
#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct Crossover {
    pub(crate) value_commitment: JubJubExtended,
    pub(crate) nonce: BlsScalar,
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
        let mut buf = [0_u8; Self::SIZE];

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
        let nonce = BlsScalar::from_slice(&bytes[32..])?;

        let encrypted_data = PoseidonCipher::from_slice(&bytes[64..])?;

        Ok(Crossover {
            value_commitment,
            nonce,
            encrypted_data,
        })
    }
}

impl Crossover {
    /// Represent the crossover as a sequence of scalars to be used as input for
    /// sponge hash functions
    ///
    /// It is composed by 3 scalars, in order:
    /// * Value commitment X
    /// * Value commitment Y
    /// * Nonce
    ///
    /// And also appends the scalars that composes the [`PoseidonCipher`]
    #[must_use]
    pub fn to_hash_inputs(
        &self,
    ) -> [BlsScalar; 3 + PoseidonCipher::cipher_size()] {
        let mut inputs = [BlsScalar::zero(); 3 + PoseidonCipher::cipher_size()];

        inputs[..2].copy_from_slice(&self.value_commitment().to_hash_inputs());
        inputs[2] = self.nonce;
        inputs[3..].copy_from_slice(self.encrypted_data.cipher());

        inputs
    }

    /// Sponge hash of the crossover hash inputs representation
    #[must_use]
    pub fn hash(&self) -> BlsScalar {
        sponge::hash(&self.to_hash_inputs())
    }

    /// Returns the Nonce used for the encrypt / decrypt of data for this note
    #[must_use]
    pub const fn nonce(&self) -> &BlsScalar {
        &self.nonce
    }

    /// Returns the value commitment `H(value, blinding_factor)`
    #[must_use]
    pub const fn value_commitment(&self) -> &JubJubExtended {
        &self.value_commitment
    }

    /// Returns the encrypted data
    #[must_use]
    pub const fn encrypted_data(&self) -> &PoseidonCipher {
        &self.encrypted_data
    }
}
