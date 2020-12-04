// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Fee module contains the logic related to `Crossover` structure

use crate::{BlsScalar, Error, JubJubExtended, JubJubScalar};

#[cfg(feature = "canon")]
use canonical::Canon;
#[cfg(feature = "canon")]
use canonical_derive::Canon;

use dusk_jubjub::JubJubAffine;
use dusk_pki::jubjub_decode;
use poseidon252::cipher::PoseidonCipher;
use poseidon252::sponge::hash;

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

impl Crossover {
    /// Returns the serialized size of the Crossover
    pub const fn serialized_size() -> usize {
        32 * 2 + PoseidonCipher::cipher_size_bytes()
    }

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

    /// Converts a Crossover into it's byte representation
    pub fn to_bytes(&self) -> [u8; Crossover::serialized_size()] {
        let mut buf = [0u8; Crossover::serialized_size()];
        let mut n = 0;

        buf[n..n + 32].copy_from_slice(
            &JubJubAffine::from(&self.value_commitment).to_bytes()[..],
        );
        n += 32;

        buf[n..n + 32].copy_from_slice(&self.nonce.to_bytes()[..]);
        n += 32;

        buf[n..n + PoseidonCipher::cipher_size_bytes()]
            .copy_from_slice(&self.encrypted_data.to_bytes()[..]);
        n += PoseidonCipher::cipher_size_bytes();

        debug_assert_eq!(n, Crossover::serialized_size());

        buf
    }

    /// Attempts to convert a byte representation of a note into a `Note`,
    /// failing if the input is invalid
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < Crossover::serialized_size() {
            return Err(Error::InvalidCrossoverConversion);
        }

        let mut bytes_32 = [0u8; 32];
        let mut one_cipher = [0u8; PoseidonCipher::cipher_size_bytes()];

        let mut n = 0;

        bytes_32.copy_from_slice(&bytes[n..n + 32]);
        let value_commitment =
            JubJubExtended::from(jubjub_decode::<JubJubAffine>(&bytes_32)?);
        n += 32;

        bytes_32.copy_from_slice(&bytes[n..n + 32]);
        let nonce = jubjub_decode::<JubJubScalar>(&bytes_32)?;
        n += 32;

        one_cipher.copy_from_slice(
            &bytes[n..n + PoseidonCipher::cipher_size_bytes()],
        );
        let encrypted_data = PoseidonCipher::from_bytes(&one_cipher)
            .ok_or(Error::InvalidCipher)?;

        Ok(Crossover {
            value_commitment,
            nonce,
            encrypted_data,
        })
    }
}
