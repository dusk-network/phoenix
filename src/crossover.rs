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
    /// Returns a hash represented by `H(value_commitment)`
    pub fn hash(&self) -> BlsScalar {
        let value_commitment = self.value_commitment().to_hash_inputs();

        hash::<2>(&value_commitment)
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
