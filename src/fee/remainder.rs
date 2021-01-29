// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Remainder module contains the logic related to `Remainder` structure

use dusk_pki::Ownable;
use dusk_pki::StealthAddress;

#[cfg(feature = "canon")]
use canonical::Canon;
#[cfg(feature = "canon")]
use canonical_derive::Canon;

use poseidon252::sponge::hash;

use crate::BlsScalar;

/// The Remainder structure.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "canon", derive(Canon))]
pub struct Remainder {
    /// The gas_changes set for the remainder
    pub(crate) gas_changes: u64,
    /// The stealth address
    pub(crate) stealth_address: StealthAddress,
}

impl PartialEq for Remainder {
    fn eq(&self, other: &Self) -> bool {
        self.hash() == other.hash()
    }
}

impl Eq for Remainder {}

impl Remainder {
    /// Return a hash represented by `H(gas, H([pskr]))`
    pub fn hash(&self) -> BlsScalar {
        let pk_r = self.stealth_address().pk_r().as_ref().to_hash_inputs();

        hash(&[BlsScalar::from(self.gas_changes), pk_r[0], pk_r[1]])
    }
}

impl Ownable for Remainder {
    fn stealth_address(&self) -> &StealthAddress {
        &self.stealth_address
    }
}
