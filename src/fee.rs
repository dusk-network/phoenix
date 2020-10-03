// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Fee module contains the logic related to `Fee` and `Remainder` structure

use std::io::{self, Read, Write};

use dusk_pki::Ownable;
use dusk_pki::{PublicSpendKey, StealthAddress};

use poseidon252::sponge::sponge::sponge_hash;

use crate::{BlsScalar, JubJubScalar};

mod remainder;
pub use remainder::Remainder;

/// The Fee structure
#[derive(Clone, Copy, Debug)]
pub struct Fee {
    /// The gas limit set for the fee
    pub gas_limit: u64,
    /// the gas price set for the fee
    pub gas_price: u64,
    pub(crate) stealth_address: StealthAddress,
}

impl PartialEq for Fee {
    fn eq(&self, other: &Self) -> bool {
        self.hash() == other.hash()
    }
}

impl Eq for Fee {}

impl Default for Fee {
    fn default() -> Self {
        Fee::new(0, 0, &PublicSpendKey::default())
    }
}

impl Read for Fee {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut buf = io::BufWriter::new(&mut buf[..]);
        let mut n = 0;

        n += buf.write(&self.gas_limit.to_le_bytes())?;
        n += buf.write(&self.gas_price.to_le_bytes())?;
        n += buf.write(&self.stealth_address.to_bytes())?;

        buf.flush()?;
        Ok(n)
    }
}

impl Write for Fee {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut buf = io::BufReader::new(&buf[..]);

        let mut one_u64 = [0u8; 8];
        let mut one_stealth_address = [0u8; 64];
        let mut n = 0;

        buf.read_exact(&mut one_u64)?;
        n += one_u64.len();
        self.gas_limit = u64::from_le_bytes(one_u64);

        buf.read_exact(&mut one_u64)?;
        n += one_u64.len();
        self.gas_price = u64::from_le_bytes(one_u64);

        buf.read_exact(&mut one_stealth_address)?;
        n += one_stealth_address.len();
        self.stealth_address =
            StealthAddress::from_bytes(&one_stealth_address)?;

        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Fee {
    /// Create a new Fee with inner randomness
    pub fn new(gas_limit: u64, gas_price: u64, psk: &PublicSpendKey) -> Self {
        let r = JubJubScalar::random(&mut rand::thread_rng());

        Self::deterministic(gas_limit, gas_price, &r, psk)
    }

    /// Create a new Fee without inner randomness
    pub fn deterministic(
        gas_limit: u64,
        gas_price: u64,
        r: &JubJubScalar,
        psk: &PublicSpendKey,
    ) -> Self {
        let stealth_address = psk.gen_stealth_address(r);

        Fee {
            gas_limit,
            gas_price,
            stealth_address,
        }
    }

    /// Return a hash represented by `H(gas_limit, gas_price, H([pskr]))`
    pub fn hash(&self) -> BlsScalar {
        let pk_r = self.stealth_address().pk_r().to_hash_inputs();

        sponge_hash(&[
            BlsScalar::from(self.gas_limit),
            BlsScalar::from(self.gas_price),
            pk_r[0],
            pk_r[1],
        ])
    }

    /// Generates a remainder from the fee and the given gas consumed
    pub fn gen_remainder(&self, gas_consumed: u64) -> Remainder {
        // Consuming more gas than the limit provided should never
        // occur, and it's not responsability of the `Remainder` to
        // check that.
        // Here defensively ensure it's not panicking, capping the gas
        // consumed to the gas limit.
        let gas_consumed = std::cmp::min(gas_consumed, self.gas_limit);
        let gas_changes = (self.gas_limit - gas_consumed) * self.gas_price;

        Remainder {
            gas_changes,
            stealth_address: self.stealth_address,
        }
    }
}

impl Ownable for Fee {
    fn stealth_address(&self) -> &StealthAddress {
        &self.stealth_address
    }
}
