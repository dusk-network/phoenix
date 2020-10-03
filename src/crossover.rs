// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Fee module contains the logic related to `Crossover` structure

use std::io::{self, Read, Write};

use dusk_pki::jubjub_decode;

use poseidon252::cipher::PoseidonCipher;
use poseidon252::sponge::sponge::sponge_hash;

use poseidon252::cipher::ENCRYPTED_DATA_SIZE;

use crate::{BlsScalar, Error, JubJubAffine, JubJubExtended, JubJubScalar};

/// Crossover structure containing obfuscated encrypted data
#[derive(Clone, Copy, Debug, Default)]
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

impl Read for Crossover {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut buf = io::BufWriter::new(&mut buf[..]);
        let mut n = 0;

        n += buf.write(
            &JubJubAffine::from(&self.value_commitment).to_bytes()[..],
        )?;
        n += buf.write(&self.nonce.to_bytes())?;
        n += buf.write(&self.encrypted_data.to_bytes())?;

        buf.flush()?;
        Ok(n)
    }
}

impl Write for Crossover {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut buf = io::BufReader::new(&buf[..]);

        let mut one_scalar = [0u8; 32];
        let mut one_cipher = [0u8; ENCRYPTED_DATA_SIZE];
        let mut n = 0;

        buf.read_exact(&mut one_scalar)?;
        n += one_scalar.len();
        self.value_commitment =
            JubJubExtended::from(jubjub_decode::<JubJubAffine>(&one_scalar)?);

        buf.read_exact(&mut one_scalar)?;
        n += one_scalar.len();
        self.nonce = jubjub_decode::<JubJubScalar>(&one_scalar)?;

        buf.read_exact(&mut one_cipher)?;
        n += one_cipher.len();
        self.encrypted_data = PoseidonCipher::from_bytes(&one_cipher)
            .ok_or(Error::InvalidCipher)?;

        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Crossover {
    /// Returns a hash represented by `H(value_commitment)`
    pub fn hash(&self) -> BlsScalar {
        let value_commitment = self.value_commitment().to_hash_inputs();

        sponge_hash(&value_commitment)
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
