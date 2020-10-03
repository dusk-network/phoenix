// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use kelvin::{ByteHash, Content, Sink, Source};
use std::convert::TryFrom;
use std::convert::TryInto;
use std::io::{self, Read, Write};

use dusk_pki::jubjub_decode;
use dusk_pki::Ownable;
use dusk_pki::{PublicSpendKey, SecretSpendKey, StealthAddress, ViewKey};

use dusk_plonk::jubjub::{dhke, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use poseidon252::cipher::PoseidonCipher;
use poseidon252::sponge::sponge::sponge_hash;
use poseidon252::StorageScalar;

use crate::{BlsScalar, Error, JubJubAffine, JubJubExtended, JubJubScalar};

use poseidon252::cipher::{CIPHER_SIZE, ENCRYPTED_DATA_SIZE};

/// The types of a Note
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum NoteType {
    /// Defines a Transparent type of Note
    Transparent = 0,
    /// Defines an Obfuscated type of Note
    Obfuscated = 1,
}

impl TryFrom<u8> for NoteType {
    type Error = Error;

    fn try_from(note_type: u8) -> Result<Self, Self::Error> {
        match note_type {
            0 => Ok(NoteType::Transparent),
            1 => Ok(NoteType::Obfuscated),
            n => Err(Error::InvalidNoteType(n)),
        }
    }
}

impl TryFrom<i32> for NoteType {
    type Error = Error;

    fn try_from(note_type: i32) -> Result<Self, Self::Error> {
        (note_type as u8).try_into()
    }
}

/// A note that does not encrypt its value
#[derive(Clone, Copy, Debug)]
pub struct Note {
    pub(crate) note_type: NoteType,
    pub(crate) value_commitment: JubJubExtended,
    pub(crate) nonce: JubJubScalar,
    pub(crate) stealth_address: StealthAddress,
    pub(crate) pos: u64,
    pub(crate) encrypted_data: PoseidonCipher,
}

impl PartialEq for Note {
    fn eq(&self, other: &Self) -> bool {
        self.hash() == other.hash()
    }
}

impl Eq for Note {}

impl Default for Note {
    fn default() -> Self {
        Note::new(NoteType::Transparent, &PublicSpendKey::default(), 0)
    }
}

impl Read for Note {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut buf = io::BufWriter::new(&mut buf[..]);
        let mut n = 0;

        n += buf.write(&[self.note_type as u8])?;
        n += buf.write(
            &JubJubAffine::from(&self.value_commitment).to_bytes()[..],
        )?;
        n += buf.write(&self.nonce.to_bytes())?;
        n += buf.write(&self.stealth_address.to_bytes())?;
        n += buf.write(&self.pos.to_le_bytes())?;
        n += buf.write(&self.encrypted_data.to_bytes())?;

        buf.flush()?;
        Ok(n)
    }
}

impl Write for Note {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut buf = io::BufReader::new(&buf[..]);

        let mut one_byte = [0u8; 1];
        let mut one_scalar = [0u8; 32];
        let mut one_u64 = [0u8; 8];
        let mut one_stealth_address = [0u8; 64];
        let mut one_cipher = [0u8; ENCRYPTED_DATA_SIZE];
        let mut n = 0;

        buf.read_exact(&mut one_byte)?;
        n += one_byte.len();
        self.note_type = one_byte[0].try_into()?;

        buf.read_exact(&mut one_scalar)?;
        n += one_scalar.len();
        self.value_commitment =
            JubJubExtended::from(jubjub_decode::<JubJubAffine>(&one_scalar)?);

        buf.read_exact(&mut one_scalar)?;
        n += one_scalar.len();
        self.nonce = jubjub_decode::<JubJubScalar>(&one_scalar)?;

        buf.read_exact(&mut one_stealth_address)?;
        n += one_stealth_address.len();
        self.stealth_address =
            StealthAddress::from_bytes(&one_stealth_address)?;

        buf.read_exact(&mut one_u64)?;
        n += one_u64.len();
        self.pos = u64::from_le_bytes(one_u64);

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

impl Note {
    /// Creates a new phoenix output note
    pub fn new(note_type: NoteType, psk: &PublicSpendKey, value: u64) -> Self {
        let r = JubJubScalar::random(&mut rand::thread_rng());
        let nonce = JubJubScalar::random(&mut rand::thread_rng());
        let blinding_factor = JubJubScalar::random(&mut rand::thread_rng());

        Self::deterministic(note_type, &r, nonce, psk, value, blinding_factor)
    }

    /// Creates a new transparent note
    pub fn transparent(psk: &PublicSpendKey, value: u64) -> Self {
        Self::new(NoteType::Transparent, psk, value)
    }

    /// Creates a new obfuscated note
    pub fn obfuscated(psk: &PublicSpendKey, value: u64) -> Self {
        Self::new(NoteType::Obfuscated, psk, value)
    }

    /// Create a new phoenix output note without inner randomness
    pub fn deterministic(
        note_type: NoteType,
        r: &JubJubScalar,
        nonce: JubJubScalar,
        psk: &PublicSpendKey,
        value: u64,
        blinding_factor: JubJubScalar,
    ) -> Self {
        let stealth_address = psk.gen_stealth_address(r);

        let value_commitment = JubJubScalar::from(value);
        let value_commitment = (GENERATOR_EXTENDED * value_commitment)
            + (GENERATOR_NUMS_EXTENDED * blinding_factor);

        // Output notes have undefined position
        let pos = 0;

        let encrypted_data = match note_type {
            NoteType::Transparent => {
                let mut encrypted_data = [BlsScalar::zero(); CIPHER_SIZE];
                encrypted_data[0] = BlsScalar::from(value);
                PoseidonCipher::new(encrypted_data)
            }
            NoteType::Obfuscated => {
                let shared_secret = dhke(r, psk.A());
                let nonce = BlsScalar::from(nonce);
                let value = BlsScalar::from(value);
                let blinding_factor = BlsScalar::from(blinding_factor);

                PoseidonCipher::encrypt(
                    &[value, blinding_factor],
                    &shared_secret,
                    &nonce,
                )
            }
        };

        Note {
            note_type,
            value_commitment,
            nonce,
            stealth_address,
            pos,
            encrypted_data,
        }
    }

    fn decrypt_data(&self, vk: &ViewKey) -> Result<(u64, JubJubScalar), Error> {
        let R = self.stealth_address.R();
        let shared_secret = dhke(vk.a(), R);
        let nonce = BlsScalar::from(self.nonce);

        let data = self.encrypted_data.decrypt(&shared_secret, &nonce)?;

        let value = data[0].reduce();
        let value = value.0[0];

        // Converts the BLS Scalar into a JubJub Scalar.
        let blinding_factor = JubJubScalar::from_bytes(&data[1].to_bytes());

        // If the `vk` is wrong it might fails since the resulting BLS Scalar
        // might not fit into a JubJub Scalar.
        if blinding_factor.is_none().into() {
            return Err(Error::InvalidBlindingFactor);
        }

        // Safe to unwrap
        Ok((value, blinding_factor.unwrap()))
    }

    /// Create a unique nullifier for the note
    pub fn gen_nullifier(&self, sk: &SecretSpendKey) -> BlsScalar {
        let sk_r = sk.sk_r(&self.stealth_address);
        let sk_r = BlsScalar::from(sk_r);
        let pos = BlsScalar::from(self.pos());

        sponge_hash(&[sk_r, pos])
    }

    /// Return a hash represented by `H(value_commitment, pos, H([R]),
    /// H([pskr]))`
    pub fn hash(&self) -> BlsScalar {
        let value_commitment = self.value_commitment().to_hash_inputs();
        let pk_r = self.stealth_address().pk_r().to_hash_inputs();

        sponge_hash(&[
            value_commitment[0],
            value_commitment[1],
            BlsScalar::from(self.pos()),
            pk_r[0],
            pk_r[1],
        ])
    }

    /// Return the type of the note
    pub fn note(&self) -> NoteType {
        self.note_type
    }

    /// Return the position of the note on the tree.
    pub fn pos(&self) -> u64 {
        self.pos
    }

    /// Set the position of the note on the tree.
    /// This, naturally, won't reflect immediatelly on the data storage
    pub fn set_pos(&mut self, pos: u64) {
        self.pos = pos;
    }

    /// Nonce used for the encrypt / decrypt of data for this note
    pub fn nonce(&self) -> &JubJubScalar {
        &self.nonce
    }

    /// Return the value commitment `H(value, blinding_factor)`
    pub fn value_commitment(&self) -> &JubJubExtended {
        &self.value_commitment
    }

    /// Attempt to decrypt the note value provided a [`ViewKey`]. Always
    /// succeeds for transparent notes, might fails or return random values for
    /// obfuscated notes if the provided view key is wrong.
    pub fn value(&self, vk: Option<&ViewKey>) -> Result<u64, Error> {
        match self.note_type {
            NoteType::Transparent => {
                let value = self.encrypted_data.cipher();
                let value = value[0].reduce();
                Ok(value.0[0])
            }
            NoteType::Obfuscated if vk.is_some() => {
                let (value, _) = self.decrypt_data(vk.unwrap())?;
                Ok(value)
            }
            _ => Err(Error::MissingViewKey),
        }
    }

    /// Decrypt the blinding factor with the provided [`ViewKey`]
    ///
    /// If the decrypt fails, a random value is returned
    pub fn blinding_factor(
        &self,
        vk: Option<&ViewKey>,
    ) -> Result<JubJubScalar, Error> {
        match self.note_type {
            NoteType::Transparent => Ok(JubJubScalar::zero()),
            NoteType::Obfuscated if vk.is_some() => {
                let (_, blinding_factor) = self.decrypt_data(vk.unwrap())?;
                Ok(blinding_factor)
            }
            _ => Err(Error::MissingViewKey),
        }
    }
}

impl Ownable for Note {
    fn stealth_address(&self) -> &StealthAddress {
        &self.stealth_address
    }
}

impl<H: ByteHash> Content<H> for Note {
    fn persist(&mut self, sink: &mut Sink<H>) -> io::Result<()> {
        (self.note_type as u8).persist(sink)?;

        sink.write_all(&JubJubAffine::from(&self.value_commitment).to_bytes())?;
        sink.write_all(&self.stealth_address.to_bytes())?;

        sink.write_all(&self.nonce.to_bytes())?;
        self.pos.persist(sink)?;

        sink.write_all(&self.encrypted_data.to_bytes())?;
        Ok(())
    }

    fn restore(source: &mut Source<H>) -> io::Result<Self> {
        let mut one_scalar = [0u8; 32];
        let mut one_stealth_address = [0u8; 64];
        let mut one_cipher = [0u8; ENCRYPTED_DATA_SIZE];

        let note_type = u8::restore(source)?.try_into()?;

        source.read_exact(&mut one_scalar)?;
        let value_commitment =
            JubJubExtended::from(jubjub_decode::<JubJubAffine>(&one_scalar)?);

        source.read_exact(&mut one_stealth_address)?;
        let stealth_address = StealthAddress::try_from(&one_stealth_address)?;

        source.read_exact(&mut one_scalar)?;
        let nonce = jubjub_decode::<JubJubScalar>(&one_scalar)?;

        let pos = u64::restore(source)?;

        source.read_exact(&mut one_cipher)?;
        let encrypted_data = PoseidonCipher::from_bytes(&one_cipher)
            .ok_or(Error::InvalidCipher)?;

        Ok(Note {
            note_type,
            value_commitment,
            nonce,
            stealth_address,
            pos,
            encrypted_data,
        })
    }
}

impl From<&Note> for StorageScalar {
    fn from(value: &Note) -> Self {
        StorageScalar(value.hash())
    }
}

impl From<Note> for StorageScalar {
    fn from(value: Note) -> Self {
        (&value).into()
    }
}
