// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for
// details.

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

use crate::{
    chunk_of, BlsScalar, Error, JubJubAffine, JubJubExtended, JubJubScalar,
};

use poseidon252::cipher::ENCRYPTED_DATA_SIZE;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum NoteType {
    Transparent = 0,
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
#[derive(Clone, Copy)]
pub struct Note {
    note_type: NoteType,
    value_commitment: JubJubExtended,
    nonce: JubJubScalar,
    stealth_address: StealthAddress,
    pos: u64,
    encrypted_data: [u8; ENCRYPTED_DATA_SIZE],
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

// TODO: Remove once we have encrypted data type
impl std::fmt::Debug for Note {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Note")
            .field("note_type", &self.note_type)
            .field("value_commitment", &self.value_commitment)
            .field("nonce", &self.nonce)
            .field("stealth_address", &self.stealth_address)
            .field("pos", &self.pos)
            .field(
                "encrypted_data",
                &format_args!("{:?}", &self.encrypted_data),
            )
            .finish()
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
        n += buf.write(&self.encrypted_data[..])?;

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

        buf.read_exact(&mut self.encrypted_data)?;
        n += self.encrypted_data.len();

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
        let value_commitment = &(GENERATOR_EXTENDED * value_commitment)
            + &(GENERATOR_NUMS_EXTENDED * blinding_factor);

        // Output notes have undefined position
        let pos = 0;

        let encrypted_data = match note_type {
            NoteType::Transparent => {
                chunk_of!(ENCRYPTED_DATA_SIZE; &value.to_le_bytes())
            }
            NoteType::Obfuscated => {
                let shared_secret = dhke(r, psk.A());
                let nonce = BlsScalar::from(nonce);
                let value = BlsScalar::from(value);
                let blinding_factor = BlsScalar::from(blinding_factor);

                let mut cipher = PoseidonCipher::encrypt(
                    &[value, blinding_factor],
                    &shared_secret,
                    &nonce,
                );

                // TODO: replace the internals of PoseidonCipher with a plain
                // array.
                // Adding an infallible `to_bytes` method too.
                let mut encrypted_data = [0u8; 96];
                cipher
                    .read_exact(&mut encrypted_data)
                    .expect("Cannot encode PoseidonCipher");
                encrypted_data
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

    /// Reconstruct a Note from its individual fields.
    pub fn reconstruct(
        note_type: NoteType,
        value_commitment: JubJubExtended,
        nonce: JubJubScalar,
        stealth_address: StealthAddress,
        pos: u64,
        encrypted_data: [u8; ENCRYPTED_DATA_SIZE],
    ) -> Self {
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

        // TODO: replace the internals of PoseidonCipher with a plain
        // array.
        let mut cipher = PoseidonCipher::default();

        cipher.write(&self.encrypted_data[..])?;

        let data = cipher.decrypt(&shared_secret, &nonce)?;

        // Converts the least significant bytes of the decrypted value
        // into `u64`, therefore even with a wrong `vk` cannot fails.
        let value = u64::from_le_bytes(chunk_of!(8; data[0].to_bytes()[..8]));

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
                let bytes = chunk_of!(8; &self.encrypted_data);
                Ok(u64::from_le_bytes(bytes))
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
    fn stealth_address<'a>(&'a self) -> &'a StealthAddress {
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

        sink.write_all(&self.encrypted_data)?;
        Ok(())
    }

    fn restore(source: &mut Source<H>) -> io::Result<Self> {
        let mut one_scalar = [0u8; 32];
        let mut one_stealth_address = [0u8; 64];

        let note_type = u8::restore(source)?.try_into()?;

        source.read_exact(&mut one_scalar)?;
        let value_commitment =
            JubJubExtended::from(jubjub_decode::<JubJubAffine>(&one_scalar)?);

        source.read_exact(&mut one_stealth_address)?;
        let stealth_address = StealthAddress::try_from(&one_stealth_address)?;

        source.read_exact(&mut one_scalar)?;
        let nonce = jubjub_decode::<JubJubScalar>(&one_scalar)?;

        let pos = u64::restore(source)?;

        let mut encrypted_data = [0u8; ENCRYPTED_DATA_SIZE];
        source.read_exact(&mut encrypted_data)?;

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
