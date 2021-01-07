// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use core::convert::{TryFrom, TryInto};

use dusk_jubjub::{dhke, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use dusk_pki::{
    jubjub_decode, Ownable, PublicSpendKey, SecretSpendKey, StealthAddress,
    ViewKey,
};
use poseidon252::cipher::PoseidonCipher;
use poseidon252::sponge::hash;
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "canon")]
use canonical::Canon;
#[cfg(feature = "canon")]
use canonical_derive::Canon;

use crate::fee::Remainder;
use crate::{BlsScalar, Error, JubJubAffine, JubJubExtended, JubJubScalar};

/// Blinder used for transparent
const TRANSPARENT_BLINDER: JubJubScalar = JubJubScalar::zero();

/// The types of a Note
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[cfg_attr(feature = "canon", derive(Canon))]
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
#[cfg_attr(feature = "canon", derive(Canon))]
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

impl Note {
    /// Creates a new phoenix output note
    pub fn new<R: RngCore + CryptoRng>(
        rng: &mut R,
        note_type: NoteType,
        psk: &PublicSpendKey,
        value: u64,
        blinding_factor: JubJubScalar,
    ) -> Self {
        let r = JubJubScalar::random(rng);
        let nonce = JubJubScalar::random(rng);

        Self::deterministic(note_type, &r, nonce, psk, value, blinding_factor)
    }

    /// Creates a new transparent note
    ///
    /// The blinding factor will be constant zero since the value commitment
    /// exists only to shield the value. The value is not hidden for transparent
    /// notes, so this can be trivially treated as a constant.
    pub fn transparent<R: RngCore + CryptoRng>(
        rng: &mut R,
        psk: &PublicSpendKey,
        value: u64,
    ) -> Self {
        Self::new(rng, NoteType::Transparent, psk, value, TRANSPARENT_BLINDER)
    }

    /// Creates a new obfuscated note
    ///
    /// The provided blinding factor will be used to calculate the value
    /// commitment of the note. The tuple (value, blinding_factor), known by
    /// the caller of this function, must be later used to prove the
    /// knowledge of the value commitment of this note.
    pub fn obfuscated<R: RngCore + CryptoRng>(
        rng: &mut R,
        psk: &PublicSpendKey,
        value: u64,
        blinding_factor: JubJubScalar,
    ) -> Self {
        Self::new(rng, NoteType::Obfuscated, psk, value, blinding_factor)
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

        // Output notes have undefined position, equals to u64's MAX value
        let pos = u64::MAX;

        let encrypted_data = match note_type {
            NoteType::Transparent => {
                let zero = TRANSPARENT_BLINDER.into();
                let mut encrypted_data = [zero; PoseidonCipher::cipher_size()];

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

        hash(&[sk_r, pos])
    }

    /// Return the internal representation of scalars to be hashed
    pub fn hash_inputs(&self) -> [BlsScalar; 12] {
        let value_commitment = self.value_commitment().to_hash_inputs();
        let pk_r = self.stealth_address().pk_r().to_hash_inputs();
        let R = self.stealth_address().R().to_hash_inputs();
        let cipher = self.encrypted_data.cipher();

        [
            BlsScalar::from(self.note_type as u64),
            value_commitment[0],
            value_commitment[1],
            BlsScalar::from(self.nonce),
            pk_r[0],
            pk_r[1],
            R[0],
            R[1],
            BlsScalar::from(self.pos()),
            cipher[0],
            cipher[1],
            cipher[2],
        ]
    }

    /// Return a hash represented by `H(note_type, value_commitment,
    /// H(StealthAddress), pos, encrypted_data)
    pub fn hash(&self) -> BlsScalar {
        hash(&self.hash_inputs())
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

    /// Returns the cipher of the encrypted data
    pub fn cipher(&self) -> &[BlsScalar; PoseidonCipher::cipher_size()] {
        self.encrypted_data.cipher()
    }

    /// Attempt to decrypt the note value provided a [`ViewKey`]. Always
    /// succeeds for transparent notes, might fails or return random values for
    /// obfuscated notes if the provided view key is wrong.
    pub fn value(&self, vk: Option<&ViewKey>) -> Result<u64, Error> {
        match (self.note_type, vk) {
            (NoteType::Transparent, _) => {
                let value = self.encrypted_data.cipher();
                let value = value[0].reduce();
                Ok(value.0[0])
            }
            (NoteType::Obfuscated, Some(vk)) => {
                self.decrypt_data(vk).map(|(value, _)| value)
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
        match (self.note_type, vk) {
            (NoteType::Transparent, _) => Ok(TRANSPARENT_BLINDER),
            (NoteType::Obfuscated, Some(vk)) => self
                .decrypt_data(vk)
                .map(|(_, blinding_factor)| blinding_factor),
            _ => Err(Error::MissingViewKey),
        }
    }

    /// Converts a Note into a byte representation
    pub fn to_bytes(&self) -> [u8; Note::serialized_size()] {
        let mut buf = [0u8; Note::serialized_size()];
        let mut n = 0;

        buf[n] = self.note_type as u8;
        n += 1;

        buf[n..n + 32].copy_from_slice(
            &JubJubAffine::from(&self.value_commitment).to_bytes()[..],
        );
        n += 32;

        buf[n..n + 32].copy_from_slice(&self.nonce.to_bytes()[..]);
        n += 32;

        buf[n..n + 64].copy_from_slice(&self.stealth_address.to_bytes()[..]);
        n += 64;

        buf[n..n + 8].copy_from_slice(&self.pos.to_le_bytes()[..]);
        n += 8;

        buf[n..n + PoseidonCipher::cipher_size_bytes()]
            .copy_from_slice(&self.encrypted_data.to_bytes()[..]);
        n += PoseidonCipher::cipher_size_bytes();

        debug_assert_eq!(n, Note::serialized_size());

        buf
    }

    /// Attempts to convert a byte representation of a note into a `Note`,
    /// failing if the input is invalid
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < Note::serialized_size() {
            return Err(Error::InvalidNoteConversion);
        }

        let mut one_scalar = [0u8; 32];
        let mut one_u64 = [0u8; 8];
        let mut one_stealth_address = [0u8; 64];
        let mut one_cipher = [0u8; PoseidonCipher::cipher_size_bytes()];

        let mut n = 0;

        let note_type = bytes[0].try_into()?;
        n += 1;

        one_scalar.copy_from_slice(&bytes[n..n + 32]);
        let value_commitment =
            JubJubExtended::from(jubjub_decode::<JubJubAffine>(&one_scalar)?);
        n += 32;

        one_scalar.copy_from_slice(&bytes[n..n + 32]);
        let nonce = jubjub_decode::<JubJubScalar>(&one_scalar)?;
        n += 32;

        one_stealth_address.copy_from_slice(&bytes[n..n + 64]);
        let stealth_address = StealthAddress::from_bytes(&one_stealth_address)?;
        n += 64;

        one_u64.copy_from_slice(&bytes[n..n + 8]);
        let pos = u64::from_le_bytes(one_u64);
        n += 8;

        one_cipher.copy_from_slice(
            &bytes[n..n + PoseidonCipher::cipher_size_bytes()],
        );
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

    /// Returns the size in bytes required to serialize the Note
    pub const fn serialized_size() -> usize {
        let note_type = 1;
        let value_commitment = 32;
        let nonce = 32;
        let stealth_address = 64;
        let pos = 8;

        note_type
            + value_commitment
            + nonce
            + stealth_address
            + pos
            + PoseidonCipher::cipher_size_bytes()
    }

    /// Create a new transparent note from a provided random number generator
    /// and the remainder of a transaction for the provided public spend key
    pub fn from_remainder<R: RngCore + CryptoRng>(
        rng: &mut R,
        remainder: Remainder,
        psk: &PublicSpendKey,
    ) -> Self {
        let mut note = Note::transparent(rng, psk, remainder.gas_changes);

        note.stealth_address = remainder.stealth_address;

        note
    }
}

impl Ownable for Note {
    fn stealth_address(&self) -> &StealthAddress {
        &self.stealth_address
    }
}
