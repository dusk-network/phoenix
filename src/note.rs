// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![allow(clippy::exhaustive_enums)] // Must be at module level to apply to derive Archive :-L
                                    // Added #[non_exhaustive] nevertheless

use core::convert::{TryFrom, TryInto};

use dusk_bytes::{DeserializableSlice, Error as BytesError, Serializable};
use dusk_jubjub::{dhke, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use dusk_pki::{
    Ownable, PublicSpendKey, SecretSpendKey, StealthAddress, ViewKey,
};
use dusk_poseidon::cipher::PoseidonCipher;
use dusk_poseidon::sponge::hash;
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

use crate::{BlsScalar, Error, JubJubAffine, JubJubExtended, JubJubScalar};

/// Blinder used for transparent
pub(crate) const TRANSPARENT_BLINDER: JubJubScalar = JubJubScalar::zero();

/// The types of a Note
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
#[non_exhaustive]
#[allow(clippy::module_name_repetitions)]
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

#[allow(
    clippy::cast_sign_loss,
    clippy::as_conversions,
    clippy::cast_possible_truncation
)]
impl TryFrom<i32> for NoteType {
    type Error = Error;

    fn try_from(note_type: i32) -> Result<Self, Self::Error> {
        (note_type as u8).try_into()
    }
}

/// A note that does not encrypt its value
#[derive(Clone, Copy, Debug)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct Note {
    pub(crate) note_type: NoteType,
    pub(crate) value_commitment: JubJubExtended,
    pub(crate) nonce: BlsScalar,
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
        let nonce = BlsScalar::random(rng);

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

    /// Creates a new transparent note
    ///
    /// This is equivalent to [`transparent`] but taking only a stealth address,
    /// a value, and a nonce. This is done to be able to generate a note
    /// directly for a stealth address, as opposed to a public spend key.
    #[must_use]
    pub fn transparent_stealth(
        stealth_address: StealthAddress,
        value: u64,
        nonce: BlsScalar,
    ) -> Self {
        let value_commitment = JubJubScalar::from(value);
        let value_commitment = (GENERATOR_EXTENDED * value_commitment)
            + (GENERATOR_NUMS_EXTENDED * TRANSPARENT_BLINDER);

        let pos = u64::MAX;

        let zero = TRANSPARENT_BLINDER.into();
        let mut encrypted_data = [zero; PoseidonCipher::cipher_size()];

        encrypted_data[0] = BlsScalar::from(value);

        let encrypted_data = PoseidonCipher::new(encrypted_data);

        Note {
            note_type: NoteType::Transparent,
            value_commitment,
            nonce,
            stealth_address,
            pos,
            encrypted_data,
        }
    }

    /// Creates a new obfuscated note
    ///
    /// The provided blinding factor will be used to calculate the value
    /// commitment of the note. The tuple (value, ``blinding_factor``), known by
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
    #[must_use]
    pub fn deterministic(
        note_type: NoteType,
        r: &JubJubScalar,
        nonce: BlsScalar,
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

    fn decrypt_data(
        &self,
        vk: &ViewKey,
    ) -> Result<(u64, JubJubScalar), BytesError> {
        let r = self.stealth_address.R();
        let shared_secret = dhke(vk.a(), r);

        let data = self
            .encrypted_data
            .decrypt(&shared_secret, &self.nonce)
            .ok_or(BytesError::InvalidData)?;

        let value = data[0].reduce();
        let value = value.0[0];

        // Converts the BLS Scalar into a JubJub Scalar.
        // If the `vk` is wrong it might fails since the resulting BLS Scalar
        // might not fit into a JubJub Scalar.
        let blinding_factor = JubJubScalar::from_bytes(&data[1].to_bytes())?;

        Ok((value, blinding_factor))
    }

    /// Create a unique nullifier for the note
    ///
    /// This nullifier is represeted as `H(sk_r · G', pos)`
    #[must_use]
    pub fn gen_nullifier(&self, sk: &SecretSpendKey) -> BlsScalar {
        let sk_r = sk.sk_r(&self.stealth_address);
        let pk_prime = GENERATOR_NUMS_EXTENDED * sk_r.as_ref();
        let pk_prime = pk_prime.to_hash_inputs();

        let pos = BlsScalar::from(self.pos);

        hash(&[pk_prime[0], pk_prime[1], pos])
    }

    /// Return the internal representation of scalars to be hashed
    #[must_use]
    #[allow(clippy::as_conversions)]
    pub fn hash_inputs(&self) -> [BlsScalar; 12] {
        let value_commitment = self.value_commitment().to_hash_inputs();
        let pk_r = self.stealth_address().pk_r().as_ref().to_hash_inputs();
        let r = self.stealth_address().R().to_hash_inputs();
        let cipher = self.encrypted_data.cipher();

        [
            BlsScalar::from(self.note_type as u64),
            value_commitment[0],
            value_commitment[1],
            self.nonce,
            pk_r[0],
            pk_r[1],
            r[0],
            r[1],
            BlsScalar::from(self.pos),
            cipher[0],
            cipher[1],
            cipher[2],
        ]
    }

    /// Return a hash represented by `H(note_type, value_commitment,
    /// H(StealthAddress), pos, encrypted_data)`
    #[must_use]
    pub fn hash(&self) -> BlsScalar {
        hash(&self.hash_inputs())
    }

    /// Return the type of the note
    #[must_use]
    pub const fn note(&self) -> NoteType {
        self.note_type
    }

    /// Return the position of the note on the tree.
    #[must_use]
    pub const fn pos(&self) -> &u64 {
        &self.pos
    }

    /// Set the position of the note on the tree.
    /// This, naturally, won't reflect immediatelly on the data storage
    pub fn set_pos(&mut self, pos: u64) {
        self.pos = pos;
    }

    /// Nonce used for the encrypt / decrypt of data for this note
    #[must_use]
    pub const fn nonce(&self) -> &BlsScalar {
        &self.nonce
    }

    /// Return the value commitment `H(value, blinding_factor)`
    #[must_use]
    pub const fn value_commitment(&self) -> &JubJubExtended {
        &self.value_commitment
    }

    /// Returns the cipher of the encrypted data
    #[must_use]
    pub const fn cipher(&self) -> &[BlsScalar; PoseidonCipher::cipher_size()] {
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
            (NoteType::Obfuscated, Some(vk)) => self
                .decrypt_data(vk)
                .map(|(value, _)| value)
                .map_err(|_| Error::InvalidCipher),
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
                .map(|(_, blinding_factor)| blinding_factor)
                .map_err(|_| Error::InvalidCipher),
            _ => Err(Error::MissingViewKey),
        }
    }
}

impl Ownable for Note {
    fn stealth_address(&self) -> &StealthAddress {
        &self.stealth_address
    }
}

impl Serializable<{ 137 + PoseidonCipher::SIZE }> for Note {
    type Error = BytesError;
    /// Converts a Note into a byte representation

    #[allow(clippy::as_conversions)]
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0_u8; Self::SIZE];

        buf[0] = self.note_type as u8;

        buf[1..33].copy_from_slice(
            &JubJubAffine::from(&self.value_commitment).to_bytes(),
        );
        buf[33..65].copy_from_slice(&self.nonce.to_bytes());
        buf[65..129].copy_from_slice(&self.stealth_address.to_bytes());
        buf[129..137].copy_from_slice(&self.pos.to_le_bytes());
        buf[137..].copy_from_slice(&self.encrypted_data.to_bytes());
        buf
    }

    /// Attempts to convert a byte representation of a note into a `Note`,
    /// failing if the input is invalid
    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let mut one_u64 = [0_u8; 8];

        let note_type =
            bytes[0].try_into().map_err(|_| BytesError::InvalidData)?;
        let value_commitment =
            JubJubExtended::from(JubJubAffine::from_slice(&bytes[1..33])?);
        let nonce = BlsScalar::from_slice(&bytes[33..65])?;
        let stealth_address = StealthAddress::from_slice(&bytes[65..129])?;

        one_u64.copy_from_slice(&bytes[129..137]);
        let pos = u64::from_le_bytes(one_u64);

        let encrypted_data = PoseidonCipher::from_slice(&bytes[137..])?;

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
