// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use core::convert::{TryFrom, TryInto};

use crate::{Error, Ownable, PublicKey, SecretKey, StealthAddress, ViewKey};
use dusk_bls12_381::BlsScalar;
use dusk_bytes::{DeserializableSlice, Error as BytesError, Serializable};
use dusk_jubjub::{
    dhke, JubJubAffine, JubJubExtended, JubJubScalar, GENERATOR_EXTENDED,
    GENERATOR_NUMS_EXTENDED,
};

use crate::aes;

use dusk_poseidon::sponge::hash;
use ff::Field;
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

/// Blinder used for transparent
pub(crate) const TRANSPARENT_BLINDER: JubJubScalar = JubJubScalar::zero();

/// Size of the Phoenix notes plaintext: value (8 bytes) + blinder (32 bytes)
pub(crate) const PLAINTEXT_SIZE: usize = 40;

/// Size of the Phoenix notes encryption
pub(crate) const ENCRYPTION_SIZE: usize =
    PLAINTEXT_SIZE + aes::ENCRYPTION_EXTRA_SIZE;

/// The types of a Note
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
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
#[derive(Clone, Debug)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct Note {
    pub(crate) note_type: NoteType,
    pub(crate) value_commitment: JubJubExtended,
    pub(crate) stealth_address: StealthAddress,
    pub(crate) pos: u64,
    pub(crate) encryption: [u8; ENCRYPTION_SIZE],
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
        pk: &PublicKey,
        value: u64,
        blinding_factor: JubJubScalar,
    ) -> Self {
        let r = JubJubScalar::random(&mut *rng);
        let stealth_address = pk.gen_stealth_address(&r);

        let value_commitment = JubJubScalar::from(value);
        let value_commitment = (GENERATOR_EXTENDED * value_commitment)
            + (GENERATOR_NUMS_EXTENDED * blinding_factor);

        // Output notes have undefined position, equals to u64's MAX value
        let pos = u64::MAX;

        let encryption = match note_type {
            NoteType::Transparent => {
                let mut encryption = [0u8; ENCRYPTION_SIZE];
                encryption[..u64::SIZE].copy_from_slice(&value.to_bytes());

                encryption
            }
            NoteType::Obfuscated => {
                let shared_secret = dhke(&r, pk.A());
                let blinding_factor = BlsScalar::from(blinding_factor);

                let mut plaintext = value.to_bytes().to_vec();
                plaintext.append(&mut blinding_factor.to_bytes().to_vec());

                aes::encrypt(&shared_secret, &plaintext, rng)
                    .expect("Encrypted correctly.")
            }
        };

        Note {
            note_type,
            value_commitment,
            stealth_address,
            pos,
            encryption,
        }
    }

    /// Creates a new transparent note
    ///
    /// The blinding factor will be constant zero since the value commitment
    /// exists only to shield the value. The value is not hidden for transparent
    /// notes, so this can be trivially treated as a constant.
    pub fn transparent<R: RngCore + CryptoRng>(
        rng: &mut R,
        pk: &PublicKey,
        value: u64,
    ) -> Self {
        Self::new(rng, NoteType::Transparent, pk, value, TRANSPARENT_BLINDER)
    }

    /// Creates a new transparent note
    ///
    /// This is equivalent to [`transparent`] but taking only a stealth address,
    /// and a value. This is done to be able to generate a note
    /// directly for a stealth address, as opposed to a public key.
    pub fn transparent_stealth(
        stealth_address: StealthAddress,
        value: u64,
    ) -> Self {
        let value_commitment = JubJubScalar::from(value);
        let value_commitment = (GENERATOR_EXTENDED * value_commitment)
            + (GENERATOR_NUMS_EXTENDED * TRANSPARENT_BLINDER);

        let pos = u64::MAX;

        let mut encryption = [0u8; ENCRYPTION_SIZE];
        encryption[..u64::SIZE].copy_from_slice(&value.to_bytes());

        Note {
            note_type: NoteType::Transparent,
            value_commitment,
            stealth_address,
            pos,
            encryption,
        }
    }

    /// Creates a new obfuscated note
    ///
    /// The provided blinding factor will be used to calculate the value
    /// commitment of the note. The tuple (value, blinding_factor), known by
    /// the caller of this function, must be later used to prove the
    /// knowledge of the value commitment of this note.
    pub fn obfuscated<R: RngCore + CryptoRng>(
        rng: &mut R,
        pk: &PublicKey,
        value: u64,
        blinding_factor: JubJubScalar,
    ) -> Self {
        Self::new(rng, NoteType::Obfuscated, pk, value, blinding_factor)
    }

    /// Creates a new empty [`Note`]
    pub fn empty() -> Self {
        Self {
            note_type: NoteType::Transparent,
            value_commitment: JubJubExtended::default(),
            stealth_address: StealthAddress::default(),
            pos: 0,
            encryption: [0; ENCRYPTION_SIZE],
        }
    }

    fn decrypt_data(
        &self,
        vk: &ViewKey,
    ) -> Result<(u64, JubJubScalar), BytesError> {
        let R = self.stealth_address.R();
        let shared_secret = dhke(vk.a(), R);

        let dec_plaintext: [u8; PLAINTEXT_SIZE] =
            aes::decrypt(&shared_secret, &self.encryption)?;

        let value = u64::from_slice(&dec_plaintext[..u64::SIZE])?;

        // Converts the BLS Scalar into a JubJub Scalar.
        // If the `vk` is wrong it might fails since the resulting BLS Scalar
        // might not fit into a JubJub Scalar.
        let blinding_factor =
            match JubJubScalar::from_slice(&dec_plaintext[u64::SIZE..])?.into()
            {
                Some(scalar) => scalar,
                None => return Err(BytesError::InvalidData),
            };

        Ok((value, blinding_factor))
    }

    /// Create a unique nullifier for the note
    ///
    /// This nullifier is represeted as `H(note_sk · G', pos)`
    pub fn gen_nullifier(&self, sk: &SecretKey) -> BlsScalar {
        let note_sk = sk.gen_note_sk(self.stealth_address);
        let pk_prime = GENERATOR_NUMS_EXTENDED * note_sk.as_ref();
        let pk_prime = pk_prime.to_hash_inputs();

        let pos = BlsScalar::from(self.pos);

        hash(&[pk_prime[0], pk_prime[1], pos])
    }

    /// Return the internal representation of scalars to be hashed
    pub fn hash_inputs(&self) -> [BlsScalar; 6] {
        let value_commitment = self.value_commitment().to_hash_inputs();
        let note_pk =
            self.stealth_address().note_pk().as_ref().to_hash_inputs();

        [
            BlsScalar::from(self.note_type as u64),
            value_commitment[0],
            value_commitment[1],
            note_pk[0],
            note_pk[1],
            BlsScalar::from(self.pos),
        ]
    }

    /// Return a hash represented by `H(note_type, value_commitment,
    /// H(StealthAddress), pos, encrypted_data)
    pub fn hash(&self) -> BlsScalar {
        hash(&self.hash_inputs())
    }

    /// Return the type of the note
    pub const fn note(&self) -> NoteType {
        self.note_type
    }

    /// Return the position of the note on the tree.
    pub const fn pos(&self) -> &u64 {
        &self.pos
    }

    /// Set the position of the note on the tree.
    /// This, naturally, won't reflect immediatelly on the data storage
    pub fn set_pos(&mut self, pos: u64) {
        self.pos = pos;
    }

    /// Return the value commitment `H(value, blinding_factor)`
    pub const fn value_commitment(&self) -> &JubJubExtended {
        &self.value_commitment
    }

    /// Returns the cipher of the encrypted data
    pub const fn encryption(&self) -> &[u8; ENCRYPTION_SIZE] {
        &self.encryption
    }

    /// Attempt to decrypt the note value provided a [`ViewKey`]. Always
    /// succeeds for transparent notes, might fails or return random values for
    /// obfuscated notes if the provided view key is wrong.
    pub fn value(&self, vk: Option<&ViewKey>) -> Result<u64, Error> {
        match (self.note_type, vk) {
            (NoteType::Transparent, _) => {
                let value =
                    u64::from_slice(&self.encryption[..u64::SIZE]).unwrap();
                Ok(value)
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

// Serialize into 105 + ENCRYPTION_SIZE bytes, where 105 is the size of all the
// note elements without the encryption. ENCRYPTION_SIZE = PLAINTEXT_SIZE +
// ENCRYPTION_EXTRA_SIZE
impl Serializable<{ 105 + ENCRYPTION_SIZE }> for Note {
    type Error = BytesError;

    /// Converts a Note into a byte representation
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];

        buf[0] = self.note_type as u8;

        buf[1..33].copy_from_slice(
            &JubJubAffine::from(&self.value_commitment).to_bytes(),
        );
        buf[33..97].copy_from_slice(&self.stealth_address.to_bytes());
        buf[97..105].copy_from_slice(&self.pos.to_le_bytes());
        buf[105..].copy_from_slice(&self.encryption);
        buf
    }

    /// Attempts to convert a byte representation of a note into a `Note`,
    /// failing if the input is invalid
    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let mut one_u64 = [0u8; 8];

        let note_type =
            bytes[0].try_into().map_err(|_| BytesError::InvalidData)?;
        let value_commitment =
            JubJubExtended::from(JubJubAffine::from_slice(&bytes[1..33])?);
        let stealth_address = StealthAddress::from_slice(&bytes[33..97])?;

        one_u64.copy_from_slice(&bytes[97..105]);
        let pos = u64::from_le_bytes(one_u64);

        let mut encryption = [0u8; ENCRYPTION_SIZE];
        encryption.copy_from_slice(&bytes[105..]);

        Ok(Note {
            note_type,
            value_commitment,
            stealth_address,
            pos,
            encryption,
        })
    }
}
