// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use core::convert::{TryFrom, TryInto};

use dusk_bls12_381::BlsScalar;
use dusk_bytes::{DeserializableSlice, Error as BytesError, Serializable};
use dusk_jubjub::{dhke, JubJubAffine, JubJubScalar, GENERATOR_NUMS_EXTENDED};
use dusk_poseidon::{Domain, Hash};
use ff::Field;
use jubjub_elgamal::{DecryptFrom, Encryption as ElGamal};
use jubjub_schnorr::{PublicKey as NotePublicKey, SecretKey as NoteSecretKey};
use rand::{CryptoRng, RngCore};

use crate::{
    aes, transparent_value_commitment, value_commitment, Error, PublicKey,
    SecretKey, StealthAddress, ViewKey,
};

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

/// Blinder used for transparent notes.
pub(crate) const TRANSPARENT_BLINDER: JubJubScalar = JubJubScalar::zero();

/// Size of the Phoenix notes plaintext: value (8 bytes) + blinder (32 bytes)
pub(crate) const PLAINTEXT_SIZE: usize = 40;

/// Size of the Phoenix notes value_enc
pub const VALUE_ENC_SIZE: usize = PLAINTEXT_SIZE + aes::ENCRYPTION_EXTRA_SIZE;

/// The types of a Note
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

/// Phoenix Note struct
#[derive(Clone, Debug, Eq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Note {
    pub(crate) note_type: NoteType,
    pub(crate) value_commitment: JubJubAffine,
    pub(crate) stealth_address: StealthAddress,
    #[cfg_attr(
        feature = "serde",
        serde(with = "serde_with::As::<serde_with::DisplayFromStr>")
    )]
    pub(crate) pos: u64,
    #[cfg_attr(
        feature = "serde",
        serde(with = "serde_with::As::<serde_with::hex::Hex>")
    )]
    pub(crate) value_enc: [u8; VALUE_ENC_SIZE],
    pub(crate) sender: Sender,
}

impl PartialEq for Note {
    fn eq(&self, other: &Self) -> bool {
        self.value_enc == other.value_enc
            && self.sender == other.sender
            && self.hash() == other.hash()
    }
}

impl Note {
    /// Creates a new phoenix output note
    pub fn new<R: RngCore + CryptoRng>(
        rng: &mut R,
        note_type: NoteType,
        sender_pk: &PublicKey,
        receiver_pk: &PublicKey,
        value: u64,
        value_blinder: JubJubScalar,
        sender_blinder: [JubJubScalar; 2],
    ) -> Self {
        let r = JubJubScalar::random(&mut *rng);
        let stealth_address = receiver_pk.gen_stealth_address(&r);

        let value_commitment = value_commitment(value, value_blinder);

        // Output notes have undefined position, equals to u64's MAX value
        let pos = u64::MAX;

        let value_enc = match note_type {
            NoteType::Transparent => {
                let mut value_enc = [0u8; VALUE_ENC_SIZE];
                value_enc[..u64::SIZE].copy_from_slice(&value.to_bytes());

                value_enc
            }
            NoteType::Obfuscated => {
                let shared_secret = dhke(&r, receiver_pk.A());
                let value_blinder = BlsScalar::from(value_blinder);

                let mut plaintext = value.to_bytes().to_vec();
                plaintext.append(&mut value_blinder.to_bytes().to_vec());

                let salt = stealth_address.to_bytes();

                aes::encrypt(&shared_secret, &salt, &plaintext, rng)
                    .expect("Encrypted correctly.")
            }
        };

        Note {
            note_type,
            value_commitment,
            stealth_address,
            pos,
            value_enc,
            sender: Sender::encrypt(
                stealth_address.note_pk(),
                sender_pk,
                &sender_blinder,
            ),
        }
    }

    /// Creates a new transparent note
    ///
    /// The blinding factor will be constant zero since the value commitment
    /// exists only to shield the value. The value is not hidden for transparent
    /// notes, so this can be trivially treated as a constant.
    pub fn transparent<R: RngCore + CryptoRng>(
        rng: &mut R,
        sender_pk: &PublicKey,
        receiver_pk: &PublicKey,
        value: u64,
        sender_blinder: [JubJubScalar; 2],
    ) -> Self {
        Self::new(
            rng,
            NoteType::Transparent,
            sender_pk,
            receiver_pk,
            value,
            TRANSPARENT_BLINDER,
            sender_blinder,
        )
    }

    /// Creates a new transparent note
    ///
    /// This is equivalent to [`transparent`] but taking only a stealth address
    /// and a value. This is done to be able to generate a note
    /// directly for a stealth address, as opposed to a public key.
    pub fn transparent_stealth(
        stealth_address: StealthAddress,
        value: u64,
        sender: impl Into<Sender>,
    ) -> Self {
        let value_commitment = transparent_value_commitment(value);

        let pos = u64::MAX;

        let mut value_enc = [0u8; VALUE_ENC_SIZE];
        value_enc[..u64::SIZE].copy_from_slice(&value.to_bytes());

        Note {
            note_type: NoteType::Transparent,
            value_commitment,
            stealth_address,
            pos,
            value_enc,
            sender: sender.into(),
        }
    }

    /// Creates a new obfuscated note
    ///
    /// The provided blinding factor will be used to calculate the value
    /// commitment of the note. The tuple (value, value_blinder), known by
    /// the caller of this function, must be later used to prove the
    /// knowledge of the value commitment of this note.
    pub fn obfuscated<R: RngCore + CryptoRng>(
        rng: &mut R,
        sender_pk: &PublicKey,
        receiver_pk: &PublicKey,
        value: u64,
        value_blinder: JubJubScalar,
        sender_blinder: [JubJubScalar; 2],
    ) -> Self {
        Self::new(
            rng,
            NoteType::Obfuscated,
            sender_pk,
            receiver_pk,
            value,
            value_blinder,
            sender_blinder,
        )
    }

    /// Creates a new empty [`Note`]
    pub fn empty() -> Self {
        Self {
            note_type: NoteType::Transparent,
            value_commitment: JubJubAffine::default(),
            stealth_address: StealthAddress::default(),
            pos: 0,
            value_enc: [0; VALUE_ENC_SIZE],
            sender: Sender::Encryption(
                [(JubJubAffine::default(), JubJubAffine::default()); 2],
            ),
        }
    }

    fn decrypt_value(
        &self,
        vk: &ViewKey,
    ) -> Result<(u64, JubJubScalar), Error> {
        let R = self.stealth_address.R();
        let shared_secret = dhke(vk.a(), R);

        let salt = self.stealth_address.to_bytes();

        let dec_plaintext: [u8; PLAINTEXT_SIZE] =
            aes::decrypt(&shared_secret, &salt, &self.value_enc)?;

        let value = u64::from_slice(&dec_plaintext[..u64::SIZE])?;

        // Converts the BLS Scalar into a JubJub Scalar.
        // If the `vk` is wrong it might fails since the resulting BLS Scalar
        // might not fit into a JubJub Scalar.
        let value_blinder =
            match JubJubScalar::from_slice(&dec_plaintext[u64::SIZE..])?.into()
            {
                Some(scalar) => scalar,
                None => return Err(Error::InvalidData),
            };

        Ok((value, value_blinder))
    }

    /// Create a unique nullifier for the note
    ///
    /// This nullifier is represeted as `H(note_sk · G', pos)`
    pub fn gen_nullifier(&self, sk: &SecretKey) -> BlsScalar {
        let note_sk = sk.gen_note_sk(&self.stealth_address);
        let pk_prime = GENERATOR_NUMS_EXTENDED * note_sk.as_ref();
        let pk_prime = pk_prime.to_hash_inputs();

        let pos = BlsScalar::from(self.pos);

        Hash::digest(Domain::Other, &[pk_prime[0], pk_prime[1], pos])[0]
    }

    /// Return the internal representation of scalars to be hashed
    pub fn hash_inputs(&self) -> [BlsScalar; 6] {
        let note_pk =
            self.stealth_address().note_pk().as_ref().to_hash_inputs();

        [
            BlsScalar::from(self.note_type as u64),
            self.value_commitment.get_u(),
            self.value_commitment.get_v(),
            note_pk[0],
            note_pk[1],
            BlsScalar::from(self.pos),
        ]
    }

    /// Return a hash represented by `H(note_type, value_commitment,
    /// H(StealthAddress), pos, encrypted_data)
    pub fn hash(&self) -> BlsScalar {
        Hash::digest(Domain::Other, &self.hash_inputs())[0]
    }

    /// Return the type of the note
    pub const fn note_type(&self) -> NoteType {
        self.note_type
    }

    /// Return the position of the note on the tree.
    pub const fn pos(&self) -> &u64 {
        &self.pos
    }

    /// Returns the the stealth address associated with the note.
    pub const fn stealth_address(&self) -> &StealthAddress {
        &self.stealth_address
    }

    /// Set the position of the note on the tree.
    /// This, naturally, won't reflect immediatelly on the data storage
    pub fn set_pos(&mut self, pos: u64) {
        self.pos = pos;
    }

    /// Return the value commitment `H(value, value_blinder)`
    pub const fn value_commitment(&self) -> &JubJubAffine {
        &self.value_commitment
    }

    /// Returns the cipher of the encrypted data
    pub const fn value_enc(&self) -> &[u8; VALUE_ENC_SIZE] {
        &self.value_enc
    }

    /// Returns elgamal encryption of the sender's [`PublicKey`] encrypted using
    /// the [`StealthAddress::note_pk`] so only the receiver of the [`Note`]
    /// can decrypt.
    pub const fn sender(&self) -> &Sender {
        &self.sender
    }

    /// Attempt to decrypt the note value provided a [`ViewKey`]. Always
    /// succeeds for transparent notes, might fails or return random values for
    /// obfuscated notes if the provided view key is wrong.
    pub fn value(&self, vk: Option<&ViewKey>) -> Result<u64, Error> {
        match (self.note_type, vk) {
            (NoteType::Transparent, _) => {
                let value =
                    u64::from_slice(&self.value_enc[..u64::SIZE]).unwrap();
                Ok(value)
            }
            (NoteType::Obfuscated, Some(vk)) => {
                self.decrypt_value(vk).map(|(value, _)| value)
            }
            _ => Err(Error::MissingViewKey),
        }
    }

    /// Decrypt the blinding factor with the provided [`ViewKey`]
    ///
    /// If the decrypt fails, a random value is returned
    pub fn value_blinder(
        &self,
        vk: Option<&ViewKey>,
    ) -> Result<JubJubScalar, Error> {
        match (self.note_type, vk) {
            (NoteType::Transparent, _) => Ok(TRANSPARENT_BLINDER),
            (NoteType::Obfuscated, Some(vk)) => self
                .decrypt_value(vk)
                .map(|(_, value_blinder)| value_blinder),
            _ => Err(Error::MissingViewKey),
        }
    }
}

const SIZE: usize = 1
    + JubJubAffine::SIZE
    + StealthAddress::SIZE
    + u64::SIZE
    + VALUE_ENC_SIZE
    + Sender::SIZE;

impl Serializable<SIZE> for Note {
    type Error = BytesError;

    /// Converts a Note into a byte representation
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];

        buf[0] = self.note_type as u8;

        let mut start = 1;

        buf[start..start + JubJubAffine::SIZE]
            .copy_from_slice(&self.value_commitment.to_bytes());
        start += JubJubAffine::SIZE;

        buf[start..start + StealthAddress::SIZE]
            .copy_from_slice(&self.stealth_address.to_bytes());
        start += StealthAddress::SIZE;

        buf[start..start + u64::SIZE].copy_from_slice(&self.pos.to_le_bytes());
        start += u64::SIZE;

        buf[start..start + VALUE_ENC_SIZE].copy_from_slice(&self.value_enc);
        start += VALUE_ENC_SIZE;

        buf[start..start + Sender::SIZE]
            .copy_from_slice(&self.sender.to_bytes());

        buf
    }

    /// Attempts to convert a byte representation of a note into a `Note`,
    /// failing if the input is invalid
    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let note_type =
            bytes[0].try_into().map_err(|_| BytesError::InvalidData)?;

        let mut buf = &bytes[1..];

        let value_commitment = JubJubAffine::from_reader(&mut buf)?;

        let stealth_address = StealthAddress::from_reader(&mut buf)?;

        let pos = u64::from_reader(&mut buf)?;

        let mut value_enc = [0u8; VALUE_ENC_SIZE];
        value_enc.copy_from_slice(&buf[..VALUE_ENC_SIZE]);
        buf = &buf[VALUE_ENC_SIZE..];

        let sender = Sender::from_reader(&mut buf)?;

        Ok(Note {
            note_type,
            value_commitment,
            stealth_address,
            pos,
            value_enc,
            sender,
        })
    }
}

/// The sender of the `Note`.
/// This can be either the encrypted sender's [`PublicKey`], if the [`Note`] was
/// created as an output note of a phoenix-transaction, or some contract-data if
/// the [`Note`] was created in another way, e.g. by withdrawing from a
/// contract.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Sender {
    /// The sender's [`PublicKey`], encrypted using the note_pk of the
    /// stealth-address.
    Encryption([(JubJubAffine, JubJubAffine); 2]),
    /// Information to identify the origin of a `Note`, if it wasn't created as
    /// a phoenix-transaction output-note.
    ContractInfo(
        #[cfg_attr(
            feature = "serde",
            serde(with = "serde_with::As::<serde_with::hex::Hex>")
        )]
        [u8; 4 * JubJubAffine::SIZE],
    ),
}

impl Sender {
    /// Create a new [`Sender`] enum by encrypting the sender's [`PublicKey`] in
    /// a way that only the receiver of the note can decrypt.
    pub fn encrypt(
        note_pk: &NotePublicKey,
        sender_pk: &PublicKey,
        blinder: &[JubJubScalar; 2],
    ) -> Self {
        let (sender_enc_A, _) = ElGamal::encrypt(
            note_pk.as_ref(),
            sender_pk.A(),
            None,
            &blinder[0],
        );

        let (sender_enc_B, _) = ElGamal::encrypt(
            note_pk.as_ref(),
            sender_pk.B(),
            None,
            &blinder[1],
        );

        let sender_enc_A: (JubJubAffine, JubJubAffine) =
            (sender_enc_A.c1().into(), sender_enc_A.c2().into());
        let sender_enc_B: (JubJubAffine, JubJubAffine) =
            (sender_enc_B.c1().into(), sender_enc_B.c2().into());

        Self::Encryption([sender_enc_A, sender_enc_B])
    }

    /// Decrypts the [`PublicKey`] of the sender of the [`Note`], using the
    /// [`NoteSecretKey`] generated by the receiver's [`SecretKey`] and the
    /// [`StealthAddress`] of the [`Note`].
    ///
    /// Note: Decryption with an *incorrect* [`NoteSecretKey`] will still yield
    /// a [`PublicKey`], but in this case, the public-key will be a random one
    /// that has nothing to do with the sender's [`PublicKey`].
    ///
    /// Returns an error if the sender is of type [`Sender::ContractInfo`].
    pub fn decrypt(&self, note_sk: &NoteSecretKey) -> Result<PublicKey, Error> {
        let sender_enc = match self {
            Sender::Encryption(enc) => enc,
            Sender::ContractInfo(_) => {
                return Err(Error::InvalidEncryption);
            }
        };

        let sender_enc_A =
            ElGamal::new(sender_enc[0].0.into(), sender_enc[0].1.into());
        let sender_enc_B =
            ElGamal::new(sender_enc[1].0.into(), sender_enc[1].1.into());

        let decrypt_A =
            sender_enc_A.decrypt(&DecryptFrom::SecretKey(*note_sk.as_ref()));
        let decrypt_B =
            sender_enc_B.decrypt(&DecryptFrom::SecretKey(*note_sk.as_ref()));

        Ok(PublicKey::new(decrypt_A, decrypt_B))
    }
}

impl Serializable<{ 1 + 4 * JubJubAffine::SIZE }> for Sender {
    type Error = BytesError;

    /// Converts a Note into a byte representation
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];

        match self {
            Sender::Encryption(sender_enc) => {
                buf[0] = 0;
                let mut start = 1;

                buf[start..start + JubJubAffine::SIZE]
                    .copy_from_slice(&sender_enc[0].0.to_bytes());
                start += JubJubAffine::SIZE;

                buf[start..start + JubJubAffine::SIZE]
                    .copy_from_slice(&sender_enc[0].1.to_bytes());
                start += JubJubAffine::SIZE;

                buf[start..start + JubJubAffine::SIZE]
                    .copy_from_slice(&sender_enc[1].0.to_bytes());
                start += JubJubAffine::SIZE;

                buf[start..start + JubJubAffine::SIZE]
                    .copy_from_slice(&sender_enc[1].1.to_bytes());
            }
            Sender::ContractInfo(contract_data) => {
                buf[0] = 1;
                buf[1..].copy_from_slice(&contract_data[..]);
            }
        }

        buf
    }

    /// Attempts to convert a byte representation of a note into a `Note`,
    /// failing if the input is invalid
    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let sender = match bytes[0] {
            0 => {
                let mut buf = &bytes[1..];
                let sender_enc_A_0 = JubJubAffine::from_reader(&mut buf)?;
                let sender_enc_A_1 = JubJubAffine::from_reader(&mut buf)?;
                let sender_enc_B_0 = JubJubAffine::from_reader(&mut buf)?;
                let sender_enc_B_1 = JubJubAffine::from_reader(&mut buf)?;
                Sender::Encryption([
                    (sender_enc_A_0, sender_enc_A_1),
                    (sender_enc_B_0, sender_enc_B_1),
                ])
            }
            1 => {
                let mut contract_data = [0u8; 4 * JubJubAffine::SIZE];
                contract_data.copy_from_slice(&bytes[1..Self::SIZE]);
                Sender::ContractInfo(contract_data)
            }
            _ => return Err(BytesError::InvalidData),
        };

        Ok(sender)
    }
}
