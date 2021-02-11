// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::{BlsScalar, Error, JubJubExtended, JubJubScalar, Note, NoteType};

#[cfg(feature = "canon")]
use canonical::Canon;
#[cfg(feature = "canon")]
use canonical_derive::Canon;

use dusk_bytes::{DeserializableSlice, Serializable};
use dusk_jubjub::{dhke, JubJubAffine};
use dusk_pki::PublicSpendKey;
use dusk_poseidon::cipher::PoseidonCipher;
use rand_core::{CryptoRng, RngCore};

/// Message structure with value commitment
#[derive(Clone, Copy, Debug, Default, PartialEq)]
#[cfg_attr(feature = "canon", derive(Canon))]
pub struct Message {
    value_commitment: JubJubExtended,
    nonce: JubJubScalar,
    encrypted_data: PoseidonCipher,
}

impl Message {
    /// Create a new message
    ///
    /// `r` will be later used to decrypt the value and blinding factor
    pub fn new<R: RngCore + CryptoRng>(
        rng: &mut R,
        r: &JubJubScalar,
        psk: &PublicSpendKey,
        value: u64,
    ) -> Self {
        let nonce = JubJubScalar::random(rng);
        let blinding_factor = JubJubScalar::random(rng);

        let note = Note::deterministic(
            NoteType::Obfuscated,
            r,
            nonce,
            psk,
            value,
            blinding_factor,
        );
        let Note {
            value_commitment,
            nonce,
            encrypted_data,
            ..
        } = note;

        Self {
            value_commitment,
            nonce,
            encrypted_data,
        }
    }

    /// Value commitment representation of the message
    pub fn value_commitment(&self) -> &JubJubExtended {
        &self.value_commitment
    }

    /// Nonce used for the encryption of the value and blinding factor
    pub fn nonce(&self) -> &JubJubScalar {
        &self.nonce
    }

    /// Returns the cipher of the encrypted data
    pub fn cipher(&self) -> &[BlsScalar; PoseidonCipher::cipher_size()] {
        self.encrypted_data.cipher()
    }

    /// Decrypt the value and blinding factor provided the `r` used in the
    /// creation of the message
    pub fn decrypt(
        &self,
        r: &JubJubScalar,
        psk: &PublicSpendKey,
    ) -> Result<(u64, JubJubScalar), Error> {
        let shared_secret = dhke(r, psk.A());
        let nonce = BlsScalar::from(self.nonce);

        let data = self.encrypted_data.decrypt(&shared_secret, &nonce)?;

        let value = data[0].reduce();
        let value = value.0[0];

        // Converts the BLS Scalar into a JubJub Scalar.
        let blinding_factor = JubJubScalar::from_bytes(&data[1].to_bytes())
            .map_err(|_| Error::InvalidBlindingFactor)?;

        Ok((value, blinding_factor))
    }
}

impl
    Serializable<
        { JubJubAffine::SIZE + JubJubScalar::SIZE + PoseidonCipher::SIZE },
    > for Message
{
    type Error = Error;

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        let mut b = &mut bytes[..];

        let value_commitment =
            JubJubAffine::from(self.value_commitment).to_bytes();
        b[..JubJubAffine::SIZE].copy_from_slice(&value_commitment);
        b = &mut b[JubJubAffine::SIZE..];

        b[..JubJubScalar::SIZE].copy_from_slice(&self.nonce.to_bytes());
        b = &mut b[JubJubScalar::SIZE..];

        b.copy_from_slice(&self.encrypted_data.to_bytes());

        bytes
    }

    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let mut bytes = &bytes[..];

        let value_commitment: JubJubExtended =
            JubJubAffine::from_slice(&bytes[..JubJubAffine::SIZE])
                .map_err(|_| Error::InvalidCommitment)?
                .into();
        bytes = &bytes[JubJubAffine::SIZE..];

        let nonce = JubJubScalar::from_slice(&bytes[..JubJubScalar::SIZE])
            .map_err(|_| Error::InvalidNonce)?;
        bytes = &bytes[JubJubScalar::SIZE..];

        let encrypted_data = PoseidonCipher::from_slice(bytes)
            .map_err(|_| Error::InvalidCipher)?;

        Ok(Self {
            value_commitment,
            nonce,
            encrypted_data,
        })
    }
}

#[test]
fn message_consistency() {
    use dusk_jubjub::{GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
    use dusk_pki::SecretSpendKey;

    let rng = &mut rand::thread_rng();

    let ssk = SecretSpendKey::random(rng);
    let psk = ssk.public_spend_key();
    let psk_wrong = SecretSpendKey::random(rng).public_spend_key();

    let r = JubJubScalar::random(rng);
    let r_wrong = JubJubScalar::random(rng);
    let value = 105;

    let message = Message::new(rng, &r, &psk, value);
    let value_commitment = message.value_commitment();
    let (value_p, blinding_factor) = message.decrypt(&r, &psk).unwrap();
    assert!(message.decrypt(&r_wrong, &psk).is_err());
    assert!(message.decrypt(&r, &psk_wrong).is_err());

    let a = GENERATOR_EXTENDED * JubJubScalar::from(value);
    let b = GENERATOR_NUMS_EXTENDED * blinding_factor;
    let value_commitment_p = a + b;

    assert_eq!(value, value_p);
    assert_eq!(value_commitment, &value_commitment_p);
}

#[test]
fn message_bytes() {
    use dusk_pki::SecretSpendKey;

    let rng = &mut rand::thread_rng();

    let ssk = SecretSpendKey::random(rng);
    let psk = ssk.public_spend_key();

    let r = JubJubScalar::random(rng);
    let value = 106;

    let m = Message::new(rng, &r, &psk, value);
    let m_p = m.to_bytes();
    let m_p = Message::from_bytes(&m_p).unwrap();

    assert_eq!(m, m_p);
}
