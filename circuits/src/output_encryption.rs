// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Proof that output-note ciphertexts contain their commitment openings.

use dusk_bls12_381::BlsScalar;
use dusk_bytes::{DeserializableSlice, Error as BytesError, Serializable};
#[cfg(feature = "plonk")]
use dusk_jubjub::{GENERATOR, GENERATOR_NUMS};
use dusk_jubjub::{JubJubAffine, JubJubScalar};
use phoenix_core::{
    Note, NoteType, OUTPUT_NOTES, PublicKey, VALUE_ENC_SCALARS,
};
#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

/// Circuit proving that both output-note payloads encrypt their public
/// commitment openings.
///
/// A verifier must bind every public input to the serialized output notes, and
/// bind the value commitments to those supplied to the transaction circuit.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct OutputEncryptionCircuit {
    /// The opening and encryption information for both output notes.
    pub outputs: [OutputEncryptionInfo; OUTPUT_NOTES],
}

impl OutputEncryptionCircuit {
    /// The serialized size of an [`OutputEncryptionCircuit`].
    pub const SIZE: usize = OUTPUT_NOTES * OutputEncryptionInfo::SIZE;
}

impl Default for OutputEncryptionCircuit {
    fn default() -> Self {
        Self {
            outputs: core::array::from_fn(|_| OutputEncryptionInfo::default()),
        }
    }
}

impl Serializable<{ OUTPUT_NOTES * OUTPUT_ENCRYPTION_INFO_SIZE }>
    for OutputEncryptionCircuit
{
    type Error = BytesError;

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        for (info, output) in self
            .outputs
            .iter()
            .zip(bytes.chunks_exact_mut(OutputEncryptionInfo::SIZE))
        {
            output.copy_from_slice(&info.to_bytes());
        }
        bytes
    }

    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let mut reader = &bytes[..];
        Ok(Self {
            outputs: [
                OutputEncryptionInfo::from_reader(&mut reader)?,
                OutputEncryptionInfo::from_reader(&mut reader)?,
            ],
        })
    }
}

/// Witnesses and public note fields needed to prove one output encryption.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct OutputEncryptionInfo {
    /// Whether the note exposes or encrypts its opening.
    pub note_type: NoteType,
    /// The value committed by the output note.
    pub value: u64,
    /// The output note's public value commitment.
    pub value_commitment: JubJubAffine,
    /// The blinder opening the public value commitment.
    pub value_blinder: JubJubScalar,
    /// The encrypted opening and nonce published by the note.
    pub value_enc: [BlsScalar; VALUE_ENC_SCALARS],
    /// The ephemeral point published in the note's stealth address.
    pub R: JubJubAffine,
    /// The receiver's private circuit input `A` used to derive the encryption
    /// key. Its relation to the stealth address is intentionally not disclosed
    /// by the output note.
    pub receiver_A: JubJubAffine,
    /// The ephemeral scalar returned by [`Note::new_with_ephemeral`].
    pub encryption_secret: JubJubScalar,
}

impl OutputEncryptionInfo {
    /// Construct proof inputs from a note and the private values used to create
    /// it.
    ///
    /// # Errors
    ///
    /// Returns [`phoenix_core::Error::InvalidData`] when the note's encrypted
    /// fields are not canonically encoded scalars.
    pub fn new(
        note: &Note,
        receiver_pk: &PublicKey,
        value: u64,
        value_blinder: JubJubScalar,
        encryption_secret: JubJubScalar,
    ) -> Result<Self, phoenix_core::Error> {
        Ok(Self {
            note_type: note.note_type(),
            value,
            value_commitment: *note.value_commitment(),
            value_blinder,
            value_enc: note.value_enc_scalars()?,
            R: JubJubAffine::from(note.stealth_address().R()),
            receiver_A: JubJubAffine::from(receiver_pk.A()),
            encryption_secret,
        })
    }
}

impl Default for OutputEncryptionInfo {
    fn default() -> Self {
        Self {
            note_type: NoteType::Transparent,
            value: 0,
            value_commitment: JubJubAffine::default(),
            value_blinder: JubJubScalar::default(),
            value_enc: [BlsScalar::default(); VALUE_ENC_SCALARS],
            R: JubJubAffine::default(),
            receiver_A: JubJubAffine::default(),
            encryption_secret: JubJubScalar::default(),
        }
    }
}

const OUTPUT_ENCRYPTION_INFO_SIZE: usize = u8::SIZE
    + u64::SIZE
    + JubJubAffine::SIZE
    + JubJubScalar::SIZE
    + VALUE_ENC_SCALARS * BlsScalar::SIZE
    + 2 * JubJubAffine::SIZE
    + JubJubScalar::SIZE;

impl Serializable<OUTPUT_ENCRYPTION_INFO_SIZE> for OutputEncryptionInfo {
    type Error = BytesError;

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        let mut offset = 0;

        bytes[offset] = self.note_type as u8;
        offset += u8::SIZE;
        bytes[offset..offset + u64::SIZE]
            .copy_from_slice(&self.value.to_bytes());
        offset += u64::SIZE;
        bytes[offset..offset + JubJubAffine::SIZE]
            .copy_from_slice(&self.value_commitment.to_bytes());
        offset += JubJubAffine::SIZE;
        bytes[offset..offset + JubJubScalar::SIZE]
            .copy_from_slice(&self.value_blinder.to_bytes());
        offset += JubJubScalar::SIZE;
        for cipher in self.value_enc {
            bytes[offset..offset + BlsScalar::SIZE]
                .copy_from_slice(&cipher.to_bytes());
            offset += BlsScalar::SIZE;
        }
        bytes[offset..offset + JubJubAffine::SIZE]
            .copy_from_slice(&self.R.to_bytes());
        offset += JubJubAffine::SIZE;
        bytes[offset..offset + JubJubAffine::SIZE]
            .copy_from_slice(&self.receiver_A.to_bytes());
        offset += JubJubAffine::SIZE;
        bytes[offset..offset + JubJubScalar::SIZE]
            .copy_from_slice(&self.encryption_secret.to_bytes());

        bytes
    }

    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let mut reader = &bytes[..];

        let note_type = u8::from_reader(&mut reader)?
            .try_into()
            .map_err(|_| BytesError::InvalidData)?;
        let value = u64::from_reader(&mut reader)?;
        let value_commitment = JubJubAffine::from_reader(&mut reader)?;
        let value_blinder = JubJubScalar::from_reader(&mut reader)?;
        let mut value_enc = [BlsScalar::default(); VALUE_ENC_SCALARS];
        for cipher in &mut value_enc {
            *cipher = BlsScalar::from_reader(&mut reader)?;
        }
        let R = JubJubAffine::from_reader(&mut reader)?;
        let receiver_A = JubJubAffine::from_reader(&mut reader)?;
        let encryption_secret = JubJubScalar::from_reader(&mut reader)?;

        Ok(Self {
            note_type,
            value,
            value_commitment,
            value_blinder,
            value_enc,
            R,
            receiver_A,
            encryption_secret,
        })
    }
}

#[cfg(feature = "plonk")]
use dusk_plonk::prelude::{Circuit, Composer, Error as PlonkError, Witness};
#[cfg(feature = "plonk")]
use dusk_poseidon::encrypt_gadget;

#[cfg(feature = "plonk")]
impl Circuit for OutputEncryptionCircuit {
    /// Prove, for both outputs, that:
    ///
    /// - the public commitment opens to the private value and blinder;
    /// - the public ephemeral point is `r·G`;
    /// - an obfuscated payload is the authenticated encryption of that same
    ///   opening under `r·A`; or
    /// - a transparent payload is the canonical cleartext encoding.
    ///
    /// The public inputs for each output are, in order, its value commitment,
    /// note type, encrypted opening, and ephemeral point `R`.
    fn circuit(&self, composer: &mut Composer) -> Result<(), PlonkError> {
        for output in &self.outputs {
            let value = composer.append_witness(output.value);
            composer.component_range::<32>(value);
            let value_blinder = composer.append_witness(output.value_blinder);

            let expected_commitment =
                composer.append_public_point(output.value_commitment);
            let value_point =
                composer.component_mul_generator(value, GENERATOR)?;
            let blinder_point = composer
                .component_mul_generator(value_blinder, GENERATOR_NUMS)?;
            let commitment =
                composer.component_add_point(value_point, blinder_point);
            composer.assert_equal_point(expected_commitment, commitment);

            let note_type = composer
                .append_public(BlsScalar::from(output.note_type as u64));
            composer.component_boolean(note_type);
            let value_enc =
                output.value_enc.map(|value| composer.append_public(value));
            let R = composer.append_public_point(output.R);

            let encryption_secret =
                composer.append_witness(output.encryption_secret);
            let expected_R = composer
                .component_mul_generator(encryption_secret, GENERATOR)?;
            composer.assert_equal_point(R, expected_R);

            let receiver_A = composer.append_point(output.receiver_A);
            let shared_secret =
                composer.component_mul_point(encryption_secret, receiver_A);
            let encrypted: [Witness; 3] = encrypt_gadget(
                composer,
                [value, value_blinder],
                &shared_secret,
                &value_enc[3],
            )
            .expect("two-element value encryption should be valid")
            .try_into()
            .expect("two elements produce three cipher elements");

            let clear = [value, Composer::ZERO, Composer::ZERO];
            for ((public, encrypted), clear) in
                value_enc[..3].iter().zip(encrypted).zip(clear)
            {
                let expected =
                    composer.component_select(note_type, encrypted, clear);
                composer.assert_equal(*public, expected);
            }

            enforce_zero_for_transparent(composer, note_type, value_enc[3]);
            enforce_zero_for_transparent(composer, note_type, value_blinder);
        }

        Ok(())
    }
}

#[cfg(feature = "plonk")]
fn enforce_zero_for_transparent(
    composer: &mut Composer,
    note_type: Witness,
    value: Witness,
) {
    let selected = composer.component_select(note_type, value, Composer::ZERO);
    composer.assert_equal(value, selected);
}
