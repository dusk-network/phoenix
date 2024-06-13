// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![allow(non_snake_case)]

use dusk_bls12_381::BlsScalar;
use dusk_bytes::{DeserializableSlice, Serializable};
use dusk_jubjub::{JubJubAffine, JubJubExtended, JubJubScalar};
use ff::Field;
use jubjub_schnorr::{SecretKey as SchnorrSecretKey, Signature};
use rand::{CryptoRng, RngCore};

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

use crate::{encryption::elgamal, PublicKey, SecretKey, OUTPUT_NOTES};

/// Parameters needed to prove a recipient in-circuit
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct RecipientParameters {
    /// Public key of the transaction sender
    pub sender_pk: PublicKey,
    /// Note public keys of each note recipient
    pub output_npk: [JubJubAffine; OUTPUT_NOTES],
    /// Signatures of 'payload_hash' verifiable using 'pk_A' and 'pk_B'
    pub sig: [Signature; OUTPUT_NOTES],
    /// Asymmetric encryption of 'pk_A' using both recipients 'npk'
    pub enc_A: [(JubJubExtended, JubJubExtended); OUTPUT_NOTES],
    /// Asymmetric encryption of 'pk_B' using both recipients 'npk'
    pub enc_B: [(JubJubExtended, JubJubExtended); OUTPUT_NOTES],
    /// Randomness needed to encrypt/decrypt 'pk_A'
    pub r_A: [JubJubScalar; OUTPUT_NOTES],
    /// Randomness needed to encrypt/decrypt 'pk_B'
    pub r_B: [JubJubScalar; OUTPUT_NOTES],
}

impl Default for RecipientParameters {
    fn default() -> Self {
        let sk =
            SecretKey::new(JubJubScalar::default(), JubJubScalar::default());
        let sender_pk = PublicKey::from(&sk);

        Self {
            sender_pk,
            output_npk: [JubJubAffine::default(), JubJubAffine::default()],
            sig: [Signature::default(), Signature::default()],
            enc_A: [(JubJubExtended::default(), JubJubExtended::default());
                OUTPUT_NOTES],
            enc_B: [(JubJubExtended::default(), JubJubExtended::default());
                OUTPUT_NOTES],
            r_A: [JubJubScalar::default(); OUTPUT_NOTES],
            r_B: [JubJubScalar::default(); OUTPUT_NOTES],
        }
    }
}

const PARAMS_SIZE: usize = PublicKey::SIZE
    + JubJubAffine::SIZE * OUTPUT_NOTES
    + Signature::SIZE * OUTPUT_NOTES
    + JubJubAffine::SIZE * 2 * OUTPUT_NOTES
    + JubJubAffine::SIZE * 2 * OUTPUT_NOTES
    + JubJubScalar::SIZE * OUTPUT_NOTES
    + JubJubScalar::SIZE * OUTPUT_NOTES;

impl Serializable<PARAMS_SIZE> for RecipientParameters {
    type Error = dusk_bytes::Error;

    fn from_bytes(buf: &[u8; PARAMS_SIZE]) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let mut reader = &buf[..];

        let sender_pk = PublicKey::from_reader(&mut reader)?;

        let output_npk_0 = JubJubAffine::from_reader(&mut reader)?;
        let output_npk_1 = JubJubAffine::from_reader(&mut reader)?;

        let sig_0 = Signature::from_reader(&mut reader)?;
        let sig_1 = Signature::from_reader(&mut reader)?;

        let enc_A_0_0 = JubJubAffine::from_reader(&mut reader)?;
        let enc_A_1_0 = JubJubAffine::from_reader(&mut reader)?;
        let enc_A_0_1 = JubJubAffine::from_reader(&mut reader)?;
        let enc_A_1_1 = JubJubAffine::from_reader(&mut reader)?;

        let enc_B_0_0 = JubJubAffine::from_reader(&mut reader)?;
        let enc_B_1_0 = JubJubAffine::from_reader(&mut reader)?;
        let enc_B_0_1 = JubJubAffine::from_reader(&mut reader)?;
        let enc_B_1_1 = JubJubAffine::from_reader(&mut reader)?;

        let r_A_0 = JubJubScalar::from_reader(&mut reader)?;
        let r_A_1 = JubJubScalar::from_reader(&mut reader)?;

        let r_B_0 = JubJubScalar::from_reader(&mut reader)?;
        let r_B_1 = JubJubScalar::from_reader(&mut reader)?;

        Ok(Self {
            sender_pk,
            output_npk: [output_npk_0, output_npk_1],
            sig: [sig_0, sig_1],
            enc_A: [
                (enc_A_0_0.into(), enc_A_1_0.into()),
                (enc_A_0_1.into(), enc_A_1_1.into()),
            ],
            enc_B: [
                (enc_B_0_0.into(), enc_B_1_0.into()),
                (enc_B_0_1.into(), enc_B_1_1.into()),
            ],
            r_A: [r_A_0, r_A_1],
            r_B: [r_B_0, r_B_1],
        })
    }

    fn to_bytes(&self) -> [u8; PARAMS_SIZE] {
        let mut bytes = [0u8; PARAMS_SIZE];

        bytes[0..64].copy_from_slice(&self.sender_pk.to_bytes());

        bytes[64..96].copy_from_slice(&self.output_npk[0].to_bytes());
        bytes[96..128].copy_from_slice(&self.output_npk[1].to_bytes());

        bytes[128..192].copy_from_slice(&self.sig[0].to_bytes());
        bytes[192..256].copy_from_slice(&self.sig[1].to_bytes());

        let enc_A_0_0 = JubJubAffine::from(self.enc_A[0].0);
        let enc_A_1_0 = JubJubAffine::from(self.enc_A[0].1);
        let enc_A_0_1 = JubJubAffine::from(self.enc_A[1].0);
        let enc_A_1_1 = JubJubAffine::from(self.enc_A[1].1);

        bytes[256..288].copy_from_slice(&enc_A_0_0.to_bytes());
        bytes[288..320].copy_from_slice(&enc_A_1_0.to_bytes());
        bytes[320..352].copy_from_slice(&enc_A_0_1.to_bytes());
        bytes[352..384].copy_from_slice(&enc_A_1_1.to_bytes());

        let enc_B_0_0 = JubJubAffine::from(self.enc_B[0].0);
        let enc_B_1_0 = JubJubAffine::from(self.enc_B[0].1);
        let enc_B_0_1 = JubJubAffine::from(self.enc_B[1].0);
        let enc_B_1_1 = JubJubAffine::from(self.enc_B[1].1);

        bytes[384..416].copy_from_slice(&enc_B_0_0.to_bytes());
        bytes[416..448].copy_from_slice(&enc_B_1_0.to_bytes());
        bytes[448..480].copy_from_slice(&enc_B_0_1.to_bytes());
        bytes[480..512].copy_from_slice(&enc_B_1_1.to_bytes());

        bytes[512..544].copy_from_slice(&self.r_A[0].to_bytes());
        bytes[544..576].copy_from_slice(&self.r_A[1].to_bytes());

        bytes[576..608].copy_from_slice(&self.r_B[0].to_bytes());
        bytes[608..640].copy_from_slice(&self.r_B[1].to_bytes());

        bytes
    }
}

impl RecipientParameters {
    /// Create the recipient parameter
    pub fn new(
        rng: &mut (impl RngCore + CryptoRng),
        sender_sk: &SecretKey,
        output_npk: [JubJubAffine; OUTPUT_NOTES],
        payload_hash: BlsScalar,
    ) -> Self {
        // Encrypt the public key of the sender. We need to encrypt
        // both 'A' and 'B', using both tx output note public keys.
        let sender_pk = PublicKey::from(sender_sk);

        let r_A = [
            JubJubScalar::random(&mut *rng),
            JubJubScalar::random(&mut *rng),
        ];
        let r_B = [
            JubJubScalar::random(&mut *rng),
            JubJubScalar::random(&mut *rng),
        ];

        let (A_enc_1_c1, A_enc_1_c2) = elgamal::encrypt(
            &output_npk[0].into(), // note_pk_1.as_ref(),
            sender_pk.A(),
            &r_A[0],
        );

        let (B_enc_1_c1, B_enc_1_c2) = elgamal::encrypt(
            &output_npk[0].into(), // note_pk_1.as_ref(),
            sender_pk.B(),
            &r_B[0],
        );
        let (A_enc_2_c1, A_enc_2_c2) = elgamal::encrypt(
            &output_npk[1].into(), // note_pk_2.as_ref(),
            sender_pk.A(),
            &r_A[1],
        );

        let (B_enc_2_c1, B_enc_2_c2) = elgamal::encrypt(
            &output_npk[1].into(), // note_pk_2.as_ref(),
            sender_pk.B(),
            &r_B[1],
        );

        let enc_A = [(A_enc_1_c1, A_enc_1_c2), (A_enc_2_c1, A_enc_2_c2)];
        let enc_B = [(B_enc_1_c1, B_enc_1_c2), (B_enc_2_c1, B_enc_2_c2)];

        // Sign the payload hash using both 'a' and 'b'
        let schnorr_sk_a = SchnorrSecretKey::from(sender_sk.a());
        let sig_A = schnorr_sk_a.sign(rng, payload_hash);

        let schnorr_sk_b = SchnorrSecretKey::from(sender_sk.b());
        let sig_B = schnorr_sk_b.sign(rng, payload_hash);

        let sig = [sig_A, sig_B];

        RecipientParameters {
            sender_pk,
            output_npk,
            sig,
            enc_A,
            enc_B,
            r_A,
            r_B,
        }
    }
}
