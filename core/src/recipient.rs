// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![allow(non_snake_case)]

use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{JubJubAffine, JubJubExtended, JubJubScalar};
use ff::Field;
use jubjub_schnorr::{SecretKey as SchnorrSecretKey, Signature};
use rand::{CryptoRng, RngCore};

use crate::{encryption::elgamal, PublicKey, SecretKey, OUTPUT_NOTES};

/// Parameters needed to prove a recipient in-circuit
#[derive(Debug, Clone, Copy)]
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
