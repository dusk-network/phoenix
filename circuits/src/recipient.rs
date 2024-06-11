// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![allow(non_snake_case)]

use dusk_jubjub::JubJubScalar;
use dusk_plonk::prelude::*;
use ff::Field;
use jubjub_schnorr::{gadgets, SecretKey as SchnorrSecretKey, Signature};
use rand::{CryptoRng, RngCore};

use crate::elgamal;
use phoenix_core::{PublicKey, SecretKey};

const TX_OUTPUT_NOTES: usize = 2;

/// Parameters needed to prove a recipient in-circuit
#[derive(Debug, Clone, Copy)]
pub struct RecipientParameters {
    /// Public key of the transaction sender
    pub sender_pk: PublicKey,
    /// Note public keys of each note recipient
    pub output_npk: [JubJubAffine; TX_OUTPUT_NOTES],
    /// Signatures of 'payload_hash' verifiable using 'pk_A' and 'pk_B'
    pub sig: [Signature; TX_OUTPUT_NOTES],
    /// Asymmetric encryption of 'pk_A' using both recipients 'npk'
    pub enc_A: [(JubJubExtended, JubJubExtended); TX_OUTPUT_NOTES],
    /// Asymmetric encryption of 'pk_B' using both recipients 'npk'
    pub enc_B: [(JubJubExtended, JubJubExtended); TX_OUTPUT_NOTES],
    /// Randomness needed to encrypt/decrypt 'pk_A'
    pub r_A: [JubJubScalar; TX_OUTPUT_NOTES],
    /// Randomness needed to encrypt/decrypt 'pk_B'
    pub r_B: [JubJubScalar; TX_OUTPUT_NOTES],
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
                TX_OUTPUT_NOTES],
            enc_B: [(JubJubExtended::default(), JubJubExtended::default());
                TX_OUTPUT_NOTES],
            r_A: [JubJubScalar::default(); TX_OUTPUT_NOTES],
            r_B: [JubJubScalar::default(); TX_OUTPUT_NOTES],
        }
    }
}

impl RecipientParameters {
    /// Create the recipient parameter
    pub fn new(
        rng: &mut (impl RngCore + CryptoRng),
        sender_sk: &SecretKey,
        output_npk: [JubJubAffine; TX_OUTPUT_NOTES],
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

/// Gadget to prove a valid origin for a given transaction.
pub(crate) fn gadget(
    composer: &mut Composer,
    rp: &RecipientParameters,
    payload_hash: Witness,
) -> Result<(), Error> {
    // VERIFY A SIGNATURE FOR EACH KEY 'A' AND 'B'
    let pk_A = composer.append_point(rp.sender_pk.A());
    let pk_B = composer.append_point(rp.sender_pk.B());

    let sig_A_u = composer.append_witness(*rp.sig[0].u());
    let sig_A_R = composer.append_point(rp.sig[0].R());

    let sig_B_u = composer.append_witness(*rp.sig[1].u());
    let sig_B_R = composer.append_point(rp.sig[1].R());

    gadgets::verify_signature(composer, sig_A_u, sig_A_R, pk_A, payload_hash)?;
    gadgets::verify_signature(composer, sig_B_u, sig_B_R, pk_B, payload_hash)?;

    // ENCRYPT EACH KEY 'A' and 'B' USING EACH OUTPUT 'NPK'
    let note_pk_1 = composer.append_public_point(rp.output_npk[0]);
    let note_pk_2 = composer.append_public_point(rp.output_npk[1]);

    let r_A_1 = composer.append_witness(rp.r_A[0]);
    let r_A_2 = composer.append_witness(rp.r_A[1]);

    let r_B_1 = composer.append_witness(rp.r_B[0]);
    let r_B_2 = composer.append_witness(rp.r_B[1]);

    let (enc_A_1_c1, enc_A_1_c2) =
        elgamal::encrypt_gadget(composer, note_pk_1, pk_A, r_A_1)?;
    let (enc_A_2_c1, enc_A_2_c2) =
        elgamal::encrypt_gadget(composer, note_pk_2, pk_A, r_A_2)?;

    let (enc_B_1_c1, enc_B_1_c2) =
        elgamal::encrypt_gadget(composer, note_pk_1, pk_B, r_B_1)?;
    let (enc_B_2_c1, enc_B_2_c2) =
        elgamal::encrypt_gadget(composer, note_pk_2, pk_B, r_B_2)?;

    composer.assert_equal_public_point(enc_A_1_c1, rp.enc_A[0].0);
    composer.assert_equal_public_point(enc_A_1_c2, rp.enc_A[0].1);
    composer.assert_equal_public_point(enc_A_2_c1, rp.enc_A[1].0);
    composer.assert_equal_public_point(enc_A_2_c2, rp.enc_A[1].1);

    composer.assert_equal_public_point(enc_B_1_c1, rp.enc_B[0].0);
    composer.assert_equal_public_point(enc_B_1_c2, rp.enc_B[0].1);
    composer.assert_equal_public_point(enc_B_2_c1, rp.enc_B[1].0);
    composer.assert_equal_public_point(enc_B_2_c2, rp.enc_B[1].1);

    Ok(())
}
