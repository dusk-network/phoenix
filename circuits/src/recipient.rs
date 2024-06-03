// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::JubJubScalar;
use dusk_plonk::prelude::*;
use jubjub_schnorr::{gadgets, Signature};

use crate::elgamal;
use phoenix_core::PublicKey;

use rand::rngs::StdRng;
use rand_core::SeedableRng;

use phoenix_core::SecretKey;

const TX_OUTPUT_NOTES: usize = 2;

/// Parameters needed to prove a recipient in-circuit
#[derive(Debug, Clone, Copy)]
pub struct RecipientParameters {
    /// Public key of the transaction recipient
    pub recipient_pk: PublicKey,
    /// Note public keys of each note receiver
    pub receiver_npk_vec: [JubJubAffine; TX_OUTPUT_NOTES],
    /// Signatures of 'payload_hash' verifiable using 'pk_A' and 'pk_B'
    pub sig_vec: [Signature; TX_OUTPUT_NOTES],
    /// Asymmetric encryption of 'pk_A' using both receivers 'npk'
    pub enc_A_vec: [(JubJubExtended, JubJubExtended); TX_OUTPUT_NOTES],
    /// Asymmetric encryption of 'pk_B' using both receivers 'npk'
    pub enc_B_vec: [(JubJubExtended, JubJubExtended); TX_OUTPUT_NOTES],
    /// Randomness needed to encrypt/decrypt 'pk_A'
    pub r_A_vec: [JubJubScalar; TX_OUTPUT_NOTES],
    /// Randomness needed to encrypt/decrypt 'pk_B'
    pub r_B_vec: [JubJubScalar; TX_OUTPUT_NOTES],
}

impl Default for RecipientParameters {
    fn default() -> Self {
        let mut rng = StdRng::seed_from_u64(0xbeef);

        let sk = SecretKey::random(&mut rng);
        let recipient_pk = PublicKey::from(&sk);

        Self {
            recipient_pk,
            receiver_npk_vec: [
                JubJubAffine::default(),
                JubJubAffine::default(),
            ],
            sig_vec: [Signature::default(), Signature::default()],
            enc_A_vec: [(JubJubExtended::default(), JubJubExtended::default());
                TX_OUTPUT_NOTES],
            enc_B_vec: [(JubJubExtended::default(), JubJubExtended::default());
                TX_OUTPUT_NOTES],
            r_A_vec: [JubJubScalar::default(); TX_OUTPUT_NOTES],
            r_B_vec: [JubJubScalar::default(); TX_OUTPUT_NOTES],
        }
    }
}

/// Gadget to prove a valid origin for a given transaction.
pub(crate) fn gadget(
    composer: &mut Composer,
    rp: &RecipientParameters,
    payload_hash: &Witness,
) -> Result<(), Error> {
    // VERIFY A SIGNATURE FOR EACH KEY 'A' AND 'B'
    let pk_A = composer.append_point(rp.recipient_pk.A());
    let pk_B = composer.append_point(rp.recipient_pk.B());

    let sig_A_u = composer.append_witness(*rp.sig_vec[0].u());
    let sig_A_R = composer.append_point(rp.sig_vec[0].R());

    let sig_B_u = composer.append_witness(*rp.sig_vec[1].u());
    let sig_B_R = composer.append_point(rp.sig_vec[1].R());

    gadgets::verify_signature(composer, sig_A_u, sig_A_R, pk_A, *payload_hash)?;
    gadgets::verify_signature(composer, sig_B_u, sig_B_R, pk_B, *payload_hash)?;

    // ENCRYPT EACH KEY 'A' and 'B' USING EACH OUTPUT 'NPK'
    let note_pk_1 = composer.append_public_point(rp.receiver_npk_vec[0]);
    let note_pk_2 = composer.append_public_point(rp.receiver_npk_vec[1]);

    let r_A_1 = composer.append_witness(rp.r_A_vec[0]);
    let r_A_2 = composer.append_witness(rp.r_A_vec[1]);

    let r_B_1 = composer.append_witness(rp.r_B_vec[0]);
    let r_B_2 = composer.append_witness(rp.r_B_vec[1]);

    let (enc_A_1_c1, enc_A_1_c2) =
        elgamal::encrypt_gadget(composer, note_pk_1, pk_A, r_A_1)?;
    let (enc_A_2_c1, enc_A_2_c2) =
        elgamal::encrypt_gadget(composer, note_pk_2, pk_A, r_A_2)?;

    let (enc_B_1_c1, enc_B_1_c2) =
        elgamal::encrypt_gadget(composer, note_pk_1, pk_B, r_B_1)?;
    let (enc_B_2_c1, enc_B_2_c2) =
        elgamal::encrypt_gadget(composer, note_pk_2, pk_B, r_B_2)?;

    composer.assert_equal_public_point(enc_A_1_c1, rp.enc_A_vec[0].0);
    composer.assert_equal_public_point(enc_A_1_c2, rp.enc_A_vec[0].1);
    composer.assert_equal_public_point(enc_A_2_c1, rp.enc_A_vec[1].0);
    composer.assert_equal_public_point(enc_A_2_c2, rp.enc_A_vec[1].1);

    composer.assert_equal_public_point(enc_B_1_c1, rp.enc_B_vec[0].0);
    composer.assert_equal_public_point(enc_B_1_c2, rp.enc_B_vec[0].1);
    composer.assert_equal_public_point(enc_B_2_c1, rp.enc_B_vec[1].0);
    composer.assert_equal_public_point(enc_B_2_c2, rp.enc_B_vec[1].1);

    Ok(())
}
