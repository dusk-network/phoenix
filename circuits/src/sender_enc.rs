// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![allow(non_snake_case)]

use dusk_jubjub::JubJubAffine;
use dusk_plonk::prelude::*;
use jubjub_schnorr::{gadgets, Signature as SchnorrSignature};
use phoenix_core::{PublicKey, OUTPUT_NOTES};

use crate::elgamal;

/// Gadget to prove a valid origin for a given transaction.
pub(crate) fn gadget(
    composer: &mut Composer,
    sender_pk: PublicKey,
    signatures: (SchnorrSignature, SchnorrSignature),
    output_npk: [JubJubAffine; OUTPUT_NOTES],
    sender_blinder: [(JubJubScalar, JubJubScalar); OUTPUT_NOTES],
    // [enc_A, enc_B] for note 0
    sender_enc_out0: [(JubJubAffine, JubJubAffine); 2],
    // [enc_A, enc_B] for note 1
    sender_enc_out1: [(JubJubAffine, JubJubAffine); 2],
    payload_hash: Witness,
) -> Result<(), Error> {
    // VERIFY A SIGNATURE FOR EACH KEY 'A' AND 'B'
    let sender_pk_A = composer.append_point(sender_pk.A());
    let sender_pk_B = composer.append_point(sender_pk.B());

    let sig_A_u = composer.append_witness(*signatures.0.u());
    let sig_A_R = composer.append_point(signatures.0.R());

    let sig_B_u = composer.append_witness(*signatures.1.u());
    let sig_B_R = composer.append_point(signatures.1.R());

    gadgets::verify_signature(
        composer,
        sig_A_u,
        sig_A_R,
        sender_pk_A,
        payload_hash,
    )?;
    gadgets::verify_signature(
        composer,
        sig_B_u,
        sig_B_R,
        sender_pk_B,
        payload_hash,
    )?;

    // ENCRYPT EACH KEY 'A' and 'B' USING EACH OUTPUT 'NPK'
    let note_pk_0 = composer.append_public_point(output_npk[0]);
    let note_pk_1 = composer.append_public_point(output_npk[1]);

    let blinder_A_0 = composer.append_witness(sender_blinder[0].0);
    let blinder_B_0 = composer.append_witness(sender_blinder[0].1);

    let blinder_A_1 = composer.append_witness(sender_blinder[1].0);
    let blinder_B_1 = composer.append_witness(sender_blinder[1].1);

    // assert that the sender encryption of the first note is correct
    // appends the values of sender_enc_out0 as public input
    assert_sender_enc(
        composer,
        sender_pk_A,
        sender_pk_B,
        note_pk_0,
        (blinder_A_0, blinder_B_0),
        sender_enc_out0,
    )?;

    // assert that the sender encryption of the second note is correct
    // appends the values of sender_enc_out1 as public input
    assert_sender_enc(
        composer,
        sender_pk_A,
        sender_pk_B,
        note_pk_1,
        (blinder_A_1, blinder_B_1),
        sender_enc_out1,
    )?;

    Ok(())
}

fn assert_sender_enc(
    composer: &mut Composer,
    sender_pk_A: WitnessPoint,
    sender_pk_B: WitnessPoint,
    note_pk: WitnessPoint,
    blinder: (Witness, Witness),
    sender_enc: [(JubJubAffine, JubJubAffine); 2],
) -> Result<(), Error> {
    let blinder_A = blinder.0;
    let (enc_A_c1, enc_A_c2) =
        elgamal::encrypt_gadget(composer, note_pk, sender_pk_A, blinder_A)?;

    let blinder_B = blinder.1;
    let (enc_B_c1, enc_B_c2) =
        elgamal::encrypt_gadget(composer, note_pk, sender_pk_B, blinder_B)?;

    let sender_enc_A = sender_enc[0];
    let sender_enc_B = sender_enc[1];

    composer.assert_equal_public_point(enc_A_c1, sender_enc_A.0);
    composer.assert_equal_public_point(enc_A_c2, sender_enc_A.1);

    composer.assert_equal_public_point(enc_B_c1, sender_enc_B.0);
    composer.assert_equal_public_point(enc_B_c2, sender_enc_B.1);

    Ok(())
}
