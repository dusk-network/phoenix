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

const TX_OUTPUT_NOTES: usize = 2;

/// Gadget to prove a valid origin for a given transaction.
pub fn gadget(
    composer: &mut Composer,
    pk: &PublicKey,
    note_pks: &[JubJubAffine; TX_OUTPUT_NOTES],
    sigs: &[Signature; TX_OUTPUT_NOTES],
    recipient_hash: &BlsScalar,
    A_encs: &[(JubJubExtended, JubJubExtended); TX_OUTPUT_NOTES],
    B_encs: &[(JubJubExtended, JubJubExtended); TX_OUTPUT_NOTES],
    r_A: &[JubJubScalar; TX_OUTPUT_NOTES],
    r_B: &[JubJubScalar; TX_OUTPUT_NOTES],
) -> Result<(), Error> {
    // VERIFY A SIGNATURE FOR EACH KEY 'A' AND 'B'
    let recipient_hash = composer.append_public(*recipient_hash);

    let pk_A = composer.append_point(pk.A());
    let pk_B = composer.append_point(pk.B());

    let sig_A_u = composer.append_witness(*sigs[0].u());
    let sig_A_R = composer.append_point(sigs[0].R());

    let sig_B_u = composer.append_witness(*sigs[1].u());
    let sig_B_R = composer.append_point(sigs[1].R());

    gadgets::verify_signature(
        composer,
        sig_A_u,
        sig_A_R,
        pk_A,
        recipient_hash,
    )?;
    gadgets::verify_signature(
        composer,
        sig_B_u,
        sig_B_R,
        pk_B,
        recipient_hash,
    )?;

    // ENCRYPT EACH KEY 'A' and 'B' USING EACH OUTPUT 'NPK'
    let note_pk_1 = composer.append_public_point(note_pks[0]);
    let note_pk_2 = composer.append_public_point(note_pks[1]);

    let r_A_1 = composer.append_witness(r_A[0]);
    let r_A_2 = composer.append_witness(r_A[1]);

    let r_B_1 = composer.append_witness(r_B[0]);
    let r_B_2 = composer.append_witness(r_B[1]);

    let (A_enc_1_c1, A_enc_1_c2) =
        elgamal::encrypt_gadget(composer, note_pk_1, pk_A, r_A_1)?;
    let (A_enc_2_c1, A_enc_2_c2) =
        elgamal::encrypt_gadget(composer, note_pk_2, pk_A, r_A_2)?;

    let (B_enc_1_c1, B_enc_1_c2) =
        elgamal::encrypt_gadget(composer, note_pk_1, pk_B, r_B_1)?;
    let (B_enc_2_c1, B_enc_2_c2) =
        elgamal::encrypt_gadget(composer, note_pk_2, pk_B, r_B_2)?;

    composer.assert_equal_public_point(A_enc_1_c1, A_encs[0].0);
    composer.assert_equal_public_point(A_enc_1_c2, A_encs[0].1);
    composer.assert_equal_public_point(A_enc_2_c1, A_encs[1].0);
    composer.assert_equal_public_point(A_enc_2_c2, A_encs[1].1);

    composer.assert_equal_public_point(B_enc_1_c1, B_encs[0].0);
    composer.assert_equal_public_point(B_enc_1_c2, B_encs[0].1);
    composer.assert_equal_public_point(B_enc_2_c1, B_encs[1].0);
    composer.assert_equal_public_point(B_enc_2_c2, B_encs[1].1);

    Ok(())
}
