// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![allow(non_snake_case)]

use dusk_plonk::prelude::*;
use jubjub_schnorr::gadgets;
use phoenix_core::RecipientParameters;

use crate::elgamal;

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
