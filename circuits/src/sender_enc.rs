// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![allow(non_snake_case)]

use dusk_jubjub::JubJubAffine;
use dusk_plonk::prelude::*;
use jubjub_elgamal as elgamal;
use jubjub_schnorr::{Signature as SchnorrSignature, gadgets};
use phoenix_core::{OUTPUT_NOTES, PublicKey};

use crate::circuit_impl::{
    append_subgroup_point, assert_distinct, assert_nonzero,
};

/// Gadget to prove a valid origin for a given transaction.
pub(crate) fn gadget(
    composer: &mut Composer,
    sender_pk: PublicKey,
    signatures: (SchnorrSignature, SchnorrSignature),
    output_npk: [JubJubAffine; OUTPUT_NOTES],
    sender_blinder: [[JubJubScalar; 2]; OUTPUT_NOTES],
    // [enc_A, enc_B] for note 0
    sender_enc_out0: [(JubJubAffine, JubJubAffine); 2],
    // [enc_A, enc_B] for note 1
    sender_enc_out1: [(JubJubAffine, JubJubAffine); 2],
    payload_hash: Witness,
) -> Result<(), Error> {
    // VERIFY A SIGNATURE FOR EACH KEY 'A' AND 'B'
    // The keys are prover-supplied, so their subgroup membership is
    // constrained where they enter the circuit. The signature gadgets
    // additionally constrain them to be non-identity, which the sender keys
    // rely on.
    let sender_pk_A = append_subgroup_point(composer, *sender_pk.A())?;
    let sender_pk_B = append_subgroup_point(composer, *sender_pk.B())?;

    let sig_A_u = composer.append_witness(*signatures.0.u());
    // The signature equation sets `R = u·G + c·A`, with `A` in the subgroup,
    // so `R` is in it without a separate check.
    let sig_A_R = composer.append_point(*signatures.0.R())?;

    let sig_B_u = composer.append_witness(*signatures.1.u());
    // The signature equation sets `R = u·G + c·B`, with `B` in the subgroup,
    // so `R` is in it without a separate check.
    let sig_B_R = composer.append_point(*signatures.1.R())?;

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
    // The output note-pks are public inputs. Their subgroup membership, and
    // their difference from the identity, are constrained in-circuit rather
    // than left to every verifier, since they are the ElGamal keys the sender
    // public key is encrypted to.
    let note_pk_0 = append_note_pk(composer, output_npk[0])?;
    let note_pk_1 = append_note_pk(composer, output_npk[1])?;

    let blinder_A_0 = composer.append_witness(sender_blinder[0][0]);
    let blinder_B_0 = composer.append_witness(sender_blinder[0][1]);

    let blinder_A_1 = composer.append_witness(sender_blinder[1][0]);
    let blinder_B_1 = composer.append_witness(sender_blinder[1][1]);

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
    sender_pk_A: TorsionFreeWitnessPoint,
    sender_pk_B: TorsionFreeWitnessPoint,
    note_pk: TorsionFreeWitnessPoint,
    blinder: (Witness, Witness),
    sender_enc: [(JubJubAffine, JubJubAffine); 2],
) -> Result<(), Error> {
    // The two component blinders must be nonzero and must differ (#330). A zero
    // blinder encrypts its key to `(identity, key)`, leaving the sender key in
    // the clear. Equal blinders give both encryptions the same `c1`, and their
    // `c2` then differ by `A - B`, a value fixed by the sender public key, so a
    // passive observer can fingerprint and link the sender. The note-key gadget
    // excludes the identity for the same reason.
    //
    // These gates constrain the BLS-field witnesses, whereas the ElGamal gadget
    // below reduces each blinder modulo the JubJub subgroup order `r`: a
    // witness of `r` would pass `assert_nonzero` yet act as a zero blinder,
    // and `a + r` would pass `assert_distinct` against `a`. Constraining
    // the witness is enough because `encrypt_unchecked` builds `c1` with
    // `component_mul_generator`, which pins each blinder to a canonical JubJub
    // scalar (`< r`); so the scalar the encryption uses is the witness these
    // gates constrain. A future change that builds `c1` without that gadget
    // must re-establish canonicality here.
    assert_nonzero(composer, blinder.0);
    assert_nonzero(composer, blinder.1);
    assert_distinct(composer, blinder.0, blinder.1);

    let blinder_A = blinder.0;
    let (enc_A_c1, enc_A_c2) = elgamal::zk::encrypt_unchecked(
        composer,
        note_pk,
        sender_pk_A,
        blinder_A,
    )?;

    let blinder_B = blinder.1;
    let (enc_B_c1, enc_B_c2) = elgamal::zk::encrypt_unchecked(
        composer,
        note_pk,
        sender_pk_B,
        blinder_B,
    )?;

    let sender_enc_A = sender_enc[0];
    let sender_enc_B = sender_enc[1];

    composer.assert_equal_public_point(enc_A_c1.into(), sender_enc_A.0)?;
    composer.assert_equal_public_point(enc_A_c2.into(), sender_enc_A.1)?;

    composer.assert_equal_public_point(enc_B_c1.into(), sender_enc_B.0)?;
    composer.assert_equal_public_point(enc_B_c2.into(), sender_enc_B.1)?;

    Ok(())
}

/// Appends the note public key of an output as a public point, constrained to
/// the prime-order subgroup and to differ from the identity.
fn append_note_pk(
    composer: &mut Composer,
    note_pk: JubJubAffine,
) -> Result<TorsionFreeWitnessPoint, Error> {
    let note_pk = composer.append_public_point(note_pk)?;
    let note_pk = composer.assert_torsion_free_point(note_pk);
    assert_non_identity(composer, note_pk);
    Ok(note_pk)
}

/// Constrains a point of the prime-order subgroup to differ from the
/// identity, in one gate, as the signature gadgets of jubjub-schnorr do.
///
/// In the subgroup only the identity has `x = 0`, so proving that `x` has an
/// inverse excludes it without branching on the witness.
fn assert_non_identity(
    composer: &mut Composer,
    point: TorsionFreeWitnessPoint,
) {
    assert_nonzero(composer, *point.x());
}
