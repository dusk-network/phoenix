// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Regressions for degenerate sender-encryption blinders.
//!
//! Each output note encrypts the two components `A` and `B` of the sender
//! public key under an independent blinder. A zero blinder encrypts its key to
//! `(identity, key)`, leaving the sender key in the clear; two equal blinders
//! of a note give both encryptions the same `c1`, and their `c2` then differ
//! by the sender-fixed `A - B`, so a passive observer can fingerprint the
//! sender. The circuit constrains each blinder to be nonzero and the two of a
//! note to differ, so such a transaction is unsatisfiable. The tests build
//! encryptions that satisfy every other equation, so that only this constraint
//! can fail.

#![cfg(feature = "plonk")]

use std::sync::LazyLock;

use dusk_jubjub::{
    GENERATOR_EXTENDED, JubJubAffine, JubJubExtended, JubJubScalar,
};
use dusk_plonk::prelude::{
    Compiler, Error as PlonkError, Prover, PublicParameters, Verifier,
};
use ff::Field;
use phoenix_circuits::TxCircuit;
use phoenix_core::{PublicKey, value_commitment};
use rand::SeedableRng;
use rand::rngs::StdRng;

mod common;
use common::*;

/// The 1-input circuit, compiled with a test SRS. Soundness does not depend
/// on the SRS.
static CIRCUIT: LazyLock<(Prover, Verifier)> = LazyLock::new(|| {
    let pp =
        PublicParameters::setup(1 << 16, &mut StdRng::seed_from_u64(0x0122))
            .expect("failed to generate the test SRS");
    Compiler::compile::<TxCircuit<HEIGHT, 1>>(&pp, LABEL)
        .expect("failed to compile circuit")
});

/// Output note information encrypting `sender_pk` to `note_pk` under the given
/// blinders, the encryption computed as the circuit computes it.
fn output_note(
    value: u64,
    value_blinder: JubJubScalar,
    note_pk: JubJubAffine,
    sender_pk: &PublicKey,
    sender_blinder: [JubJubScalar; 2],
) -> OutputNoteInfo {
    let encrypt = |key: &JubJubExtended, blinder: &JubJubScalar| {
        let c1 = GENERATOR_EXTENDED * blinder;
        let c2 = key + JubJubExtended::from(note_pk) * blinder;
        (c1.into(), c2.into())
    };

    OutputNoteInfo {
        value,
        value_commitment: value_commitment(value, value_blinder),
        value_blinder,
        note_pk,
        sender_enc: [
            encrypt(sender_pk.A(), &sender_blinder[0]),
            encrypt(sender_pk.B(), &sender_blinder[1]),
        ],
        sender_blinder,
    }
}

/// Proves and verifies the 1-input transaction spending the first test note,
/// with the given sender blinders for the two output notes.
fn prove(sender_blinder: [[JubJubScalar; 2]; 2]) -> Result<(), PlonkError> {
    let mut rng = StdRng::seed_from_u64(0x0122);
    let (prover, verifier) = &*CIRCUIT;

    let value_blinder_0 = JubJubScalar::random(&mut rng);
    let value_blinder_1 = JubJubScalar::random(&mut rng);
    let output_notes_info = [
        output_note(
            10,
            value_blinder_0,
            TP.output_npk[0],
            &TP.sender_pk,
            sender_blinder[0],
        ),
        output_note(
            5,
            value_blinder_1,
            TP.output_npk[1],
            &TP.sender_pk,
            sender_blinder[1],
        ),
    ];
    let circuit = TxCircuit {
        input_notes_info: [TP.input_notes_info[0].clone()],
        output_notes_info,
        payload_hash: TP.payload_hash,
        root: TP.root,
        deposit: TP.deposit,
        max_fee: TP.max_fee,
        sender_pk: TP.sender_pk,
        signatures: TP.signatures,
    };
    prover
        .prove(&mut rng, &circuit)
        .and_then(|(proof, pi)| verifier.verify(&proof, &pi))
}

#[test]
fn equal_sender_blinders_rejected() {
    // The same construction proves with the honest, random test blinders.
    prove(TP.sender_blinder).expect("the honest transaction proves");

    let [[a0, b0], [a1, b1]] = TP.sender_blinder;

    let err = prove([[a0, a0], [a1, b1]])
        .expect_err("equal blinders on note 0 must be unsatisfiable");
    assert_eq!(err, PlonkError::CircuitUnsatisfied);

    let err = prove([[a0, b0], [b1, b1]])
        .expect_err("equal blinders on note 1 must be unsatisfiable");
    assert_eq!(err, PlonkError::CircuitUnsatisfied);
}

#[test]
fn zero_sender_blinder_rejected() {
    // The same construction proves with the honest, random test blinders.
    prove(TP.sender_blinder).expect("the honest transaction proves");

    let [[a0, b0], [a1, b1]] = TP.sender_blinder;
    let zero = JubJubScalar::from(0u64);

    for degenerate in [
        [[zero, b0], [a1, b1]],
        [[a0, zero], [a1, b1]],
        [[a0, b0], [zero, b1]],
        [[a0, b0], [a1, zero]],
    ] {
        let err = prove(degenerate)
            .expect_err("a zero blinder must be unsatisfiable");
        assert_eq!(err, PlonkError::CircuitUnsatisfied);
    }
}
