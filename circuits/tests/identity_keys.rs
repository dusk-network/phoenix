// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Regressions for identity keys in the transaction circuit.
//!
//! The signature gadgets constrain both keys of the sender to differ from the
//! identity, and the circuit constrains the note keys of the outputs, which
//! the sender is encrypted to, likewise. A transaction with any of these keys
//! set to the identity is unsatisfiable. The tests give it signatures and
//! encryptions that satisfy every other equation, so that only this
//! constraint can fail.

#![cfg(feature = "plonk")]
#![allow(non_snake_case)]

use std::sync::LazyLock;

use dusk_bytes::Serializable;
use dusk_jubjub::{
    GENERATOR_EXTENDED, JubJubAffine, JubJubExtended, JubJubScalar,
};
use dusk_plonk::prelude::{
    Compiler, Error as PlonkError, Prover, PublicParameters, Verifier,
};
use ff::Field;
use jubjub_schnorr::Signature as SchnorrSignature;
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

/// A signature that verifies for the identity key under any challenge.
fn identity_key_signature(rng: &mut StdRng) -> SchnorrSignature {
    let u = JubJubScalar::random(&mut *rng);
    let R = JubJubAffine::from(GENERATOR_EXTENDED * u);

    let mut bytes = [0u8; SchnorrSignature::SIZE];
    bytes[..32].copy_from_slice(&u.to_bytes());
    bytes[32..].copy_from_slice(&R.to_bytes());
    SchnorrSignature::from_bytes(&bytes).expect("R is a prime-order point")
}

/// Output note information encrypting `sender_pk` to `note_pk`, the
/// encryption computed as the circuit computes it.
fn output_note(
    rng: &mut StdRng,
    value: u64,
    note_pk: JubJubAffine,
    sender_pk: &PublicKey,
    sender_blinder: [JubJubScalar; 2],
) -> OutputNoteInfo {
    let value_blinder = JubJubScalar::random(&mut *rng);
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
/// with the given sender key, signatures and output note keys.
fn prove(
    sender_pk: PublicKey,
    signatures: (SchnorrSignature, SchnorrSignature),
    output_npk: [JubJubAffine; 2],
) -> Result<(), PlonkError> {
    let mut rng = StdRng::seed_from_u64(0x0122);
    let (prover, verifier) = &*CIRCUIT;

    let output_notes_info = [
        output_note(
            &mut rng,
            10,
            output_npk[0],
            &sender_pk,
            TP.sender_blinder[0],
        ),
        output_note(
            &mut rng,
            5,
            output_npk[1],
            &sender_pk,
            TP.sender_blinder[1],
        ),
    ];
    let circuit = TxCircuit {
        input_notes_info: [TP.input_notes_info[0].clone()],
        output_notes_info,
        payload_hash: TP.payload_hash,
        root: TP.root,
        deposit: TP.deposit,
        max_fee: TP.max_fee,
        sender_pk,
        signatures,
    };
    prover
        .prove(&mut rng, &circuit)
        .and_then(|(proof, pi)| verifier.verify(&proof, &pi))
}

#[test]
fn identity_sender_key_rejected() {
    // The same construction proves for an honest sender key.
    prove(TP.sender_pk, TP.signatures, TP.output_npk)
        .expect("the honest sender proves");

    let identity = JubJubExtended::identity();
    let (A, B) = (*TP.sender_pk.A(), *TP.sender_pk.B());
    let (sig_A, sig_B) = TP.signatures;

    let sig_identity = identity_key_signature(&mut StdRng::seed_from_u64(0xa));
    let err = prove(
        PublicKey::new(identity, B),
        (sig_identity, sig_B),
        TP.output_npk,
    )
    .expect_err("an identity sender key A must be unsatisfiable");
    assert_eq!(err, PlonkError::CircuitUnsatisfied);

    let sig_identity = identity_key_signature(&mut StdRng::seed_from_u64(0xb));
    let err = prove(
        PublicKey::new(A, identity),
        (sig_A, sig_identity),
        TP.output_npk,
    )
    .expect_err("an identity sender key B must be unsatisfiable");
    assert_eq!(err, PlonkError::CircuitUnsatisfied);
}

#[test]
fn identity_output_note_key_rejected() {
    // The same construction proves for honest output note keys.
    prove(TP.sender_pk, TP.signatures, TP.output_npk)
        .expect("the honest transaction proves");

    let identity = JubJubAffine::identity();
    let [npk_0, npk_1] = TP.output_npk;

    for output_npk in [[identity, npk_1], [npk_0, identity]] {
        let err = prove(TP.sender_pk, TP.signatures, output_npk)
            .expect_err("an identity output note key must be unsatisfiable");
        assert_eq!(err, PlonkError::CircuitUnsatisfied);
    }
}
