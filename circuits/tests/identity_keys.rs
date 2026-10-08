// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Regression for an identity sender key.
//!
//! The signature gadgets constrain both keys of the sender to differ from the
//! identity, so a transaction whose sender key has an identity `A` or `B` is
//! unsatisfiable. The test signs for that key with a signature that satisfies
//! the signature equation, so that only this constraint can fail.

#![cfg(feature = "plonk")]
#![allow(non_snake_case)]

use std::sync::LazyLock;

use dusk_bytes::Serializable;
use dusk_jubjub::{
    GENERATOR_EXTENDED, JubJubAffine, JubJubExtended, JubJubScalar,
};
use dusk_plonk::prelude::{Compiler, Error as PlonkError, PublicParameters};
use ff::Field;
use jubjub_elgamal::Encryption as ElGamal;
use jubjub_schnorr::Signature as SchnorrSignature;
use phoenix_circuits::TxCircuit;
use phoenix_core::{PublicKey, value_commitment};
use rand::SeedableRng;
use rand::rngs::StdRng;

mod common;
use common::*;

/// A test SRS for the 1-input circuit. Soundness does not depend on the SRS.
static PP: LazyLock<PublicParameters> = LazyLock::new(|| {
    PublicParameters::setup(1 << 16, &mut StdRng::seed_from_u64(0x0122))
        .expect("failed to generate the test SRS")
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

/// Output note information encrypting `sender_pk`.
fn output_note(
    rng: &mut StdRng,
    value: u64,
    note_pk: JubJubAffine,
    sender_pk: &PublicKey,
    sender_blinder: [JubJubScalar; 2],
) -> OutputNoteInfo {
    let value_blinder = JubJubScalar::random(&mut *rng);
    let encrypt = |key: &JubJubExtended, blinder| {
        let (enc, _) =
            ElGamal::encrypt(&note_pk.into(), key, None, blinder).unwrap();
        (enc.c1().into(), enc.c2().into())
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

#[test]
fn identity_sender_key_rejected() {
    let mut rng = StdRng::seed_from_u64(0x0122);
    let (prover, verifier) =
        Compiler::compile::<TxCircuit<HEIGHT, 1>>(&PP, LABEL)
            .expect("failed to compile circuit");

    let mut prove = |sender_pk: PublicKey, signatures| {
        let output_notes_info = [
            output_note(
                &mut rng,
                10,
                TP.output_npk[0],
                &sender_pk,
                TP.sender_blinder[0],
            ),
            output_note(
                &mut rng,
                5,
                TP.output_npk[1],
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
    };

    // The same construction proves for an honest sender key.
    prove(TP.sender_pk, TP.signatures).expect("the honest sender proves");

    let identity = JubJubExtended::identity();
    let (A, B) = (*TP.sender_pk.A(), *TP.sender_pk.B());
    let (sig_A, sig_B) = TP.signatures;

    let sig_identity = identity_key_signature(&mut StdRng::seed_from_u64(0xa));
    let err = prove(PublicKey::new(identity, B), (sig_identity, sig_B))
        .expect_err("an identity sender key A must be unsatisfiable");
    assert_eq!(err, PlonkError::CircuitUnsatisfied);

    let sig_identity = identity_key_signature(&mut StdRng::seed_from_u64(0xb));
    let err = prove(PublicKey::new(A, identity), (sig_A, sig_identity))
        .expect_err("an identity sender key B must be unsatisfiable");
    assert_eq!(err, PlonkError::CircuitUnsatisfied);
}
