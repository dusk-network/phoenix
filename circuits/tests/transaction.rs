// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg(feature = "plonk")]

use rand::SeedableRng;
use rand::rngs::StdRng;

use dusk_plonk::prelude::Compiler;

use phoenix_circuits::TxCircuit;

mod common;
use common::*;

#[test]
fn test_transfer_circuit_1_2() {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let (prover, verifier) =
        Compiler::compile::<TxCircuit<HEIGHT, 1>>(&TP.pp, LABEL)
            .expect("failed to compile circuit");

    let input_notes_info = [TP.input_notes_info[0].clone()];

    // create 2 testing tx output notes
    let output_notes_info = [
        create_output_note_information(
            &mut rng,
            10,
            TP.output_npk[0],
            TP.sender_blinder[0],
        ),
        create_output_note_information(
            &mut rng,
            5,
            TP.output_npk[1],
            TP.sender_blinder[1],
        ),
    ];

    let (proof, public_inputs) = prover
        .prove(
            &mut rng,
            &TxCircuit {
                input_notes_info,
                output_notes_info,
                payload_hash: TP.payload_hash,
                root: TP.root,
                deposit: TP.deposit,
                max_fee: TP.max_fee,
                sender_pk: TP.sender_pk,
                signatures: TP.signatures,
            },
        )
        .expect("failed to prove");

    verifier
        .verify(&proof, &public_inputs)
        .expect("failed to verify proof");
}

#[test]
fn test_transfer_circuit_2_2() {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let (prover, verifier) =
        Compiler::compile::<TxCircuit<HEIGHT, 2>>(&TP.pp, LABEL)
            .expect("failed to compile circuit");

    let input_notes_info = [
        TP.input_notes_info[0].clone(),
        TP.input_notes_info[1].clone(),
    ];

    // create 2 testing tx output notes
    let output_notes_info = [
        create_output_note_information(
            &mut rng,
            35,
            TP.output_npk[0],
            TP.sender_blinder[0],
        ),
        create_output_note_information(
            &mut rng,
            5,
            TP.output_npk[1],
            TP.sender_blinder[1],
        ),
    ];

    let (proof, public_inputs) = prover
        .prove(
            &mut rng,
            &TxCircuit {
                input_notes_info,
                output_notes_info,
                payload_hash: TP.payload_hash,
                root: TP.root,
                deposit: TP.deposit,
                max_fee: TP.max_fee,
                sender_pk: TP.sender_pk,
                signatures: TP.signatures,
            },
        )
        .expect("failed to prove");

    verifier
        .verify(&proof, &public_inputs)
        .expect("failed to verify proof");
}

#[test]
fn test_transfer_circuit_3_2() {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let (prover, verifier) =
        Compiler::compile::<TxCircuit<HEIGHT, 3>>(&TP.pp, LABEL)
            .expect("failed to compile circuit");

    let input_notes_info = [
        TP.input_notes_info[0].clone(),
        TP.input_notes_info[1].clone(),
        TP.input_notes_info[2].clone(),
    ];

    // create 2 testing tx output notes
    let output_notes_info = [
        create_output_note_information(
            &mut rng,
            35,
            TP.output_npk[0],
            TP.sender_blinder[0],
        ),
        create_output_note_information(
            &mut rng,
            30,
            TP.output_npk[1],
            TP.sender_blinder[1],
        ),
    ];

    let (proof, public_inputs) = prover
        .prove(
            &mut rng,
            &TxCircuit {
                input_notes_info,
                output_notes_info,
                payload_hash: TP.payload_hash,
                root: TP.root,
                deposit: TP.deposit,
                max_fee: TP.max_fee,
                sender_pk: TP.sender_pk,
                signatures: TP.signatures,
            },
        )
        .expect("failed to prove");

    verifier
        .verify(&proof, &public_inputs)
        .expect("failed to verify proof");
}

#[test]
fn test_transfer_circuit_4_2() {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let (prover, verifier) =
        Compiler::compile::<TxCircuit<HEIGHT, 4>>(&TP.pp, LABEL)
            .expect("failed to compile circuit");

    let input_notes_info = [
        TP.input_notes_info[0].clone(),
        TP.input_notes_info[1].clone(),
        TP.input_notes_info[2].clone(),
        TP.input_notes_info[3].clone(),
    ];

    // create 2 testing tx output notes
    let output_notes_info = [
        create_output_note_information(
            &mut rng,
            60,
            TP.output_npk[0],
            TP.sender_blinder[0],
        ),
        create_output_note_information(
            &mut rng,
            30,
            TP.output_npk[1],
            TP.sender_blinder[1],
        ),
    ];

    let (proof, public_inputs) = prover
        .prove(
            &mut rng,
            &TxCircuit {
                input_notes_info,
                output_notes_info,
                payload_hash: TP.payload_hash,
                root: TP.root,
                deposit: TP.deposit,
                max_fee: TP.max_fee,
                sender_pk: TP.sender_pk,
                signatures: TP.signatures,
            },
        )
        .expect("failed to prove");

    verifier
        .verify(&proof, &public_inputs)
        .expect("failed to verify proof");
}
