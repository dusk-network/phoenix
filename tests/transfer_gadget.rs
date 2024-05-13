// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use rand_core::{CryptoRng, OsRng, RngCore};

use phoenix_core::transfer::{InputNote, OutputNote};
use phoenix_core::{
    transfer::TransferCircuit, Note, PublicKey, SecretKey, ViewKey,
};
use poseidon_merkle::{Item, Tree};

use dusk_plonk::prelude::*;

#[macro_use]
extern crate lazy_static;

static LABEL: &[u8; 12] = b"dusk-network";
const CAPACITY: usize = 17; // capacity required for the setup

const HEIGHT: usize = 17;
const ARITY: usize = 4;

struct TestingParameters {
    pp: PublicParameters,
    input_notes: [InputNote<HEIGHT, ARITY>; 4],
    output_notes: [OutputNote; 2],
    skeleton_hash: BlsScalar,
    root: BlsScalar,
    crossover: u64,
    max_fee: u64,
}

lazy_static! {
    static ref TP: TestingParameters = {
        let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng).unwrap();

        let mut rng = OsRng;
        let sk = SecretKey::random(&mut rng);

        let mut tree = Tree::<(), HEIGHT, ARITY>::new();

        let skeleton_hash = BlsScalar::from(1234u64);

        // create and insert into the tree 4 testing notes
        let input_notes =
            create_test_input_notes::<4>(&mut tree, &sk, skeleton_hash, &mut rng);

        // retrieve the root from the tree after inserting the notes
        let root = tree.root().hash;

        // create 2 testing circuit output notes
        let output_notes = [
            create_test_output_note(&sk, &mut rng),
            create_test_output_note(&sk, &mut rng),
        ];

        let crossover = 0;
        let max_fee = 0;

        TestingParameters { pp, input_notes, output_notes, skeleton_hash, root, crossover, max_fee }
    };
}

fn create_and_insert_test_note(
    tree: &mut Tree<(), HEIGHT, ARITY>,
    pk: &PublicKey,
    pos: u64,
    value: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Note {
    let mut note = Note::transparent(rng, pk, value);
    note.set_pos(pos);

    let item = Item {
        hash: note.hash(),
        data: (),
    };
    tree.insert(*note.pos(), item);

    note
}

fn create_test_input_notes<const I: usize>(
    tree: &mut Tree<(), HEIGHT, ARITY>,
    sk: &SecretKey,
    skeleton_hash: BlsScalar,
    rng: &mut (impl RngCore + CryptoRng),
) -> [InputNote<HEIGHT, ARITY>; I] {
    let pk = PublicKey::from(sk);

    let mut notes = Vec::new();
    for i in 0..I {
        notes.push(create_and_insert_test_note(
            tree,
            &pk,
            i.try_into().unwrap(),
            0,
            rng,
        ));
    }

    let mut input_notes = Vec::new();
    for i in 0..I {
        let merkle_opening = tree.opening(*notes[i].pos()).expect("Tree read.");
        let input_note =
            InputNote::new(&notes[i], merkle_opening, &sk, skeleton_hash, rng)
                .expect("Note created properly.");

        input_notes.push(input_note);
    }

    input_notes.try_into().unwrap()
}

fn create_test_output_note(
    sk: &SecretKey,
    rng: &mut (impl RngCore + CryptoRng),
) -> OutputNote {
    let note = Note::transparent(rng, &PublicKey::from(sk), 0);
    OutputNote::new(&note, &ViewKey::from(sk)).expect("Note created properly.")
}

#[test]
fn test_transfer_circuit_1_2() {
    let (prover, verifier) =
        Compiler::compile::<TransferCircuit<HEIGHT, ARITY, 1>>(&TP.pp, LABEL)
            .expect("failed to compile circuit");

    let input_notes = [TP.input_notes[0].clone()];

    let (proof, public_inputs) = prover
        .prove(
            &mut OsRng,
            &TransferCircuit::new(
                input_notes,
                TP.output_notes.clone(),
                TP.skeleton_hash,
                TP.root,
                TP.crossover,
                TP.max_fee,
            ),
        )
        .expect("failed to prove");

    verifier
        .verify(&proof, &public_inputs)
        .expect("failed to verify proof");
}

#[test]
fn test_transfer_circuit_2_2() {
    let (prover, verifier) =
        Compiler::compile::<TransferCircuit<HEIGHT, ARITY, 2>>(&TP.pp, LABEL)
            .expect("failed to compile circuit");

    let input_notes = [TP.input_notes[0].clone(), TP.input_notes[1].clone()];

    let (proof, public_inputs) = prover
        .prove(
            &mut OsRng,
            &TransferCircuit::new(
                input_notes,
                TP.output_notes.clone(),
                TP.skeleton_hash,
                TP.root,
                TP.crossover,
                TP.max_fee,
            ),
        )
        .expect("failed to prove");

    verifier
        .verify(&proof, &public_inputs)
        .expect("failed to verify proof");
}

#[test]
fn test_transfer_circuit_3_2() {
    let (prover, verifier) =
        Compiler::compile::<TransferCircuit<HEIGHT, ARITY, 3>>(&TP.pp, LABEL)
            .expect("failed to compile circuit");

    let input_notes = [
        TP.input_notes[0].clone(),
        TP.input_notes[1].clone(),
        TP.input_notes[2].clone(),
    ];

    let (proof, public_inputs) = prover
        .prove(
            &mut OsRng,
            &TransferCircuit::new(
                input_notes,
                TP.output_notes.clone(),
                TP.skeleton_hash,
                TP.root,
                TP.crossover,
                TP.max_fee,
            ),
        )
        .expect("failed to prove");

    verifier
        .verify(&proof, &public_inputs)
        .expect("failed to verify proof");
}

#[test]
fn test_transfer_circuit_4_2() {
    let (prover, verifier) =
        Compiler::compile::<TransferCircuit<HEIGHT, ARITY, 4>>(&TP.pp, LABEL)
            .expect("failed to compile circuit");

    let (proof, public_inputs) = prover
        .prove(
            &mut OsRng,
            &TransferCircuit::new(
                TP.input_notes.clone(),
                TP.output_notes.clone(),
                TP.skeleton_hash,
                TP.root,
                TP.crossover,
                TP.max_fee,
            ),
        )
        .expect("failed to prove");

    verifier
        .verify(&proof, &public_inputs)
        .expect("failed to verify proof");
}
