// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg(feature = "plonk")]

use rand::rngs::StdRng;
use rand::SeedableRng;
use rand::{CryptoRng, RngCore};

use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{JubJubAffine, JubJubScalar, GENERATOR_NUMS_EXTENDED};
use dusk_plonk::prelude::{Compiler, PublicParameters};
use ff::Field;
use jubjub_elgamal::Encryption as ElGamal;
use jubjub_schnorr::{
    SecretKey as SchnorrSecretKey, Signature as SchnorrSignature,
};
use poseidon_merkle::{Item, Tree};

use phoenix_circuits::{InputNoteInfo, OutputNoteInfo, TxCircuit};
use phoenix_core::{
    value_commitment, Note, PublicKey, SecretKey, ViewKey, OUTPUT_NOTES,
};

#[macro_use]
extern crate lazy_static;

static LABEL: &[u8; 12] = b"dusk-network";

const HEIGHT: usize = 17;

struct TestingParameters {
    pp: PublicParameters,
    input_notes_info: Vec<InputNoteInfo<HEIGHT>>,
    payload_hash: BlsScalar,
    root: BlsScalar,
    deposit: u64,
    max_fee: u64,
    sender_pk: PublicKey,
    output_npk: [JubJubAffine; OUTPUT_NOTES],
    signatures: (SchnorrSignature, SchnorrSignature),
    sender_blinder: [[JubJubScalar; 2]; OUTPUT_NOTES],
}

lazy_static! {
    static ref TP: TestingParameters = {
        const CAPACITY: usize = 17;

        let mut rng = StdRng::seed_from_u64(0xc0b);

        let pp = PublicParameters::setup(1 << CAPACITY, &mut rng).unwrap();
        let sender_sk = SecretKey::random(&mut rng);
        let sender_pk = PublicKey::from(&sender_sk);
        let receiver_pk = PublicKey::from(&SecretKey::random(&mut rng));

        let mut tree = Tree::<(), HEIGHT>::new();
        let payload_hash = BlsScalar::from(1234u64);

        // create and insert into the tree 4 testing tx input notes
        let input_notes_info = create_test_input_notes_information(
            &mut rng,
            &mut tree,
            &sender_sk,
            payload_hash
        );

        // retrieve the root from the tree after inserting the notes
        let root = tree.root().hash;

        let deposit = 5;
        let max_fee = 5;


        // generate both ouput note public keys
        let receiver_npk = *receiver_pk.gen_stealth_address(
            &JubJubScalar::random(&mut rng)
        ).note_pk().as_ref();
        let sender_npk = *sender_pk.gen_stealth_address(
            &JubJubScalar::random(&mut rng)
        ).note_pk().as_ref();
        let output_npk = [
            JubJubAffine::from(receiver_npk),
            JubJubAffine::from(sender_npk),
        ];

        // Sign the payload hash using both 'a' and 'b' of the sender_sk
        let schnorr_sk_a = SchnorrSecretKey::from(sender_sk.a());
        let sig_a = schnorr_sk_a.sign(&mut rng, payload_hash);
        let schnorr_sk_b = SchnorrSecretKey::from(sender_sk.b());
        let sig_b = schnorr_sk_b.sign(&mut rng, payload_hash);

        // sender blinder for the output notes
        let sender_blinder_0 = [
            JubJubScalar::random(&mut rng),
            JubJubScalar::random(&mut rng),
        ];
        let sender_blinder_1 = [
            JubJubScalar::random(&mut rng),
            JubJubScalar::random(&mut rng),
        ];

        TestingParameters {
            pp,
            input_notes_info,
            payload_hash,
            root,
            deposit,
            max_fee,
            sender_pk,
            output_npk,
            signatures: (sig_a, sig_b),
            sender_blinder: [sender_blinder_0, sender_blinder_1]
        }
    };
}

fn create_and_insert_test_note(
    rng: &mut (impl RngCore + CryptoRng),
    tree: &mut Tree<(), HEIGHT>,
    sender_pk: &PublicKey,
    pos: u64,
    value: u64,
) -> Note {
    let sender_blinder = [
        JubJubScalar::random(&mut *rng),
        JubJubScalar::random(&mut *rng),
    ];

    // create a note that belongs to the sender
    let mut note =
        Note::transparent(rng, sender_pk, sender_pk, value, sender_blinder);
    note.set_pos(pos);

    let item = Item {
        hash: note.hash(),
        data: (),
    };
    tree.insert(*note.pos(), item);

    note
}

fn create_test_input_notes_information(
    rng: &mut (impl RngCore + CryptoRng),
    tree: &mut Tree<(), HEIGHT>,
    sender_sk: &SecretKey,
    payload_hash: BlsScalar,
) -> Vec<InputNoteInfo<HEIGHT>> {
    let sender_pk = PublicKey::from(sender_sk);
    let sender_vk = ViewKey::from(sender_sk);
    let total_inputs = 4;

    // we first need to crate all the notes and insert them into the tree before
    // we can fetch their openings
    let mut notes = Vec::new();
    for i in 0..total_inputs {
        notes.push(create_and_insert_test_note(
            rng,
            tree,
            &sender_pk,
            i.try_into().unwrap(),
            25,
        ));
    }

    let mut input_notes_info = Vec::new();
    for note in notes.into_iter() {
        let note_sk = sender_sk.gen_note_sk(note.stealth_address());
        let merkle_opening = tree
            .opening(*note.pos())
            .expect("There should be a note at the given position");
        let note_pk_p =
            JubJubAffine::from(GENERATOR_NUMS_EXTENDED * note_sk.as_ref());
        let value = note
            .value(Some(&sender_vk))
            .expect("sender_sk should own the note");
        let value_blinder = note
            .value_blinder(Some(&sender_vk))
            .expect("sender_sk should own the note");
        let nullifier = note.gen_nullifier(&sender_sk);
        let signature = note_sk.sign_double(rng, payload_hash);
        input_notes_info.push(InputNoteInfo {
            merkle_opening,
            note,
            note_pk_p,
            value,
            value_blinder,
            nullifier,
            signature,
        });
    }

    input_notes_info
}

fn create_output_note_information(
    rng: &mut (impl RngCore + CryptoRng),
    value: u64,
    note_pk: JubJubAffine,
    sender_blinder: [JubJubScalar; 2],
) -> OutputNoteInfo {
    let value_blinder = JubJubScalar::random(&mut *rng);
    let value_commitment = value_commitment(value, value_blinder);

    let sender_blinder_a = sender_blinder[0];
    let (sender_enc_a, _) = ElGamal::encrypt(
        &note_pk.into(),
        TP.sender_pk.A(),
        None,
        &sender_blinder_a,
    );

    let sender_blinder_b = sender_blinder[1];
    let (sender_enc_b, _) = ElGamal::encrypt(
        &note_pk.into(),
        TP.sender_pk.B(),
        None,
        &sender_blinder_b,
    );

    let sender_enc_a = (sender_enc_a.c1().into(), sender_enc_a.c2().into());
    let sender_enc_b = (sender_enc_b.c1().into(), sender_enc_b.c2().into());

    OutputNoteInfo {
        value,
        value_commitment,
        value_blinder,
        note_pk,
        sender_enc: [sender_enc_a, sender_enc_b],
        sender_blinder,
    }
}

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
