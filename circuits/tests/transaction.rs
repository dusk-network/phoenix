// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use rand::rngs::StdRng;
use rand::SeedableRng;
use rand::{CryptoRng, RngCore};

use dusk_jubjub::{JubJubScalar, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};

use dusk_plonk::prelude::*;
use ff::Field;
use jubjub_schnorr::SecretKey as SchnorrSecretKey;

use phoenix_circuits::{
    elgamal,
    transaction::{TxCircuit, TxInputNote, TxOutputNote},
    RecipientParameters,
};
use phoenix_core::{Note, PublicKey, SecretKey};

use poseidon_merkle::{Item, Tree};

#[macro_use]
extern crate lazy_static;

static LABEL: &[u8; 12] = b"dusk-network";
const CAPACITY: usize = 17; // capacity required for the setup

const HEIGHT: usize = 17;

struct TestingParameters {
    pp: PublicParameters,
    tx_input_notes: [TxInputNote<HEIGHT>; 4],
    payload_hash: BlsScalar,
    root: BlsScalar,
    deposit: u64,
    max_fee: u64,
    rp: RecipientParameters,
}

lazy_static! {
    static ref TP: TestingParameters = {
        let mut rng = StdRng::seed_from_u64(0xc0b);

        let pp = PublicParameters::setup(1 << CAPACITY, &mut rng).unwrap();
        let sk = SecretKey::random(&mut rng);

        let mut tree = Tree::<(), HEIGHT>::new();
        let payload_hash = BlsScalar::from(1234u64);

        // create and insert into the tree 4 testing tx input notes
        let tx_input_notes =
            create_test_tx_input_notes::<4>(&mut rng, &mut tree, &sk, payload_hash);

        // retrieve the root from the tree after inserting the notes
        let root = tree.root().hash;

        let deposit = 5;
        let max_fee = 5;

        // Compute the tx output note public keys using
        // the recipient public key
        let recipient_pk = PublicKey::from(&sk);

        let r = JubJubScalar::random(&mut rng);
        let sa = recipient_pk.gen_stealth_address(&r);
        let note_pk_1 = sa.note_pk();

        let r = JubJubScalar::random(&mut rng);
        let sa = recipient_pk.gen_stealth_address(&r);
        let note_pk_2 = sa.note_pk();

        let recipient_npk_vec = [
            JubJubAffine::from(note_pk_1.as_ref()),
            JubJubAffine::from(note_pk_2.as_ref()),
        ];

        // Encrypt the public key of the sender. We need to encrypt
        // both 'A' and 'B', using both tx output note public keys.
        // We use the same 'sk' just for testing.
        let sender_pk = PublicKey::from(&sk);

        #[allow(non_snake_case)]
        let r_A_1 = JubJubScalar::random(&mut rng);
        #[allow(non_snake_case)]
        let (A_enc_1_c1, A_enc_1_c2) =
            elgamal::encrypt(note_pk_1.as_ref(), &sender_pk.A(), &r_A_1);

        #[allow(non_snake_case)]
        let r_B_1 = JubJubScalar::random(&mut rng);
        #[allow(non_snake_case)]
        let (B_enc_1_c1, B_enc_1_c2) =
            elgamal::encrypt(note_pk_1.as_ref(), &sender_pk.B(), &r_B_1);
        #[allow(non_snake_case)]
        let r_A_2 = JubJubScalar::random(&mut rng);
        #[allow(non_snake_case)]
        let (A_enc_2_c1, A_enc_2_c2) =
            elgamal::encrypt(note_pk_2.as_ref(), &sender_pk.A(), &r_A_2);

        #[allow(non_snake_case)]
        let r_B_2 = JubJubScalar::random(&mut rng);
        #[allow(non_snake_case)]
        let (B_enc_2_c1, B_enc_2_c2) =
            elgamal::encrypt(note_pk_2.as_ref(), &sender_pk.B(), &r_B_2);

        #[allow(non_snake_case)]
        let enc_A_vec = [(A_enc_1_c1, A_enc_1_c2), (A_enc_2_c1, A_enc_2_c2)];
        #[allow(non_snake_case)]
        let enc_B_vec = [(B_enc_1_c1, B_enc_1_c2), (B_enc_2_c1, B_enc_2_c2)];

        #[allow(non_snake_case)]
        let r_A_vec = [r_A_1, r_A_2];
        #[allow(non_snake_case)]
        let r_B_vec = [r_B_1, r_B_2];

        // Sign the payload hash using both 'a' and 'b'
        let schnorr_sk_a = SchnorrSecretKey::from(sk.a());
        #[allow(non_snake_case)]
        let sig_A = schnorr_sk_a.sign(&mut rng, payload_hash);

        let schnorr_sk_b = SchnorrSecretKey::from(sk.b());
        #[allow(non_snake_case)]
        let sig_B = schnorr_sk_b.sign(&mut rng, payload_hash);

        let sig_vec = [sig_A, sig_B];

        let rp = RecipientParameters { sender_pk, recipient_npk_vec, sig_vec, enc_A_vec, enc_B_vec, r_A_vec, r_B_vec };

        TestingParameters { pp, tx_input_notes, payload_hash, root, deposit, max_fee, rp }
    };
}

fn create_and_insert_test_note(
    rng: &mut (impl RngCore + CryptoRng),
    tree: &mut Tree<(), HEIGHT>,
    pk: &PublicKey,
    pos: u64,
    value: u64,
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

fn create_test_tx_input_notes<const I: usize>(
    rng: &mut (impl RngCore + CryptoRng),
    tree: &mut Tree<(), HEIGHT>,
    sk: &SecretKey,
    payload_hash: BlsScalar,
) -> [TxInputNote<HEIGHT>; I] {
    let pk = PublicKey::from(sk);

    let mut notes = Vec::new();
    for i in 0..I {
        notes.push(create_and_insert_test_note(
            rng,
            tree,
            &pk,
            i.try_into().unwrap(),
            25,
        ));
    }

    let mut input_notes = Vec::new();
    for i in 0..I {
        let merkle_opening = tree.opening(*notes[i].pos()).expect("Tree read.");
        let input_note =
            TxInputNote::new(rng, &notes[i], merkle_opening, &sk, payload_hash)
                .expect("Note created properly.");

        input_notes.push(input_note);
    }

    input_notes.try_into().unwrap()
}

// we don't care if the test output notes are spendable
fn create_test_tx_output_note(value: u64) -> TxOutputNote {
    let blinding_factor = JubJubScalar::from(42u64);

    let value_commitment = JubJubAffine::from(
        (GENERATOR_EXTENDED * JubJubScalar::from(value))
            + (GENERATOR_NUMS_EXTENDED * blinding_factor),
    );

    TxOutputNote::new(value, value_commitment, blinding_factor)
}

#[test]
fn test_transfer_circuit_1_2() {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let (prover, verifier) =
        Compiler::compile::<TxCircuit<HEIGHT, 1>>(&TP.pp, LABEL)
            .expect("failed to compile circuit");

    let input_notes = [TP.tx_input_notes[0].clone()];

    // create 2 testing tx output notes
    let tx_output_notes = [
        create_test_tx_output_note(10),
        create_test_tx_output_note(5),
    ];

    let (proof, public_inputs) = prover
        .prove(
            &mut rng,
            &TxCircuit::new(
                input_notes,
                tx_output_notes,
                TP.payload_hash,
                TP.root,
                TP.deposit,
                TP.max_fee,
                TP.rp,
            ),
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

    let input_notes =
        [TP.tx_input_notes[0].clone(), TP.tx_input_notes[1].clone()];

    // create 2 testing tx output notes
    let tx_output_notes = [
        create_test_tx_output_note(35),
        create_test_tx_output_note(5),
    ];

    let (proof, public_inputs) = prover
        .prove(
            &mut rng,
            &TxCircuit::new(
                input_notes,
                tx_output_notes,
                TP.payload_hash,
                TP.root,
                TP.deposit,
                TP.max_fee,
                TP.rp,
            ),
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

    let input_notes = [
        TP.tx_input_notes[0].clone(),
        TP.tx_input_notes[1].clone(),
        TP.tx_input_notes[2].clone(),
    ];

    // create 2 testing tx output notes
    let tx_output_notes = [
        create_test_tx_output_note(35),
        create_test_tx_output_note(30),
    ];

    let (proof, public_inputs) = prover
        .prove(
            &mut rng,
            &TxCircuit::new(
                input_notes,
                tx_output_notes,
                TP.payload_hash,
                TP.root,
                TP.deposit,
                TP.max_fee,
                TP.rp,
            ),
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

    // create 2 testing tx output notes
    let tx_output_notes = [
        create_test_tx_output_note(60),
        create_test_tx_output_note(30),
    ];

    let (proof, public_inputs) = prover
        .prove(
            &mut rng,
            &TxCircuit::new(
                TP.tx_input_notes.clone(),
                tx_output_notes,
                TP.payload_hash,
                TP.root,
                TP.deposit,
                TP.max_fee,
                TP.rp,
            ),
        )
        .expect("failed to prove");

    verifier
        .verify(&proof, &public_inputs)
        .expect("failed to verify proof");
}
