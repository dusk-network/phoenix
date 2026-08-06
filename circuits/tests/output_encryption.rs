// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg(feature = "plonk")]

use dusk_bls12_381::BlsScalar;
use dusk_bytes::Serializable;
use dusk_jubjub::{JubJubAffine, JubJubScalar};
use dusk_plonk::prelude::{Circuit, Compiler};
use ff::Field;
use phoenix_circuits::{OutputEncryptionCircuit, OutputEncryptionInfo};
use phoenix_core::{Note, NoteType, PublicKey, SecretKey, value_commitment};
use rand::SeedableRng;
use rand::rngs::StdRng;

#[allow(dead_code)]
mod common;
use common::{LABEL, load_production_crs};

fn output(
    rng: &mut StdRng,
    sender_pk: &PublicKey,
    receiver_pk: &PublicKey,
    note_type: NoteType,
    value: u64,
) -> OutputEncryptionInfo {
    let value_blinder = match note_type {
        NoteType::Transparent => JubJubScalar::zero(),
        NoteType::Obfuscated => JubJubScalar::random(&mut *rng),
    };
    let sender_blinder = [
        JubJubScalar::random(&mut *rng),
        JubJubScalar::random(&mut *rng),
    ];
    let (note, encryption_secret) = Note::new_with_ephemeral(
        rng,
        note_type,
        sender_pk,
        receiver_pk,
        value,
        value_blinder,
        sender_blinder,
    );

    OutputEncryptionInfo::new(
        &note,
        receiver_pk,
        value,
        value_blinder,
        encryption_secret,
    )
    .expect("the note constructor emits canonical scalars")
}

fn expected_public_inputs(circuit: &OutputEncryptionCircuit) -> Vec<BlsScalar> {
    let mut inputs = Vec::new();
    for output in &circuit.outputs {
        inputs.push(output.value_commitment.get_u());
        inputs.push(output.value_commitment.get_v());
        inputs.push(BlsScalar::from(output.note_type as u64));
        inputs.extend(output.value_enc);
        inputs.push(output.R.get_u());
        inputs.push(output.R.get_v());
    }
    inputs
}

#[test]
fn binds_output_ciphertexts_to_their_commitment_openings() {
    let mut rng = StdRng::seed_from_u64(0xc1f3);
    let pp = load_production_crs();
    let (prover, verifier) =
        Compiler::compile::<OutputEncryptionCircuit>(&pp, LABEL)
            .expect("the auxiliary circuit must fit the production CRS");

    assert!(OutputEncryptionCircuit::default().size() < 1 << 17);

    let sender_pk = PublicKey::from(&SecretKey::random(&mut rng));
    let receiver_pk = PublicKey::from(&SecretKey::random(&mut rng));
    let honest = OutputEncryptionCircuit {
        outputs: [
            output(
                &mut rng,
                &sender_pk,
                &receiver_pk,
                NoteType::Obfuscated,
                10,
            ),
            output(&mut rng, &sender_pk, &sender_pk, NoteType::Transparent, 5),
        ],
    };

    assert_eq!(
        honest,
        OutputEncryptionCircuit::from_bytes(&honest.to_bytes())
            .expect("the auxiliary circuit should round-trip")
    );
    let (proof, public_inputs) = prover
        .prove(&mut rng, &honest)
        .expect("honest encrypted and transparent outputs should prove");
    assert_eq!(public_inputs, expected_public_inputs(&honest));
    verifier
        .verify(&proof, &public_inputs)
        .expect("honest output encryptions should verify");

    let committed_value = 10;
    let committed_blinder = JubJubScalar::random(&mut rng);
    let encrypted_value = 1_000;
    let encrypted_blinder = JubJubScalar::random(&mut rng);
    let sender_blinder = [
        JubJubScalar::random(&mut rng),
        JubJubScalar::random(&mut rng),
    ];
    let (encrypted_note, encryption_secret) = Note::new_with_ephemeral(
        &mut rng,
        NoteType::Obfuscated,
        &sender_pk,
        &receiver_pk,
        encrypted_value,
        encrypted_blinder,
        sender_blinder,
    );
    let mut encoded = encrypted_note.to_bytes();
    encoded[1..1 + JubJubAffine::SIZE].copy_from_slice(
        &value_commitment(committed_value, committed_blinder).to_bytes(),
    );
    let malformed_note =
        Note::from_bytes(&encoded).expect("the individual fields are valid");
    let malformed = OutputEncryptionInfo::new(
        &malformed_note,
        &receiver_pk,
        committed_value,
        committed_blinder,
        encryption_secret,
    )
    .expect("the ciphertext fields are canonical");

    let malformed_circuit = OutputEncryptionCircuit {
        outputs: [malformed, honest.outputs[1].clone()],
    };
    assert!(
        prover.prove(&mut rng, &malformed_circuit).is_err(),
        "a ciphertext containing a different opening was proved"
    );

    let mut tampered = honest.clone();
    tampered.outputs[0].value_enc[0] += BlsScalar::one();
    assert!(
        prover.prove(&mut rng, &tampered).is_err(),
        "a tampered ciphertext was proved"
    );

    let mut noncanonical_transparent = honest.clone();
    noncanonical_transparent.outputs[1].value_enc[1] = BlsScalar::one();
    assert!(
        prover.prove(&mut rng, &noncanonical_transparent).is_err(),
        "a non-canonical transparent payload was proved"
    );

    let mut wrong_receiver = honest.clone();
    let other_receiver = PublicKey::from(&SecretKey::random(&mut rng));
    wrong_receiver.outputs[0].receiver_A =
        JubJubAffine::from(other_receiver.A());
    assert!(
        prover.prove(&mut rng, &wrong_receiver).is_err(),
        "a ciphertext under a different receiver key was proved"
    );

    let mut wrong_ephemeral = honest;
    wrong_ephemeral.outputs[0].encryption_secret += JubJubScalar::one();
    assert!(
        prover.prove(&mut rng, &wrong_ephemeral).is_err(),
        "an encryption secret inconsistent with R was proved"
    );
}
