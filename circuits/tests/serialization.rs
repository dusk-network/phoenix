// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use rand::rngs::StdRng;
use rand::SeedableRng;
use rand::{CryptoRng, Rng, RngCore};

use dusk_bls12_381::BlsScalar;
use dusk_bytes::{Error as BytesError, Serializable};
use dusk_jubjub::{JubJubAffine, JubJubScalar, GENERATOR_EXTENDED};
use ff::Field;
use jubjub_schnorr::{Signature as SchnorrSignature, SignatureDouble};
use poseidon_merkle::{Item, Tree};

use phoenix_circuits::{InputNoteInfo, OutputNoteInfo, TxCircuit};
use phoenix_core::{Note, PublicKey, SecretKey};

const HEIGHT: usize = 17;

#[test]
fn tx_ciruit_1_2() -> Result<(), BytesError> {
    let mut rng = StdRng::seed_from_u64(0xbeef);

    let circuit = random_circuit::<1>(&mut rng);
    let circuit_bytes = circuit.to_var_bytes();

    assert_eq!(
        circuit,
        TxCircuit::<HEIGHT, 1>::from_slice(&circuit_bytes[..])?
    );

    Ok(())
}

#[test]
fn tx_ciruit_2_2() -> Result<(), BytesError> {
    let mut rng = StdRng::seed_from_u64(0xbeef);

    let circuit = random_circuit::<1>(&mut rng);
    let circuit_bytes = circuit.to_var_bytes();

    assert_eq!(
        circuit,
        TxCircuit::<HEIGHT, 1>::from_slice(&circuit_bytes[..])?
    );

    Ok(())
}

#[test]
fn tx_ciruit_3_2() -> Result<(), BytesError> {
    let mut rng = StdRng::seed_from_u64(0xbeef);

    let circuit = random_circuit::<1>(&mut rng);
    let circuit_bytes = circuit.to_var_bytes();

    assert_eq!(
        circuit,
        TxCircuit::<HEIGHT, 1>::from_slice(&circuit_bytes[..])?
    );

    Ok(())
}

#[test]
fn tx_ciruit_4_2() -> Result<(), BytesError> {
    let mut rng = StdRng::seed_from_u64(0xbeef);

    let circuit = random_circuit::<1>(&mut rng);
    let circuit_bytes = circuit.to_var_bytes();

    assert_eq!(
        circuit,
        TxCircuit::<HEIGHT, 1>::from_slice(&circuit_bytes[..])?
    );

    Ok(())
}

fn random_circuit<const I: usize>(
    rng: &mut (impl RngCore + CryptoRng),
) -> TxCircuit<HEIGHT, I> {
    let mut input_notes_info = Vec::new();
    for _ in 0..I {
        input_notes_info.push(random_input_note_info(rng));
    }

    let sender_pk = PublicKey::from(&SecretKey::random(rng));

    let mut signature_0_bytes = [0u8; SchnorrSignature::SIZE];
    // generate random signature_0.u
    signature_0_bytes[..32]
        .copy_from_slice(&JubJubScalar::random(&mut *rng).to_bytes()[..]);
    signature_0_bytes[32..]
        .copy_from_slice(&random_jubjub_affine(rng).to_bytes()[..]);

    let mut signature_1_bytes = [0u8; SchnorrSignature::SIZE];
    // generate random signature_1.u
    signature_1_bytes[..32]
        .copy_from_slice(&JubJubScalar::random(&mut *rng).to_bytes()[..]);
    // generate random signature_1.R
    signature_0_bytes[32..]
        .copy_from_slice(&random_jubjub_affine(rng).to_bytes()[..]);

    TxCircuit {
        input_notes_info: input_notes_info
            .try_into()
            .expect("there are exactly I inputs"),
        output_notes_info: [
            random_output_note_info(rng),
            random_output_note_info(rng),
        ],
        payload_hash: BlsScalar::random(&mut *rng),
        root: BlsScalar::random(&mut *rng),
        deposit: rng.gen(),
        max_fee: rng.gen(),
        sender_pk,
        signatures: (
            SchnorrSignature::from_bytes(&signature_0_bytes)
                .expect("the signature bytes should be correct"),
            SchnorrSignature::from_bytes(&signature_1_bytes)
                .expect("the signature bytes should be correct"),
        ),
    }
}

fn random_input_note_info(
    rng: &mut (impl RngCore + CryptoRng),
) -> InputNoteInfo<HEIGHT> {
    let pk = PublicKey::from(&SecretKey::random(rng));
    let value_blinder = JubJubScalar::random(&mut *rng);
    let sender_blinder = [
        JubJubScalar::random(&mut *rng),
        JubJubScalar::random(&mut *rng),
    ];

    let mut note =
        Note::obfuscated(rng, &pk, &pk, 42, value_blinder, sender_blinder);
    note.set_pos(42);
    let mut notes_tree = Tree::<(), HEIGHT>::new();
    let item = Item {
        hash: note.hash(),
        data: (),
    };
    notes_tree.insert(*note.pos(), item);
    let merkle_opening = notes_tree
        .opening(*note.pos())
        .expect("The note should was added at the given position");
    let note_pk_p = random_jubjub_affine(rng);

    let mut signature_bytes = [0u8; SignatureDouble::SIZE];
    // generate random signature.u
    signature_bytes[..JubJubScalar::SIZE]
        .copy_from_slice(&JubJubScalar::random(&mut *rng).to_bytes()[..]);
    let mut offset = JubJubScalar::SIZE;
    // generate random signature.R
    signature_bytes[offset..offset + JubJubAffine::SIZE]
        .copy_from_slice(&random_jubjub_affine(rng).to_bytes()[..]);
    offset += JubJubAffine::SIZE;
    // generate random signature.R_prime
    signature_bytes[offset..offset + JubJubAffine::SIZE]
        .copy_from_slice(&random_jubjub_affine(rng).to_bytes()[..]);

    InputNoteInfo {
        merkle_opening,
        note,
        note_pk_p,
        value: rng.gen(),
        value_blinder: JubJubScalar::random(&mut *rng),
        nullifier: BlsScalar::random(&mut *rng),
        signature: SignatureDouble::from_bytes(&signature_bytes)
            .expect("signature-bytes to be correct"),
    }
}

fn random_output_note_info(
    rng: &mut (impl RngCore + CryptoRng),
) -> OutputNoteInfo {
    let value_commitment = random_jubjub_affine(rng);
    let note_pk = random_jubjub_affine(rng);

    let sender_enc_0_0 = random_jubjub_affine(rng);
    let sender_enc_0_1 = random_jubjub_affine(rng);
    let sender_enc_1_0 = random_jubjub_affine(rng);
    let sender_enc_1_1 = random_jubjub_affine(rng);

    OutputNoteInfo {
        value: rng.gen(),
        value_commitment,
        value_blinder: JubJubScalar::random(&mut *rng),
        note_pk,
        sender_enc: [
            (sender_enc_0_0, sender_enc_0_1),
            (sender_enc_1_0, sender_enc_1_1),
        ],
        sender_blinder: [
            JubJubScalar::random(&mut *rng),
            JubJubScalar::random(&mut *rng),
        ],
    }
}

fn random_jubjub_affine(rng: &mut (impl RngCore + CryptoRng)) -> JubJubAffine {
    (GENERATOR_EXTENDED * &JubJubScalar::random(&mut *rng)).into()
}
