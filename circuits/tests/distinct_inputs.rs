// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Regression for a transaction repeating an input note.
//!
//! The circuit constrains the input positions in the tree of notes to be
//! pairwise distinct, so a transaction with the same note in two inputs is
//! unsatisfiable, although each input passes its own checks.

#![cfg(feature = "plonk")]

use std::sync::LazyLock;

use dusk_plonk::prelude::{Compiler, Error as PlonkError, PublicParameters};
use phoenix_circuits::TxCircuit;
use rand::SeedableRng;
use rand::rngs::StdRng;

mod common;
use common::*;

/// A test SRS that fits every input variant. Soundness does not depend on the
/// SRS, and the production CRS only fits the 1- and 2-input circuits under
/// `dusk-plonk`'s blinding degree.
static PP: LazyLock<PublicParameters> = LazyLock::new(|| {
    PublicParameters::setup(1 << 17, &mut StdRng::seed_from_u64(0xd15))
        .expect("failed to generate the test SRS")
});

/// Proves the honest transaction spending the first `I` test notes, then the
/// same transaction with input `j` replaced by a copy of input `i`, for every
/// pair `i < j`. Every test note has the same value, so a copy leaves the
/// balance intact and only the distinct-position constraint can fail.
fn assert_duplicate_input_rejected<const I: usize>(output_values: [u64; 2]) {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let (prover, verifier) =
        Compiler::compile::<TxCircuit<HEIGHT, I>>(&PP, LABEL)
            .expect("failed to compile circuit");

    let input_notes_info: [InputNoteInfo<HEIGHT>; I] =
        core::array::from_fn(|i| TP.input_notes_info[i].clone());
    let output_notes_info = [
        create_output_note_information(
            &mut rng,
            output_values[0],
            TP.output_npk[0],
            TP.sender_blinder[0],
        ),
        create_output_note_information(
            &mut rng,
            output_values[1],
            TP.output_npk[1],
            TP.sender_blinder[1],
        ),
    ];
    let circuit = TxCircuit {
        input_notes_info,
        output_notes_info,
        payload_hash: TP.payload_hash,
        root: TP.root,
        deposit: TP.deposit,
        max_fee: TP.max_fee,
        sender_pk: TP.sender_pk,
        signatures: TP.signatures,
    };

    let (proof, public_inputs) = prover
        .prove(&mut rng, &circuit)
        .expect("the honest transaction should prove");
    verifier
        .verify(&proof, &public_inputs)
        .expect("the honest proof should verify");

    for i in 0..I {
        for j in i + 1..I {
            let mut duplicate = circuit.clone();
            duplicate.input_notes_info[j] = circuit.input_notes_info[i].clone();

            let result = prover.prove(&mut rng, &duplicate);
            assert!(
                matches!(result, Err(PlonkError::CircuitUnsatisfied)),
                "spending input {i} again as input {j} must be unsatisfiable, \
                 got {:?}",
                result.map(|_| "a proof"),
            );
        }
    }
}

#[test]
fn duplicate_input_rejected_2_2() {
    assert_duplicate_input_rejected::<2>([35, 5]);
}

#[test]
fn duplicate_input_rejected_3_2() {
    assert_duplicate_input_rejected::<3>([35, 30]);
}

#[test]
fn duplicate_input_rejected_4_2() {
    assert_duplicate_input_rejected::<4>([60, 30]);
}
