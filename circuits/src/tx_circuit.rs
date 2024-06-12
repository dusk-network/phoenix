// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{JubJubAffine, JubJubScalar, GENERATOR, GENERATOR_NUMS};
use dusk_plonk::prelude::*;
use dusk_poseidon::{Domain, HashGadget};
use jubjub_schnorr::gadgets;
use poseidon_merkle::{zk::opening_gadget, Item, Tree};

use rand::rngs::StdRng;
use rand::SeedableRng;

extern crate alloc;
use alloc::vec::Vec;

use phoenix_core::{Note, SecretKey, OUTPUT_NOTES};

use crate::{recipient::gadget as recipient_gadget, RecipientParameters};

pub(crate) mod notes;
use notes::{TxInputNote, TxOutputNote};

/// Transaction gadget proving the following properties in ZK for a generic
/// `I` [`TxInputNote`] and [`OUTPUT_NOTES`] (2) [`TxOutputNote`]:
///
/// 1. Membership: every [`TxInputNote`] is included in the Merkle tree of
///    notes.
/// 2. Ownership: the sender holds the note secret key for every
///    [`TxInputNote`].
/// 3. Nullification: the nullifier is calculated correctly.
/// 4. Minting: the value commitment for every [`TxOutputNote`] is computed
///    correctly.
/// 5. Balance integrity: the sum of the values of all [`TxInputNote`] is equal
///    to the sum of the values of all [`TxOutputNote`] + the gas fee + a
///    deposit, where a deposit refers to funds being transfered to a contract.
///
/// The gadget appends the following public input values to the circuit:
/// - `root`
/// - `[nullifier; I]`
/// - `[output_value_commitment; 2]`
/// - `max_fee`
/// - `deposit`
fn nullify_gadget<const H: usize, const I: usize>(
    composer: &mut Composer,
    payload_hash: &Witness,
    root: &BlsScalar,
    tx_input_notes: &[TxInputNote<H>; I],
    tx_output_notes: &[TxOutputNote; OUTPUT_NOTES],
    max_fee: u64,
    deposit: u64,
) -> Result<(), Error> {
    let root_pi = composer.append_public(*root);

    let mut tx_input_notes_sum = Composer::ZERO;

    // NULLIFY ALL TX INPUT NOTES
    for tx_input_note in tx_input_notes {
        // APPEND THE WITNESSES TO THE CIRCUIT
        let w_tx_input_note = tx_input_note.append_to_circuit(composer);

        // VERIFY THE DOUBLE KEY SCHNORR SIGNATURE
        gadgets::verify_signature_double(
            composer,
            w_tx_input_note.signature_u,
            w_tx_input_note.signature_r,
            w_tx_input_note.signature_r_p,
            w_tx_input_note.note_pk,
            w_tx_input_note.note_pk_p,
            *payload_hash,
        )?;

        // COMPUTE AND ASSERT THE NULLIFIER
        let nullifier = HashGadget::digest(
            composer,
            Domain::Other,
            &[
                *w_tx_input_note.note_pk_p.x(),
                *w_tx_input_note.note_pk_p.y(),
                w_tx_input_note.pos,
            ],
        )[0];
        composer.assert_equal(nullifier, w_tx_input_note.nullifier);

        // PERFORM A RANGE CHECK ([0, 2^64 - 1]) ON THE VALUE OF THE NOTE
        composer.component_range::<32>(w_tx_input_note.value);

        // SUM UP ALL THE TX INPUT NOTE VALUES
        let constraint = Constraint::new()
            .left(1)
            .a(tx_input_notes_sum)
            .right(1)
            .b(w_tx_input_note.value);
        tx_input_notes_sum = composer.gate_add(constraint);

        // COMMIT TO THE VALUE OF THE NOTE
        let pc_1 = composer
            .component_mul_generator(w_tx_input_note.value, GENERATOR)?;
        let pc_2 = composer.component_mul_generator(
            w_tx_input_note.blinding_factor,
            GENERATOR_NUMS,
        )?;
        let value_commitment = composer.component_add_point(pc_1, pc_2);

        // COMPUTE THE NOTE HASH
        let note_hash = HashGadget::digest(
            composer,
            Domain::Other,
            &[
                w_tx_input_note.note_type,
                *value_commitment.x(),
                *value_commitment.y(),
                *w_tx_input_note.note_pk.x(),
                *w_tx_input_note.note_pk.y(),
                w_tx_input_note.pos,
            ],
        )[0];

        // VERIFY THE MERKLE OPENING
        let root =
            opening_gadget(composer, &tx_input_note.merkle_opening, note_hash);
        composer.assert_equal(root, root_pi);
    }

    let mut tx_output_sum = Composer::ZERO;

    // COMMIT TO ALL TX OUTPUT NOTES
    for tx_output_note in tx_output_notes {
        // APPEND THE WITNESSES TO THE CIRCUIT
        let w_tx_output_note = tx_output_note.append_to_circuit(composer);

        // PERFORM A RANGE CHECK ([0, 2^64 - 1]) ON THE VALUE OF THE NOTE
        composer.component_range::<32>(w_tx_output_note.value);

        // SUM UP ALL THE TX OUTPUT NOTE VALUES
        let constraint = Constraint::new()
            .left(1)
            .a(tx_output_sum)
            .right(1)
            .b(w_tx_output_note.value);
        tx_output_sum = composer.gate_add(constraint);

        // COMMIT TO THE VALUE OF THE NOTE
        let pc_1 = composer
            .component_mul_generator(w_tx_output_note.value, GENERATOR)?;
        let pc_2 = composer.component_mul_generator(
            w_tx_output_note.blinding_factor,
            GENERATOR_NUMS,
        )?;
        let value_commitment = composer.component_add_point(pc_1, pc_2);

        composer.assert_equal_point(
            w_tx_output_note.value_commitment,
            value_commitment,
        );
    }

    let max_fee = composer.append_public(max_fee);
    let deposit = composer.append_public(deposit);

    // SUM UP THE DEPOSIT AND THE MAX FEE
    let constraint = Constraint::new()
        .left(1)
        .a(tx_output_sum)
        .right(1)
        .b(max_fee)
        .fourth(1)
        .d(deposit);
    tx_output_sum = composer.gate_add(constraint);

    // VERIFY BALANCE
    composer.assert_equal(tx_input_notes_sum, tx_output_sum);

    Ok(())
}

/// Declaration of the transaction circuit calling the [`gadget`].
#[derive(Debug)]
pub struct TxCircuit<const H: usize, const I: usize> {
    tx_input_notes: [TxInputNote<H>; I],
    tx_output_notes: [TxOutputNote; OUTPUT_NOTES],
    payload_hash: BlsScalar,
    root: BlsScalar,
    deposit: u64,
    max_fee: u64,
    rp: RecipientParameters,
}

impl<const H: usize, const I: usize> Default for TxCircuit<H, I> {
    fn default() -> Self {
        let sk =
            SecretKey::new(JubJubScalar::default(), JubJubScalar::default());

        let mut tree = Tree::<(), H>::new();
        let payload_hash = BlsScalar::default();

        let mut tx_input_notes = Vec::new();
        let note = Note::empty();
        let item = Item {
            hash: note.hash(),
            data: (),
        };
        tree.insert(*note.pos(), item);

        for _ in 0..I {
            let merkle_opening = tree.opening(*note.pos()).expect("Tree read.");
            let tx_input_note = TxInputNote::new(
                &mut StdRng::seed_from_u64(0xb001),
                &note,
                merkle_opening,
                &sk,
                payload_hash,
            )
            .expect("Note created properly.");

            tx_input_notes.push(tx_input_note);
        }

        let tx_output_note_1 = TxOutputNote {
            value: 0,
            value_commitment: JubJubAffine::default(),
            blinding_factor: JubJubScalar::default(),
        };
        let tx_output_note_2 = tx_output_note_1.clone();

        let tx_output_notes = [tx_output_note_1, tx_output_note_2];

        let root = BlsScalar::default();
        let deposit = u64::default();
        let max_fee = u64::default();

        let rp = RecipientParameters::default();

        Self {
            tx_input_notes: tx_input_notes.try_into().unwrap(),
            tx_output_notes,
            payload_hash,
            root,
            deposit,
            max_fee,
            rp,
        }
    }
}

impl<const H: usize, const I: usize> TxCircuit<H, I> {
    /// Create a new transfer circuit
    pub fn new(
        tx_input_notes: [TxInputNote<H>; I],
        tx_output_notes: [TxOutputNote; OUTPUT_NOTES],
        payload_hash: BlsScalar,
        root: BlsScalar,
        deposit: u64,
        max_fee: u64,
        rp: RecipientParameters,
    ) -> Self {
        Self {
            tx_input_notes,
            tx_output_notes,
            payload_hash,
            root,
            deposit,
            max_fee,
            rp,
        }
    }
}

impl<const H: usize, const I: usize> Circuit for TxCircuit<H, I> {
    /// The circuit has the following public inputs:
    /// - `payload_hash`
    /// - `root`
    /// - `[nullifier; I]`
    /// - `[output_value_commitment; 2]`
    /// - `max_fee`
    /// - `deposit`
    /// - `(npk_1, npk_2)`
    /// - `(enc_A_npk_1, enc_A_npk_2)`
    /// - `(enc_B_npk_1, enc_B_npk_2)`
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        // Make the payload hash a public input of the circuit
        let payload_hash = composer.append_public(self.payload_hash);

        // Nullify all the tx input notes
        nullify_gadget::<H, I>(
            composer,
            &payload_hash,
            &self.root,
            &self.tx_input_notes,
            &self.tx_output_notes,
            self.max_fee,
            self.deposit,
        )?;

        // Prove correctness of the sender keys encryption
        recipient_gadget(composer, &self.rp, payload_hash)?;

        Ok(())
    }
}
