// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! The [`Circuit`] trait implementation on [`TxCircuit`].

use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{GENERATOR, GENERATOR_NUMS};
use dusk_plonk::prelude::{
    Circuit, Composer, Constraint, Error as PlonkError, Witness, WitnessPoint,
};
use dusk_poseidon::{Domain, HashGadget};
use jubjub_schnorr::gadgets;
use poseidon_merkle::zk::opening_gadget;

use crate::{sender_enc, InputNoteInfo, TxCircuit};

impl<const H: usize, const I: usize> Circuit for TxCircuit<H, I> {
    /// Transaction gadget proving the following properties in ZK for a generic
    /// `I` input-notes and [`OUTPUT_NOTES`] output-notes:
    ///
    /// 1. Membership: every input-note is included in the Merkle tree of notes.
    /// 2. Ownership: the sender holds the note secret key for every input-note.
    /// 3. Nullification: the nullifier is calculated correctly.
    /// 4. Minting: the value commitment for every input-note is computed
    ///    correctly.
    /// 5. Balance integrity: the sum of the values of all input-notes is equal
    ///    to the sum of the values of all output-notes + the gas fee + a
    ///    deposit, where a deposit refers to funds being transferred to a
    ///    contract.
    /// 6. Sender-data: Verify that the sender was encrypted correctly for each
    ///    output-note.
    ///
    /// The circuit has the following public inputs:
    /// - `payload_hash`
    /// - `root`
    /// - `[nullifier; I]`
    /// - `[output_value_commitment; 2]`
    /// - `max_fee`
    /// - `deposit`
    /// - `(npk_out_0, npk_out_1)`
    /// - `(enc_A_npk_out_0, enc_B_npk_out_0)`
    /// - `(enc_A_npk_out_1, enc_B_npk_out_1)`
    fn circuit(&self, composer: &mut Composer) -> Result<(), PlonkError> {
        // Make the payload hash a public input of the circuit
        let payload_hash = composer.append_public(self.payload_hash);

        // Append the root as public input
        let root_pi = composer.append_public(self.root);

        let mut input_notes_sum = Composer::ZERO;

        // Check membership, ownership and nullification of all input notes
        for input_note_info in &self.input_notes_info {
            let (
                note_pk,
                note_pk_p,
                note_type,
                pos,
                value,
                value_blinder,
                nullifier,
                signature_u,
                signature_r,
                signature_r_p,
            ) = input_note_info.append_to_circuit(composer);

            // Verify: 2. Ownership
            gadgets::verify_signature_double(
                composer,
                signature_u,
                signature_r,
                signature_r_p,
                note_pk,
                note_pk_p,
                payload_hash,
            )?;

            // Verify: 3. Nullification
            let computed_nullifier = HashGadget::digest(
                composer,
                Domain::Other,
                &[*note_pk_p.x(), *note_pk_p.y(), pos],
            )[0];
            composer.assert_equal(computed_nullifier, nullifier);

            // Perform a range check ([0, 2^64 - 1]) on the value of the note
            composer.component_range::<32>(value);

            // Sum up all the input note values
            let constraint = Constraint::new()
                .left(1)
                .a(input_notes_sum)
                .right(1)
                .b(value);
            input_notes_sum = composer.gate_add(constraint);

            // Commit to the value of the note
            let pc_1 = composer.component_mul_generator(value, GENERATOR)?;
            let pc_2 = composer
                .component_mul_generator(value_blinder, GENERATOR_NUMS)?;
            let value_commitment = composer.component_add_point(pc_1, pc_2);

            // Compute the note hash
            let note_hash = HashGadget::digest(
                composer,
                Domain::Other,
                &[
                    note_type,
                    *value_commitment.x(),
                    *value_commitment.y(),
                    *note_pk.x(),
                    *note_pk.y(),
                    pos,
                ],
            )[0];

            // Verify: 1. Membership
            let root = opening_gadget(
                composer,
                &input_note_info.merkle_opening,
                note_hash,
            );
            composer.assert_equal(root, root_pi);
        }

        let mut tx_output_sum = Composer::ZERO;

        // Commit to all output notes
        for output_note_info in &self.output_notes_info {
            // Append the witnesses to the circuit
            let value = composer.append_witness(output_note_info.value);
            // Append the value-commitment as public input
            let expected_value_commitment =
                composer.append_public_point(output_note_info.value_commitment);
            let value_blinder =
                composer.append_witness(output_note_info.value_blinder);

            // Perform a range check ([0, 2^64 - 1]) on the value of the note
            composer.component_range::<32>(value);

            // Sum up all the output note values
            let constraint =
                Constraint::new().left(1).a(tx_output_sum).right(1).b(value);
            tx_output_sum = composer.gate_add(constraint);

            // Commit to the value of the note
            let pc_1 = composer.component_mul_generator(value, GENERATOR)?;
            let pc_2 = composer
                .component_mul_generator(value_blinder, GENERATOR_NUMS)?;
            let computed_value_commitment =
                composer.component_add_point(pc_1, pc_2);

            // Verify: 4. Minting
            composer.assert_equal_point(
                expected_value_commitment,
                computed_value_commitment,
            );
        }

        // Append max_fee and deposit as public inputs
        let max_fee = composer.append_public(self.max_fee);
        let deposit = composer.append_public(self.deposit);

        // Add the deposit and the max fee to the sum of the output-values
        let constraint = Constraint::new()
            .left(1)
            .a(tx_output_sum)
            .right(1)
            .b(max_fee)
            .fourth(1)
            .d(deposit);
        tx_output_sum = composer.gate_add(constraint);

        // Verify: 5. Balance integrity
        composer.assert_equal(input_notes_sum, tx_output_sum);

        // Verify: 6. Sender-data
        // appends as public input the note-pk of both output-notes:
        // `(npk_out_0, npk_out_1)`
        // and the encryption of the sender-pk.A and sender-pk.B,
        // encrypted first with the note-pk of one output note:
        // `(enc_A_npk_out_0, enc_B_npk_out_0)
        // and then with the note-pk of the other note:
        // `(enc_A_npk_out_1, enc_B_npk_out_1)
        sender_enc::gadget(
            composer,
            self.sender_pk,
            self.signatures,
            [
                self.output_notes_info[0].note_pk,
                self.output_notes_info[1].note_pk,
            ],
            [
                self.output_notes_info[0].sender_blinder,
                self.output_notes_info[1].sender_blinder,
            ],
            self.output_notes_info[0].sender_enc,
            self.output_notes_info[1].sender_enc,
            payload_hash,
        )?;

        Ok(())
    }
}

impl<const H: usize> InputNoteInfo<H> {
    fn append_to_circuit(
        &self,
        composer: &mut Composer,
    ) -> (
        WitnessPoint,
        WitnessPoint,
        Witness,
        Witness,
        Witness,
        Witness,
        Witness,
        Witness,
        WitnessPoint,
        WitnessPoint,
    ) {
        // Append the nullifier as public-input
        let nullifier = composer.append_public(self.nullifier);

        let note_pk = composer
            .append_point(*self.note.stealth_address().note_pk().as_ref());
        let note_pk_p = composer.append_point(self.note_pk_p);

        let note_type = composer
            .append_witness(BlsScalar::from(self.note.note_type() as u64));
        let pos = composer.append_witness(BlsScalar::from(*self.note.pos()));

        let value = composer.append_witness(self.value);
        let value_blinder = composer.append_witness(self.value_blinder);

        let signature_u = composer.append_witness(*self.signature.u());
        let signature_r = composer.append_point(self.signature.R());
        let signature_r_p = composer.append_point(self.signature.R_prime());

        (
            note_pk,
            note_pk_p,
            note_type,
            pos,
            value,
            value_blinder,
            nullifier,
            signature_u,
            signature_r,
            signature_r_p,
        )
    }
}
