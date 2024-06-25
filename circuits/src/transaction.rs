// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{
    JubJubAffine, JubJubScalar, GENERATOR, GENERATOR_NUMS,
    GENERATOR_NUMS_EXTENDED,
};
use dusk_plonk::prelude::*;
use dusk_poseidon::{Domain, Hash, HashGadget};
use jubjub_schnorr::{gadgets, Signature as SchnorrSignature, SignatureDouble};
use poseidon_merkle::{zk::opening_gadget, Item, Opening, Tree};

use rand::rngs::StdRng;
use rand::{CryptoRng, RngCore, SeedableRng};

extern crate alloc;
use alloc::vec::Vec;

use phoenix_core::{
    Error as PhoenixError, Note, PublicKey, SecretKey, ViewKey, OUTPUT_NOTES,
};

use crate::sender_enc;

/// Struct representing a note willing to be spent, in a way
/// suitable for being introduced in the transfer circuit
#[derive(Debug, Clone)]
pub struct TxInputNote<const H: usize> {
    /// the merkle opening for the note
    pub merkle_opening: Opening<(), H>,
    /// the input note
    pub note: Note,
    /// the note-public-key prime
    pub note_pk_p: JubJubAffine,
    /// the value associated to the note
    pub value: u64,
    /// the value blinder used to obfuscate the value
    pub value_blinder: JubJubScalar,
    /// the nullifier used to spend the note
    pub nullifier: BlsScalar,
    /// the signature of the payload-hash
    pub signature: SignatureDouble,
}

#[derive(Debug, Clone)]
struct WitnessTxInputNote {
    note_pk: WitnessPoint,
    note_pk_p: WitnessPoint,
    note_type: Witness,
    pos: Witness,
    value: Witness,
    value_blinder: Witness,
    nullifier: Witness,
    signature_u: Witness,
    signature_r: WitnessPoint,
    signature_r_p: WitnessPoint,
}

impl<const H: usize> TxInputNote<H> {
    /// Create a tx input note
    pub fn new(
        rng: &mut (impl RngCore + CryptoRng),
        note: &Note,
        merkle_opening: poseidon_merkle::Opening<(), H>,
        sk: &SecretKey,
        payload_hash: BlsScalar,
    ) -> Result<crate::transaction::TxInputNote<H>, PhoenixError> {
        let note_sk = sk.gen_note_sk(note.stealth_address());
        let note_pk_p =
            JubJubAffine::from(GENERATOR_NUMS_EXTENDED * note_sk.as_ref());

        let vk = ViewKey::from(sk);
        let value = note.value(Some(&vk))?;
        let value_blinder = note.value_blinder(Some(&vk))?;

        let nullifier = Hash::digest(
            Domain::Other,
            &[note_pk_p.get_u(), note_pk_p.get_v(), (*note.pos()).into()],
        )[0];

        let signature = note_sk.sign_double(rng, payload_hash);

        Ok(crate::transaction::TxInputNote {
            merkle_opening,
            note: note.clone(),
            note_pk_p,
            value,
            value_blinder,
            nullifier,
            signature,
        })
    }

    fn append_to_circuit(&self, composer: &mut Composer) -> WitnessTxInputNote {
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

        WitnessTxInputNote {
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
        }
    }
}

/// Struct representing a note willing to be created, in a way
/// suitable for being introduced in the transfer circuit
#[derive(Debug, Clone)]
pub struct TxOutputNote {
    value: u64,
    value_commitment: JubJubAffine,
    value_blinder: JubJubScalar,
    note_pk: JubJubAffine,
    sender_enc: [(JubJubAffine, JubJubAffine); 2],
}

impl TxOutputNote {
    /// Create a new `TxOutputNote`.
    pub fn new(
        value: u64,
        value_commitment: JubJubAffine,
        value_blinder: JubJubScalar,
        note_pk: JubJubAffine,
        sender_enc: [(JubJubAffine, JubJubAffine); 2],
    ) -> Self {
        Self {
            value,
            value_commitment,
            value_blinder,
            note_pk,
            sender_enc,
        }
    }
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
    sender_pk: PublicKey,
    signatures: (SchnorrSignature, SchnorrSignature),
    sender_blinder: [[JubJubScalar; 2]; OUTPUT_NOTES],
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
            value_blinder: JubJubScalar::default(),
            note_pk: JubJubAffine::default(),
            sender_enc: [(JubJubAffine::default(), JubJubAffine::default()); 2],
        };
        let tx_output_note_2 = tx_output_note_1.clone();

        let tx_output_notes = [tx_output_note_1, tx_output_note_2];

        let root = BlsScalar::default();
        let deposit = u64::default();
        let max_fee = u64::default();

        let signatures =
            (SchnorrSignature::default(), SchnorrSignature::default());
        let sender_blinder =
            [[JubJubScalar::default(), JubJubScalar::default()]; OUTPUT_NOTES];

        Self {
            tx_input_notes: tx_input_notes.try_into().unwrap(),
            tx_output_notes,
            payload_hash,
            root,
            deposit,
            max_fee,
            sender_pk: PublicKey::from(&sk),
            signatures,
            sender_blinder,
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
        sender_pk: PublicKey,
        signatures: (SchnorrSignature, SchnorrSignature),
        sender_blinder: [[JubJubScalar; 2]; OUTPUT_NOTES],
    ) -> Self {
        Self {
            tx_input_notes,
            tx_output_notes,
            payload_hash,
            root,
            deposit,
            max_fee,
            sender_pk,
            signatures,
            sender_blinder,
        }
    }
}

impl<const H: usize, const I: usize> Circuit for TxCircuit<H, I> {
    /// Transaction gadget proving the following properties in ZK for a generic
    /// `I` [`TxInputNote`] and [`OUTPUT_NOTES`] [`TxOutputNote`]:
    ///
    /// 1. Membership: every [`TxInputNote`] is included in the Merkle tree of
    ///    notes.
    /// 2. Ownership: the sender holds the note secret key for every
    ///    [`TxInputNote`].
    /// 3. Nullification: the nullifier is calculated correctly.
    /// 4. Minting: the value commitment for every [`TxOutputNote`] is computed
    ///    correctly.
    /// 5. Balance integrity: the sum of the values of all [`TxInputNote`] is
    ///    equal to the sum of the values of all [`TxOutputNote`] + the gas fee
    ///    + a deposit, where a deposit refers to funds being transfered to a
    ///    contract.
    /// 6. Sender-data: Verify that the sender was encrypted correctly.
    ///
    /// The circuit has the following public inputs:
    /// - `payload_hash`
    /// - `root`
    /// - `[nullifier; I]`
    /// - `[output_value_commitment; 2]`
    /// - `max_fee`
    /// - `deposit`
    /// - `(npk_0, npk_1)`
    /// - `(enc_A_npk_0, enc_B_npk_0)`
    /// - `(enc_A_npk_1, enc_B_npk_1)`
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        // Make the payload hash a public input of the circuit
        let payload_hash = composer.append_public(self.payload_hash);

        // Append the root as public input
        let root_pi = composer.append_public(self.root);

        let mut tx_input_notes_sum = Composer::ZERO;

        // Check membership, ownership and nullification of all input notes
        for tx_input_note in &self.tx_input_notes {
            let w_tx_input_note = tx_input_note.append_to_circuit(composer);

            // Verify: 2. Ownership
            gadgets::verify_signature_double(
                composer,
                w_tx_input_note.signature_u,
                w_tx_input_note.signature_r,
                w_tx_input_note.signature_r_p,
                w_tx_input_note.note_pk,
                w_tx_input_note.note_pk_p,
                payload_hash,
            )?;

            // Verify: 3. Nullification
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

            // Perform a range check ([0, 2^64 - 1]) on the value of the note
            composer.component_range::<32>(w_tx_input_note.value);

            // Sum up all the tx input note values
            let constraint = Constraint::new()
                .left(1)
                .a(tx_input_notes_sum)
                .right(1)
                .b(w_tx_input_note.value);
            tx_input_notes_sum = composer.gate_add(constraint);

            // Commit to the value of the note
            let pc_1 = composer
                .component_mul_generator(w_tx_input_note.value, GENERATOR)?;
            let pc_2 = composer.component_mul_generator(
                w_tx_input_note.value_blinder,
                GENERATOR_NUMS,
            )?;
            let value_commitment = composer.component_add_point(pc_1, pc_2);

            // Compute the note hash
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

            // Verify: 1. Membership
            let root = opening_gadget(
                composer,
                &tx_input_note.merkle_opening,
                note_hash,
            );
            composer.assert_equal(root, root_pi);
        }

        let mut tx_output_sum = Composer::ZERO;

        // Commit to all tx output notes
        for tx_output_note in &self.tx_output_notes {
            // Append the witnesses to the circuit
            let value = composer.append_witness(tx_output_note.value);
            let expected_value_commitment =
                composer.append_public_point(tx_output_note.value_commitment);
            let value_blinder =
                composer.append_witness(tx_output_note.value_blinder);

            // Perform a range check ([0, 2^64 - 1]) on the value OF THE NOTE
            composer.component_range::<32>(value);

            // Sum up all the tx output note values
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
        composer.assert_equal(tx_input_notes_sum, tx_output_sum);

        // Verify: 6. Sender-data
        sender_enc::gadget(
            composer,
            self.sender_pk,
            self.signatures,
            [
                self.tx_output_notes[0].note_pk,
                self.tx_output_notes[1].note_pk,
            ],
            self.sender_blinder,
            self.tx_output_notes[0].sender_enc,
            self.tx_output_notes[1].sender_enc,
            payload_hash,
        )?;

        Ok(())
    }
}
