// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{
    JubJubScalar, GENERATOR, GENERATOR_NUMS, GENERATOR_NUMS_EXTENDED,
};
use dusk_plonk::prelude::*;
use dusk_poseidon::sponge;
use jubjub_schnorr::{gadgets, SignatureDouble};
use poseidon_merkle::{zk::opening_gadget, Item, Opening, Tree};

use rand::rngs::StdRng;
use rand_core::{CryptoRng, RngCore, SeedableRng};

extern crate alloc;
use alloc::vec::Vec;

use crate::Note;
use crate::{Error as PhoenixError, SecretKey, ViewKey};

const OUTPUT: usize = 2;

/// Struct representing a note willing to be spent, in a way
/// suitable for being introduced in the transfer circuit
#[derive(Debug, Clone)]
pub struct InputNote<const H: usize, const A: usize> {
    pub(crate) merkle_opening: Opening<(), H, A>,
    pub(crate) note: Note,
    pub(crate) note_pk_p: JubJubAffine,
    pub(crate) value: u64,
    pub(crate) blinding_factor: JubJubScalar,
    pub(crate) nullifier: BlsScalar,
    pub(crate) signature: SignatureDouble,
}

#[derive(Debug, Clone)]
struct WitnessInputNote {
    note_pk: WitnessPoint,
    note_pk_p: WitnessPoint,
    note_type: Witness,
    pos: Witness,
    value: Witness,
    blinding_factor: Witness,
    nullifier: Witness,
    signature_u: Witness,
    signature_r: WitnessPoint,
    signature_r_p: WitnessPoint,
}

impl<const H: usize, const A: usize> InputNote<H, A> {
    /// Create a circuit input note
    pub fn new(
        note: &Note,
        merkle_opening: poseidon_merkle::Opening<(), H, A>,
        sk: &SecretKey,
        skeleteon_hash: BlsScalar,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<crate::transfer::InputNote<H, A>, PhoenixError> {
        let note_sk = sk.gen_note_sk(note);
        let note_pk_p =
            JubJubAffine::from(GENERATOR_NUMS_EXTENDED * note_sk.as_ref());

        let vk = ViewKey::from(sk);
        let value = note.value(Some(&vk))?;
        let blinding_factor = note.blinding_factor(Some(&vk))?;

        let nullifier = sponge::hash(&[
            note_pk_p.get_u(),
            note_pk_p.get_v(),
            note.pos.into(),
        ]);

        let signature = note_sk.sign_double(rng, skeleteon_hash);

        Ok(crate::transfer::InputNote {
            merkle_opening,
            note: note.clone(),
            note_pk_p,
            value,
            blinding_factor,
            nullifier,
            signature,
        })
    }

    fn append_to_circuit(&self, composer: &mut Composer) -> WitnessInputNote {
        let nullifier = composer.append_public(self.nullifier);

        let note_pk = composer
            .append_point(*self.note.stealth_address.note_pk().as_ref());
        let note_pk_p = composer.append_point(self.note_pk_p);

        let note_type = composer
            .append_witness(BlsScalar::from(self.note.note_type() as u64));
        let pos = composer.append_witness(BlsScalar::from(*self.note.pos()));

        let value = composer.append_witness(self.value);
        let blinding_factor = composer.append_witness(self.blinding_factor);

        let signature_u = composer.append_witness(*self.signature.u());
        let signature_r = composer.append_point(self.signature.R());
        let signature_r_p = composer.append_point(self.signature.R_prime());

        WitnessInputNote {
            note_pk,
            note_pk_p,

            note_type,
            pos,
            value,
            blinding_factor,

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
pub struct OutputNote {
    pub(crate) value: u64,
    pub(crate) value_commitment: JubJubAffine,
    pub(crate) blinding_factor: JubJubScalar,
}

#[derive(Debug, Clone)]
struct WitnessOutputNote {
    value: Witness,
    value_commitment: WitnessPoint,
    blinding_factor: Witness,
}

impl OutputNote {
    /// Create a circuit output note
    pub fn new(
        note: &Note,
        vk: &ViewKey,
    ) -> Result<crate::transfer::OutputNote, PhoenixError> {
        Ok(crate::transfer::OutputNote {
            value: note.value(Some(vk))?,
            value_commitment: note.value_commitment.into(),
            blinding_factor: note.blinding_factor(Some(vk))?,
        })
    }

    fn append_to_circuit(&self, composer: &mut Composer) -> WitnessOutputNote {
        let value = composer.append_witness(self.value);
        let value_commitment =
            composer.append_public_point(self.value_commitment);
        let blinding_factor = composer.append_witness(self.blinding_factor);

        WitnessOutputNote {
            value,
            value_commitment,
            blinding_factor,
        }
    }
}

/// Transfer gadget expecting I input notes to be spent and O output
/// notes to be created.
pub fn gadget<const H: usize, const A: usize, const I: usize>(
    composer: &mut Composer,
    input_notes: &[InputNote<H, A>; I],
    output_notes: &[OutputNote; OUTPUT],
    skeleton_hash: &BlsScalar,
    root: &BlsScalar,
    crossover: u64,
    max_fee: u64,
) -> Result<(), Error> {
    let skeleton_hash_pi = composer.append_public(*skeleton_hash);
    let root_pi = composer.append_public(*root);

    let mut input_notes_sum = Composer::ZERO;

    // NULLIFY ALL INPUT NOTES
    for input_note in input_notes {
        // APPEND THE WITNESSES TO THE CIRCUIT
        let w_input_note = input_note.append_to_circuit(composer);

        // VERIFY THE DOUBLE KEY SCHNORR SIGNATURE
        gadgets::verify_signature_double(
            composer,
            w_input_note.signature_u,
            w_input_note.signature_r,
            w_input_note.signature_r_p,
            w_input_note.note_pk,
            w_input_note.note_pk_p,
            skeleton_hash_pi,
        )?;

        // COMPUTE AND ASSERT THE NULLIFIER
        let nullifier = sponge::gadget(
            composer,
            &[
                *w_input_note.note_pk_p.x(),
                *w_input_note.note_pk_p.y(),
                w_input_note.pos,
            ],
        );
        composer.assert_equal(nullifier, w_input_note.nullifier);

        // PERFORM A RANGE CHECK ([0, 2^64 - 1]) ON THE VALUE OF THE NOTE
        composer.component_range::<32>(w_input_note.value);

        // SUM UP ALL THE SPENT VALUES
        let constraint = Constraint::new()
            .left(1)
            .a(input_notes_sum)
            .right(1)
            .b(w_input_note.value);
        input_notes_sum = composer.gate_add(constraint);

        // COMMIT TO THE VALUE OF THE NOTE
        let pc_1 =
            composer.component_mul_generator(w_input_note.value, GENERATOR)?;
        let pc_2 = composer.component_mul_generator(
            w_input_note.blinding_factor,
            GENERATOR_NUMS,
        )?;
        let value_commitment = composer.component_add_point(pc_1, pc_2);

        // COMPUTE THE NOTE HASH
        let note_hash = sponge::gadget(
            composer,
            &[
                w_input_note.note_type,
                *value_commitment.x(),
                *value_commitment.y(),
                *w_input_note.note_pk.x(),
                *w_input_note.note_pk.y(),
                w_input_note.pos,
            ],
        );

        // VERIFY THE MERKLE OPENING
        let root =
            opening_gadget(composer, &input_note.merkle_opening, note_hash);
        composer.assert_equal(root, root_pi);
    }

    let mut output_sum = Composer::ZERO;

    // COMMIT TO ALL OUTPUT NOTES
    for output_note in output_notes {
        // APPEND THE WITNESSES TO THE CIRCUIT
        let w_output_note = output_note.append_to_circuit(composer);

        // PERFORM A RANGE CHECK ([0, 2^64 - 1]) ON THE VALUE OF THE NOTE
        composer.component_range::<32>(w_output_note.value);

        // SUM UP ALL THE CREATED NOTE VALUES
        let constraint = Constraint::new()
            .left(1)
            .a(output_sum)
            .right(1)
            .b(w_output_note.value);
        output_sum = composer.gate_add(constraint);

        // COMMIT TO THE VALUE OF THE NOTE
        let pc_1 =
            composer.component_mul_generator(w_output_note.value, GENERATOR)?;
        let pc_2 = composer.component_mul_generator(
            w_output_note.blinding_factor,
            GENERATOR_NUMS,
        )?;
        let value_commitment = composer.component_add_point(pc_1, pc_2);

        composer.assert_equal_point(
            w_output_note.value_commitment,
            value_commitment,
        );
    }

    let max_fee = composer.append_public(max_fee);
    let crossover = composer.append_public(crossover);

    // SUM UP THE CROSSOVER AND THE MAX FEE
    let constraint = Constraint::new()
        .left(1)
        .a(output_sum)
        .right(1)
        .b(max_fee)
        .fourth(1)
        .d(crossover);
    output_sum = composer.gate_add(constraint);

    // VERIFY BALANCE
    composer.assert_equal(input_notes_sum, output_sum);

    Ok(())
}

/// Declaration of the transfer circuit
#[derive(Debug)]
pub struct TransferCircuit<const H: usize, const A: usize, const I: usize> {
    input_notes: [InputNote<H, A>; I],
    output_notes: [OutputNote; OUTPUT],
    skeleton_hash: BlsScalar,
    root: BlsScalar,
    crossover: u64,
    max_fee: u64,
}

impl<const H: usize, const A: usize, const I: usize> Default
    for TransferCircuit<H, A, I>
{
    fn default() -> Self {
        let mut rng = StdRng::seed_from_u64(0xbeef);

        let sk = SecretKey::random(&mut rng);
        let vk = ViewKey::from(&sk);

        let mut tree = Tree::<(), H, A>::new();
        let skeleton_hash = BlsScalar::default();

        let mut input_notes = Vec::new();
        let note = Note::empty();
        let item = Item {
            hash: note.hash(),
            data: (),
        };
        tree.insert(*note.pos(), item);

        for _ in 0..I {
            let merkle_opening = tree.opening(*note.pos()).expect("Tree read.");
            let input_note = InputNote::new(
                &note,
                merkle_opening,
                &sk,
                skeleton_hash,
                &mut rng,
            )
            .expect("Note created properly.");

            input_notes.push(input_note);
        }

        let output_note_1 =
            OutputNote::new(&note, &vk).expect("Note created properly.");
        let output_note_2 =
            OutputNote::new(&note, &vk).expect("Note created properly.");

        let output_notes = [output_note_1, output_note_2];

        let root = BlsScalar::default();
        let crossover = u64::default();
        let max_fee = u64::default();

        Self {
            input_notes: input_notes.try_into().unwrap(),
            output_notes,
            skeleton_hash,
            root,
            crossover,
            max_fee,
        }
    }
}

impl<const H: usize, const A: usize, const I: usize> TransferCircuit<H, A, I> {
    /// Create a new transfer circuit
    pub fn new(
        input_notes: [InputNote<H, A>; I],
        output_notes: [OutputNote; OUTPUT],
        skeleton_hash: BlsScalar,
        root: BlsScalar,
        crossover: u64,
        max_fee: u64,
    ) -> Self {
        Self {
            input_notes,
            output_notes,
            skeleton_hash,
            root,
            crossover,
            max_fee,
        }
    }
}

impl<const H: usize, const A: usize, const I: usize> Circuit
    for TransferCircuit<H, A, I>
{
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        gadget::<H, A, I>(
            composer,
            &self.input_notes,
            &self.output_notes,
            &self.skeleton_hash,
            &self.root,
            self.crossover,
            self.max_fee,
        )?;
        Ok(())
    }
}
