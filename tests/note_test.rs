// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![allow(clippy::unused_io_amount)]

use dusk_pki::Ownable;
use std::convert::TryInto;

use phoenix_core::{Crossover, Error, Fee, Note, NoteType};
use std::io::{Read, Write};

use dusk_pki::{PublicSpendKey, SecretSpendKey};
use dusk_plonk::bls12_381::Scalar as BlsScalar;
use dusk_plonk::jubjub::Fr as JubJubScalar;
use dusk_plonk::prelude::*;

use kelvin::Blake2b;
use poseidon252::merkle_proof::merkle_opening_gadget;
use poseidon252::{PoseidonAnnotation, PoseidonTree};

use anyhow::Result;
use assert_matches::*;

#[test]
fn transparent_note() -> Result<(), Error> {
    let ssk = SecretSpendKey::default();
    let psk = ssk.public_key();
    let value = 25;

    let mut note = Note::transparent(&psk, value);

    let mut buff = vec![0u8; 2048];
    note.read(buff.as_mut_slice())?;

    let mut deser_note = Note::default();
    assert_ne!(note, deser_note);

    deser_note.write(buff.as_slice())?;
    assert_eq!(note, deser_note);

    assert_eq!(deser_note.note(), NoteType::Transparent);
    assert_eq!(value, deser_note.value(None)?);

    Ok(())
}

#[test]
fn obfuscated_note() -> Result<(), Error> {
    let ssk = SecretSpendKey::default();
    let psk = ssk.public_key();
    let vk = ssk.view_key();
    let value = 25;

    let mut note = Note::obfuscated(&psk, value);

    let mut buff = vec![0u8; 2048];
    note.read(buff.as_mut_slice())?;

    // TODO: `Note::default()` is just for `Transparent`, maybe we need a
    // method for obfuscated?
    let mut deser_note =
        Note::new(NoteType::Obfuscated, &PublicSpendKey::default(), 0);
    assert_ne!(note, deser_note);

    deser_note.write(buff.as_slice())?;
    assert_eq!(note, deser_note);

    assert_eq!(deser_note.note(), NoteType::Obfuscated);
    assert_eq!(value, deser_note.value(Some(&vk))?);

    Ok(())
}

#[test]
fn obfuscated_deterministic_note() -> Result<(), Error> {
    let ssk = SecretSpendKey::default();
    let psk = ssk.public_key();
    let vk = ssk.view_key();
    let value = 25;

    let r = JubJubScalar::random(&mut rand::thread_rng());
    let nonce = JubJubScalar::random(&mut rand::thread_rng());
    let blinding_factor = JubJubScalar::random(&mut rand::thread_rng());

    let note = Note::deterministic(
        NoteType::Obfuscated,
        &r,
        nonce,
        &psk,
        value,
        blinding_factor,
    );

    assert_eq!(value, note.value(Some(&vk))?);
    assert_eq!(blinding_factor, note.blinding_factor(Some(&vk))?);

    Ok(())
}

#[test]
fn note_keys_consistency() {
    let ssk = SecretSpendKey::default();
    let psk = ssk.public_key();
    let vk = ssk.view_key();
    let value = 25;

    let wrong_ssk = SecretSpendKey::default();
    let wrong_vk = wrong_ssk.view_key();

    assert_ne!(ssk, wrong_ssk);
    assert_ne!(vk, wrong_vk);

    let note = Note::obfuscated(&psk, value);

    assert!(!wrong_vk.owns(&note));
    assert!(vk.owns(&note));
}

#[test]
fn fee_and_crossover_generation() -> Result<(), Error> {
    let ssk = SecretSpendKey::default();
    let psk = ssk.public_key();
    let vk = ssk.view_key();
    let value = 25;

    let note = Note::obfuscated(&psk, value);
    let (fee, crossover): (Fee, Crossover) = note.try_into()?;

    let wrong_fee = Fee::default();
    let wrong_note: Note = (wrong_fee, crossover).into();

    assert_ne!(note, wrong_note);
    assert_matches!(
        wrong_note.value(Some(&vk)),
        Err(Error::CipherError(_)),
        "Expected to fail the decryption of the cipher"
    );

    let correct_note: Note = (fee, crossover).into();

    assert_eq!(note, correct_note);
    assert_eq!(value, correct_note.value(Some(&vk))?);
    Ok(())
}

#[test]
fn fail_fee_and_crossover_from_transparent() -> Result<(), Error> {
    let ssk = SecretSpendKey::default();
    let psk = ssk.public_key();
    let value = 25;

    let note = Note::transparent(&psk, value);
    let result: Result<(Fee, Crossover), Error> = note.try_into();

    assert_matches!(
        result,
        Err(Error::InvalidNoteConversion),
        "Expected to fail the Note Conversion"
    );

    Ok(())
}

#[test]
fn transparent_from_fee_remainder() -> Result<(), Error> {
    let ssk = SecretSpendKey::default();
    let psk = ssk.public_key();
    let vk = ssk.view_key();

    let gas_consumed = 3;
    let gas_limit = 10;
    let gas_price = 2;

    let fee = Fee::new(gas_limit, gas_price, &psk);

    let note: Note = fee.gen_remainder(gas_consumed).into();

    assert_eq!(note.stealth_address(), fee.stealth_address());
    assert_eq!(
        note.value(Some(&vk))?,
        (gas_limit - gas_consumed) * gas_price
    );

    Ok(())
}

#[test]
fn transparent_from_fee_remainder_with_invalid_consumed() -> Result<(), Error> {
    let ssk = SecretSpendKey::default();
    let psk = ssk.public_key();
    let vk = ssk.view_key();

    let gas_consumed = 30;
    let gas_limit = 10;
    let gas_price = 2;

    let fee = Fee::new(gas_limit, gas_price, &psk);

    let note: Note = fee.gen_remainder(gas_consumed).into();

    assert_eq!(note.stealth_address(), fee.stealth_address());
    assert_eq!(note.value(Some(&vk))?, 0);

    Ok(())
}

#[test]
fn note_tree_storage() -> Result<()> {
    let ssk = SecretSpendKey::default();
    let psk = ssk.public_key();
    let value = 25;

    let note = Note::transparent(&psk, value);

    // Store the note in the tree
    let mut tree = PoseidonTree::<Note, PoseidonAnnotation, Blake2b>::new(4);
    let idx = tree.push(note.into()).unwrap();

    // Fetch the note from the tree
    let branch = tree.poseidon_branch(idx).unwrap().unwrap();

    // Now, let's see if we can make a valid merkle opening proof.
    let pub_params = PublicParameters::setup(1 << 14, &mut rand::thread_rng())?;
    let (ck, vk) = pub_params.trim(1 << 13)?;

    let mut prover = Prover::new(b"NoteTest");
    let hash = prover.mut_cs().add_input(note.hash());
    let root = merkle_opening_gadget(
        prover.mut_cs(),
        branch.clone(),
        hash,
        branch.root.clone(),
    );
    prover.mut_cs().constrain_to_constant(
        root,
        BlsScalar::zero(),
        -branch.root,
    );

    prover.preprocess(&ck).unwrap();
    let proof = prover.prove(&ck).unwrap();

    let mut verifier = Verifier::new(b"NoteTest");
    let hash = verifier.mut_cs().add_input(note.hash());
    let root = merkle_opening_gadget(
        verifier.mut_cs(),
        branch.clone(),
        hash,
        branch.root.clone(),
    );
    verifier.mut_cs().constrain_to_constant(
        root,
        BlsScalar::zero(),
        -branch.root,
    );

    verifier.preprocess(&ck).unwrap();
    let pi = verifier.mut_cs().public_inputs.clone();
    verifier.verify(&proof, &vk, &pi).unwrap();

    Ok(())
}
