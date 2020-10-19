// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![allow(clippy::unused_io_amount)]

use dusk_pki::Ownable;
use dusk_pki::{PublicSpendKey, SecretSpendKey};
use dusk_plonk::jubjub::{Fr as JubJubScalar, GENERATOR_EXTENDED};
use dusk_plonk::prelude::*;
use phoenix_core::{Error, Note, NoteType};
use poseidon252::sponge::sponge::sponge_hash;
use rand::thread_rng;
use rand::Rng;
use std::io::{Read, Write};

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
fn test_note_hash() {
    let value: u64 = rand::thread_rng().gen();
    let sk = JubJubScalar::from(300 as u64);
    let sk2 = JubJubScalar::from(100 as u64);
    let pk = GENERATOR_EXTENDED * sk;
    let pk2 = GENERATOR_EXTENDED * sk2;
    let key = &PublicSpendKey::new(pk, pk2);
    let note = Note::new(NoteType::Transparent, key, value);

    let value_commitment = note.value_commitment().to_hash_inputs();
    let pk_r = note.stealth_address().pk_r().to_hash_inputs();

    let hash_of_note = sponge_hash(&[
        value_commitment[0],
        value_commitment[1],
        BlsScalar::from(note.pos()),
        pk_r[0],
        pk_r[1],
    ]);

    assert_eq!(hash_of_note, note.hash());
}

#[test]
fn test_note_hash_variables() {
    let value: u64 = rand::thread_rng().gen();
    let sk = JubJubScalar::from(300 as u64);
    let sk2 = JubJubScalar::from(100 as u64);
    let pk = GENERATOR_EXTENDED * sk;
    let pk2 = GENERATOR_EXTENDED * sk2;
    let key = &PublicSpendKey::new(pk, pk2);
    let note = Note::new(NoteType::Transparent, key, value);

    let value_commitment = note.value_commitment().to_hash_inputs();
    let pk_r = note.stealth_address().pk_r().to_hash_inputs();

    let hash_of_note = sponge_hash(&[
        value_commitment[0],
        value_commitment[1],
        BlsScalar::from(note.pos()),
        pk_r[0],
        pk_r[1],
    ]);

    assert_eq!(hash_of_note, note.hash());
}
