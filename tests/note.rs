// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for details.

use phoenix_core::{Error, Note, NoteType};
use std::io::{Read, Write};

use dusk_pki::{PublicSpendKey, SecretSpendKey};
use dusk_plonk::jubjub::Fr as JubJubScalar;

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
