// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{JubJubScalar, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use ff::Field;
use phoenix_core::{
    Error, Note, NoteType, Ownability, Ownable, PublicKey, SecretKey, ViewKey,
};
use rand::rngs::StdRng;
use rand::SeedableRng;

#[test]
fn transparent_note() -> Result<(), Error> {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let sk = SecretKey::random(&mut rng);
    let pk = PublicKey::from(&sk);
    let value = 25;

    let note = Note::transparent(&mut rng, &pk, value);

    assert_eq!(note.note_type(), NoteType::Transparent);
    assert_eq!(value, note.value(None)?);

    Ok(())
}

#[test]
fn transparent_stealth_note() -> Result<(), Error> {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let sk = SecretKey::random(&mut rng);
    let pk = PublicKey::from(&sk);

    let r = JubJubScalar::random(&mut rng);
    let sa = pk.gen_stealth_address(&r);

    let r = JubJubScalar::random(&mut rng);
    let sync_address = pk.gen_sync_address(&r);

    let value = 25;

    let note = Note::transparent_stealth(sa, sync_address, value);

    assert_eq!(note.note_type(), NoteType::Transparent);
    assert_eq!(value, note.value(None)?);
    assert_eq!(sa, note.stealth_address());

    Ok(())
}

#[test]
fn obfuscated_note() -> Result<(), Error> {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let sk = SecretKey::random(&mut rng);
    let pk = PublicKey::from(&sk);
    let vk = ViewKey::from(&sk);
    let value = 25;

    let blinding_factor = JubJubScalar::random(&mut rng);
    let note = Note::obfuscated(&mut rng, &pk, value, blinding_factor);

    assert_eq!(note.note_type(), NoteType::Obfuscated);
    assert_eq!(value, note.value(Some(&vk))?);

    Ok(())
}

#[test]
fn obfuscated_deterministic_note() -> Result<(), Error> {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let sk = SecretKey::random(&mut rng);
    let pk = PublicKey::from(&sk);
    let vk = ViewKey::from(&sk);
    let value = 25;

    let blinding_factor = JubJubScalar::random(&mut rng);

    let note =
        Note::new(&mut rng, NoteType::Obfuscated, &pk, value, blinding_factor);

    assert_eq!(value, note.value(Some(&vk))?);
    assert_eq!(blinding_factor, note.blinding_factor(Some(&vk))?);

    Ok(())
}

#[test]
fn value_commitment_transparent() {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let sk = SecretKey::random(&mut rng);
    let vk = ViewKey::from(&sk);
    let pk = PublicKey::from(&sk);
    let value = 25;

    let note = Note::transparent(&mut rng, &pk, value);

    let value = note
        .value(Some(&vk))
        .expect("Value not returned with the correct view key");
    let value = JubJubScalar::from(value);

    let blinding_factor = note
        .blinding_factor(Some(&vk))
        .expect("Blinding factor not returned with the correct view key");

    let commitment = note.value_commitment();
    let commitment_p = (GENERATOR_EXTENDED * value)
        + (GENERATOR_NUMS_EXTENDED * blinding_factor);

    assert_eq!(commitment, &commitment_p);
}

#[test]
fn value_commitment_obfuscated() {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let sk = SecretKey::random(&mut rng);
    let vk = ViewKey::from(&sk);
    let pk = PublicKey::from(&sk);
    let value = 25;

    let blinding_factor = JubJubScalar::random(&mut rng);
    let note = Note::obfuscated(&mut rng, &pk, value, blinding_factor);

    let value = note
        .value(Some(&vk))
        .expect("Value not returned with the correct view key");
    let value = JubJubScalar::from(value);

    let blinding_factor = note
        .blinding_factor(Some(&vk))
        .expect("Blinding factor not returned with the correct view key");

    let commitment = note.value_commitment();
    let commitment_p = (GENERATOR_EXTENDED * value)
        + (GENERATOR_NUMS_EXTENDED * blinding_factor);

    assert_eq!(commitment, &commitment_p);
}

#[test]
fn note_keys_consistency() {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let sk = SecretKey::random(&mut rng);
    let pk = PublicKey::from(&sk);
    let vk = ViewKey::from(&sk);
    let value = 25;

    let wrong_sk = SecretKey::random(&mut rng);
    let wrong_vk = ViewKey::from(&wrong_sk);

    assert_ne!(sk, wrong_sk);
    assert_ne!(vk, wrong_vk);

    let blinding_factor = JubJubScalar::random(&mut rng);
    let note = Note::obfuscated(&mut rng, &pk, value, blinding_factor);

    assert!(!wrong_vk.owns(&note));
    assert!(vk.owns(&note));

    assert!(!wrong_vk.owns_unchecked(&note));
    assert!(vk.owns_unchecked(&note));
}
