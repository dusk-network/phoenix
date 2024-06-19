// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{JubJubAffine, JubJubScalar};
use ff::Field;
use phoenix_core::{
    elgamal, value_commitment, Error, Note, NoteType, PublicKey, SecretKey,
    ViewKey,
};
use rand::rngs::StdRng;
use rand::SeedableRng;

#[test]
fn transparent_note() -> Result<(), Error> {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let sk = SecretKey::random(&mut rng);
    let pk = PublicKey::from(&sk);
    let value = 25;

    let sender_blinder = [
        JubJubScalar::random(&mut rng),
        JubJubScalar::random(&mut rng),
    ];

    let note = Note::transparent(&mut rng, &pk, value, sender_blinder);

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
    let stealth = pk.gen_stealth_address(&r);

    let value = 25;

    let sender_blinder = [
        JubJubScalar::random(&mut rng),
        JubJubScalar::random(&mut rng),
    ];
    let sender_enc_a = elgamal::encrypt(
        pk.A(),
        stealth.note_pk().as_ref(),
        &sender_blinder[0],
    );

    let sender_enc_b = elgamal::encrypt(
        pk.B(),
        stealth.note_pk().as_ref(),
        &sender_blinder[0],
    );
    let sender_enc_a: (JubJubAffine, JubJubAffine) =
        (sender_enc_a.0.into(), sender_enc_a.1.into());
    let sender_enc_b: (JubJubAffine, JubJubAffine) =
        (sender_enc_b.0.into(), sender_enc_b.1.into());

    let note =
        Note::transparent_stealth(stealth, value, [sender_enc_a, sender_enc_b]);

    assert_eq!(note.note_type(), NoteType::Transparent);
    assert_eq!(value, note.value(None)?);
    assert_eq!(stealth, *note.stealth_address());

    Ok(())
}

#[test]
fn obfuscated_note() -> Result<(), Error> {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let sk = SecretKey::random(&mut rng);
    let pk = PublicKey::from(&sk);
    let vk = ViewKey::from(&sk);
    let value = 25;

    let value_blinder = JubJubScalar::random(&mut rng);
    let sender_blinder = [
        JubJubScalar::random(&mut rng),
        JubJubScalar::random(&mut rng),
    ];

    let note =
        Note::obfuscated(&mut rng, &pk, value, value_blinder, sender_blinder);

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

    let value_blinder = JubJubScalar::random(&mut rng);
    let sender_blinder = [
        JubJubScalar::random(&mut rng),
        JubJubScalar::random(&mut rng),
    ];

    let note = Note::new(
        &mut rng,
        NoteType::Obfuscated,
        &pk,
        value,
        value_blinder,
        sender_blinder,
    );

    assert_eq!(value, note.value(Some(&vk))?);
    assert_eq!(value_blinder, note.value_blinder(Some(&vk))?);

    Ok(())
}

#[test]
fn value_commitment_transparent() {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let sk = SecretKey::random(&mut rng);
    let vk = ViewKey::from(&sk);
    let pk = PublicKey::from(&sk);
    let value = 25;
    let sender_blinder = [
        JubJubScalar::random(&mut rng),
        JubJubScalar::random(&mut rng),
    ];

    let note = Note::transparent(&mut rng, &pk, value, sender_blinder);

    let value = note
        .value(Some(&vk))
        .expect("The note should be owned by the provided vk");

    let value_blinder = note
        .value_blinder(Some(&vk))
        .expect("The note should be owned by the provided vk");

    let commitment = note.value_commitment();
    let commitment_p = value_commitment(value, value_blinder);

    assert_eq!(commitment, &commitment_p.into());
}

#[test]
fn value_commitment_obfuscated() {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let sk = SecretKey::random(&mut rng);
    let vk = ViewKey::from(&sk);
    let pk = PublicKey::from(&sk);
    let value = 25;

    let value_blinder = JubJubScalar::random(&mut rng);
    let sender_blinder = [
        JubJubScalar::random(&mut rng),
        JubJubScalar::random(&mut rng),
    ];

    let note =
        Note::obfuscated(&mut rng, &pk, value, value_blinder, sender_blinder);

    let value = note
        .value(Some(&vk))
        .expect("The note should be owned by the provided vk");

    let value_blinder = note
        .value_blinder(Some(&vk))
        .expect("The note should be owned by the provided vk");

    let commitment = note.value_commitment();
    let commitment_p = value_commitment(value, value_blinder);

    assert_eq!(commitment, &commitment_p.into());
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

    let value_blinder = JubJubScalar::random(&mut rng);
    let sender_blinder = [
        JubJubScalar::random(&mut rng),
        JubJubScalar::random(&mut rng),
    ];

    let note =
        Note::obfuscated(&mut rng, &pk, value, value_blinder, sender_blinder);

    assert!(!wrong_vk.owns(&note));
    assert!(vk.owns(&note));
}
