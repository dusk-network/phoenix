// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::JubJubScalar;
use ff::Field;
use phoenix_core::{
    encrypt_sender, value_commitment, Error, Note, NoteType, PublicKey,
    SecretKey, ViewKey,
};
use rand::rngs::StdRng;
use rand::SeedableRng;

const TRANSPARENT_BLINDER: JubJubScalar = JubJubScalar::zero();

#[test]
fn transparent_note() -> Result<(), Error> {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let sender_pk = PublicKey::from(&SecretKey::random(&mut rng));
    let receiver_sk = SecretKey::random(&mut rng);
    let receiver_pk = PublicKey::from(&receiver_sk);

    let value = 25;

    let sender_blinder = [
        JubJubScalar::random(&mut rng),
        JubJubScalar::random(&mut rng),
    ];

    let note = Note::transparent(
        &mut rng,
        &sender_pk,
        &receiver_pk,
        value,
        sender_blinder,
    );

    assert_eq!(note.note_type(), NoteType::Transparent);
    assert_eq!(
        value_commitment(value, TRANSPARENT_BLINDER),
        *note.value_commitment()
    );
    assert_eq!(value, note.value(None)?);
    assert_eq!(
        sender_pk,
        note.decrypt_sender(&receiver_sk.gen_note_sk(note.stealth_address()))
    );

    Ok(())
}

#[test]
fn transparent_stealth_note() -> Result<(), Error> {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let sender_pk = PublicKey::from(&SecretKey::random(&mut rng));
    let receiver_sk = SecretKey::random(&mut rng);
    let receiver_pk = PublicKey::from(&receiver_sk);

    let r = JubJubScalar::random(&mut rng);
    let stealth = receiver_pk.gen_stealth_address(&r);

    let value = 25;

    let sender_enc = encrypt_sender(
        stealth.note_pk(),
        &sender_pk,
        &[
            JubJubScalar::random(&mut rng),
            JubJubScalar::random(&mut rng),
        ],
    );

    let note = Note::transparent_stealth(stealth, value, sender_enc);

    assert_eq!(note.note_type(), NoteType::Transparent);
    assert_eq!(
        value_commitment(value, TRANSPARENT_BLINDER),
        *note.value_commitment()
    );
    assert_eq!(value, note.value(None)?);
    assert_eq!(stealth, *note.stealth_address());
    assert_eq!(
        sender_pk,
        note.decrypt_sender(&receiver_sk.gen_note_sk(note.stealth_address()))
    );

    Ok(())
}

#[test]
fn obfuscated_note() -> Result<(), Error> {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let sender_pk = PublicKey::from(&SecretKey::random(&mut rng));
    let receiver_sk = SecretKey::random(&mut rng);
    let receiver_pk = PublicKey::from(&receiver_sk);
    let receiver_vk = ViewKey::from(&receiver_sk);

    let value = 25;

    let value_blinder = JubJubScalar::random(&mut rng);
    let sender_blinder = [
        JubJubScalar::random(&mut rng),
        JubJubScalar::random(&mut rng),
    ];

    let note = Note::obfuscated(
        &mut rng,
        &sender_pk,
        &receiver_pk,
        value,
        value_blinder,
        sender_blinder,
    );

    assert_eq!(
        value_commitment(value, value_blinder),
        *note.value_commitment()
    );
    assert_eq!(note.note_type(), NoteType::Obfuscated);
    assert_eq!(value, note.value(Some(&receiver_vk))?);
    assert_eq!(
        sender_pk,
        note.decrypt_sender(&receiver_sk.gen_note_sk(note.stealth_address()))
    );

    Ok(())
}

#[test]
fn obfuscated_deterministic_note() -> Result<(), Error> {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let sender_pk = PublicKey::from(&SecretKey::random(&mut rng));
    let receiver_sk = SecretKey::random(&mut rng);
    let receiver_pk = PublicKey::from(&receiver_sk);
    let receiver_vk = ViewKey::from(&receiver_sk);
    let value = 25;

    let value_blinder = JubJubScalar::random(&mut rng);
    let sender_blinder = [
        JubJubScalar::random(&mut rng),
        JubJubScalar::random(&mut rng),
    ];

    let note = Note::new(
        &mut rng,
        NoteType::Obfuscated,
        &sender_pk,
        &receiver_pk,
        value,
        value_blinder,
        sender_blinder,
    );

    assert_eq!(
        value_commitment(value, value_blinder),
        *note.value_commitment()
    );
    assert_eq!(value, note.value(Some(&receiver_vk))?);
    assert_eq!(value_blinder, note.value_blinder(Some(&receiver_vk))?);
    assert_eq!(
        sender_pk,
        note.decrypt_sender(&receiver_sk.gen_note_sk(note.stealth_address()))
    );

    Ok(())
}
