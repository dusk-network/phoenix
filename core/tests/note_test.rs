// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::Serializable;
use dusk_jubjub::{JubJubAffine, JubJubScalar};
use ff::Field;
use phoenix_core::{
    value_commitment, Error, Note, NoteType, PublicKey, SecretKey, Sender,
    ViewKey,
};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

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
        note.sender()
            .decrypt(&receiver_sk.gen_note_sk(note.stealth_address()))?
    );
    assert_eq!(note, Note::from_bytes(&note.to_bytes())?);

    Ok(())
}

#[test]
fn transparent_stealth_note() -> Result<(), Error> {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let receiver_sk = SecretKey::random(&mut rng);
    let receiver_pk = PublicKey::from(&receiver_sk);

    let r = JubJubScalar::random(&mut rng);
    let stealth = receiver_pk.gen_stealth_address(&r);

    let value = 25;

    let mut sender_data = [0u8; 4 * JubJubAffine::SIZE];
    rng.fill_bytes(&mut sender_data);
    let sender = Sender::ContractInfo(sender_data);

    let note = Note::transparent_stealth(stealth, value, sender);

    assert_eq!(note.note_type(), NoteType::Transparent);
    assert_eq!(
        value_commitment(value, TRANSPARENT_BLINDER),
        *note.value_commitment()
    );
    assert_eq!(value, note.value(None)?);
    assert_eq!(stealth, *note.stealth_address());
    assert_eq!(Sender::ContractInfo(sender_data), *note.sender());
    assert_eq!(note, Note::from_bytes(&note.to_bytes())?);

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
        note.sender()
            .decrypt(&receiver_sk.gen_note_sk(note.stealth_address()))?
    );
    assert_eq!(note, Note::from_bytes(&note.to_bytes())?);

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
        note.sender()
            .decrypt(&receiver_sk.gen_note_sk(note.stealth_address()))?
    );
    assert_eq!(note, Note::from_bytes(&note.to_bytes())?);

    Ok(())
}
