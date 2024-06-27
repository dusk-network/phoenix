// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::{DeserializableSlice, Serializable};
use dusk_jubjub::JubJubScalar;
use ff::Field;
use phoenix_core::{Note, PublicKey, SecretKey, ViewKey};
use rand::rngs::StdRng;
use rand::SeedableRng;
use zeroize::Zeroize;

#[test]
fn sk_from_bytes() {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let sk = SecretKey::random(&mut rng);
    let sk_bytes = sk.to_bytes();

    assert_eq!(
        sk,
        SecretKey::from_slice(&sk_bytes).expect("deserialization should pass")
    );
}

#[test]
fn sk_zeroize() {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let mut sk = SecretKey::random(&mut rng);
    let sk_zeroized =
        SecretKey::new(JubJubScalar::zero(), JubJubScalar::zero());

    // sanity check
    assert_ne!(sk, sk_zeroized);

    sk.zeroize();
    assert_eq!(sk, sk_zeroized);
}

#[test]
fn keys_encoding() {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let sk = SecretKey::random(&mut rng);
    let vk = ViewKey::from(&sk);
    let pk = PublicKey::from(&sk);

    assert_eq!(vk, ViewKey::from_bytes(&vk.to_bytes()).unwrap());
    assert_eq!(pk, PublicKey::from_bytes(&pk.to_bytes()).unwrap());
}

#[test]
fn keys_consistency() {
    use dusk_jubjub::{JubJubScalar, GENERATOR_EXTENDED};

    const NOTE_VALUE: u64 = 42;

    let mut rng = StdRng::seed_from_u64(0xc0b);

    let r = JubJubScalar::random(&mut rng);

    let sender_pk = PublicKey::from(&SecretKey::random(&mut rng));
    let receiver_sk = SecretKey::random(&mut rng);
    let receiver_pk = PublicKey::from(&receiver_sk);
    let receiver_vk = ViewKey::from(&receiver_sk);

    let sender_blinder = [
        JubJubScalar::random(&mut rng),
        JubJubScalar::random(&mut rng),
    ];
    let note = Note::transparent(
        &mut rng,
        &sender_pk,
        &receiver_pk,
        NOTE_VALUE,
        sender_blinder,
    );

    assert!(receiver_vk.owns(note.stealth_address()));
    assert!(receiver_sk.owns(note.stealth_address()));

    let wrong_sk = SecretKey::random(&mut rng);
    let wrong_vk = ViewKey::from(&wrong_sk);

    assert_ne!(receiver_sk, wrong_sk);
    assert_ne!(receiver_vk, wrong_vk);

    assert!(!wrong_vk.owns(note.stealth_address()));
    assert!(!wrong_sk.owns(note.stealth_address()));

    let sa = receiver_pk.gen_stealth_address(&r);

    let note_sk = receiver_sk.gen_note_sk(&sa);
    let wrong_note_sk = wrong_sk.gen_note_sk(&sa);

    assert_eq!(
        sa.note_pk().as_ref(),
        &(GENERATOR_EXTENDED * note_sk.as_ref())
    );
    assert_ne!(
        sa.note_pk().as_ref(),
        &(GENERATOR_EXTENDED * wrong_note_sk.as_ref())
    );
}
