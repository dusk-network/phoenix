// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::{DeserializableSlice, Serializable};
use dusk_jubjub::JubJubScalar;
use ff::Field;
use phoenix_core::{PublicKey, SecretKey, ViewKey};
use rand_core::OsRng;
use zeroize::Zeroize;

#[test]
fn sk_from_bytes() {
    let sk = SecretKey::random(&mut OsRng);
    let sk_bytes = sk.to_bytes();

    assert_eq!(
        sk,
        SecretKey::from_slice(&sk_bytes).expect("deserialization should pass")
    );
}

#[test]
fn sk_zeroize() {
    let mut sk = SecretKey::random(&mut OsRng);
    let sk_zeroized =
        SecretKey::new(JubJubScalar::zero(), JubJubScalar::zero());

    // sanity check
    assert_ne!(sk, sk_zeroized);

    sk.zeroize();
    assert_eq!(sk, sk_zeroized);
}

#[test]
fn keys_encoding() {
    let sk = SecretKey::random(&mut OsRng);
    let vk = ViewKey::from(&sk);
    let pk = PublicKey::from(&sk);

    assert_eq!(vk, ViewKey::from_bytes(&vk.to_bytes()).unwrap());
    assert_eq!(pk, PublicKey::from_bytes(&pk.to_bytes()).unwrap());
}

#[test]
fn keys_consistency() {
    use dusk_jubjub::{JubJubScalar, GENERATOR_EXTENDED};

    let r = JubJubScalar::random(&mut OsRng);
    let sk = SecretKey::random(&mut OsRng);
    let pk = PublicKey::from(&sk);
    let vk = ViewKey::from(&sk);
    let sa = pk.gen_stealth_address(&r);

    assert!(vk.owns(&sa));

    let wrong_sk = SecretKey::random(&mut OsRng);
    let wrong_vk = ViewKey::from(&wrong_sk);

    assert_ne!(sk, wrong_sk);
    assert_ne!(vk, wrong_vk);

    assert!(!wrong_vk.owns(&sa));

    let note_sk = sk.gen_note_sk(&sa);
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
