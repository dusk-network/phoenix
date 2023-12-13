// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::{DeserializableSlice, Serializable};
use ff::Field;
use phoenix_core::{PublicKey, SecretKey, ViewKey};
use rand_core::OsRng;

#[test]
fn ssk_from_bytes() {
    let ssk_a = SecretKey::random(&mut OsRng);
    let bytes = ssk_a.to_bytes();
    let ssk_b = SecretKey::from_slice(&bytes).expect("Serde error");

    assert_eq!(ssk_a, ssk_b);
}

#[test]
fn keys_encoding() {
    let ssk = SecretKey::random(&mut OsRng);
    let vk = ViewKey::from(ssk);
    let psk = PublicKey::from(ssk);

    assert_eq!(vk, ViewKey::from_bytes(&vk.to_bytes()).unwrap());
    assert_eq!(psk, PublicKey::from_bytes(&psk.to_bytes()).unwrap());
}

#[test]
fn keys_consistency() {
    use dusk_jubjub::{JubJubScalar, GENERATOR_EXTENDED};

    let r = JubJubScalar::random(&mut OsRng);
    let ssk = SecretKey::random(&mut OsRng);
    let psk = PublicKey::from(ssk);
    let vk = ViewKey::from(ssk);
    let sa = psk.gen_stealth_address(&r);

    assert!(vk.owns(&sa));

    let wrong_ssk = SecretKey::random(&mut OsRng);
    let wrong_vk = ViewKey::from(wrong_ssk);

    assert_ne!(ssk, wrong_ssk);
    assert_ne!(vk, wrong_vk);

    assert!(!wrong_vk.owns(&sa));

    let sk_r = ssk.sk_r(&sa);
    let wrong_sk_r = wrong_ssk.sk_r(&sa);

    assert_eq!(sa.address(), &(GENERATOR_EXTENDED * sk_r.as_ref()));
    assert_ne!(sa.address(), &(GENERATOR_EXTENDED * wrong_sk_r.as_ref()));
}
