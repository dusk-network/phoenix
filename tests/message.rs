// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::Serializable;
use dusk_jubjub::JubJubScalar;
use dusk_jubjub::{GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED};
use ff::Field;
use phoenix_core::{Message, PublicKey, SecretKey};
use rand_core::OsRng;

#[test]
fn message_consistency() {
    let mut rng = OsRng;

    let ssk = SecretKey::random(&mut rng);
    let psk = PublicKey::from(ssk);
    let psk_wrong = PublicKey::from(SecretKey::random(&mut rng));

    let r = JubJubScalar::random(&mut rng);
    let r_wrong = JubJubScalar::random(&mut rng);
    let value = 105;

    let message = Message::new(&mut rng, &r, &psk, value);
    let value_commitment = message.value_commitment();
    let (value_p, blinding_factor) = message.decrypt(&r, &psk).unwrap();
    assert!(message.decrypt(&r_wrong, &psk).is_err());
    assert!(message.decrypt(&r, &psk_wrong).is_err());

    let a = GENERATOR_EXTENDED * JubJubScalar::from(value);
    let b = GENERATOR_NUMS_EXTENDED * blinding_factor;
    let value_commitment_p = a + b;

    assert_eq!(value, value_p);
    assert_eq!(value_commitment, &value_commitment_p);
}

#[test]
fn message_bytes() {
    let mut rng = OsRng;

    let ssk = SecretKey::random(&mut rng);
    let psk = PublicKey::from(ssk);

    let r = JubJubScalar::random(&mut rng);
    let value = 106;

    let m = Message::new(&mut rng, &r, &psk, value);
    let m_p = m.to_bytes();
    let m_p = Message::from_bytes(&m_p).unwrap();

    assert_eq!(m, m_p);
}
