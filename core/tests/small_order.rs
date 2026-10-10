// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Stealth addresses whose `R` is small-order or has a small-order component.
//!
//! The shared secret `a · R` behind `owns` and `gen_note_sk` is derived
//! through `dhke`, which clears the cofactor. Multiplying `R` by `a` directly
//! keeps `(a mod 8) · T` of a small-order component `T` instead, so which of
//! the addresses `note_pk = H(a · R0 + g · T) · G + B`, `g` in `0..8`, a
//! wallet recognises would depend on `a mod 8`.

#![allow(non_snake_case)]

use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{
    GENERATOR_EXTENDED, JubJubAffine, JubJubExtended, JubJubScalar,
};
use ff::Field;
use jubjub_schnorr::PublicKey as NotePublicKey;
use phoenix_core::{
    Note, PublicKey, SecretKey, Sender, StealthAddress, ViewKey, hash,
};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

/// A point of order 8: the small-order component `P - 8⁻¹ · (8 · P)` of a
/// curve point `P`.
fn order_eight_point() -> JubJubExtended {
    let inv8 = JubJubScalar::from(8u64).invert().unwrap();
    let mut rng = StdRng::seed_from_u64(8);
    loop {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let Some(P) =
            Option::<JubJubAffine>::from(JubJubAffine::from_bytes(bytes))
        else {
            continue;
        };
        let P = JubJubExtended::from(P);
        let T = P - P.mul_by_cofactor() * inv8;
        if !bool::from(T.double().double().is_identity()) {
            assert!(bool::from(T.mul_by_cofactor().is_identity()));
            return T;
        }
    }
}

/// A random key whose secret `a` is `k` modulo 8.
fn key_with_a_mod_8(rng: &mut StdRng, k: u8) -> SecretKey {
    let a = JubJubScalar::random(&mut *rng);
    let a_mod_8 = a.to_bytes()[0] & 7;
    let a = a - JubJubScalar::from(u64::from(a_mod_8))
        + JubJubScalar::from(u64::from(k));
    assert_eq!(a.to_bytes()[0] & 7, k);

    SecretKey::new(a, JubJubScalar::random(&mut *rng))
}

/// `H(a · R + g · T) · G + B`, a `note_pk` for an `R` with the small-order
/// component `T`, tuned to `a mod 8 = g`.
fn crafted_note_pk(
    a_R: JubJubExtended,
    T: JubJubExtended,
    g: u64,
    pk: &PublicKey,
) -> NotePublicKey {
    let shared = a_R + T * JubJubScalar::from(g);
    NotePublicKey::from_raw_unchecked(
        GENERATOR_EXTENDED * hash(&shared) + pk.B(),
    )
}

/// The `g` in `0..8` for which `owns` recognises the crafted address.
fn owned_tunings(
    R: JubJubExtended,
    a_R: JubJubExtended,
    T: JubJubExtended,
    sk: &SecretKey,
) -> Vec<u64> {
    let vk = ViewKey::from(sk);
    let pk = PublicKey::from(sk);

    (0..8)
        .filter(|&g| {
            let stealth = StealthAddress::from_raw_unchecked(
                R,
                crafted_note_pk(a_R, T, g, &pk),
            );
            let owned = vk.owns(&stealth);
            assert_eq!(owned, sk.owns(&stealth), "view and secret key agree");
            owned
        })
        .collect()
}

#[test]
fn small_order_component_of_R_ignored() {
    let mut rng = StdRng::seed_from_u64(0xc0b);
    let T = order_eight_point();

    for k in 0..8 {
        let sk = key_with_a_mod_8(&mut rng, k);
        let R0 = GENERATOR_EXTENDED * JubJubScalar::random(&mut rng);
        let a_R0 = R0 * sk.a();

        // Multiplying `R` by `a` directly recognises `g = a mod 8` only.
        // Through `dhke`, only `g = 0` is recognised, whatever `a`.
        assert_eq!(
            owned_tunings(R0 + T, a_R0, T, &sk),
            vec![0],
            "a = {k} mod 8"
        );
    }
}

#[test]
fn small_order_R_owned_by_no_key() {
    let mut rng = StdRng::seed_from_u64(0xc0b);
    let T = order_eight_point();

    for k in 0..8 {
        let sk = key_with_a_mod_8(&mut rng, k);

        // `R = j · T` runs over the identity and every point of small order.
        // Multiplying it by `a` directly recognises the address tuned to
        // `g = a · j mod 8`, which depends on `a mod 8` for `j = 1`.
        for j in 0..8 {
            let R = T * JubJubScalar::from(j);
            assert_eq!(
                owned_tunings(R, JubJubExtended::identity(), T, &sk),
                Vec::<u64>::new(),
                "a = {k} mod 8, R = {j} · T"
            );
        }
    }
}

#[test]
fn note_sk_ignores_small_order_component_of_R() {
    let mut rng = StdRng::seed_from_u64(0xc0b);
    let T = order_eight_point();

    let sk = SecretKey::random(&mut rng);
    let pk = PublicKey::from(&sk);
    let sender = Sender::ContractInfo([0; 128]);

    // An address of the key, and the same address with `T` added to `R`.
    let stealth = pk.gen_stealth_address(&JubJubScalar::random(&mut rng));
    let shifted =
        StealthAddress::from_raw_unchecked(stealth.R() + T, *stealth.note_pk());

    let note_sk = sk.gen_note_sk(&stealth).expect("`R` is of prime order");
    assert_eq!(
        sk.gen_note_sk(&shifted)
            .expect("`R` has a prime-order part"),
        note_sk
    );
    assert!(sk.owns(&shifted));

    let note = Note::transparent_stealth(stealth, 1, sender);
    let shifted_note = Note::transparent_stealth(shifted, 1, sender);
    assert_eq!(
        shifted_note.gen_nullifier(&sk),
        Some(note.gen_nullifier(&sk).expect("`R` is of prime order"))
    );

    // An identity or small-order `R` has no note secret key, nor nullifier.
    for j in 0..8 {
        let R = T * JubJubScalar::from(j);
        let stealth = StealthAddress::from_raw_unchecked(R, *stealth.note_pk());

        assert_eq!(sk.gen_note_sk(&stealth), None, "R = {j} · T");
        let note = Note::transparent_stealth(stealth, 1, sender);
        assert_eq!(note.gen_nullifier(&sk), None::<BlsScalar>, "R = {j} · T");
    }
}
