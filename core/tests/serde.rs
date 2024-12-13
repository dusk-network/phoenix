// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg(feature = "serde")]

use dusk_bls12_381::BlsScalar;
use dusk_bytes::Serializable;
use dusk_jubjub::{JubJubAffine, JubJubScalar};
use ff::Field;
use jubjub_schnorr::{PublicKey as NotePublicKey, SecretKey as NoteSecretKey};
use phoenix_core::{
    Note, NoteType, PublicKey, SecretKey, Sender, StealthAddress, TxSkeleton,
    ViewKey,
};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

fn create_note(rng: &mut StdRng) -> Note {
    let sender_pk = PublicKey::from(&SecretKey::random(rng));
    let receiver_sk = SecretKey::random(rng);
    let receiver_pk = PublicKey::from(&receiver_sk);
    let value = 25;
    let value_blinder = JubJubScalar::random(StdRng::seed_from_u64(0xc0b));
    let sender_blinder = [
        JubJubScalar::random(StdRng::seed_from_u64(0xdead)),
        JubJubScalar::random(StdRng::seed_from_u64(0xbeef)),
    ];
    Note::new(
        rng,
        NoteType::Obfuscated,
        &sender_pk,
        &receiver_pk,
        value,
        value_blinder,
        sender_blinder,
    )
}

#[test]
fn serde_public_key() {
    let mut rng = StdRng::seed_from_u64(0xc0b);
    let sk = SecretKey::random(&mut rng);
    let pk = PublicKey::from(&sk);
    let ser = serde_json::to_string(&pk).unwrap();
    let deser = serde_json::from_str(&ser).unwrap();
    assert_eq!(pk, deser);
}

#[test]
fn serde_secret_key() {
    let mut rng = StdRng::seed_from_u64(0xc0b);
    let sk = SecretKey::random(&mut rng);
    let ser = serde_json::to_string(&sk).unwrap();
    let deser = serde_json::from_str(&ser).unwrap();
    assert_eq!(sk, deser);
}

#[test]
fn serde_view_key() {
    let mut rng = StdRng::seed_from_u64(0xc0b);
    let sk = SecretKey::random(&mut rng);
    let vk = ViewKey::from(&sk);
    let ser = serde_json::to_string(&vk).unwrap();
    let deser = serde_json::from_str(&ser).unwrap();
    assert_eq!(vk, deser);
}

#[test]
fn serde_note_type() {
    let obfuscated = NoteType::Obfuscated;
    let transparent = NoteType::Transparent;
    let obf_ser = serde_json::to_string(&obfuscated).unwrap();
    let trans_ser = serde_json::to_string(&transparent).unwrap();
    let obf_deser = serde_json::from_str(&obf_ser).unwrap();
    let trans_deser = serde_json::from_str(&trans_ser).unwrap();
    assert_eq!(obfuscated, obf_deser);
    assert_eq!(transparent, trans_deser);
}

#[test]
fn serde_stealth_address() {
    let mut rng = StdRng::seed_from_u64(0xc0b);
    let scalar = JubJubScalar::random(&mut rng);
    let pk = PublicKey::from(&SecretKey::random(&mut rng));
    let stealth_addr = pk.gen_stealth_address(&scalar);
    let ser = serde_json::to_string(&stealth_addr).unwrap();
    let deser = serde_json::from_str(&ser).unwrap();
    assert_eq!(stealth_addr, deser);
}

#[test]
fn serde_sender() {
    let mut rng = StdRng::seed_from_u64(0xc0b);
    let mut contract_info = [0; 4 * JubJubAffine::SIZE];
    rng.fill_bytes(&mut contract_info);
    let s1 = Sender::ContractInfo(contract_info);
    let sender_pk = PublicKey::from(&SecretKey::random(&mut rng));
    let note_pk = NotePublicKey::from(&NoteSecretKey::random(&mut rng));
    let blinder = [
        JubJubScalar::random(&mut rng),
        JubJubScalar::random(&mut rng),
    ];
    let s2 = Sender::encrypt(&note_pk, &sender_pk, &blinder);

    let ser1 = serde_json::to_string(&s1).unwrap();
    let ser2 = serde_json::to_string(&s2).unwrap();
    let deser1 = serde_json::from_str(&ser1).unwrap();
    let deser2 = serde_json::from_str(&ser2).unwrap();

    assert_eq!(s1, deser1);
    assert_eq!(s2, deser2);
}

#[test]
fn serde_note() {
    let mut rng = StdRng::seed_from_u64(0xc0b);
    let note = create_note(&mut rng);
    let ser = serde_json::to_string(&note).unwrap();
    let deser = serde_json::from_str(&ser).unwrap();
    assert_eq!(note, deser);
}

#[test]
fn serde_tx_skeleton() {
    let mut rng = StdRng::seed_from_u64(0xc0b);
    let root = BlsScalar::random(&mut rng);
    let mut nullifiers = Vec::new();
    for _ in 0..rng.gen_range(0..10) {
        nullifiers.push(BlsScalar::random(&mut rng));
    }
    let outputs = [create_note(&mut rng), create_note(&mut rng)];
    let max_fee = rng.gen_range(10..1000);
    let deposit = rng.gen_range(10..1000);

    let ts = TxSkeleton {
        root,
        nullifiers,
        outputs,
        max_fee,
        deposit,
    };
    let ser = serde_json::to_string(&ts).unwrap();
    let deser = serde_json::from_str(&ser).unwrap();
    assert_eq!(ts, deser);
}

#[test]
fn serde_wrong_encoded() {
    let wrong_encoded = "wrong-encoded";
    let public_key: Result<PublicKey, _> = serde_json::from_str(&wrong_encoded);
    assert!(public_key.is_err());

    let secret_key: Result<SecretKey, _> = serde_json::from_str(&wrong_encoded);
    assert!(secret_key.is_err());

    let view_key: Result<ViewKey, _> = serde_json::from_str(&wrong_encoded);
    assert!(view_key.is_err());

    let note_type: Result<NoteType, _> = serde_json::from_str(&wrong_encoded);
    assert!(note_type.is_err());

    let stealth_address: Result<StealthAddress, _> =
        serde_json::from_str(&wrong_encoded);
    assert!(stealth_address.is_err());
}

#[test]
fn serde_too_long_encoded() {
    let length_65_enc = "\"Hovyh2MvKLSnTfv2aKMMD1s7MgzWVCdzKJbbLwzU3kgVmo2JugxpGPASJWVQVXcxUqxtxVrQ63myzLRr1ko6oJvyv\"";

    let public_key: Result<PublicKey, _> = serde_json::from_str(&length_65_enc);
    assert!(public_key.is_err());

    let secret_key: Result<SecretKey, _> = serde_json::from_str(&length_65_enc);
    assert!(secret_key.is_err());

    let view_key: Result<ViewKey, _> = serde_json::from_str(&length_65_enc);
    assert!(view_key.is_err());

    let stealth_address: Result<StealthAddress, _> =
        serde_json::from_str(&length_65_enc);
    assert!(stealth_address.is_err());
}

#[test]
fn serde_too_short_encoded() {
    let length_63_enc = "\"YrHj6pQ3kRkpELFJK8a8ESdYyXaH9fQeb4pXRNEb8mSxDCrin1bF4uHz9BN13kN15mmH5fxXXSAusfLLGLrjCF\"";

    let public_key: Result<PublicKey, _> = serde_json::from_str(&length_63_enc);
    assert!(public_key.is_err());

    let secret_key: Result<SecretKey, _> = serde_json::from_str(&length_63_enc);
    assert!(secret_key.is_err());

    let view_key: Result<ViewKey, _> = serde_json::from_str(&length_63_enc);
    assert!(view_key.is_err());

    let stealth_address: Result<StealthAddress, _> =
        serde_json::from_str(&length_63_enc);
    assert!(stealth_address.is_err());
}

#[test]
fn serde_unknown_variant() {
    let unknown = "\"unknown-variant\"";

    let note_type: Result<NoteType, _> = serde_json::from_str(&unknown);
    assert!(note_type.is_err());
}
