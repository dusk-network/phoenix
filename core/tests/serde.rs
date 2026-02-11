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
use serde::Serialize;

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

fn assert_canonical_json<T>(
    input: &T,
    expected: &str,
) -> Result<String, Box<dyn std::error::Error>>
where
    T: ?Sized + Serialize,
{
    let serialized = serde_json::to_string(input)?;
    let input_canonical: serde_json::Value = serialized.parse()?;
    let expected_canonical: serde_json::Value = expected.parse()?;
    assert_eq!(input_canonical, expected_canonical);
    Ok(serialized)
}

#[test]
fn serde_public_key() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(0xc0b);
    let sk = SecretKey::random(&mut rng);
    let pk = PublicKey::from(&sk);
    let ser = assert_canonical_json(
        &pk,
        "\"nrkRNs188TSAy7LdQcwDfbghZEk3agdT7b7h83ynP6KcFb8ExYvUyE6r3v2yrt2Tie8pybzobLGebF6LapsDnAa\"",
    )?;
    let deser = serde_json::from_str(&ser)?;
    assert_eq!(pk, deser);
    Ok(())
}

#[test]
fn serde_secret_key() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(0xc0b);
    let sk = SecretKey::random(&mut rng);
    let ser = assert_canonical_json(
        &sk,
        "\"4VWvwJK79fznAuRZm9qP6Eqv57hLuYGU2PkoJJxYii2C7kquTNQYAygrJuYVLY1vsmVHSLifNtCdcN6dHN69rJKC\"",
    )?;
    let deser = serde_json::from_str(&ser)?;
    assert_eq!(sk, deser);
    Ok(())
}

#[test]
fn serde_view_key() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(0xc0b);
    let sk = SecretKey::random(&mut rng);
    let vk = ViewKey::from(&sk);
    let ser = assert_canonical_json(
        &vk,
        "\"4VWvwJK79fznAuRZm9qP6Eqv57hLuYGU2PkoJJxYii2CB6ZEEiHSgjYzXkaiQaAq7TDr6zEyuqUgpzLRcXfq1pdU\"",
    )?;
    let deser = serde_json::from_str(&ser)?;
    assert_eq!(vk, deser);
    Ok(())
}

#[test]
fn serde_note_type() -> Result<(), Box<dyn std::error::Error>> {
    let obfuscated = NoteType::Obfuscated;
    let transparent = NoteType::Transparent;
    let obf_ser = assert_canonical_json(&obfuscated, "\"Obfuscated\"")?;
    let trans_ser = assert_canonical_json(&transparent, "\"Transparent\"")?;
    let obf_deser = serde_json::from_str(&obf_ser)?;
    let trans_deser = serde_json::from_str(&trans_ser)?;
    assert_eq!(obfuscated, obf_deser);
    assert_eq!(transparent, trans_deser);
    Ok(())
}

#[test]
fn serde_stealth_address() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(0xc0b);
    let scalar = JubJubScalar::random(&mut rng);
    let pk = PublicKey::from(&SecretKey::random(&mut rng));
    let stealth_addr = pk.gen_stealth_address(&scalar);
    let ser = assert_canonical_json(
        &stealth_addr,
        "\"nrkRNs188TSAy7LdQcwDfbghZEk3agdT7b7h83ynP6KU2WHtBFqNXSZt9qJwZDZmhWPakFuWRg4m5hRHH2kF5su\"",
    )?;
    let deser = serde_json::from_str(&ser)?;
    assert_eq!(stealth_addr, deser);
    Ok(())
}

#[test]
fn serde_sender() -> Result<(), Box<dyn std::error::Error>> {
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

    let ser1 =
        assert_canonical_json(&s1, include_str!("./serde/sender_1.json"))?;
    let ser2 =
        assert_canonical_json(&s2, include_str!("./serde/sender_2.json"))?;
    let deser1 = serde_json::from_str(&ser1)?;
    let deser2 = serde_json::from_str(&ser2)?;

    assert_eq!(s1, deser1);
    assert_eq!(s2, deser2);

    Ok(())
}

#[test]
fn serde_note() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(0xc0b);
    let note = create_note(&mut rng);
    let ser = assert_canonical_json(&note, include_str!("./serde/note.json"))?;
    let deser = serde_json::from_str(&ser)?;
    assert_eq!(note, deser);
    Ok(())
}

#[test]
fn serde_tx_skeleton() -> Result<(), Box<dyn std::error::Error>> {
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
    let ser =
        assert_canonical_json(&ts, include_str!("./serde/tx_skeleton.json"))?;
    let deser = serde_json::from_str(&ser)?;
    assert_eq!(ts, deser);
    Ok(())
}

#[test]
fn serde_wrong_encoded() {
    let wrong_encoded = "\"wrong-encoded\"";
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
