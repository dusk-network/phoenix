// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::Serializable;
use dusk_jubjub::{
    Fq, GENERATOR_EXTENDED, JubJubAffine, JubJubExtended, JubJubScalar,
};
use ff::Field;
use phoenix_core::{
    Error, Note, NoteType, PublicKey, SecretKey, Sender, StealthAddress,
    ViewKey, value_commitment,
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

#[test]
fn checked_stealth_decode_rejects_identity() {
    // The default stealth address is built from identity points.
    let bytes = StealthAddress::default().to_bytes();

    // The checked decode rejects non-prime-order stealth points: an identity
    // `R` collapses the value-encryption key `dhke(vk.a, R)` to a shared secret
    // anyone can derive, and an identity `note_pk` exposes the
    // ElGamal-encrypted sender public key.
    assert!(StealthAddress::from_bytes_checked(&bytes).is_err());

    // The strict and legacy decoders stay permissive so replaying
    // already-finalized transactions keeps working.
    assert!(StealthAddress::from_bytes(&bytes).is_ok());
    assert!(StealthAddress::from_bytes_legacy_compat(&bytes).is_ok());
}

#[test]
fn checked_stealth_decode_rejects_torsion() {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let receiver_pk = PublicKey::from(&SecretKey::random(&mut rng));
    let stealth =
        receiver_pk.gen_stealth_address(&JubJubScalar::random(&mut rng));

    // Canonical encoding of a non-identity, small-order (torsion) point: the
    // order-2 point (0, -1) on JubJub. The checked decode rejects it while the
    // legacy decode (on-curve only) accepts it. (Operand-level coverage of the
    // prime-order guard lives in the `stealth_address` unit tests.)
    let torsion = JubJubAffine::from_raw_unchecked(Fq::ZERO, -Fq::ONE);

    let mut bytes = stealth.to_bytes();
    bytes[..32].copy_from_slice(&torsion.to_bytes());
    // The point decode underlying `from_bytes` already rejects torsion points,
    // so the checked decode rejects this one before the prime-order guard runs.
    assert!(StealthAddress::from_bytes(&bytes).is_err());
    assert!(StealthAddress::from_bytes_checked(&bytes).is_err());
    assert!(StealthAddress::from_bytes_legacy_compat(&bytes).is_ok());
}

#[test]
fn strict_decode_rejects_mixed_order_stealth_point() {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let receiver_pk = PublicKey::from(&SecretKey::random(&mut rng));
    let stealth =
        receiver_pk.gen_stealth_address(&JubJubScalar::random(&mut rng));

    // A mixed-order point: the prime-order generator plus the order-2 point.
    // It is neither small-order nor torsion-free, so only a decoder enforcing
    // the full torsion-free property rejects it. The prime-order guard leans on
    // `from_bytes` for that half, so pin it here.
    let order_two = JubJubAffine::from_raw_unchecked(Fq::ZERO, -Fq::ONE);
    let mixed_order = JubJubAffine::from(
        GENERATOR_EXTENDED + JubJubExtended::from(order_two),
    );

    let mut bytes = stealth.to_bytes();
    bytes[..32].copy_from_slice(&mixed_order.to_bytes());
    assert!(StealthAddress::from_bytes(&bytes).is_err());
    assert!(StealthAddress::from_bytes_checked(&bytes).is_err());
    assert!(StealthAddress::from_bytes_legacy_compat(&bytes).is_ok());
}

#[test]
fn strict_decode_accepts_identity_stealth_note() {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let mut sender_data = [0u8; 4 * JubJubAffine::SIZE];
    rng.fill_bytes(&mut sender_data);

    let note = Note::transparent_stealth(
        StealthAddress::default(),
        25,
        Sender::ContractInfo(sender_data),
    );

    // A note with an identity stealth address must still round-trip through the
    // strict decoder, which replays already-finalized transactions; the
    // prime-order gate lives on the checked decoder instead
    // (see the `TxSkeleton::from_slice_checked` tests).
    assert_eq!(note, Note::from_bytes(&note.to_bytes()).unwrap());
}

#[test]
fn note_not_owned() {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let owner_pk = PublicKey::from(&SecretKey::random(&mut rng));
    let value_blinder = JubJubScalar::random(&mut rng);
    let sender_blinder = [
        JubJubScalar::random(&mut rng),
        JubJubScalar::random(&mut rng),
    ];

    let note = Note::obfuscated(
        &mut rng,
        &owner_pk,
        &owner_pk,
        42,
        value_blinder,
        sender_blinder,
    );

    let not_owner_sk = SecretKey::random(&mut rng);
    let not_owner_vk = ViewKey::from(&not_owner_sk);

    assert!(note.value(Some(&not_owner_vk)).is_err());
}
