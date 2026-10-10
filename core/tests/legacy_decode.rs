// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Strict and legacy-compatible decoding of notes, senders, stealth addresses
//! and transaction skeletons.
//!
//! The strict decoders take a point through the `dusk-jubjub` point decoder,
//! which since 0.15.2 rejects a point with a small-order component. The
//! legacy-compatible decoders accept any point on the curve, so that
//! historical transactions carrying such points still decode. The two agree
//! on the bytes of honestly created notes, whose points are torsion-free, and
//! only there.

use dusk_bls12_381::BlsScalar;
use dusk_bytes::{Error as BytesError, Serializable};
use dusk_jubjub::{Fq, JubJubAffine, JubJubExtended, JubJubScalar};
use ff::Field;
use phoenix_core::{
    NOTE_VAL_ENC_SIZE, Note, PublicKey, SecretKey, Sender, StealthAddress,
    TxSkeleton,
};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

/// Offsets of the points in an encoded `Note`.
const VALUE_COMMITMENT: usize = 1;
const R: usize = VALUE_COMMITMENT + 32;
const NOTE_PK: usize = R + 32;
const SENDER: usize = NOTE_PK + 32 + 8 + NOTE_VAL_ENC_SIZE;
const SENDER_POINTS: [usize; 4] =
    [SENDER + 1, SENDER + 33, SENDER + 65, SENDER + 97];

/// Notes as wallets and the transfer contract create them.
fn honest_notes(rng: &mut StdRng) -> Vec<Note> {
    let sender_pk = PublicKey::from(&SecretKey::random(&mut *rng));
    let receiver_pk = PublicKey::from(&SecretKey::random(&mut *rng));
    let mut blinder = || JubJubScalar::random(&mut *rng);
    let (value_blinder, sender_blinder) = (blinder(), [blinder(), blinder()]);

    let mut obfuscated = Note::obfuscated(
        rng,
        &sender_pk,
        &receiver_pk,
        42,
        value_blinder,
        sender_blinder,
    );
    obfuscated.set_pos(7);
    let transparent =
        Note::transparent(rng, &sender_pk, &receiver_pk, 42, sender_blinder);
    let mut contract_info = [0u8; 4 * JubJubAffine::SIZE];
    rng.fill_bytes(&mut contract_info);
    let withdrawal = Note::transparent_stealth(
        receiver_pk.gen_stealth_address(&JubJubScalar::random(&mut *rng)),
        42,
        Sender::ContractInfo(contract_info),
    );

    // The empty note's points are all the identity, which is torsion-free.
    vec![obfuscated, transparent, withdrawal, Note::empty()]
}

fn skeleton(outputs: [Note; 2]) -> TxSkeleton {
    TxSkeleton {
        root: BlsScalar::from(1u64),
        nullifiers: vec![BlsScalar::from(2u64), BlsScalar::from(3u64)],
        outputs,
        max_fee: 4,
        deposit: 5,
    }
}

/// The encoding of the point at `offset` of `bytes`, plus the order-two point
/// `(0, -1)`.
fn add_order_two(bytes: &[u8], offset: usize) -> [u8; 32] {
    let mut point = [0u8; 32];
    point.copy_from_slice(&bytes[offset..offset + 32]);
    let point = Option::<JubJubAffine>::from(JubJubAffine::from_bytes(point))
        .expect("an encoded point");
    let order_two = JubJubAffine::from_raw_unchecked(Fq::ZERO, -Fq::ONE);

    JubJubAffine::from(JubJubExtended::from(point) + order_two).to_bytes()
}

#[test]
fn honest_bytes_decode_alike() {
    let mut rng = StdRng::seed_from_u64(0xc0b);
    let notes = honest_notes(&mut rng);

    for note in &notes {
        let bytes = note.to_bytes();
        assert_eq!(&Note::from_bytes(&bytes).unwrap(), note);

        let sender = note.sender().to_bytes();
        assert_eq!(&Sender::from_bytes(&sender).unwrap(), note.sender());
        assert_eq!(
            &Sender::from_bytes_legacy_compat(&sender).unwrap(),
            note.sender()
        );

        let stealth = note.stealth_address().to_bytes();
        assert_eq!(
            &StealthAddress::from_bytes(&stealth).unwrap(),
            note.stealth_address()
        );
        assert_eq!(
            &StealthAddress::from_bytes_legacy_compat(&stealth).unwrap(),
            note.stealth_address()
        );

        for other in &notes {
            let skeleton = skeleton([note.clone(), other.clone()]);
            let bytes = skeleton.to_var_bytes();

            let strict = TxSkeleton::from_slice(&bytes).unwrap();
            let legacy = TxSkeleton::from_slice_legacy_compat(&bytes).unwrap();
            assert_eq!(strict, skeleton);
            assert_eq!(legacy, skeleton);
            assert_eq!(legacy.to_var_bytes(), bytes);
        }
    }
}

#[test]
fn legacy_decoders_keep_small_order_components() {
    let mut rng = StdRng::seed_from_u64(0xc0b);
    let notes = honest_notes(&mut rng);
    let other = notes[1].clone();

    // A small-order component in each point of an obfuscated note, and in the
    // sender ciphertexts of a transparent one.
    let mut offsets = vec![(0, VALUE_COMMITMENT), (0, R), (0, NOTE_PK)];
    for note in [0, 1] {
        offsets.extend(SENDER_POINTS.map(|offset| (note, offset)));
    }

    for (note, offset) in offsets {
        let mut note_bytes = notes[note].to_bytes();
        let point = add_order_two(&note_bytes, offset);
        note_bytes[offset..offset + 32].copy_from_slice(&point);

        // The strict decoders reject the point.
        assert_eq!(Note::from_bytes(&note_bytes), Err(BytesError::InvalidData));
        let mut bytes =
            skeleton([notes[note].clone(), other.clone()]).to_var_bytes();
        let note_at = BlsScalar::SIZE + u64::SIZE + 2 * BlsScalar::SIZE;
        bytes[note_at..note_at + Note::SIZE].copy_from_slice(&note_bytes);
        assert_eq!(
            TxSkeleton::from_slice(&bytes),
            Err(BytesError::InvalidData)
        );

        // The legacy-compatible decoder keeps it, byte for byte.
        let legacy = TxSkeleton::from_slice_legacy_compat(&bytes)
            .expect("an on-curve point decodes");
        assert_eq!(legacy.outputs[0].to_bytes(), note_bytes);
        assert_eq!(legacy.to_var_bytes(), bytes);

        let sender = &note_bytes[SENDER..];
        let sender: &[u8; Sender::SIZE] = sender.try_into().unwrap();
        if offset >= SENDER {
            assert_eq!(
                Sender::from_bytes(sender),
                Err(BytesError::InvalidData)
            );
        }
        assert_eq!(
            Sender::from_bytes_legacy_compat(sender).unwrap(),
            *legacy.outputs[0].sender()
        );
    }
}

#[test]
fn sender_decoders_reject_alike() {
    let mut rng = StdRng::seed_from_u64(0xc0b);
    let notes = honest_notes(&mut rng);
    let honest = notes[0].sender().to_bytes();

    // An unknown variant tag.
    let mut tag = honest;
    tag[0] = 2;
    // A point encoding with a coordinate outside the field.
    let mut not_a_point = honest;
    not_a_point[1..33].copy_from_slice(&[0xff; 32]);

    for bytes in [tag, not_a_point] {
        assert_eq!(Sender::from_bytes(&bytes), Err(BytesError::InvalidData));
        assert_eq!(
            Sender::from_bytes_legacy_compat(&bytes),
            Err(BytesError::InvalidData)
        );
    }

    // Contract information is opaque to both.
    let mut contract_info = [0xffu8; Sender::SIZE];
    contract_info[0] = 1;
    let sender = Sender::from_bytes(&contract_info).unwrap();
    assert_eq!(Sender::from_bytes_legacy_compat(&contract_info), Ok(sender));
}
