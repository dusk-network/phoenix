// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Regressions for the subgroup checks of the transaction circuit.
//!
//! The circuit constrains every key the prover supplies, and the note public
//! keys of the outputs, to the prime-order subgroup where they enter it. Each
//! test adds an offset to one of these keys and recomputes what depends on the
//! key, the signatures, the note, its nullifier and the encryptions, so that
//! every other equation of the circuit holds. With the identity as the offset,
//! the transaction must prove, which checks the construction; with the
//! order-two point `T`, it must be unsatisfiable.
//!
//! The signature nonces need no check of their own: each signature equation
//! sets its nonce equal to `u·G + c·pk`, with the key `pk` in the subgroup.

#![cfg(feature = "plonk")]
#![allow(non_snake_case)]

use std::sync::LazyLock;

use dusk_bls12_381::BlsScalar;
use dusk_bytes::Serializable;
use dusk_jubjub::{
    GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED, JubJubAffine, JubJubExtended,
    JubJubScalar,
};
use dusk_plonk::prelude::{Compiler, Error as PlonkError, PublicParameters};
use dusk_poseidon::{Domain, Hash};
use ff::Field;
use jubjub_schnorr::{
    PublicKey as NotePublicKey, Signature as SchnorrSignature, SignatureDouble,
};
use phoenix_circuits::TxCircuit;
use phoenix_core::{Note, PublicKey, StealthAddress, value_commitment};
use poseidon_merkle::{Item, Tree};
use rand::SeedableRng;
use rand::rngs::StdRng;

mod common;
use common::*;

/// A test SRS that fits every input variant. Soundness does not depend on the
/// SRS, and the production CRS only fits the 1- and 2-input circuits under
/// `dusk-plonk`'s blinding degree.
static PP: LazyLock<PublicParameters> = LazyLock::new(|| {
    PublicParameters::setup(1 << 17, &mut StdRng::seed_from_u64(0x7042))
        .expect("failed to generate the test SRS")
});

/// The order-two point `(0, -1)`.
fn order_two_point() -> JubJubExtended {
    let point = JubJubExtended::from(JubJubAffine::from_raw_unchecked(
        BlsScalar::zero(),
        -BlsScalar::one(),
    ));
    assert!(!bool::from(point.is_identity()));
    assert!(bool::from(point.double().is_identity()));
    point
}

/// The key a test adds an offset to.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Shifted {
    /// `note_pk` of the last input.
    NotePk,
    /// `note_pk_p` of the first input.
    NotePkP,
    /// `A` of the sender public key.
    SenderA,
    /// `B` of the sender public key.
    SenderB,
    /// The note public key of the given output.
    OutputNotePk(usize),
}

/// The double-signature challenge of `jubjub-schnorr`.
fn double_challenge(
    R: &JubJubExtended,
    R_p: &JubJubExtended,
    pk: &JubJubExtended,
    pk_p: &JubJubExtended,
    message: BlsScalar,
) -> JubJubScalar {
    let [R_x, R_y] = R.to_hash_inputs();
    let [R_p_x, R_p_y] = R_p.to_hash_inputs();
    let [pk_x, pk_y] = pk.to_hash_inputs();
    let [pk_p_x, pk_p_y] = pk_p.to_hash_inputs();
    let domain = BlsScalar::from(u64::from_be_bytes(*b"JJSCHDBL"));

    Hash::digest_truncated(
        Domain::Other,
        &[
            domain, R_x, R_y, R_p_x, R_p_y, pk_x, pk_y, pk_p_x, pk_p_y, message,
        ],
    )[0]
}

/// The single-signature challenge of `jubjub-schnorr`.
fn challenge(
    R: &JubJubExtended,
    pk: &JubJubExtended,
    message: BlsScalar,
) -> JubJubScalar {
    let [R_x, R_y] = R.to_hash_inputs();
    let [pk_x, pk_y] = pk.to_hash_inputs();

    Hash::digest_truncated(Domain::Other, &[R_x, R_y, pk_x, pk_y, message])[0]
}

/// A nonce `r` whose challenge `c` is even, and `c`. A signature with an even
/// challenge holds for a key plus `T` as well, as `c · T` vanishes.
fn even_challenge(
    challenge: impl Fn(JubJubScalar) -> JubJubScalar,
) -> (JubJubScalar, JubJubScalar) {
    let mut rng = StdRng::seed_from_u64(0xe7e);
    loop {
        let r = JubJubScalar::random(&mut rng);
        let c = challenge(r);
        if c.to_bytes()[0] & 1 == 0 {
            return (r, c);
        }
    }
}

/// A double signature of the payload hash with `sk`, for the keys `pk` and
/// `pk_p`.
fn sign_double(
    sk: &JubJubScalar,
    pk: &JubJubExtended,
    pk_p: &JubJubExtended,
) -> SignatureDouble {
    let (r, c) = even_challenge(|r| {
        let R = GENERATOR_EXTENDED * r;
        let R_p = GENERATOR_NUMS_EXTENDED * r;
        double_challenge(&R, &R_p, pk, pk_p, TP.payload_hash)
    });
    let u = r - c * sk;
    let (R, R_p) = (GENERATOR_EXTENDED * r, GENERATOR_NUMS_EXTENDED * r);

    // Both equations the circuit checks hold.
    assert_eq!(GENERATOR_EXTENDED * u + pk * c, R);
    assert_eq!(GENERATOR_NUMS_EXTENDED * u + pk_p * c, R_p);

    let mut bytes = [0u8; SignatureDouble::SIZE];
    bytes[..32].copy_from_slice(&u.to_bytes());
    bytes[32..64].copy_from_slice(&JubJubAffine::from(R).to_bytes());
    bytes[64..].copy_from_slice(&JubJubAffine::from(R_p).to_bytes());
    SignatureDouble::from_bytes(&bytes)
        .expect("the nonces are prime-order points")
}

/// A signature of the payload hash with `sk`, for the key `pk`.
fn sign(sk: &JubJubScalar, pk: &JubJubExtended) -> SchnorrSignature {
    let (r, c) = even_challenge(|r| {
        challenge(&(GENERATOR_EXTENDED * r), pk, TP.payload_hash)
    });
    let u = r - c * sk;
    let R = GENERATOR_EXTENDED * r;

    // The equation the circuit checks holds.
    assert_eq!(GENERATOR_EXTENDED * u + pk * c, R);

    let mut bytes = [0u8; SchnorrSignature::SIZE];
    bytes[..32].copy_from_slice(&u.to_bytes());
    bytes[32..].copy_from_slice(&JubJubAffine::from(R).to_bytes());
    SchnorrSignature::from_bytes(&bytes)
        .expect("the nonce is a prime-order point")
}

/// The ElGamal encryption of `message` to `key` with `blinder`, as the
/// circuit computes it.
fn encrypt(
    key: &JubJubExtended,
    message: &JubJubExtended,
    blinder: &JubJubScalar,
) -> (JubJubAffine, JubJubAffine) {
    let c1 = GENERATOR_EXTENDED * blinder;
    let c2 = message + key * blinder;
    (c1.into(), c2.into())
}

/// The `I`-input transaction spending the first test notes, with `offset`
/// added to the key `shifted` names. What depends on that key is recomputed
/// for it, so that every other equation of the circuit holds.
fn transaction<const I: usize>(
    shifted: Shifted,
    offset: JubJubExtended,
) -> TxCircuit<HEIGHT, I> {
    // `offset` for the key `shifted` names, the identity for the others.
    let offset_of = |key: Shifted| {
        if key == shifted {
            offset
        } else {
            JubJubExtended::identity()
        }
    };
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let mut inputs: [InputNoteInfo<HEIGHT>; I] =
        core::array::from_fn(|i| TP.input_notes_info[i].clone());
    if shifted == Shifted::NotePk {
        let input = &mut inputs[I - 1];
        let stealth_address = *input.note.stealth_address();
        let note_sk = TP.sender_sk.gen_note_sk(&stealth_address);
        let note_pk = stealth_address.note_pk().as_ref() + offset;
        let stealth_address = StealthAddress::from_raw_unchecked(
            *stealth_address.R(),
            NotePublicKey::from_raw_unchecked(note_pk),
        );

        let mut note = Note::transparent_stealth(
            stealth_address,
            input.value,
            *input.note.sender(),
        );
        note.set_pos(*input.note.pos());
        input.note = note;
        input.signature =
            sign_double(note_sk.as_ref(), &note_pk, &input.note_pk_p.into());
    }
    if shifted == Shifted::NotePkP {
        let input = &mut inputs[0];
        let note_sk = TP.sender_sk.gen_note_sk(input.note.stealth_address());
        let note_pk = *input.note.stealth_address().note_pk().as_ref();
        let note_pk_p = JubJubExtended::from(input.note_pk_p) + offset;

        let [x, y] = note_pk_p.to_hash_inputs();
        let pos = BlsScalar::from(*input.note.pos());
        input.nullifier = Hash::digest(Domain::Other, &[x, y, pos])[0];
        input.note_pk_p = note_pk_p.into();
        input.signature = sign_double(note_sk.as_ref(), &note_pk, &note_pk_p);
    }

    // The inputs in a tree of their own.
    let mut tree = Tree::<(), HEIGHT>::new();
    for input in &inputs {
        let item = Item {
            hash: input.note.hash(),
            data: (),
        };
        tree.insert(*input.note.pos(), item);
    }
    for input in &mut inputs {
        input.merkle_opening = tree
            .opening(*input.note.pos())
            .expect("the note is in the tree");
    }

    let A = TP.sender_pk.A() + offset_of(Shifted::SenderA);
    let B = TP.sender_pk.B() + offset_of(Shifted::SenderB);
    let mut signatures = TP.signatures;
    if shifted == Shifted::SenderA {
        signatures.0 = sign(TP.sender_sk.a(), &A);
    }
    if shifted == Shifted::SenderB {
        signatures.1 = sign(TP.sender_sk.b(), &B);
    }

    // The inputs hold 25 each, the fee and the deposit take 10.
    let values = [25 * I as u64 - 15, 5];
    let output_notes_info = core::array::from_fn(|k| {
        let note_pk = JubJubExtended::from(TP.output_npk[k])
            + offset_of(Shifted::OutputNotePk(k));
        let value_blinder = JubJubScalar::random(&mut rng);
        let sender_blinder = TP.sender_blinder[k];

        OutputNoteInfo {
            value: values[k],
            value_commitment: value_commitment(values[k], value_blinder),
            value_blinder,
            note_pk: note_pk.into(),
            sender_enc: [
                encrypt(&note_pk, &A, &sender_blinder[0]),
                encrypt(&note_pk, &B, &sender_blinder[1]),
            ],
            sender_blinder,
        }
    });

    TxCircuit {
        input_notes_info: inputs,
        output_notes_info,
        payload_hash: TP.payload_hash,
        root: tree.root().hash,
        deposit: TP.deposit,
        max_fee: TP.max_fee,
        sender_pk: PublicKey::new(A, B),
        signatures,
    }
}

/// For each key in `shifted`, proves the `I`-input transaction with the
/// identity added to the key, as a control of the construction, then checks
/// that the same construction with `T` added is unsatisfiable.
fn assert_rejected<const I: usize>(shifted: &[Shifted]) {
    let mut rng = StdRng::seed_from_u64(0x7042);

    let (prover, verifier) =
        Compiler::compile::<TxCircuit<HEIGHT, I>>(&PP, LABEL)
            .expect("failed to compile circuit");

    for &shifted in shifted {
        let control = transaction::<I>(shifted, JubJubExtended::identity());
        let (proof, public_inputs) =
            prover.prove(&mut rng, &control).unwrap_or_else(|err| {
                panic!("{shifted:?} with a zero offset must prove: {err:?}")
            });
        verifier
            .verify(&proof, &public_inputs)
            .unwrap_or_else(|err| {
                panic!("{shifted:?} with a zero offset must verify: {err:?}")
            });

        let result = prover
            .prove(&mut rng, &transaction::<I>(shifted, order_two_point()));
        assert!(
            matches!(result, Err(PlonkError::CircuitUnsatisfied)),
            "{shifted:?} with a small-order component must be unsatisfiable"
        );
    }
}

#[test]
fn note_pk_p_rejected_1_2() {
    assert_rejected::<1>(&[Shifted::NotePkP]);
}

#[test]
fn note_pk_p_rejected_2_2() {
    assert_rejected::<2>(&[Shifted::NotePkP]);
}

#[test]
fn note_pk_p_rejected_3_2() {
    assert_rejected::<3>(&[Shifted::NotePkP]);
}

#[test]
fn note_pk_p_rejected_4_2() {
    assert_rejected::<4>(&[Shifted::NotePkP]);
}

#[test]
fn note_pk_rejected() {
    assert_rejected::<2>(&[Shifted::NotePk]);
}

#[test]
fn sender_key_rejected() {
    assert_rejected::<2>(&[Shifted::SenderA, Shifted::SenderB]);
}

#[test]
fn output_note_pk_rejected() {
    assert_rejected::<2>(&[Shifted::OutputNotePk(0), Shifted::OutputNotePk(1)]);
}
