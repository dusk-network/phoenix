// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bls12_381::BlsScalar;
use dusk_jubjub::JubJubScalar;
use ff::Field;
use phoenix_core::{Error, Note, PublicKey, SecretKey, TxSkeleton};
use rand::SeedableRng;
use rand::rngs::StdRng;

fn output_notes(rng: &mut StdRng) -> [Note; 2] {
    let sender_pk = PublicKey::from(&SecretKey::random(rng));
    let receiver_pk = PublicKey::from(&SecretKey::random(rng));
    let value_blinder = JubJubScalar::random(&mut *rng);
    let sender_blinder = [
        JubJubScalar::random(&mut *rng),
        JubJubScalar::random(&mut *rng),
    ];
    let note1 = Note::obfuscated(
        rng,
        &sender_pk,
        &receiver_pk,
        3431,
        value_blinder,
        sender_blinder,
    );
    let note2 = Note::transparent(
        rng,
        &sender_pk,
        &receiver_pk,
        4115690,
        sender_blinder,
    );

    [note1, note2]
}

#[test]
fn serialize_1_2() -> Result<(), Error> {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let nullifiers = vec![BlsScalar::random(&mut rng)];

    let tx_skeleton = TxSkeleton {
        root: BlsScalar::random(&mut rng),
        outputs: output_notes(&mut rng),
        nullifiers,
        max_fee: 4671,
        deposit: 3426,
    };

    let deserialized = TxSkeleton::from_slice(&tx_skeleton.to_var_bytes())?;

    assert_eq!(tx_skeleton, deserialized);
    assert_eq!(
        tx_skeleton.to_hash_input_bytes(),
        deserialized.to_hash_input_bytes(),
    );

    Ok(())
}

#[test]
fn serialize_2_2() -> Result<(), Error> {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let nullifiers =
        vec![BlsScalar::random(&mut rng), BlsScalar::random(&mut rng)];

    let tx_skeleton = TxSkeleton {
        root: BlsScalar::random(&mut rng),
        outputs: output_notes(&mut rng),
        nullifiers,
        max_fee: 4415,
        deposit: 245,
    };

    let deserialized = TxSkeleton::from_slice(&tx_skeleton.to_var_bytes())?;
    assert_eq!(tx_skeleton, deserialized,);
    assert_eq!(
        tx_skeleton.to_hash_input_bytes(),
        deserialized.to_hash_input_bytes(),
    );

    Ok(())
}

#[test]
fn serialize_3_2() -> Result<(), Error> {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let nullifiers = vec![
        BlsScalar::random(&mut rng),
        BlsScalar::random(&mut rng),
        BlsScalar::random(&mut rng),
    ];

    let tx_skeleton = TxSkeleton {
        root: BlsScalar::random(&mut rng),
        outputs: output_notes(&mut rng),
        nullifiers,
        max_fee: 612,
        deposit: 793426,
    };

    let deserialized = TxSkeleton::from_slice(&tx_skeleton.to_var_bytes())?;
    assert_eq!(tx_skeleton, deserialized,);
    assert_eq!(
        tx_skeleton.to_hash_input_bytes(),
        deserialized.to_hash_input_bytes(),
    );

    Ok(())
}

#[test]
fn serialize_4_2() -> Result<(), Error> {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let nullifiers = vec![
        BlsScalar::random(&mut rng),
        BlsScalar::random(&mut rng),
        BlsScalar::random(&mut rng),
        BlsScalar::random(&mut rng),
    ];

    let tx_skeleton = TxSkeleton {
        root: BlsScalar::random(&mut rng),
        outputs: output_notes(&mut rng),
        nullifiers,
        max_fee: 451239,
        deposit: 4776780,
    };

    let deserialized = TxSkeleton::from_slice(&tx_skeleton.to_var_bytes())?;
    assert_eq!(tx_skeleton, deserialized,);
    assert_eq!(
        tx_skeleton.to_hash_input_bytes(),
        deserialized.to_hash_input_bytes(),
    );

    Ok(())
}
