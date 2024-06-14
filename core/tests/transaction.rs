// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg(feature = "alloc")]

use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{JubJubScalar, GENERATOR};
use ff::Field;
use phoenix_core::{
    Error, Note, PublicKey, RecipientParameters, SecretKey, TxSkeleton,
};
use rand::rngs::OsRng;

#[test]
fn transaction_parse() -> Result<(), Error> {
    let mut rng = OsRng;

    let sk = SecretKey::random(&mut rng);
    let pk = PublicKey::from(&sk);

    let value = 25;
    let blinding_factor = JubJubScalar::random(&mut rng);
    let note = Note::obfuscated(&mut rng, &pk, value, blinding_factor);

    let root = BlsScalar::from(123);
    let nullifiers = vec![BlsScalar::from(456), BlsScalar::from(789)];
    let outputs = [note.clone(), note];
    let tx_max_fee = 0;
    let deposit = 0;

    let output_npks = [
        (GENERATOR * JubJubScalar::random(&mut rng)).into(),
        (GENERATOR * JubJubScalar::random(&mut rng)).into(),
    ];
    let hash = BlsScalar::random(&mut rng);

    let recipient_params =
        RecipientParameters::new(&mut rng, &sk, output_npks, hash);

    let tx_skeleton = TxSkeleton {
        root,
        nullifiers,
        outputs,
        tx_max_fee,
        deposit,
        recipient_params,
    };
    let bytes_of_transaction = tx_skeleton.to_var_bytes();
    assert_eq!(
        tx_skeleton,
        TxSkeleton::from_slice(&bytes_of_transaction).unwrap()
    );
    Ok(())
}
