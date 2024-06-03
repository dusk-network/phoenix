// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg(feature = "alloc")]

use dusk_bls12_381::BlsScalar;
use dusk_jubjub::JubJubScalar;
use ff::Field;
use phoenix_core::{Error, Note, PublicKey, SecretKey, TxSkeleton};
use rand_core::OsRng;

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

    let tx_skeleton = TxSkeleton {
        root,
        nullifiers,
        outputs,
        tx_max_fee,
        deposit,
    };
    let bytes_of_transaction = tx_skeleton.to_var_bytes();
    assert_eq!(
        tx_skeleton,
        TxSkeleton::from_slice(&bytes_of_transaction).unwrap()
    );
    Ok(())
}
