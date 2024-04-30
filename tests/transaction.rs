// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

#![cfg(feature = "alloc")]

use core::convert::TryInto;

use dusk_bls12_381::BlsScalar;
use dusk_jubjub::JubJubScalar;
use ff::Field;
use phoenix_core::transaction::Execution;
use phoenix_core::{Error, Note, PublicKey, SecretKey, Transaction};
use rand_core::OsRng;

#[test]
fn transfer_parse() -> Result<(), Error> {
    let mut rng = OsRng;

    let sk = SecretKey::random(&mut rng);
    let pk = PublicKey::from(&sk);

    let value = 25;
    let blinding_factor = JubJubScalar::random(&mut rng);
    let note = Note::obfuscated(&mut rng, &pk, value, blinding_factor);

    let (fee, crossover) = note.clone().try_into()?;
    let anchor = BlsScalar::from(123);
    let nullifiers = vec![BlsScalar::from(456), BlsScalar::from(789)];
    let outputs = vec![note];
    let proof = vec![23, 45, 67];
    let transaction = Transaction {
        anchor,
        nullifiers,
        outputs,
        fee,
        crossover: Some(crossover),
        proof,
        exec: None,
    };
    let bytes_of_transaction = transaction.to_var_bytes();
    assert_eq!(
        transaction,
        Transaction::from_slice(&bytes_of_transaction).unwrap()
    );
    Ok(())
}

#[test]
fn call_parse() -> Result<(), Error> {
    let mut rng = OsRng;

    let sk = SecretKey::random(&mut rng);
    let pk = PublicKey::from(&sk);

    let value = 25;
    let blinding_factor = JubJubScalar::random(&mut rng);
    let note = Note::obfuscated(&mut rng, &pk, value, blinding_factor);

    let (fee, crossover) = note.clone().try_into()?;
    let anchor = BlsScalar::from(123);
    let nullifiers = vec![BlsScalar::from(456), BlsScalar::from(789)];
    let outputs = vec![note];
    let proof = vec![23, 45, 67];
    let exec = Some(Execution::Call {
        contract: [0; 32],
        fn_name: "TestString".to_string(),
        fn_arg: vec![4, 5, 6],
    });
    let transaction = Transaction {
        anchor,
        nullifiers,
        outputs,
        fee,
        crossover: Some(crossover),
        proof,
        exec,
    };
    let bytes_of_transaction = transaction.to_var_bytes();
    assert_eq!(
        transaction,
        Transaction::from_slice(&bytes_of_transaction).unwrap()
    );
    Ok(())
}

#[test]
fn deploy_parse() -> Result<(), Error> {
    let mut rng = OsRng;

    let sk = SecretKey::random(&mut rng);
    let pk = PublicKey::from(&sk);

    let value = 25;
    let blinding_factor = JubJubScalar::random(&mut rng);
    let note = Note::obfuscated(&mut rng, &pk, value, blinding_factor);

    let (fee, crossover) = note.clone().try_into()?;
    let anchor = BlsScalar::from(123);
    let nullifiers = vec![BlsScalar::from(456), BlsScalar::from(789)];
    let outputs = vec![note];
    let proof = vec![23, 45, 67];
    let exec = Some(Execution::Deploy {
        owner: Box::new(pk),
        bytecode: b"some-strange-bytecode.wasm".to_vec(),
        constructor_args: b"some-strange-ctor".to_vec(),
    });
    let transaction = Transaction {
        anchor,
        nullifiers,
        outputs,
        fee,
        crossover: Some(crossover),
        proof,
        exec,
    };
    let bytes_of_transaction = transaction.to_var_bytes();
    assert_eq!(
        transaction,
        Transaction::from_slice(&bytes_of_transaction).unwrap()
    );
    Ok(())
}
