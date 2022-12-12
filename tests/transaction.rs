// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use core::convert::TryInto;

use dusk_bls12_381::BlsScalar;
use dusk_jubjub::JubJubScalar;
use dusk_pki::SecretSpendKey;
use phoenix_core::{Error, Note, Transaction};
use rand_core::OsRng;

// pub anchor: BlsScalar,
// pub nullifiers: Vec<BlsScalar>,
// pub outputs: Vec<Note>,
// pub fee: Fee,
// pub crossover: Option<Crossover>,
// pub proof: Vec<u8>,
// pub call: Option<(BlsScalar, String, Vec<u8>)>,

#[test]
fn transaction_parse() -> Result<(), Error> {
    let rng = &mut OsRng;

    let ssk = SecretSpendKey::random(rng);
    let psk = ssk.public_spend_key();

    let value = 25;
    let blinding_factor = JubJubScalar::random(rng);
    let note = Note::obfuscated(rng, &psk, value, blinding_factor);

    let (fee, crossover) = note.try_into()?;
    let anchor = BlsScalar::from(123);
    let nullifiers = vec![BlsScalar::from(456), BlsScalar::from(789)];
    let outputs = vec![note];
    let proof = vec![23, 45, 67];
    let call = Some((
        BlsScalar::from(234),
        "TestString".to_string(),
        vec![4, 5, 6],
    ));
    let transaction = Transaction {
        anchor,
        nullifiers,
        outputs,
        fee,
        crossover: Some(crossover),
        proof,
        call,
    };
    let bytes_of_transaction = transaction.to_var_bytes();
    assert_eq!(
        transaction,
        Transaction::from_slice(&bytes_of_transaction).unwrap()
    );
    Ok(())
}
