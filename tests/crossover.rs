// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use core::convert::TryInto;

use dusk_jubjub::JubJubScalar;
use ff::Field;
use phoenix_core::{Error, Message, Note, PublicKey, SecretKey};
use rand_core::OsRng;

#[test]
fn crossover_hash() -> Result<(), Error> {
    let mut rng = OsRng;

    let ssk = SecretKey::random(&mut rng);
    let psk = PublicKey::from(ssk);

    let value = 25;
    let blinding_factor = JubJubScalar::random(&mut rng);
    let note = Note::obfuscated(&mut rng, &psk, value, blinding_factor);

    let value = 25;
    let blinding_factor = JubJubScalar::random(&mut rng);
    let note_p = Note::obfuscated(&mut rng, &psk, value, blinding_factor);

    let (_, crossover) = note.try_into()?;
    let (_, crossover_p) = note_p.try_into()?;

    let hash = crossover.hash();
    let hash_p = crossover_p.hash();

    assert_ne!(hash, hash_p);

    Ok(())
}

#[test]
fn message_hash() -> Result<(), Error> {
    let mut rng = OsRng;

    let ssk = SecretKey::random(&mut rng);
    let psk = PublicKey::from(ssk);
    let value = 25;

    let r = JubJubScalar::random(&mut rng);
    let message = Message::new(&mut rng, &r, &psk, value);

    let r_p = JubJubScalar::random(&mut rng);
    let message_p = Message::new(&mut rng, &r_p, &psk, value);

    let hash = message.hash();
    let hash_p = message_p.hash();

    assert_ne!(hash, hash_p);

    Ok(())
}
