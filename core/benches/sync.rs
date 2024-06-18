// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use criterion::{criterion_group, criterion_main, Criterion};

use rand::rngs::StdRng;
use rand::SeedableRng;

use dusk_jubjub::JubJubScalar;
use ff::Field;
use phoenix_core::{Note, NoteType, PublicKey, SecretKey};

const SIZE: usize = 1000000;

fn push_notes() -> (SecretKey, Vec<Note>) {
    let mut rng = StdRng::seed_from_u64(0xbeef);
    let our_sk = SecretKey::random(&mut rng);
    let our_pk = PublicKey::from(&our_sk);

    let mut notes = Vec::with_capacity(SIZE);

    for i in 0..SIZE {
        let pk = if i % 10 == 0 {
            PublicKey::from(&SecretKey::random(&mut rng))
        } else {
            our_pk
        };
        let value_blinder = JubJubScalar::random(&mut rng);

        let sender_blinder = [
            JubJubScalar::random(&mut rng),
            JubJubScalar::random(&mut rng),
        ];
        notes.push(Note::new(
            &mut rng,
            NoteType::Obfuscated,
            &pk,
            42,
            value_blinder,
            sender_blinder,
        ));
    }
    (our_sk, notes)
}

fn sync(c: &mut Criterion) {
    let (our_sk, notes) = push_notes();
    c.bench_function("owns", |b| {
        b.iter(|| {
            for i in 0..SIZE {
                our_sk.owns(&notes[i]);
            }
        });
    });
    c.bench_function("owns_unchecked", |b| {
        b.iter(|| {
            for i in 0..SIZE {
                our_sk.owns_unchecked(&notes[i]);
            }
        });
    });
}

criterion_group!(benches, sync);
criterion_main!(benches);
