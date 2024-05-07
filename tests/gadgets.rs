// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{JubJubAffine, JubJubScalar, GENERATOR_EXTENDED};
use ff::Field;
use rand_core::OsRng;

use phoenix_core::{elgamal, PublicKey, SecretKey};

use dusk_plonk::prelude::*;

static LABEL: &[u8; 12] = b"dusk-network";
const CAPACITY: usize = 13; // capacity required for the setup

#[derive(Default, Debug)]
pub struct ElGamalCircuit {
    public_key: JubJubAffine,
    secret_key: JubJubScalar,
    plaintext: JubJubAffine,
    r: JubJubScalar,
    ciphertext_1: JubJubAffine,
    ciphertext_2: JubJubAffine,
}

impl ElGamalCircuit {
    pub fn new(
        public_key: &JubJubExtended,
        secret_key: &JubJubScalar,
        plaintext: &JubJubExtended,
        r: &JubJubScalar,
        ciphertext_1: &JubJubExtended,
        ciphertext_2: &JubJubExtended,
    ) -> Self {
        Self {
            public_key: JubJubAffine::from(public_key),
            secret_key: *secret_key,
            plaintext: JubJubAffine::from(plaintext),
            r: *r,
            ciphertext_1: JubJubAffine::from(ciphertext_1),
            ciphertext_2: JubJubAffine::from(ciphertext_2),
        }
    }
}

impl Circuit for ElGamalCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        // IMPORT INPUTS
        let public_key = composer.append_point(self.public_key);
        let secret_key = composer.append_witness(self.secret_key);
        let plaintext = composer.append_point(self.plaintext);
        let r = composer.append_witness(self.r);

        // ENCRYPT
        let (ciphertext_1, ciphertext_2) =
            elgamal::encrypt_gadget(composer, public_key, plaintext, r)?;

        // ASSERT RESULT MAKING THE CIPHERTEXT PUBLIC
        composer.assert_equal_public_point(ciphertext_1, self.ciphertext_1);
        composer.assert_equal_public_point(ciphertext_2, self.ciphertext_2);

        // DECRYPT
        let dec_plaintext = elgamal::decrypt_gadget(
            composer,
            secret_key,
            ciphertext_1,
            ciphertext_2,
        );

        // ASSERT RESULTING PLAINTEXT
        composer.assert_equal_point(dec_plaintext, plaintext);

        Ok(())
    }
}

#[test]
fn test_elgamal_gadgets() {
    let sk = SecretKey::random(&mut OsRng);
    let pk = PublicKey::from(&sk);

    let message = GENERATOR_EXTENDED * JubJubScalar::from(1234u64);
    let r = JubJubScalar::random(&mut OsRng);
    let (c1, c2) = elgamal::encrypt(pk.A(), &message, &r);

    let pp = PublicParameters::setup(1 << CAPACITY, &mut OsRng).unwrap();

    let (prover, verifier) = Compiler::compile::<ElGamalCircuit>(&pp, LABEL)
        .expect("failed to compile circuit");

    let (proof, public_inputs) = prover
        .prove(
            &mut OsRng,
            &ElGamalCircuit::new(&pk.A(), &sk.a(), &message, &r, &c1, &c2),
        )
        .expect("failed to prove");

    verifier
        .verify(&proof, &public_inputs)
        .expect("failed to verify proof");
}
