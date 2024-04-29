// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{JubJubAffine, JubJubScalar, GENERATOR, GENERATOR_EXTENDED};
use dusk_plonk::prelude::*;
use ff::Field;
use rand_core::OsRng;

use phoenix_core::{aes, elgamal, PublicKey, SecretKey};

static LABEL: &[u8; 12] = b"dusk-network";
const CAPACITY: usize = 12; // capacity required for the setup

#[derive(Default, Debug)]
pub struct ElGamalCircuit {
    public_key: JubJubAffine,
    plaintext: JubJubAffine,
    r: JubJubScalar,
    ciphertext_1: JubJubAffine,
    ciphertext_2: JubJubAffine,
}

impl ElGamalCircuit {
    pub fn new(
        public_key: &JubJubExtended,
        plaintext: &JubJubExtended,
        r: &JubJubScalar,
        ciphertext_1: &JubJubExtended,
        ciphertext_2: &JubJubExtended,
    ) -> Self {
        Self {
            public_key: JubJubAffine::from(public_key),
            plaintext: JubJubAffine::from(plaintext),
            r: *r,
            ciphertext_1: JubJubAffine::from(ciphertext_1),
            ciphertext_2: JubJubAffine::from(ciphertext_2),
        }
    }
}

impl Circuit for ElGamalCircuit {
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error> {
        elgamal::zk_encrypt(
            composer,
            &self.public_key,
            &self.plaintext,
            &self.r,
            &self.ciphertext_1,
            &self.ciphertext_2,
        )?;
        Ok(())
    }
}

#[test]
fn test_aes_encrypt_and_decrypt() {
    const PLAINTEXT_SIZE: usize = 20;
    const ENCRYPTION_SIZE: usize = PLAINTEXT_SIZE + aes::ENCRYPTION_EXTRA_SIZE;

    let shared_secret_key =
        JubJubAffine::from(GENERATOR * JubJubScalar::from(1234u64));

    let plaintext = b"00112233445566778899";
    let encryption: [u8; ENCRYPTION_SIZE] =
        aes::encrypt(&shared_secret_key, plaintext, &mut OsRng)
            .expect("Encrypted correctly.");
    let dec_plaintext = aes::decrypt(&shared_secret_key, &encryption)
        .expect("Decrypted correctly.");

    assert_eq!(&dec_plaintext, plaintext);
}

#[test]
fn test_elgamal_encrypt_and_decrypt() {
    let sk = SecretKey::random(&mut OsRng);
    let pk = PublicKey::from(&sk);

    let message = GENERATOR_EXTENDED * JubJubScalar::from(1234u64);

    // Encrypt using a fresh random value 'r'
    let r = JubJubScalar::random(&mut OsRng);
    let (c1, c2) = elgamal::encrypt(pk.A(), &message, &r);

    // Assert decryption
    let dec_message = elgamal::decrypt(sk.a(), &c1, &c2);
    assert_eq!(message, dec_message);

    // Assert decryption using an incorrect key
    let dec_message_wrong = elgamal::decrypt(sk.b(), &c1, &c2);
    assert_ne!(message, dec_message_wrong);
}

#[test]
fn test_elgamal_zk_encrypt() {
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
            &ElGamalCircuit::new(&pk.A(), &message, &r, &c1, &c2),
        )
        .expect("failed to prove");

    verifier
        .verify(&proof, &public_inputs)
        .expect("failed to verify proof");
}
