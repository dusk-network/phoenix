// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{JubJubAffine, JubJubScalar, GENERATOR, GENERATOR_EXTENDED};
use ff::Field;
use rand_core::OsRng;

use phoenix_core::{aes, elgamal, PublicKey, SecretKey};

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
