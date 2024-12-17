// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{JubJubAffine, JubJubScalar, GENERATOR};
use phoenix_core::aes;
use rand::rngs::StdRng;
use rand::SeedableRng;

#[test]
fn test_aes_encrypt_and_decrypt() {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    const PLAINTEXT_SIZE: usize = 20;
    const ENCRYPTION_SIZE: usize = PLAINTEXT_SIZE + aes::ENCRYPTION_EXTRA_SIZE;

    let shared_secret_key =
        JubJubAffine::from(GENERATOR * JubJubScalar::from(1234u64));

    let plaintext = b"00112233445566778899";
    let salt = b"0123456789";
    let encryption: [u8; ENCRYPTION_SIZE] =
        aes::encrypt(&shared_secret_key, salt, plaintext, &mut rng)
            .expect("Encrypted correctly.");
    let dec_plaintext = aes::decrypt(&shared_secret_key, salt, &encryption)
        .expect("Decrypted correctly.");

    assert_eq!(&dec_plaintext, plaintext);
}
