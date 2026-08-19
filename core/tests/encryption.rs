// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{GENERATOR, JubJubAffine, JubJubScalar};
use phoenix_core::{Error, aes};
use rand::SeedableRng;
use rand::rngs::StdRng;

fn assert_bad_length<T>(
    result: Result<T, Error>,
    found: usize,
    expected: usize,
) {
    match result {
        Err(Error::BadLength(actual_found, actual_expected)) => {
            assert_eq!(actual_found, found);
            assert_eq!(actual_expected, expected);
        }
        Err(error) => panic!("expected BadLength, got {error:?}"),
        Ok(_) => panic!("expected BadLength, got Ok"),
    }
}

fn shared_secret_key() -> JubJubAffine {
    JubJubAffine::from(GENERATOR * JubJubScalar::from(1234u64))
}

#[test]
fn test_aes_encrypt_and_decrypt() {
    let mut rng = StdRng::seed_from_u64(0xc0b);

    const PLAINTEXT_SIZE: usize = 20;
    const ENCRYPTION_SIZE: usize = PLAINTEXT_SIZE + aes::ENCRYPTION_EXTRA_SIZE;

    let shared_secret_key = shared_secret_key();

    let plaintext = b"00112233445566778899";
    let salt = b"0123456789";
    let encryption: [u8; ENCRYPTION_SIZE] =
        aes::encrypt(&shared_secret_key, salt, plaintext, &mut rng)
            .expect("Encrypted correctly.");
    let dec_plaintext = aes::decrypt(&shared_secret_key, salt, &encryption)
        .expect("Decrypted correctly.");

    assert_eq!(&dec_plaintext, plaintext);
}

#[test]
fn aes_encrypt_rejects_mismatched_output_lengths_without_panicking() {
    const PLAINTEXT_SIZE: usize = 20;
    const ENCRYPTION_SIZE: usize = PLAINTEXT_SIZE + aes::ENCRYPTION_EXTRA_SIZE;

    let shared_secret_key = shared_secret_key();
    let plaintext = [0x42; PLAINTEXT_SIZE];
    let salt = b"0123456789";
    let mut rng = StdRng::seed_from_u64(0xc0b);

    let short = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        aes::encrypt::<_, { ENCRYPTION_SIZE - 1 }>(
            &shared_secret_key,
            salt,
            &plaintext,
            &mut rng,
        )
    }))
    .expect("invalid encryption length must not unwind");
    assert_bad_length(short, ENCRYPTION_SIZE - 1, ENCRYPTION_SIZE);

    let long = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        aes::encrypt::<_, { ENCRYPTION_SIZE + 1 }>(
            &shared_secret_key,
            salt,
            &plaintext,
            &mut rng,
        )
    }))
    .expect("invalid encryption length must not unwind");
    assert_bad_length(long, ENCRYPTION_SIZE + 1, ENCRYPTION_SIZE);

    let below_nonce =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            aes::encrypt::<_, 0>(&shared_secret_key, salt, &plaintext, &mut rng)
        }))
        .expect("undersized encryption output must not unwind");
    assert_bad_length(below_nonce, 0, ENCRYPTION_SIZE);
}

#[test]
fn aes_decrypt_rejects_invalid_lengths_without_panicking() {
    const PLAINTEXT_SIZE: usize = 20;
    const ENCRYPTION_SIZE: usize = PLAINTEXT_SIZE + aes::ENCRYPTION_EXTRA_SIZE;

    let shared_secret_key = shared_secret_key();
    let salt = b"0123456789";

    for encryption in [&[][..], &[0u8; 11], &[0u8; ENCRYPTION_SIZE - 1]] {
        let result = std::panic::catch_unwind(|| {
            aes::decrypt::<PLAINTEXT_SIZE>(&shared_secret_key, salt, encryption)
        })
        .expect("short encryption must not unwind");
        assert_bad_length(result, encryption.len(), ENCRYPTION_SIZE);
    }

    let oversized = [0u8; ENCRYPTION_SIZE + 1];
    let result = std::panic::catch_unwind(|| {
        aes::decrypt::<PLAINTEXT_SIZE>(&shared_secret_key, salt, &oversized)
    })
    .expect("oversized encryption must not unwind");
    assert_bad_length(result, oversized.len(), ENCRYPTION_SIZE);

    let mut rng = StdRng::seed_from_u64(0xc0b);
    let plaintext = [0x42; PLAINTEXT_SIZE];
    let valid_encryption = aes::encrypt::<_, ENCRYPTION_SIZE>(
        &shared_secret_key,
        salt,
        &plaintext,
        &mut rng,
    )
    .expect("matching lengths should encrypt");

    let result = std::panic::catch_unwind(|| {
        aes::decrypt::<{ PLAINTEXT_SIZE - 1 }>(
            &shared_secret_key,
            salt,
            &valid_encryption,
        )
    })
    .expect("mismatched plaintext size must not unwind");
    assert_bad_length(result, ENCRYPTION_SIZE, ENCRYPTION_SIZE - 1);
}
