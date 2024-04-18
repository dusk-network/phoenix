// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{JubJubAffine, JubJubScalar, GENERATOR};
use rand_core::OsRng;

use phoenix_core::{decrypt, encrypt, ENCRYPTION_EXTRA_SIZE};

#[test]
fn test_encrypt_and_decrypt() {
    const PLAINTEXT_SIZE: usize = 20;
    const ENCRYPTION_SIZE: usize = PLAINTEXT_SIZE + ENCRYPTION_EXTRA_SIZE;

    let shared_secret_key =
        JubJubAffine::from(GENERATOR * JubJubScalar::from(1234u64));

    let plaintext = b"00112233445566778899";
    let encryption: [u8; ENCRYPTION_SIZE] =
        encrypt(&shared_secret_key, plaintext, &mut OsRng)
            .expect("Encrypted correctly.");
    let dec_plaintext =
        decrypt(&shared_secret_key, &encryption).expect("Decrypted correctly.");

    assert_eq!(&dec_plaintext, plaintext);
}
