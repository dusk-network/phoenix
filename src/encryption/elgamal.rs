// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::{JubJubExtended, JubJubScalar, GENERATOR};
use dusk_plonk::prelude::*;

/// Encrypts a JubJubExtended plaintext given a public key and a fresh random
/// number, returning a ciphertext (JubJubExtended, JubJubExtended)
pub fn encrypt(
    public_key: &JubJubExtended,
    plaintext: &JubJubExtended,
    r: &JubJubScalar,
) -> (JubJubExtended, JubJubExtended) {
    let S = public_key * r;

    let ciphertext_1 = GENERATOR * r;
    let ciphertext_2 = plaintext + S;

    (ciphertext_1, ciphertext_2)
}

/// Decrypts a ciphertext given a secret key,
/// returning a JubJubExtended plaintext
pub fn decrypt(
    secret_key: &JubJubScalar,
    ciphertext_1: &JubJubExtended,
    ciphertext_2: &JubJubExtended,
) -> JubJubExtended {
    ciphertext_2 - ciphertext_1 * secret_key
}

/// Encrypt in-circuit a plaintext
pub fn zk_encrypt(
    composer: &mut Composer,
    public_key: &JubJubAffine,
    plaintext: &JubJubAffine,
    r: &JubJubScalar,
    ciphertext_1: &JubJubAffine,
    ciphertext_2: &JubJubAffine,
) -> Result<(), Error> {
    // IMPORT INPUTS
    let public_key = composer.append_point(*public_key);
    let plaintext = composer.append_point(*plaintext);
    let r = composer.append_witness(*r);

    // ENCRYPT
    let S = composer.component_mul_point(r, public_key);
    let ciphertext_1_p = composer.component_mul_generator(r, GENERATOR)?;
    let ciphertext_2_p = composer.component_add_point(plaintext, S);

    // ASSERT RESULT MAKING THE CIPHERTEXT PUBLIC
    composer.assert_equal_public_point(ciphertext_1_p, *ciphertext_1);
    composer.assert_equal_public_point(ciphertext_2_p, *ciphertext_2);

    Ok(())
}
