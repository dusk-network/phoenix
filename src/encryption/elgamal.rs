// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! This module implements the ElGamal asymmetric cipher. It allows to
//! encrypt, decrypt, and prove encryption in Zero-Knowledge of JubJub points.
//!
//! Reference: https://link.springer.com/chapter/10.1007/3-540-39568-7_2

use dusk_jubjub::{JubJubExtended, JubJubScalar, GENERATOR};

#[cfg(feature = "zk")]
use dusk_plonk::prelude::*;

/// Encrypts a JubJubExtended plaintext given a public key and a fresh random
/// number 'r', returning a ciphertext (JubJubExtended, JubJubExtended)
pub fn encrypt(
    public_key: &JubJubExtended,
    plaintext: &JubJubExtended,
    r: &JubJubScalar,
) -> (JubJubExtended, JubJubExtended) {
    let ciphertext_1 = GENERATOR * r;
    let ciphertext_2 = plaintext + public_key * r;

    (ciphertext_1, ciphertext_2)
}

/// Decrypts a ciphertext given a secret key,
/// returning a JubJubExtended plaintext
pub fn decrypt(
    secret_key: &JubJubScalar,
    ciphertext_1: &JubJubExtended,
    ciphertext_2: &JubJubExtended,
) -> JubJubExtended {
    // return the plaintext
    ciphertext_2 - ciphertext_1 * secret_key
}

/// Encrypt in-circuit a plaintext WitnessPoint, returning
/// a ciphertext (WitnessPoint, WitnessPoint)
#[cfg(feature = "zk")]
pub fn encrypt_gadget(
    composer: &mut Composer,
    public_key: WitnessPoint,
    plaintext: WitnessPoint,
    r: Witness,
) -> Result<(WitnessPoint, WitnessPoint), Error> {
    let R = composer.component_mul_point(r, public_key);
    let ciphertext_1 = composer.component_mul_generator(r, GENERATOR)?;
    let ciphertext_2 = composer.component_add_point(plaintext, R);

    Ok((ciphertext_1, ciphertext_2))
}

/// Decrypt in-circuit a ciphertext (WitnessPoint, WitnessPoint),
/// returning a plaintext WitnessPoint
#[cfg(feature = "zk")]
pub fn decrypt_gadget(
    composer: &mut Composer,
    secret_key: Witness,
    ciphertext_1: WitnessPoint,
    ciphertext_2: WitnessPoint,
) -> WitnessPoint {
    let c1_sk = composer.component_mul_point(secret_key, ciphertext_1);
    let neg_one = composer.append_constant(-JubJubScalar::one());
    let neg_c1_sk = composer.component_mul_point(neg_one, c1_sk);

    // return plaintext
    composer.component_add_point(ciphertext_2, neg_c1_sk)
}
