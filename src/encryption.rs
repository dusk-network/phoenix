// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_jubjub::JubJubAffine;
use rand_core::{CryptoRng, RngCore};

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key,
};

use crate::Error;

const NONCE_SIZE: usize = 12;

/// Size of the extra encryption data required by the
/// cipher: the nonce (12 bytes) and the tag (16 bytes)
pub const ENCRYPTION_EXTRA_SIZE: usize = NONCE_SIZE + 16;

/// Encrypts a plaintext given a shared DH secret key, returning a vector
/// containing a nonce and the ciphertext (which includes the tag)
pub fn encrypt<R: RngCore + CryptoRng, const ENCRYPTION_SIZE: usize>(
    shared_secret_key: &JubJubAffine,
    plaintext: &[u8],
    rng: &mut R,
) -> Result<[u8; ENCRYPTION_SIZE], Error> {
    // To encrypt using AES256 we need 32-bytes keys. Thus, we use
    // the 32-bytes serialization of the 64-bytes DH key.
    let key = shared_secret_key.to_bytes();
    let key = Key::<Aes256Gcm>::from_slice(&key);

    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(rng);
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref())?;

    let mut encryption = [0u8; ENCRYPTION_SIZE];

    encryption[..NONCE_SIZE].copy_from_slice(&nonce);
    encryption[NONCE_SIZE..].copy_from_slice(&ciphertext);

    Ok(encryption)
}

/// Decrypts an encryption (nonce + ciphertext) given a shared DH secret key,
/// returning the plaintext
pub fn decrypt<const PLAINTEXT_SIZE: usize>(
    shared_secret_key: &JubJubAffine,
    encryption: &[u8],
) -> Result<[u8; PLAINTEXT_SIZE], Error> {
    // To decrypt using AES256 we need 32-bytes keys. Thus, we use
    // the 32-bytes serialization of the 64-bytes DH key.
    let key = shared_secret_key.to_bytes();
    let key = Key::<Aes256Gcm>::from_slice(&key);

    let nonce = &encryption[..NONCE_SIZE];
    let ciphertext = &encryption[NONCE_SIZE..];

    let cipher = Aes256Gcm::new(key);

    let mut plaintext = [0u8; PLAINTEXT_SIZE];
    plaintext.copy_from_slice(&cipher.decrypt(nonce.into(), ciphertext)?);

    Ok(plaintext)
}
