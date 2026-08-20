// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use aes_gcm::aead::{Aead, AeadCore, KeyInit};
use aes_gcm::{Aes256Gcm, Key};
use dusk_jubjub::JubJubAffine;
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;

use crate::Error;

const NONCE_SIZE: usize = 12;

/// Size of the extra encryption data required by the
/// cipher: the nonce (12 bytes) and the tag (16 bytes)
pub const ENCRYPTION_EXTRA_SIZE: usize = NONCE_SIZE + 16;

/// Encrypts a plaintext given a shared DH secret key, returning a vector
/// containing a nonce and the ciphertext (which includes the tag).
///
/// Returns [`Error::BadLength`] when `ENCRYPTION_SIZE` is not exactly the
/// plaintext length plus [`ENCRYPTION_EXTRA_SIZE`].
pub fn encrypt<R: RngCore + CryptoRng, const ENCRYPTION_SIZE: usize>(
    shared_secret_key: &JubJubAffine,
    salt: &[u8],
    plaintext: &[u8],
    rng: &mut R,
) -> Result<[u8; ENCRYPTION_SIZE], Error> {
    let expected_encryption_size = plaintext
        .len()
        .checked_add(ENCRYPTION_EXTRA_SIZE)
        .ok_or(Error::InvalidEncryption)?;

    if ENCRYPTION_SIZE != expected_encryption_size {
        return Err(Error::BadLength(
            ENCRYPTION_SIZE,
            expected_encryption_size,
        ));
    }

    // To encrypt using AES256 we need 32-bytes keys. Thus, we use
    // a 32-bytes key computed out of the 32-bytes serialization of the 64-bytes
    // DH key, using the HKDF algorithm.
    let ikm = shared_secret_key.to_bytes();
    let info = b"Phoenix-Dusk".to_vec();

    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .expect("32 is a valid length for Sha256 to output");

    let key = Key::<Aes256Gcm>::from_slice(&okm);

    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(rng);
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref())?;

    let mut encryption = [0u8; ENCRYPTION_SIZE];
    let (nonce_output, ciphertext_output) = encryption.split_at_mut(NONCE_SIZE);

    if ciphertext.len() != ciphertext_output.len() {
        return Err(Error::BadLength(
            ciphertext.len(),
            ciphertext_output.len(),
        ));
    }

    nonce_output.copy_from_slice(&nonce);
    ciphertext_output.copy_from_slice(&ciphertext);

    Ok(encryption)
}

/// Decrypts an encryption (nonce + ciphertext) given a shared DH secret key,
/// returning the plaintext.
///
/// Returns [`Error::BadLength`] when the input is not exactly
/// `PLAINTEXT_SIZE + ENCRYPTION_EXTRA_SIZE` bytes.
pub fn decrypt<const PLAINTEXT_SIZE: usize>(
    shared_secret_key: &JubJubAffine,
    salt: &[u8],
    encryption: &[u8],
) -> Result<[u8; PLAINTEXT_SIZE], Error> {
    let expected_encryption_size = PLAINTEXT_SIZE
        .checked_add(ENCRYPTION_EXTRA_SIZE)
        .ok_or(Error::InvalidEncryption)?;

    if encryption.len() != expected_encryption_size {
        return Err(Error::BadLength(
            encryption.len(),
            expected_encryption_size,
        ));
    }

    // To decrypt using AES256 we need 32-bytes keys. Thus, we use
    // a 32-bytes key computed out of the 32-bytes serialization of the 64-bytes
    // DH key, using the HKDF algorithm.
    let ikm = shared_secret_key.to_bytes();
    let info = b"Phoenix-Dusk".to_vec();

    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .expect("32 is a valid length for Sha256 to output");

    let key = Key::<Aes256Gcm>::from_slice(&okm);

    let (nonce, ciphertext) = encryption.split_at(NONCE_SIZE);

    let cipher = Aes256Gcm::new(key);

    let plaintext = cipher.decrypt(nonce.into(), ciphertext)?;
    let plaintext_len = plaintext.len();

    plaintext
        .try_into()
        .map_err(|_| Error::BadLength(plaintext_len, PLAINTEXT_SIZE))
}
