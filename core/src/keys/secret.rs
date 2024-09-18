// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::{keys::hash, StealthAddress};

use dusk_jubjub::{JubJubScalar, GENERATOR_EXTENDED};
use ff::Field;
use jubjub_schnorr::SecretKey as NoteSecretKey;
use zeroize::Zeroize;

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

use dusk_bytes::{DeserializableSlice, Error, Serializable};
use rand::{CryptoRng, RngCore};
use subtle::{Choice, ConstantTimeEq};

/// Secret pair of `a` and `b` defining a [`SecretKey`]
///
/// ## Safety
///
/// To ensure that no secret information lingers in memory after the variable
/// goes out of scope, we advice calling `zeroize` before the variable goes out
/// of scope.
///
/// ## Examples
///
/// Generate a random `SecretKey`:
/// ```
/// use phoenix_core::SecretKey;
/// use rand::rngs::StdRng;
/// use rand::SeedableRng;
/// use zeroize::Zeroize;
///
/// let mut rng = StdRng::seed_from_u64(12345);
/// let mut sk = SecretKey::random(&mut rng);
///
/// // do something with the sk
///
/// sk.zeroize();
/// ```
///
/// # Note
/// Implementing `ZeroizeOnDrop` seems like an excellent way to lift the burden
/// of manually zeroizing after use off the user, but unfortunately it doesn't
/// delete the memory reliably. See #244
#[derive(Clone, Eq, Debug, Zeroize)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct SecretKey {
    a: JubJubScalar,
    b: JubJubScalar,
}

impl SecretKey {
    /// This method is used to construct a new `SecretKey` from the given
    /// secret pair of `a` and `b`.
    pub fn new(a: JubJubScalar, b: JubJubScalar) -> Self {
        Self { a, b }
    }

    /// Gets `a`
    pub fn a(&self) -> &JubJubScalar {
        &self.a
    }

    /// Gets `b`
    pub fn b(&self) -> &JubJubScalar {
        &self.b
    }

    /// Deterministically create a new [`SecretKey`] from a random number
    /// generator
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let a = JubJubScalar::random(&mut *rng);
        let b = JubJubScalar::random(&mut *rng);

        SecretKey::new(a, b)
    }

    /// Generates a [`NoteSecretKey`] using the `R` of the given
    /// [`StealthAddress`]. With the formula: `note_sk = H(a · R) + b`
    pub fn gen_note_sk(&self, stealth: &StealthAddress) -> NoteSecretKey {
        let aR = stealth.R() * self.a;

        NoteSecretKey::from(hash(&aR) + self.b)
    }

    /// Checks if `note_pk ?= (H(R · a) + b) · G`
    pub fn owns(&self, stealth_address: &StealthAddress) -> bool {
        let note_sk = self.gen_note_sk(stealth_address);

        let note_pk = GENERATOR_EXTENDED * note_sk.as_ref();

        stealth_address.note_pk().as_ref() == &note_pk
    }
}

impl ConstantTimeEq for SecretKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.a.ct_eq(&other.a) & self.b.ct_eq(&other.b)
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Serializable<64> for SecretKey {
    type Error = Error;

    fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.a.to_bytes());
        bytes[32..].copy_from_slice(&self.b.to_bytes());
        bytes
    }

    fn from_bytes(buf: &[u8; 64]) -> Result<Self, Self::Error> {
        let a = JubJubScalar::from_slice(&buf[..32])?;
        let b = JubJubScalar::from_slice(&buf[32..])?;

        Ok(Self { a, b })
    }
}
