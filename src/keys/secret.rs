// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::{permutation, StealthAddress};
use dusk_jubjub::JubJubScalar;
use ff::Field;
use jubjub_schnorr::SecretKey as NoteSecretKey;

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

use dusk_bytes::{DeserializableSlice, Error, Serializable};
use rand_core::{CryptoRng, RngCore};
use subtle::{Choice, ConstantTimeEq};

/// Secret pair of `a` and `b` defining a [`SecretKey`]
#[derive(Clone, Copy, Eq, Debug)]
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

    /// Generates a [`NoteSecretKey`] using the [`StealthAddress`] given.
    /// With the formula: `sk_r = H(a · R) + b`
    pub fn sk_r(&self, sa: &StealthAddress) -> NoteSecretKey {
        let aR = sa.R() * self.a;
        let aR = permutation::hash(&aR);

        (aR + self.b).into()
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
