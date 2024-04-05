// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use crate::{keys::hash, SecretKey, StealthAddress, ViewKey};

use dusk_jubjub::{JubJubAffine, JubJubExtended, JubJubScalar};

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

use dusk_bytes::{DeserializableSlice, Error, Serializable};
use dusk_jubjub::GENERATOR_EXTENDED;
use subtle::{Choice, ConstantTimeEq};

/// Public pair of `a·G` and `b·G` defining a [`PublicKey`]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct PublicKey {
    A: JubJubExtended,
    B: JubJubExtended,
}

impl PublicKey {
    /// This method is used to construct a new `PublicKey` from the given
    /// public pair of `a·G` and `b·G`
    pub fn new(A: JubJubExtended, B: JubJubExtended) -> Self {
        Self { A, B }
    }

    /// Gets `A` (`a·G`)
    pub fn A(&self) -> &JubJubExtended {
        &self.A
    }

    /// Gets `B` (`b·G`)
    pub fn B(&self) -> &JubJubExtended {
        &self.B
    }

    /// Generates new `PKr = H(A · r) · G + B` from a given `r`
    pub fn gen_stealth_address(&self, r: &JubJubScalar) -> StealthAddress {
        let G = GENERATOR_EXTENDED;
        let R = G * r;

        let rA = self.A * r;
        let rA = hash(&rA);
        let rA = G * rA;

        let pk_r = rA + self.B;
        let pk_r = pk_r.into();

        StealthAddress { R, pk_r }
    }
}

impl ConstantTimeEq for PublicKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.A.ct_eq(&other.A) & self.B.ct_eq(&other.B)
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for PublicKey {}

impl From<SecretKey> for PublicKey {
    fn from(sk: SecretKey) -> Self {
        Self::from(&sk)
    }
}

impl From<&SecretKey> for PublicKey {
    fn from(sk: &SecretKey) -> Self {
        let A = GENERATOR_EXTENDED * sk.a();
        let B = GENERATOR_EXTENDED * sk.b();

        PublicKey::new(A, B)
    }
}

impl From<ViewKey> for PublicKey {
    fn from(vk: ViewKey) -> Self {
        Self::from(&vk)
    }
}

impl From<&ViewKey> for PublicKey {
    fn from(vk: &ViewKey) -> Self {
        let A = GENERATOR_EXTENDED * vk.a();

        PublicKey::new(A, *vk.B())
    }
}

impl Serializable<64> for PublicKey {
    type Error = Error;

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[..32].copy_from_slice(&JubJubAffine::from(self.A).to_bytes());
        bytes[32..].copy_from_slice(&JubJubAffine::from(self.B).to_bytes());
        bytes
    }

    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let A = JubJubExtended::from(JubJubAffine::from_slice(&bytes[..32])?);
        let B = JubJubExtended::from(JubJubAffine::from_slice(&bytes[32..])?);

        Ok(Self { A, B })
    }
}
