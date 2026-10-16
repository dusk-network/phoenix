// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use core::fmt;

use dusk_bytes::{DeserializableSlice, Error, Serializable};
use dusk_jubjub::{
    GENERATOR_EXTENDED, JubJubAffine, JubJubExtended, JubJubScalar,
};
#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::keys::generator::mul_generator;
use crate::keys::hash_shared_secret;
use crate::{SecretKey, StealthAddress};

/// Pair of a secret `a` and public `b·G`
///
/// The notes are encrypted against secret a, so this is used to decrypt the
/// blinding factor and value
///
/// ## Safety
///
/// The secret `a` is zeroized when the key is dropped. The key implements
/// neither `Copy` nor `Clone`, so a second copy has to be derived again.
/// Dropping does not reach the bytes a move of the key leaves behind.
///
/// ```compile_fail,E0277
/// use phoenix_core::ViewKey;
///
/// fn requires_clone<T: Clone>() {}
///
/// requires_clone::<ViewKey>();
/// ```
#[derive(Eq, Zeroize, ZeroizeOnDrop)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct ViewKey {
    a: JubJubScalar,
    #[zeroize(skip)]
    B: JubJubExtended,
}

impl fmt::Debug for ViewKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ViewKey(REDACTED)")
    }
}

impl ConstantTimeEq for ViewKey {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.a.ct_eq(&other.a) & self.B.ct_eq(&other.B)
    }
}

impl PartialEq for ViewKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl ViewKey {
    /// This method is used to construct a new `ViewKey` from the given
    /// pair of secret `a` and public `b·G`.
    pub fn new(a: JubJubScalar, B: JubJubExtended) -> Self {
        Self { a, B }
    }

    /// Gets `a`
    pub fn a(&self) -> &JubJubScalar {
        &self.a
    }

    /// Gets `B` (`b·G`)
    pub fn B(&self) -> &JubJubExtended {
        &self.B
    }

    /// Checks `note_pk = H(R · a) · G + B`
    ///
    /// `R · a` is derived through [`dhke`](dusk_jubjub::dhke), which ignores
    /// a small-order component of `R`. A stealth address whose `R` is the
    /// identity, of small order, or not on the curve is owned by no key.
    pub fn owns(&self, stealth_address: &StealthAddress) -> bool {
        hash_shared_secret(&self.a, stealth_address.R()).is_some_and(
            |hash_aR| {
                let hash_aR_G = mul_generator(&hash_aR);
                let note_pk = hash_aR_G + self.B;

                stealth_address.note_pk().as_ref() == &note_pk
            },
        )
    }
}

impl From<&SecretKey> for ViewKey {
    fn from(sk: &SecretKey) -> Self {
        let B = GENERATOR_EXTENDED * sk.b();

        ViewKey::new(*sk.a(), B)
    }
}

impl Serializable<64> for ViewKey {
    type Error = Error;

    fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.a.to_bytes());
        bytes[32..].copy_from_slice(&JubJubAffine::from(&self.B).to_bytes());
        bytes
    }

    fn from_bytes(buf: &[u8; 64]) -> Result<Self, Self::Error> {
        let a = JubJubScalar::from_slice(&buf[..32])?;
        let B = JubJubExtended::from(JubJubAffine::from_slice(&buf[32..])?);

        Ok(Self { a, B })
    }
}
