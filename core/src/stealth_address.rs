// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_bytes::{DeserializableSlice, Error, Serializable};
use dusk_jubjub::{JubJubAffine, JubJubExtended};
use jubjub_schnorr::PublicKey as NotePublicKey;
#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq};

/// To obfuscate the identity of the participants, we utilizes a Stealth Address
/// system.
/// A `StealthAddress` is composed by a one-time note-public-key (the actual
/// address) and a random point `R`.
#[derive(Default, Debug, Clone, Copy, Eq)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Serialize, Deserialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct StealthAddress {
    pub(crate) R: JubJubExtended,
    pub(crate) note_pk: NotePublicKey,
}

impl StealthAddress {
    /// Create a stealth address from its internal parts
    ///
    /// A stealth address is intended to be generated as the public counterpart
    /// of a one time secret key. If the user opts to generate the
    /// stealth address from points, there is no guarantee a secret one time
    /// key counterpart will be known, and this stealth address will
    /// not provide the required arguments to generate it.
    ///
    /// For additional information, check [PublicKey::from_raw_unchecked].
    pub const fn from_raw_unchecked(
        R: JubJubExtended,
        note_pk: NotePublicKey,
    ) -> Self {
        Self { R, note_pk }
    }

    /// Gets the random point `R`
    pub const fn R(&self) -> &JubJubExtended {
        &self.R
    }

    /// Gets the `note_pk`
    pub const fn note_pk(&self) -> &NotePublicKey {
        &self.note_pk
    }

    /// Decode a `StealthAddress` from 64 bytes, requiring `R` and `note_pk` to
    /// lie in the prime-order subgroup.
    ///
    /// The transaction circuit constrains membership of neither point, so this
    /// decoder is what rejects them: an identity `R` collapses the
    /// value-encryption key `dhke(vk.a, R)` to a shared secret anyone can
    /// derive, and an identity `note_pk` publishes the ElGamal-encrypted sender
    /// public key. A stealth address that must reject these points has to be
    /// decoded through here — [`Serializable::from_bytes`] does not, and the
    /// archived/rkyv path validates layout only.
    ///
    /// Membership is enforced in two halves, because a point is prime-order
    /// exactly when it is torsion-free and not the identity. The point decode
    /// rejects torsion, so this only has to reject the identity, which is
    /// torsion-free and survives it. The torsion half rests on the
    /// `dusk-jubjub` requirement in `Cargo.toml`, pinned by
    /// `strict_decode_rejects_mixed_order_stealth_point`; lowering the
    /// requirement or dropping that test reopens it.
    pub fn from_bytes_checked(bytes: &[u8; Self::SIZE]) -> Result<Self, Error> {
        let stealth_address = Self::from_bytes(bytes)?;
        if stealth_address.has_identity_point() {
            return Err(Error::InvalidData);
        }
        Ok(stealth_address)
    }

    /// Returns `true` when `R` or `note_pk` is the identity.
    pub(crate) fn has_identity_point(&self) -> bool {
        bool::from(self.R.is_identity() | self.note_pk.as_ref().is_identity())
    }

    /// Decode a historical stealth address without enforcing subgroup checks
    /// on the underlying points.
    pub fn from_bytes_legacy_compat(
        bytes: &[u8; Self::SIZE],
    ) -> Result<Self, Error> {
        let r_affine = affine_from_slice_legacy_compat(&bytes[..32])?;
        let note_pk_affine = affine_from_slice_legacy_compat(&bytes[32..])?;

        Ok(Self {
            R: JubJubExtended::from(r_affine),
            note_pk: NotePublicKey::from_raw_unchecked(JubJubExtended::from(
                note_pk_affine,
            )),
        })
    }
}

impl ConstantTimeEq for StealthAddress {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.note_pk().as_ref().ct_eq(other.note_pk().as_ref())
            & self.R.ct_eq(&other.R)
    }
}

impl PartialEq for StealthAddress {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Serializable<64> for StealthAddress {
    type Error = Error;
    /// Encode the `StealthAddress` to an array of 64 bytes
    fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[..32].copy_from_slice(&JubJubAffine::from(self.R).to_bytes());
        bytes[32..].copy_from_slice(
            &JubJubAffine::from(self.note_pk().as_ref()).to_bytes(),
        );
        bytes
    }

    /// Decode the `StealthAddress` from an array of 64 bytes
    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Error> {
        let R = JubJubExtended::from(JubJubAffine::from_slice(&bytes[..32])?);
        let note_pk =
            JubJubExtended::from(JubJubAffine::from_slice(&bytes[32..])?);
        let note_pk = NotePublicKey::from_raw_unchecked(note_pk);

        Ok(StealthAddress { R, note_pk })
    }
}

pub(crate) fn affine_from_slice_legacy_compat(
    bytes: &[u8],
) -> Result<JubJubAffine, Error> {
    let mut point = [0u8; JubJubAffine::SIZE];
    point.copy_from_slice(bytes);
    Option::<JubJubAffine>::from(JubJubAffine::from_bytes(point))
        .ok_or(Error::InvalidData)
}

#[cfg(test)]
mod tests {
    use dusk_jubjub::{Fq, GENERATOR_EXTENDED};
    use ff::Field;

    use super::*;

    fn address(r: JubJubExtended, note_pk: JubJubExtended) -> StealthAddress {
        StealthAddress::from_raw_unchecked(
            r,
            NotePublicKey::from_raw_unchecked(note_pk),
        )
    }

    fn prime_order() -> JubJubExtended {
        GENERATOR_EXTENDED
    }

    fn identity() -> JubJubExtended {
        JubJubExtended::default()
    }

    fn torsion() -> JubJubExtended {
        // The order-2 point (0, -1): non-identity, not prime-order.
        JubJubExtended::from(JubJubAffine::from_raw_unchecked(
            Fq::ZERO,
            -Fq::ONE,
        ))
    }

    #[test]
    fn has_identity_point_covers_each_operand() {
        assert!(!address(prime_order(), prime_order()).has_identity_point());

        // An identity in either operand is caught, so neither is redundant.
        assert!(address(identity(), prime_order()).has_identity_point());
        assert!(address(prime_order(), identity()).has_identity_point());

        // Torsion is the point decode's half of the membership rule, not this
        // predicate's: `strict_decode_rejects_mixed_order_stealth_point` pins
        // it. If these ever fail, the two halves have drifted.
        assert!(!address(torsion(), prime_order()).has_identity_point());
        assert!(!address(prime_order(), torsion()).has_identity_point());
    }

    #[test]
    fn from_bytes_checked_accepts_valid_rejects_identity_operands() {
        // Positive path: a prime-order stealth address decodes.
        let good = address(prime_order(), prime_order());
        assert!(StealthAddress::from_bytes_checked(&good.to_bytes()).is_ok());

        // The identity is torsion-free, so it survives the point decode and
        // reaches the guard; each operand is checked in isolation.
        let bad_r = address(identity(), prime_order());
        assert_eq!(
            StealthAddress::from_bytes_checked(&bad_r.to_bytes()).unwrap_err(),
            Error::InvalidData
        );
        let bad_note_pk = address(prime_order(), identity());
        assert_eq!(
            StealthAddress::from_bytes_checked(&bad_note_pk.to_bytes())
                .unwrap_err(),
            Error::InvalidData
        );
    }
}
