// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Phoenix's Core library types and behaviors

#![allow(non_snake_case)]
#![deny(missing_docs)]
#![no_std]

mod addresses;
mod encryption;
mod error;
mod keys;
mod note;
mod recipient;

#[cfg(feature = "alloc")]
mod transaction;

pub use addresses::stealth::StealthAddress;
pub use addresses::sync::SyncAddress;
pub use encryption::{aes, elgamal};
pub use error::Error;
pub use keys::hash;
pub use keys::public::PublicKey;
pub use keys::secret::SecretKey;
pub use keys::view::ViewKey;
pub use note::{Note, NoteType, ENCRYPTION_SIZE as NOTE_ENCRYPTION_SIZE};
pub use recipient::RecipientParameters;

#[cfg(feature = "alloc")]
/// Transaction Skeleton used by the phoenix transaction model
pub use transaction::TxSkeleton;

use dusk_jubjub::{
    JubJubAffine, JubJubScalar, GENERATOR_EXTENDED, GENERATOR_NUMS_EXTENDED,
};

/// Use the pedersen commitment scheme to compute a transparent value
/// commitment.
pub fn transparent_value_commitment(value: u64) -> JubJubAffine {
    JubJubAffine::from(GENERATOR_EXTENDED * JubJubScalar::from(value))
}

/// Use the pedersen commitment scheme to compute a value commitment using a
/// blinding-factor.
pub fn value_commitment(
    value: u64,
    blinding_factor: JubJubScalar,
) -> JubJubAffine {
    JubJubAffine::from(
        (GENERATOR_EXTENDED * JubJubScalar::from(value))
            + (GENERATOR_NUMS_EXTENDED * blinding_factor),
    )
}
