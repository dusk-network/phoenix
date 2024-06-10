// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Phoenix's Core library types and behaviors

#![allow(non_snake_case)]
#![deny(missing_docs)]
#![no_std]

mod encryption;
mod error;
mod keys;
mod note;

#[cfg(feature = "alloc")]
mod transaction;

pub use encryption::aes;
pub use error::Error;
pub use keys::public::PublicKey;
pub use keys::secret::SecretKey;
pub use keys::stealth::StealthAddress;
pub use keys::sync::SyncAddress;
pub use keys::view::ViewKey;
pub use keys::{hash, Ownability, Ownable};
pub use note::{Note, NoteType};

#[cfg(feature = "alloc")]
/// Transaction Skeleton used by the phoenix transaction model
pub use transaction::TxSkeleton;
