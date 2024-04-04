// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Phoenix's Core library types and behaviors

#![allow(non_snake_case)]
#![deny(missing_docs)]
#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

/// Type's Conversion module
mod convert;
/// Crossover
pub mod crossover;
/// Phoenix's Core Errors
pub mod error;
/// Fee
pub mod fee;
/// Message representation
pub mod message;
/// Transparent and Obfuscated Notes
pub mod note;

/// Phoenix Core Keys & Addresses
mod keys;

/// Public (Spend) Key
pub use keys::public::PublicKey;
/// Secret (Spend) Key
pub use keys::secret::SecretKey;
/// Stealth Address
pub use keys::stealth::{Ownable, StealthAddress};
/// ViewKey
pub use keys::view::ViewKey;

/// Transaction types & utilities
#[cfg(feature = "alloc")]
pub mod transaction;

pub use crossover::Crossover;
pub use error::Error;
pub use fee::Fee;
pub use fee::Remainder;
pub use message::Message;
pub use note::{Note, NoteType};
#[cfg(feature = "alloc")]
pub use transaction::Transaction;
