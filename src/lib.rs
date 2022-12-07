// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Phoenix's Core library types and behaviors

#![deny(missing_docs)]
#![warn(
    clippy::pedantic,
    clippy::restriction,
    clippy::style,
    future_incompatible,
    nonstandard_style,
    rust_2018_idioms,
    unused
)]
#![allow(
    clippy::arithmetic,
    clippy::blanket_clippy_restriction_lints,
    clippy::exhaustive_structs,             // To be allowed because of derive Archive
    clippy::implicit_return,                // Very common pattern in Rust
    clippy::integer_arithmetic,
    clippy::map_err_ignore,                 // "|_|" seems preferable over "|_err|"
    clippy::missing_docs_in_private_items,  // Unimportant, or are they?
    clippy::missing_errors_doc,             // Incomplete docs as yet
    clippy::missing_inline_in_public_items, // Though allowing #[inline] for nearly everything doesn't hurt, it may be too much boilerplate, confuse some people and be of reduced benefit in WASM context
    clippy::mod_module_files,
    clippy::pattern_type_mismatch,
    clippy::pub_use,                        // Public re-exports are useful if used correctly
    clippy::separated_literal_suffix,
    clippy::shadow_reuse,
)]
#![no_std]

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

pub use crossover::Crossover;
pub use error::Error;
pub use fee::Fee;
pub use fee::Remainder;
pub use message::Message;
pub use note::{Note, NoteType};

use dusk_bls12_381::BlsScalar;
use dusk_jubjub::{JubJubAffine, JubJubExtended, JubJubScalar};
