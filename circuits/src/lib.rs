// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Phoenix's circuits and gadgets.

#![allow(non_snake_case)]
#![deny(missing_docs)]
#![no_std]

mod encryption;

/// Transaction structs, gadget, and circuit
pub mod transaction;

/// Recipient circuit
pub mod recipient;

/// ElGamal asymmetric cipher
pub use encryption::elgamal;
