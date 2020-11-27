// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_pki::Error as PkiError;
use poseidon252::Error as PoseidonError;

use core::fmt;

/// All possible errors for Phoenix's Core
#[allow(missing_docs)]
#[derive(Debug)]
pub enum Error {
    /// Invalid u8 as Note Type (expected `0` or `1`, found {0})
    InvalidNoteType(u8),
    /// Invalid Blinding Factor's value
    InvalidBlindingFactor,
    /// Invalid Cipher's value
    InvalidCipher,
    /// ViewKey required for decrypt data from Obfuscated Note
    MissingViewKey,
    /// Invalid Note Type for conversion
    InvalidNoteConversion,
    /// Dusk-Pki Error
    PKIError(PkiError),
    /// Poseidon Error
    PoseidonError,
}

impl From<PkiError> for Error {
    fn from(e: PkiError) -> Error {
        Error::PKIError(e)
    }
}

impl<E: fmt::Debug> From<PoseidonError<E>> for Error {
    fn from(_p: PoseidonError<E>) -> Error {
        // TODO - wrap the concrete error type
        Error::PoseidonError
    }
}
