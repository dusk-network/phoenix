// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use dusk_poseidon::Error as PoseidonError;

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
    /// Invalid Crossover for conversion
    InvalidCrossoverConversion,
    /// Invalid Fee for conversion
    InvalidFeeConversion,
    /// Poseidon Error
    PoseidonError,
    /// Invalid Value Commitment
    InvalidCommitment,
    /// Invalid Nonce
    InvalidNonce,
    /// Remainder is out of gas
    OutOfGas,
}

impl<E: fmt::Debug> From<PoseidonError<E>> for Error {
    fn from(_p: PoseidonError<E>) -> Error {
        // TODO - wrap the concrete error type
        Error::PoseidonError
    }
}
