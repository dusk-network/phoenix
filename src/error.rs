// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use aes_gcm::Error as AesError;
use core::fmt;
use dusk_bytes::{BadLength, Error as DuskBytesError, InvalidChar};

/// All possible errors for Phoenix's Core
#[allow(missing_docs)]
#[derive(Debug, Clone)]
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
    /// Failure to encrypt / decrypt
    BadEncryption,
    /// Invalid Value Commitment
    InvalidCommitment,
    /// Invalid Nonce
    InvalidNonce,
    /// Dusk-bytes InvalidData error
    InvalidData,
    /// Dusk-bytes BadLength error
    BadLength(usize, usize),
    /// Dusk-bytes InvalidChar error
    InvalidChar(char, usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Phoenix-Core Error: {:?}", &self)
    }
}

impl From<AesError> for Error {
    fn from(aes_error: AesError) -> Self {
        match aes_error {
            AesError => Self::BadEncryption,
        }
    }
}

impl From<Error> for DuskBytesError {
    fn from(err: Error) -> Self {
        match err {
            Error::InvalidData => DuskBytesError::InvalidData,
            Error::BadLength(found, expected) => {
                DuskBytesError::BadLength { found, expected }
            }
            Error::InvalidChar(ch, index) => {
                DuskBytesError::InvalidChar { ch, index }
            }
            _ => unreachable!(),
        }
    }
}

impl BadLength for Error {
    fn bad_length(found: usize, expected: usize) -> Self {
        Error::BadLength(found, expected)
    }
}

impl InvalidChar for Error {
    fn invalid_char(ch: char, index: usize) -> Self {
        Error::InvalidChar(ch, index)
    }
}
