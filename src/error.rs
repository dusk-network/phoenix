// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid u8 as Note Type (expected `0` or `1`, found {0}")]
    InvalidNoteType(u8),
    #[error("Invalid Blinding Factor's value")]
    InvalidBlindingFactor,
    #[error("Invalid Cipher's value")]
    InvalidCipher,
    #[error("ViewKey required for decrypt data from Obfuscated Note")]
    MissingViewKey,
    #[error("Invalid I/O")]
    Io(#[from] io::Error),
    #[error(transparent)]
    CipherError(#[from] poseidon252::cipher::CipherError),
    #[error(transparent)]
    PKIError(#[from] dusk_pki::Error),
}

impl From<Error> for io::Error {
    fn from(err: Error) -> io::Error {
        io::Error::new(io::ErrorKind::Other, format!("{}", err))
    }
}
