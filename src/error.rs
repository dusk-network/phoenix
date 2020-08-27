// Copyright (c) DUSK NETWORK. All rights reserved.
// Licensed under the MPL 2.0 license. See LICENSE file in the project root for details.

use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid u8 as Note Type (expected `0` or `1`, found {0}")]
    InvalidNoteType(u8),
    #[error("Invalid Blinding Factor's value")]
    InvalidBlindingFactor,
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
        match err {
            _ => io::Error::new(io::ErrorKind::Other, format!("{}", err)),
        }
    }
}
