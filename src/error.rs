use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid u8 as Note Type (expected `0` or `1`, found {0}")]
    InvalidNoteType(u8),
    #[error("Invalid I/O")]
    Io(#[from] io::Error),
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
