//! Error types for kingfisher-core.

use thiserror::Error;

/// The primary error type for kingfisher-core operations.
#[derive(Error, Debug)]
pub enum Error {
    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Failed to parse a blob ID from hex.
    #[error("Invalid blob ID: {0}")]
    InvalidBlobId(String),

    /// A hex decoding error occurred.
    #[error("Hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    /// Failed to open or read a Git repository.
    #[error("Git error: {0}")]
    Git(String),

    /// A generic error with a message.
    #[error("{0}")]
    Other(String),
}

impl From<gix::Error> for Error {
    fn from(e: gix::Error) -> Self {
        Error::Git(e.to_string())
    }
}

/// A specialized Result type for kingfisher-core operations.
pub type Result<T> = std::result::Result<T, Error>;
