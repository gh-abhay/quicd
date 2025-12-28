//! Error types for hq-interop protocol.

use std::io;
use thiserror::Error;

/// Result type for hq-interop operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Error type for hq-interop protocol.
#[derive(Debug, Error)]
pub enum Error {
    /// I/O error from underlying QUIC stream operations.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Invalid request format.
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    /// File not found or access denied.
    #[error("File error: {0}")]
    FileError(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),
}
