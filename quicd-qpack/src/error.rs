//! Error types for QPACK operations.
//!
//! This module defines all error conditions that can occur during QPACK
//! encoding and decoding operations. Error types map to the HTTP/3 error
//! codes specified in RFC 9204 Section 6.

use thiserror::Error;

/// Result type for QPACK operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during QPACK operations.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Decoding of a field section failed.
    ///
    /// Maps to HTTP/3 error code `QPACK_DECOMPRESSION_FAILED` (0x0200).
    /// This occurs when:
    /// - Invalid static table index
    /// - Invalid dynamic table reference
    /// - Required Insert Count is invalid
    /// - Malformed field line representation
    #[error("decompression failed: {0}")]
    DecompressionFailed(String),

    /// Error on the encoder stream.
    ///
    /// Maps to HTTP/3 error code `QPACK_ENCODER_STREAM_ERROR` (0x0201).
    /// This occurs when the decoder encounters invalid encoder instructions.
    #[error("encoder stream error: {0}")]
    EncoderStreamError(String),

    /// Error on the decoder stream.
    ///
    /// Maps to HTTP/3 error code `QPACK_DECODER_STREAM_ERROR` (0x0202).
    /// This occurs when the encoder encounters invalid decoder instructions.
    #[error("decoder stream error: {0}")]
    DecoderStreamError(String),

    /// Stream is blocked waiting for dynamic table updates.
    ///
    /// This is not a fatal error. The decoder should queue the stream
    /// and retry after processing encoder stream instructions.
    #[error("stream {0} is blocked waiting for dynamic table entry")]
    Blocked(u64),

    /// Integer encoding/decoding error.
    #[error("integer encoding error: {0}")]
    IntegerError(String),

    /// Huffman encoding/decoding error.
    #[error("huffman encoding error: {0}")]
    HuffmanError(String),

    /// Dynamic table error.
    #[error("dynamic table error: {0}")]
    DynamicTableError(String),

    /// Maximum blocked streams exceeded.
    #[error("maximum blocked streams exceeded: {0} > {1}")]
    TooManyBlockedStreams(usize, usize),

    /// Buffer too small for operation.
    #[error("buffer too small: need {0} bytes")]
    BufferTooSmall(usize),

    /// Incomplete data - need more bytes.
    #[error("incomplete data: need {0} more bytes")]
    Incomplete(usize),
}

impl Error {
    /// Returns the HTTP/3 error code for this error.
    pub fn error_code(&self) -> u64 {
        match self {
            Error::DecompressionFailed(_) => 0x0200,
            Error::EncoderStreamError(_) => 0x0201,
            Error::DecoderStreamError(_) => 0x0202,
            _ => 0x0200, // Default to decompression failed
        }
    }

    /// Returns true if this error indicates the stream is blocked.
    pub fn is_blocked(&self) -> bool {
        matches!(self, Error::Blocked(_))
    }

    /// Returns true if this is a recoverable error.
    pub fn is_recoverable(&self) -> bool {
        matches!(self, Error::Blocked(_) | Error::Incomplete(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_codes() {
        assert_eq!(
            Error::DecompressionFailed("test".into()).error_code(),
            0x0200
        );
        assert_eq!(
            Error::EncoderStreamError("test".into()).error_code(),
            0x0201
        );
        assert_eq!(
            Error::DecoderStreamError("test".into()).error_code(),
            0x0202
        );
    }

    #[test]
    fn test_blocked_error() {
        let err = Error::Blocked(42);
        assert!(err.is_blocked());
        assert!(err.is_recoverable());
    }

    #[test]
    fn test_incomplete_error() {
        let err = Error::Incomplete(10);
        assert!(!err.is_blocked());
        assert!(err.is_recoverable());
    }
}
