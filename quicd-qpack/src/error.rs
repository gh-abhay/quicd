//! QPACK error types per RFC 9204.

use std::fmt;

pub type Result<T> = std::result::Result<T, QpackError>;

/// QPACK-specific errors that map to HTTP/3 error codes.
#[cfg_attr(not(feature = "async"), derive(Clone, PartialEq, Eq))]
#[derive(Debug)]
pub enum QpackError {
    /// QPACK_DECOMPRESSION_FAILED (0x0200)
    /// Generic decompression failure.
    DecompressionFailed(String),

    /// QPACK_ENCODER_STREAM_ERROR (0x0201)
    /// Error processing encoder stream instruction.
    EncoderStreamError(String),

    /// QPACK_DECODER_STREAM_ERROR (0x0202)
    /// Error processing decoder stream instruction.
    DecoderStreamError(String),

    /// Malformed integer encoding.
    IntegerOverflow,

    /// Malformed string encoding.
    StringDecodingError(String),

    /// Invalid static table index.
    InvalidStaticIndex(u64),

    /// Invalid dynamic table index.
    InvalidDynamicIndex(u64),

    /// Dynamic table capacity exceeded.
    TableCapacityExceeded,

    /// Required Insert Count exceeds actual insert count.
    InvalidRequiredInsertCount,

    /// Stream references entries not yet acknowledged.
    BlockedStreamLimitExceeded,

    /// Buffer underflow during parsing.
    UnexpectedEof,

    /// Huffman decoding error.
    HuffmanDecodingError(String),

    /// Internal error.
    Internal(String),

    /// I/O error (for async operations).
    #[cfg(feature = "async")]
    Io(std::io::Error),
}

impl fmt::Display for QpackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QpackError::DecompressionFailed(msg) => write!(f, "Decompression failed: {}", msg),
            QpackError::EncoderStreamError(msg) => write!(f, "Encoder stream error: {}", msg),
            QpackError::DecoderStreamError(msg) => write!(f, "Decoder stream error: {}", msg),
            QpackError::IntegerOverflow => write!(f, "Integer overflow in prefix encoding"),
            QpackError::StringDecodingError(msg) => write!(f, "String decoding error: {}", msg),
            QpackError::InvalidStaticIndex(idx) => write!(f, "Invalid static table index: {}", idx),
            QpackError::InvalidDynamicIndex(idx) => {
                write!(f, "Invalid dynamic table index: {}", idx)
            }
            QpackError::TableCapacityExceeded => write!(f, "Dynamic table capacity exceeded"),
            QpackError::InvalidRequiredInsertCount => write!(f, "Invalid Required Insert Count"),
            QpackError::BlockedStreamLimitExceeded => write!(f, "Blocked stream limit exceeded"),
            QpackError::UnexpectedEof => write!(f, "Unexpected end of buffer"),
            QpackError::HuffmanDecodingError(msg) => write!(f, "Huffman decoding error: {}", msg),
            QpackError::Internal(msg) => write!(f, "Internal error: {}", msg),
            #[cfg(feature = "async")]
            QpackError::Io(err) => write!(f, "I/O error: {}", err),
        }
    }
}

#[cfg(feature = "async")]
impl From<std::io::Error> for QpackError {
    fn from(err: std::io::Error) -> Self {
        QpackError::Io(err)
    }
}

impl std::error::Error for QpackError {}
