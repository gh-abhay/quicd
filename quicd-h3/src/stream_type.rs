//! Unidirectional stream type identification per RFC 9114 Section 6.2.
//!
//! Each unidirectional stream begins with a variable-length integer indicating
//! the stream type. This module handles parsing and encoding of stream type headers.

use crate::error::{Error, ErrorCode, Result};
use crate::varint;
use bytes::{Buf, BufMut};

/// Unidirectional stream types per RFC 9114 Section 6.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamType {
    /// Control stream (0x00) - RFC 9114 Section 6.2.1.
    /// Carries connection-level frames (SETTINGS, GOAWAY, etc.).
    Control,

    /// Push stream (0x01) - RFC 9114 Section 6.2.2.
    /// Carries server push responses.
    Push,

    /// QPACK encoder stream (0x02) - RFC 9204 Section 4.2.
    /// Carries QPACK encoder instructions to update dynamic table.
    QpackEncoder,

    /// QPACK decoder stream (0x03) - RFC 9204 Section 4.2.
    /// Carries QPACK decoder instructions for acknowledgments.
    QpackDecoder,

    /// Unknown/reserved stream type - RFC 9114 Section 6.2.3.
    /// These streams MUST be ignored (includes grease values: 0x1f * N + 0x21).
    Unknown(u64),
}

impl StreamType {
    pub fn from_u64(value: u64) -> Self {
        match value {
            0x00 => Self::Control,
            0x01 => Self::Push,
            0x02 => Self::QpackEncoder,
            0x03 => Self::QpackDecoder,
            other => Self::Unknown(other),
        }
    }

    pub fn to_u64(&self) -> u64 {
        match self {
            Self::Control => 0x00,
            Self::Push => 0x01,
            Self::QpackEncoder => 0x02,
            Self::QpackDecoder => 0x03,
            Self::Unknown(v) => *v,
        }
    }

    /// Check if this is a grease/reserved stream type (0x1f * N + 0x21).
    /// Per RFC 9114 Section 6.2.3, these MUST be ignored.
    pub fn is_grease(&self) -> bool {
        match self {
            Self::Unknown(v) => (*v >= 0x21) && ((*v - 0x21) % 0x1f == 0),
            _ => false,
        }
    }
}

/// Read stream type from the beginning of a unidirectional stream.
///
/// Returns the stream type and the number of bytes consumed.
/// Unknown/reserved stream types (including grease) are returned as StreamType::Unknown.
///
/// # Errors
///
/// Returns error if buffer is empty or varint decoding fails.
pub fn read_stream_type(buf: &mut impl Buf) -> Result<StreamType> {
    let type_id = varint::decode_buf(buf)?;
    Ok(StreamType::from_u64(type_id))
}

/// Write stream type to the beginning of a unidirectional stream.
pub fn write_stream_type(stream_type: StreamType, buf: &mut impl BufMut) -> Result<usize> {
    varint::encode_buf(stream_type.to_u64(), buf)
}

