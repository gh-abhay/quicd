//! Unidirectional stream type identification per RFC 9114 Section 6.2.
//!
//! Each unidirectional stream begins with a variable-length integer indicating
//! the stream type. This module handles parsing and encoding of stream type headers.

use crate::error::{Error, ErrorCode, Result};
use crate::varint;
use bytes::{Buf, BufMut};

/// Unidirectional stream types per RFC 9114 Section 6.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum StreamType {
    /// Control stream (0x00) - RFC 9114 Section 6.2.1.
    /// Carries connection-level frames (SETTINGS, GOAWAY, etc.).
    Control = 0x00,

    /// Push stream (0x01) - RFC 9114 Section 6.2.2.
    /// Carries server push responses.
    Push = 0x01,

    /// QPACK encoder stream (0x02) - RFC 9204 Section 4.2.
    /// Carries QPACK encoder instructions to update dynamic table.
    QpackEncoder = 0x02,

    /// QPACK decoder stream (0x03) - RFC 9204 Section 4.2.
    /// Carries QPACK decoder instructions for acknowledgments.
    QpackDecoder = 0x03,
}

impl StreamType {
    pub fn from_u64(value: u64) -> Option<Self> {
        match value {
            0x00 => Some(Self::Control),
            0x01 => Some(Self::Push),
            0x02 => Some(Self::QpackEncoder),
            0x03 => Some(Self::QpackDecoder),
            _ => None,
        }
    }

    pub fn to_u64(self) -> u64 {
        self as u64
    }
}

/// Read stream type from the beginning of a unidirectional stream.
///
/// Returns the stream type and the number of bytes consumed.
///
/// # Errors
///
/// Returns error if buffer is empty or stream type is invalid/reserved.
pub fn read_stream_type(buf: &mut impl Buf) -> Result<StreamType> {
    let type_id = varint::decode_buf(buf)?;

    StreamType::from_u64(type_id).ok_or_else(|| {
        // Per RFC 9114 Section 6.2: Implementations SHOULD consider it a connection
        // error to receive an unknown stream type, as it might be critical.
        Error::protocol(
            ErrorCode::StreamCreationError,
            format!("unknown stream type: 0x{:x}", type_id),
        )
    })
}

/// Write stream type to the beginning of a unidirectional stream.
pub fn write_stream_type(stream_type: StreamType, buf: &mut impl BufMut) -> Result<usize> {
    varint::encode_buf(stream_type.to_u64(), buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_stream_type_roundtrip() {
        let types = vec![
            StreamType::Control,
            StreamType::Push,
            StreamType::QpackEncoder,
            StreamType::QpackDecoder,
        ];

        for stream_type in types {
            let mut buf = BytesMut::new();
            write_stream_type(stream_type, &mut buf).unwrap();

            let mut read_buf = buf.clone();
            let parsed = read_stream_type(&mut read_buf).unwrap();

            assert_eq!(stream_type, parsed);
            assert_eq!(read_buf.remaining(), 0);
        }
    }

    #[test]
    fn test_unknown_stream_type() {
        let mut buf = BytesMut::new();
        varint::encode_buf(0xFF, &mut buf).unwrap();

        let result = read_stream_type(&mut buf);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err().to_error_code(),
            ErrorCode::StreamCreationError
        ));
    }
}
