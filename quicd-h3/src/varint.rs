//! Variable-length integer encoding per RFC 9000 Section 16.
//!
//! HTTP/3 inherits QUIC's variable-length integer encoding for frame types,
//! frame lengths, stream type identifiers, push IDs, and settings parameters.
//!
//! We re-export the implementation from quicd-quic for consistency.

pub use quicd_quic::varint::{decode, encode, MAX};

use crate::error::{Error, ErrorCode, Result};
use bytes::{Buf, BufMut};

/// Decode a variable-length integer from a buffer that implements Buf.
///
/// Returns the decoded value and advances the buffer by the number of bytes consumed.
///
/// # Errors
///
/// Returns `FrameError` if buffer doesn't contain a complete varint.
pub fn decode_buf<B: Buf>(buf: &mut B) -> Result<u64> {
    if !buf.has_remaining() {
        return Err(Error::protocol(
            ErrorCode::FrameError,
            "incomplete varint: empty buffer",
        ));
    }

    // Peek at first byte to determine length
    let first = buf.chunk()[0];
    let len = match first >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    };

    if buf.remaining() < len {
        return Err(Error::protocol(
            ErrorCode::FrameError,
            format!("incomplete varint: need {} bytes, have {}", len, buf.remaining()),
        ));
    }

    let slice = buf.chunk();
    let (value, consumed) = decode(slice).map_err(|e| {
        Error::protocol(ErrorCode::FrameError, format!("varint decode error: {}", e))
    })?;

    buf.advance(consumed);
    Ok(value)
}

/// Encode a variable-length integer into a buffer that implements BufMut.
///
/// # Errors
///
/// Returns error if value exceeds MAX or buffer has insufficient space.
pub fn encode_buf<B: BufMut>(value: u64, buf: &mut B) -> Result<usize> {
    let required = encoded_len(value);
    if buf.remaining_mut() < required {
        return Err(Error::protocol(
            ErrorCode::InternalError,
            format!(
                "insufficient buffer space: need {} bytes, have {}",
                required,
                buf.remaining_mut()
            ),
        ));
    }

    let mut temp = [0u8; 8];
    let written = encode(value, &mut temp).map_err(|e| {
        Error::protocol(
            ErrorCode::InternalError,
            format!("varint encode error: {}", e),
        )
    })?;

    buf.put_slice(&temp[..written]);
    Ok(written)
}

/// Calculate the encoded length of a varint without encoding it.
pub fn encoded_len(value: u64) -> usize {
    if value < 64 {
        1
    } else if value < 16384 {
        2
    } else if value < 1073741824 {
        4
    } else {
        8
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_encode_decode_roundtrip() {
        let test_values = vec![0, 1, 63, 64, 16383, 16384, 1073741823, 1073741824, MAX];

        for value in test_values {
            let mut buf = BytesMut::new();
            encode_buf(value, &mut buf).unwrap();

            let mut read_buf = buf.clone();
            let decoded = decode_buf(&mut read_buf).unwrap();

            assert_eq!(value, decoded, "roundtrip failed for {}", value);
            assert_eq!(read_buf.remaining(), 0, "buffer not fully consumed");
        }
    }

    #[test]
    fn test_encoded_len() {
        assert_eq!(encoded_len(0), 1);
        assert_eq!(encoded_len(63), 1);
        assert_eq!(encoded_len(64), 2);
        assert_eq!(encoded_len(16383), 2);
        assert_eq!(encoded_len(16384), 4);
        assert_eq!(encoded_len(1073741823), 4);
        assert_eq!(encoded_len(1073741824), 8);
        assert_eq!(encoded_len(MAX), 8);
    }

    #[test]
    fn test_incomplete_varint() {
        let mut buf = BytesMut::from(&[0x40][..]); // 2-byte varint, incomplete
        let result = decode_buf(&mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_buffer() {
        let mut buf = BytesMut::new();
        let result = decode_buf(&mut buf);
        assert!(result.is_err());
    }
}
