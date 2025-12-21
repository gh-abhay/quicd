//! Zero-Copy Frame Parsing (RFC 9000 Section 12.4)
//!
//! This module provides parsers for all QUIC frame types that operate on
//! borrowed byte slices without copying data.
//!
//! ## Usage Pattern
//!
//! ```rust,ignore
//! use quicd_quic::frames::{Frame, parse::FrameParser};
//!
//! let packet_payload: &[u8] = /* decrypted packet payload */;
//! let mut parser = FrameParser::new(packet_payload);
//!
//! while let Some(frame) = parser.next_frame()? {
//!     match frame {
//!         Frame::Stream { stream_id, data, .. } => {
//!             // `data` references the original `packet_payload`
//!             handle_stream_data(stream_id, data);
//!         }
//!         _ => { /* handle other frames */ }
//!     }
//! }
//! ```

#![forbid(unsafe_code)]

use super::*;
use crate::error::{Error, Result, TransportError};

// ============================================================================
// Variable-Length Integer Parsing (RFC 9000 Section 16)
// ============================================================================

/// Parse a variable-length integer from a byte slice (RFC 9000 Section 16)
///
/// QUIC encodes integers in 1, 2, 4, or 8 bytes. The two most significant
/// bits of the first byte indicate the length:
///
/// ```text
/// 2MSB | Length | Value Range
/// -----|--------|-------------
/// 00   | 1 byte | 0-63
/// 01   | 2 bytes| 0-16383
/// 10   | 4 bytes| 0-1073741823
/// 11   | 8 bytes| 0-4611686018427387903
/// ```
///
/// # Returns
/// `(value, remaining_bytes)`
///
/// # Errors
/// Returns `Error::InvalidInput` if the buffer is too short.
#[inline]
pub fn parse_varint(data: &[u8]) -> Result<(VarInt, &[u8])> {
    if data.is_empty() {
        return Err(Error::InvalidInput);
    }
    
    let first_byte = data[0];
    let length_indicator = first_byte >> 6;
    
    match length_indicator {
        0 => {
            // 1 byte: 00xxxxxx
            let value = (first_byte & 0x3f) as u64;
            Ok((value, &data[1..]))
        }
        1 => {
            // 2 bytes: 01xxxxxx xxxxxxxx
            if data.len() < 2 {
                return Err(Error::InvalidInput);
            }
            let value = (((first_byte & 0x3f) as u64) << 8) | (data[1] as u64);
            Ok((value, &data[2..]))
        }
        2 => {
            // 4 bytes: 10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
            if data.len() < 4 {
                return Err(Error::InvalidInput);
            }
            let value = (((first_byte & 0x3f) as u64) << 24)
                | ((data[1] as u64) << 16)
                | ((data[2] as u64) << 8)
                | (data[3] as u64);
            Ok((value, &data[4..]))
        }
        3 => {
            // 8 bytes: 11xxxxxx xxxxxxxx ... xxxxxxxx
            if data.len() < 8 {
                return Err(Error::InvalidInput);
            }
            let value = (((first_byte & 0x3f) as u64) << 56)
                | ((data[1] as u64) << 48)
                | ((data[2] as u64) << 40)
                | ((data[3] as u64) << 32)
                | ((data[4] as u64) << 24)
                | ((data[5] as u64) << 16)
                | ((data[6] as u64) << 8)
                | (data[7] as u64);
            Ok((value, &data[8..]))
        }
        _ => unreachable!(),
    }
}

/// Get the encoded length of a varint value
#[inline]
pub fn varint_len(value: VarInt) -> usize {
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

// ============================================================================
// Frame Parser (Iterator-Based)
// ============================================================================

/// Zero-Copy Frame Parser
///
/// Iterates over frames in a packet payload without copying data.
pub struct FrameParser<'a> {
    data: &'a [u8],
}

impl<'a> FrameParser<'a> {
    /// Create a new frame parser for a packet payload
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
    
    /// Parse the next frame from the payload
    ///
    /// Returns `None` when all frames have been parsed.
    pub fn next_frame(&mut self) -> Result<Option<Frame<'a>>> {
        if self.data.is_empty() {
            return Ok(None);
        }
        
        let (frame, remaining) = parse_frame(self.data)?;
        self.data = remaining;
        Ok(Some(frame))
    }
    
    /// Get the remaining unparsed data
    pub fn remaining(&self) -> &'a [u8] {
        self.data
    }
}

// ============================================================================
// Individual Frame Parsers
// ============================================================================

/// Parse a single frame from a byte slice
///
/// # Returns
/// `(frame, remaining_bytes)`
pub fn parse_frame(data: &[u8]) -> Result<(Frame, &[u8])> {
    if data.is_empty() {
        return Err(Error::InvalidInput);
    }
    
    let frame_type = data[0];
    
    match frame_type {
        0x00 => parse_padding(data),
        0x01 => Ok((Frame::Ping, &data[1..])),
        0x02 | 0x03 => parse_ack(data),
        0x04 => parse_reset_stream(data),
        0x05 => parse_stop_sending(data),
        0x06 => parse_crypto(data),
        0x07 => parse_new_token(data),
        0x08..=0x0f => parse_stream(data),
        0x10 => parse_max_data(data),
        0x11 => parse_max_stream_data(data),
        0x12 | 0x13 => parse_max_streams(data),
        0x14 => parse_data_blocked(data),
        0x15 => parse_stream_data_blocked(data),
        0x16 | 0x17 => parse_streams_blocked(data),
        0x18 => parse_new_connection_id(data),
        0x19 => parse_retire_connection_id(data),
        0x1a => parse_path_challenge(data),
        0x1b => parse_path_response(data),
        0x1c | 0x1d => parse_connection_close(data),
        0x1e => Ok((Frame::HandshakeDone, &data[1..])),
        _ => Err(Error::Transport(TransportError::FrameEncodingError)),
    }
}

fn parse_padding(data: &[u8]) -> Result<(Frame, &[u8])> {
    let mut length = 0;
    while length < data.len() && data[length] == 0x00 {
        length += 1;
    }
    Ok((Frame::Padding { length }, &data[length..]))
}

fn parse_ack(data: &[u8]) -> Result<(Frame, &[u8])> {
    let has_ecn = data[0] == 0x03;
    let mut cursor = &data[1..];
    
    // Parse largest_acked
    let (largest_acked, rest) = parse_varint(cursor)?;
    cursor = rest;
    
    // Parse ack_delay
    let (ack_delay, rest) = parse_varint(cursor)?;
    cursor = rest;
    
    // Parse ack_range_count
    let (ack_range_count, rest) = parse_varint(cursor)?;
    cursor = rest;
    
    // Store pointer to ACK ranges for zero-copy
    let ack_ranges_start = cursor.as_ptr() as usize - data.as_ptr() as usize;
    
    // Skip first ACK range
    let (_, rest) = parse_varint(cursor)?;
    cursor = rest;
    
    // Skip additional ACK ranges
    for _ in 0..ack_range_count {
        let (_, rest) = parse_varint(cursor)?;
        cursor = rest;
        let (_, rest) = parse_varint(cursor)?;
        cursor = rest;
    }
    
    let ack_ranges_len = cursor.as_ptr() as usize - data.as_ptr() as usize - ack_ranges_start;
    let ack_ranges = &data[ack_ranges_start..ack_ranges_start + ack_ranges_len];
    
    // Parse ECN counts if present
    let ecn_counts = if has_ecn {
        let (ect0, rest) = parse_varint(cursor)?;
        cursor = rest;
        let (ect1, rest) = parse_varint(cursor)?;
        cursor = rest;
        let (ce, rest) = parse_varint(cursor)?;
        cursor = rest;
        
        Some(EcnCounts {
            ect0_count: ect0,
            ect1_count: ect1,
            ce_count: ce,
        })
    } else {
        None
    };
    
    Ok((Frame::Ack { largest_acked, ack_delay, ack_ranges, ecn_counts }, cursor))
}

fn parse_reset_stream(data: &[u8]) -> Result<(Frame, &[u8])> {
    let mut cursor = &data[1..];
    let (stream_id, rest) = parse_varint(cursor)?;
    cursor = rest;
    let (application_error_code, rest) = parse_varint(cursor)?;
    cursor = rest;
    let (final_size, rest) = parse_varint(cursor)?;
    
    Ok((Frame::ResetStream { stream_id, application_error_code, final_size }, rest))
}

fn parse_stop_sending(data: &[u8]) -> Result<(Frame, &[u8])> {
    let mut cursor = &data[1..];
    let (stream_id, rest) = parse_varint(cursor)?;
    cursor = rest;
    let (application_error_code, rest) = parse_varint(cursor)?;
    
    Ok((Frame::StopSending { stream_id, application_error_code }, rest))
}

fn parse_crypto(data: &[u8]) -> Result<(Frame, &[u8])> {
    let mut cursor = &data[1..];
    let (offset, rest) = parse_varint(cursor)?;
    cursor = rest;
    let (length, rest) = parse_varint(cursor)?;
    cursor = rest;
    
    if cursor.len() < length as usize {
        return Err(Error::InvalidInput);
    }
    
    let crypto_data = &cursor[..length as usize];
    Ok((Frame::Crypto { offset, data: crypto_data }, &cursor[length as usize..]))
}

fn parse_new_token(data: &[u8]) -> Result<(Frame, &[u8])> {
    let mut cursor = &data[1..];
    let (length, rest) = parse_varint(cursor)?;
    cursor = rest;
    
    if cursor.len() < length as usize {
        return Err(Error::InvalidInput);
    }
    
    let token = &cursor[..length as usize];
    Ok((Frame::NewToken { token }, &cursor[length as usize..]))
}

fn parse_stream(data: &[u8]) -> Result<(Frame, &[u8])> {
    let frame_type = data[0];
    let fin = (frame_type & 0x01) != 0;
    let has_len = (frame_type & 0x02) != 0;
    let has_off = (frame_type & 0x04) != 0;
    
    let mut cursor = &data[1..];
    let (stream_id, rest) = parse_varint(cursor)?;
    cursor = rest;
    
    let offset = if has_off {
        let (off, rest) = parse_varint(cursor)?;
        cursor = rest;
        off
    } else {
        0
    };
    
    let stream_data = if has_len {
        let (length, rest) = parse_varint(cursor)?;
        cursor = rest;
        if cursor.len() < length as usize {
            return Err(Error::InvalidInput);
        }
        let data = &cursor[..length as usize];
        cursor = &cursor[length as usize..];
        data
    } else {
        // No length field means data extends to end of packet
        let data = cursor;
        cursor = &[];
        data
    };
    
    Ok((Frame::Stream { stream_id, offset, data: stream_data, fin }, cursor))
}

fn parse_max_data(data: &[u8]) -> Result<(Frame, &[u8])> {
    let (maximum_data, rest) = parse_varint(&data[1..])?;
    Ok((Frame::MaxData { maximum_data }, rest))
}

fn parse_max_stream_data(data: &[u8]) -> Result<(Frame, &[u8])> {
    let mut cursor = &data[1..];
    let (stream_id, rest) = parse_varint(cursor)?;
    cursor = rest;
    let (maximum_stream_data, rest) = parse_varint(cursor)?;
    
    Ok((Frame::MaxStreamData { stream_id, maximum_stream_data }, rest))
}

fn parse_max_streams(data: &[u8]) -> Result<(Frame, &[u8])> {
    let bidirectional = data[0] == 0x12;
    let (maximum_streams, rest) = parse_varint(&data[1..])?;
    
    Ok((Frame::MaxStreams { maximum_streams, bidirectional }, rest))
}

fn parse_data_blocked(data: &[u8]) -> Result<(Frame, &[u8])> {
    let (maximum_data, rest) = parse_varint(&data[1..])?;
    Ok((Frame::DataBlocked { maximum_data }, rest))
}

fn parse_stream_data_blocked(data: &[u8]) -> Result<(Frame, &[u8])> {
    let mut cursor = &data[1..];
    let (stream_id, rest) = parse_varint(cursor)?;
    cursor = rest;
    let (maximum_stream_data, rest) = parse_varint(cursor)?;
    
    Ok((Frame::StreamDataBlocked { stream_id, maximum_stream_data }, rest))
}

fn parse_streams_blocked(data: &[u8]) -> Result<(Frame, &[u8])> {
    let bidirectional = data[0] == 0x16;
    let (maximum_streams, rest) = parse_varint(&data[1..])?;
    
    Ok((Frame::StreamsBlocked { maximum_streams, bidirectional }, rest))
}

fn parse_new_connection_id(data: &[u8]) -> Result<(Frame, &[u8])> {
    let mut cursor = &data[1..];
    let (sequence_number, rest) = parse_varint(cursor)?;
    cursor = rest;
    let (retire_prior_to, rest) = parse_varint(cursor)?;
    cursor = rest;
    
    if cursor.is_empty() {
        return Err(Error::InvalidInput);
    }
    
    let cid_len = cursor[0] as usize;
    cursor = &cursor[1..];
    
    if cursor.len() < cid_len + 16 {
        return Err(Error::InvalidInput);
    }
    
    let connection_id = &cursor[..cid_len];
    cursor = &cursor[cid_len..];
    
    let mut stateless_reset_token = [0u8; 16];
    stateless_reset_token.copy_from_slice(&cursor[..16]);
    cursor = &cursor[16..];
    
    Ok((Frame::NewConnectionId {
        sequence_number,
        retire_prior_to,
        connection_id,
        stateless_reset_token,
    }, cursor))
}

fn parse_retire_connection_id(data: &[u8]) -> Result<(Frame, &[u8])> {
    let (sequence_number, rest) = parse_varint(&data[1..])?;
    Ok((Frame::RetireConnectionId { sequence_number }, rest))
}

fn parse_path_challenge(data: &[u8]) -> Result<(Frame, &[u8])> {
    if data.len() < 9 {
        return Err(Error::InvalidInput);
    }
    
    let mut challenge_data = [0u8; 8];
    challenge_data.copy_from_slice(&data[1..9]);
    
    Ok((Frame::PathChallenge { data: challenge_data }, &data[9..]))
}

fn parse_path_response(data: &[u8]) -> Result<(Frame, &[u8])> {
    if data.len() < 9 {
        return Err(Error::InvalidInput);
    }
    
    let mut response_data = [0u8; 8];
    response_data.copy_from_slice(&data[1..9]);
    
    Ok((Frame::PathResponse { data: response_data }, &data[9..]))
}

fn parse_connection_close(data: &[u8]) -> Result<(Frame, &[u8])> {
    let is_transport_error = data[0] == 0x1c;
    let mut cursor = &data[1..];
    
    let (error_code, rest) = parse_varint(cursor)?;
    cursor = rest;
    
    let frame_type = if is_transport_error {
        let (ft, rest) = parse_varint(cursor)?;
        cursor = rest;
        Some(ft)
    } else {
        None
    };
    
    let (reason_len, rest) = parse_varint(cursor)?;
    cursor = rest;
    
    if cursor.len() < reason_len as usize {
        return Err(Error::InvalidInput);
    }
    
    let reason = &cursor[..reason_len as usize];
    cursor = &cursor[reason_len as usize..];
    
    Ok((Frame::ConnectionClose { error_code, frame_type, reason }, cursor))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_varint_1byte() {
        let data = [0x25]; // 37 in decimal
        let (value, rest) = parse_varint(&data).unwrap();
        assert_eq!(value, 37);
        assert!(rest.is_empty());
    }
    
    #[test]
    fn test_varint_2bytes() {
        let data = [0x7b, 0xbd]; // 15293 in decimal
        let (value, rest) = parse_varint(&data).unwrap();
        assert_eq!(value, 15293);
        assert!(rest.is_empty());
    }
    
    #[test]
    fn test_parse_ping() {
        let data = [0x01];
        let (frame, rest) = parse_frame(&data).unwrap();
        assert!(matches!(frame, Frame::Ping));
        assert!(rest.is_empty());
    }
}
