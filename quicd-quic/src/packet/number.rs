//! # Packet Number Encoding and Decoding (RFC 9000 Section 12.3, A.3)
//!
//! Packet numbers are encoded with variable length (1-4 bytes) using
//! truncation. The decoder must reconstruct the full 62-bit value.

#![forbid(unsafe_code)]

use crate::error::{Error, Result, TransportError};
use crate::types::PacketNumber;

/// Packet Number Length (1-4 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketNumberLen {
    /// 1-byte packet number
    One = 1,
    /// 2-byte packet number
    Two = 2,
    /// 3-byte packet number
    Three = 3,
    /// 4-byte packet number
    Four = 4,
}

impl PacketNumberLen {
    /// Convert from encoded length bits (0-3)
    pub fn from_bits(bits: u8) -> Option<Self> {
        match bits {
            0 => Some(PacketNumberLen::One),
            1 => Some(PacketNumberLen::Two),
            2 => Some(PacketNumberLen::Three),
            3 => Some(PacketNumberLen::Four),
            _ => None,
        }
    }

    /// Convert to encoded length bits
    pub fn to_bits(self) -> u8 {
        (self as u8) - 1
    }

    /// Get length in bytes
    pub fn len(self) -> usize {
        self as usize
    }
}

// ============================================================================
// Packet Number Decoder (RFC 9000 Appendix A.3)
// ============================================================================

/// Packet Number Decoder
///
/// Decodes truncated packet numbers by reconstructing the full 62-bit value
/// based on the largest acknowledged packet number.
///
/// **RFC 9000 Appendix A.3**: "DecodePacketNumber(largest_pn, truncated_pn, pn_nbits)"
pub trait PacketNumberDecoder {
    /// Decode a truncated packet number
    ///
    /// **Parameters**:
    /// - `largest_pn`: Largest packet number successfully processed
    /// - `truncated_pn`: Truncated packet number from wire (1-4 bytes)
    /// - `pn_nbits`: Number of bits in truncated packet number (8, 16, 24, or 32)
    ///
    /// **Returns**: Reconstructed full 62-bit packet number
    fn decode(
        &self,
        largest_pn: PacketNumber,
        truncated_pn: u32,
        pn_nbits: usize,
    ) -> PacketNumber;

    /// Parse packet number bytes from buffer
    ///
    /// Reads 1-4 bytes as big-endian integer.
    fn parse_bytes(&self, bytes: &[u8], len: PacketNumberLen) -> Result<u32>;
}

/// Default Packet Number Decoder (RFC 9000 Appendix A.3 Algorithm)
pub struct DefaultPacketNumberDecoder;

impl PacketNumberDecoder for DefaultPacketNumberDecoder {
    fn decode(
        &self,
        largest_pn: PacketNumber,
        truncated_pn: u32,
        pn_nbits: usize,
    ) -> PacketNumber {
        // RFC 9000 Appendix A.3 algorithm
        let expected_pn = largest_pn + 1;
        let pn_win = 1u64 << pn_nbits;
        let pn_hwin = pn_win / 2;
        let pn_mask = pn_win - 1;

        let truncated_pn = truncated_pn as u64;
        let candidate_pn = (expected_pn & !pn_mask) | truncated_pn;

        if candidate_pn <= expected_pn.saturating_sub(pn_hwin)
            && candidate_pn < (1u64 << 62) - pn_win
        {
            candidate_pn + pn_win
        } else if candidate_pn > expected_pn + pn_hwin && candidate_pn >= pn_win {
            candidate_pn - pn_win
        } else {
            candidate_pn
        }
    }

    fn parse_bytes(&self, bytes: &[u8], len: PacketNumberLen) -> Result<u32> {
        match len {
            PacketNumberLen::One => {
                if bytes.len() < 1 {
                    return Err(Error::Transport(TransportError::FrameEncodingError));
                }
                Ok(bytes[0] as u32)
            }
            PacketNumberLen::Two => {
                if bytes.len() < 2 {
                    return Err(Error::Transport(TransportError::FrameEncodingError));
                }
                Ok(u16::from_be_bytes([bytes[0], bytes[1]]) as u32)
            }
            PacketNumberLen::Three => {
                if bytes.len() < 3 {
                    return Err(Error::Transport(TransportError::FrameEncodingError));
                }
                Ok(u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]))
            }
            PacketNumberLen::Four => {
                if bytes.len() < 4 {
                    return Err(Error::Transport(TransportError::FrameEncodingError));
                }
                Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            }
        }
    }
}

// ============================================================================
// Packet Number Encoder (RFC 9000 Appendix A.2)
// ============================================================================

/// Packet Number Encoder
///
/// Encodes packet numbers with truncation to minimize overhead.
///
/// **RFC 9000 Appendix A.2**: "EncodePacketNumber(full_pn, largest_acked)"
pub trait PacketNumberEncoder {
    /// Determine the number of bytes needed to encode packet number
    ///
    /// **Parameters**:
    /// - `full_pn`: Full packet number to encode
    /// - `largest_acked`: Largest acknowledged packet number
    ///
    /// **Returns**: Minimum packet number length required
    fn compute_length(
        &self,
        full_pn: PacketNumber,
        largest_acked: PacketNumber,
    ) -> PacketNumberLen;

    /// Encode packet number into buffer
    ///
    /// Writes truncated packet number as big-endian bytes.
    fn encode(
        &self,
        full_pn: PacketNumber,
        len: PacketNumberLen,
        buf: &mut [u8],
    ) -> Result<()>;
}

/// Default Packet Number Encoder
pub struct DefaultPacketNumberEncoder;

impl PacketNumberEncoder for DefaultPacketNumberEncoder {
    fn compute_length(
        &self,
        full_pn: PacketNumber,
        largest_acked: PacketNumber,
    ) -> PacketNumberLen {
        let num_unacked = full_pn.saturating_sub(largest_acked);

        if num_unacked < (1u64 << 7) {
            PacketNumberLen::One
        } else if num_unacked < (1u64 << 15) {
            PacketNumberLen::Two
        } else if num_unacked < (1u64 << 23) {
            PacketNumberLen::Three
        } else {
            PacketNumberLen::Four
        }
    }

    fn encode(
        &self,
        full_pn: PacketNumber,
        len: PacketNumberLen,
        buf: &mut [u8],
    ) -> Result<()> {
        match len {
            PacketNumberLen::One => {
                if buf.is_empty() {
                    return Err(Error::Transport(TransportError::InternalError));
                }
                buf[0] = full_pn as u8;
            }
            PacketNumberLen::Two => {
                if buf.len() < 2 {
                    return Err(Error::Transport(TransportError::InternalError));
                }
                let bytes = (full_pn as u16).to_be_bytes();
                buf[0] = bytes[0];
                buf[1] = bytes[1];
            }
            PacketNumberLen::Three => {
                if buf.len() < 3 {
                    return Err(Error::Transport(TransportError::InternalError));
                }
                let bytes = (full_pn as u32).to_be_bytes();
                buf[0] = bytes[1];
                buf[1] = bytes[2];
                buf[2] = bytes[3];
            }
            PacketNumberLen::Four => {
                if buf.len() < 4 {
                    return Err(Error::Transport(TransportError::InternalError));
                }
                let bytes = (full_pn as u32).to_be_bytes();
                buf[0] = bytes[0];
                buf[1] = bytes[1];
                buf[2] = bytes[2];
                buf[3] = bytes[3];
            }
        }
        Ok(())
    }
}
