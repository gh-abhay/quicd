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

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_number_len_from_bits() {
        assert_eq!(PacketNumberLen::from_bits(0), Some(PacketNumberLen::One));
        assert_eq!(PacketNumberLen::from_bits(1), Some(PacketNumberLen::Two));
        assert_eq!(PacketNumberLen::from_bits(2), Some(PacketNumberLen::Three));
        assert_eq!(PacketNumberLen::from_bits(3), Some(PacketNumberLen::Four));
        assert_eq!(PacketNumberLen::from_bits(4), None);
    }

    #[test]
    fn test_packet_number_len_to_bits() {
        assert_eq!(PacketNumberLen::One.to_bits(), 0);
        assert_eq!(PacketNumberLen::Two.to_bits(), 1);
        assert_eq!(PacketNumberLen::Three.to_bits(), 2);
        assert_eq!(PacketNumberLen::Four.to_bits(), 3);
    }

    #[test]
    fn test_packet_number_len() {
        assert_eq!(PacketNumberLen::One.len(), 1);
        assert_eq!(PacketNumberLen::Two.len(), 2);
        assert_eq!(PacketNumberLen::Three.len(), 3);
        assert_eq!(PacketNumberLen::Four.len(), 4);
    }

    // Packet Number Encoder Tests
    #[test]
    fn test_compute_length() {
        let encoder = DefaultPacketNumberEncoder;

        // Small gap - 1 byte
        assert_eq!(
            encoder.compute_length(100, 50),
            PacketNumberLen::One
        );

        // Medium gap - 2 bytes
        assert_eq!(
            encoder.compute_length(1000, 500),
            PacketNumberLen::Two
        );

        // Large gap - 3 bytes
        assert_eq!(
            encoder.compute_length(100000, 0),
            PacketNumberLen::Three
        );

        // Very large gap - 4 bytes
        assert_eq!(
            encoder.compute_length(10000000, 0),
            PacketNumberLen::Four
        );
    }

    #[test]
    fn test_encode_packet_number_1byte() {
        let encoder = DefaultPacketNumberEncoder;
        let mut buf = [0u8; 4];

        encoder.encode(0xAB, PacketNumberLen::One, &mut buf).unwrap();
        assert_eq!(buf[0], 0xAB);
    }

    #[test]
    fn test_encode_packet_number_2byte() {
        let encoder = DefaultPacketNumberEncoder;
        let mut buf = [0u8; 4];

        encoder.encode(0x1234, PacketNumberLen::Two, &mut buf).unwrap();
        assert_eq!(buf[0], 0x12);
        assert_eq!(buf[1], 0x34);
    }

    #[test]
    fn test_encode_packet_number_3byte() {
        let encoder = DefaultPacketNumberEncoder;
        let mut buf = [0u8; 4];

        encoder.encode(0x123456, PacketNumberLen::Three, &mut buf).unwrap();
        assert_eq!(buf[0], 0x12);
        assert_eq!(buf[1], 0x34);
        assert_eq!(buf[2], 0x56);
    }

    #[test]
    fn test_encode_packet_number_4byte() {
        let encoder = DefaultPacketNumberEncoder;
        let mut buf = [0u8; 4];

        encoder.encode(0x12345678, PacketNumberLen::Four, &mut buf).unwrap();
        assert_eq!(buf[0], 0x12);
        assert_eq!(buf[1], 0x34);
        assert_eq!(buf[2], 0x56);
        assert_eq!(buf[3], 0x78);
    }

    // Packet Number Decoder Tests
    #[test]
    fn test_parse_bytes() {
        let decoder = DefaultPacketNumberDecoder;

        // 1 byte
        assert_eq!(decoder.parse_bytes(&[0xAB], PacketNumberLen::One).unwrap(), 0xAB);

        // 2 bytes
        assert_eq!(
            decoder.parse_bytes(&[0x12, 0x34], PacketNumberLen::Two).unwrap(),
            0x1234
        );

        // 3 bytes
        assert_eq!(
            decoder.parse_bytes(&[0x12, 0x34, 0x56], PacketNumberLen::Three).unwrap(),
            0x123456
        );

        // 4 bytes
        assert_eq!(
            decoder.parse_bytes(&[0x12, 0x34, 0x56, 0x78], PacketNumberLen::Four).unwrap(),
            0x12345678
        );
    }

    #[test]
    fn test_parse_bytes_insufficient_buffer() {
        let decoder = DefaultPacketNumberDecoder;

        assert!(decoder.parse_bytes(&[], PacketNumberLen::One).is_err());
        assert!(decoder.parse_bytes(&[0x00], PacketNumberLen::Two).is_err());
        assert!(decoder.parse_bytes(&[0x00, 0x00], PacketNumberLen::Three).is_err());
        assert!(decoder.parse_bytes(&[0x00, 0x00, 0x00], PacketNumberLen::Four).is_err());
    }

    #[test]
    fn test_decode_packet_number_rfc_example() {
        // RFC 9000 Appendix A.3 examples
        let decoder = DefaultPacketNumberDecoder;

        // Example: largest_pn = 0xaa82f30e, truncated_pn = 0x9b32, pn_nbits = 16
        let largest_pn = 0xaa82f30e;
        let truncated_pn = 0x9b32;
        let pn_nbits = 16;

        let decoded = decoder.decode(largest_pn, truncated_pn, pn_nbits);
        assert_eq!(decoded, 0xaa829b32);
    }

    #[test]
    fn test_decode_packet_number_wraparound() {
        let decoder = DefaultPacketNumberDecoder;

        // Test case where packet number wraps around
        let largest_pn = 0x00FF;
        let truncated_pn = 0x05; // Should decode to 0x0105, not 0x0005
        let pn_nbits = 8;

        let decoded = decoder.decode(largest_pn, truncated_pn, pn_nbits);
        assert_eq!(decoded, 0x0105);
    }

    #[test]
    fn test_decode_packet_number_no_wrap() {
        let decoder = DefaultPacketNumberDecoder;

        // Simple case: no wraparound
        let largest_pn = 100;
        let truncated_pn = 105 & 0xFF; // Truncated to 1 byte
        let pn_nbits = 8;

        let decoded = decoder.decode(largest_pn, truncated_pn, pn_nbits);
        assert_eq!(decoded, 105);
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let encoder = DefaultPacketNumberEncoder;
        let decoder = DefaultPacketNumberDecoder;

        // Test roundtrip encoding and decoding
        let test_cases = vec![
            (100, 50),
            (1000, 900),
            (65536, 65000),
            (1000000, 999000),
        ];

        for (full_pn, largest_acked) in test_cases {
            let len = encoder.compute_length(full_pn, largest_acked);
            let mut buf = [0u8; 4];
            encoder.encode(full_pn, len, &mut buf).unwrap();

            let truncated_pn = decoder.parse_bytes(&buf, len).unwrap();
            let decoded_pn = decoder.decode(largest_acked, truncated_pn, len.len() * 8);

            assert_eq!(decoded_pn, full_pn, "Failed for full_pn={}, largest_acked={}", full_pn, largest_acked);
        }
    }

    #[test]
    fn test_packet_number_space_independence() {
        let decoder = DefaultPacketNumberDecoder;

        // Different packet number spaces should decode independently
        let initial_largest = 10;
        let handshake_largest = 5;

        let truncated = 12 & 0xFF;
        let pn_nbits = 8;

        let decoded_initial = decoder.decode(initial_largest, truncated, pn_nbits);
        let decoded_handshake = decoder.decode(handshake_largest, truncated, pn_nbits);

        assert_eq!(decoded_initial, 12);
        assert_eq!(decoded_handshake, 12);
    }
}
