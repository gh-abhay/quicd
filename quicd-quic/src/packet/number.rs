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
    fn decode(&self, largest_pn: PacketNumber, truncated_pn: u32, pn_nbits: usize) -> PacketNumber;

    /// Parse packet number bytes from buffer
    ///
    /// Reads 1-4 bytes as big-endian integer.
    fn parse_bytes(&self, bytes: &[u8], len: PacketNumberLen) -> Result<u32>;
}

/// Default Packet Number Decoder (RFC 9000 Appendix A.3 Algorithm)
pub struct DefaultPacketNumberDecoder;

impl PacketNumberDecoder for DefaultPacketNumberDecoder {
    fn decode(&self, largest_pn: PacketNumber, truncated_pn: u32, pn_nbits: usize) -> PacketNumber {
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
    fn compute_length(&self, full_pn: PacketNumber, largest_acked: PacketNumber)
        -> PacketNumberLen;

    /// Encode packet number into buffer
    ///
    /// Writes truncated packet number as big-endian bytes.
    fn encode(&self, full_pn: PacketNumber, len: PacketNumberLen, buf: &mut [u8]) -> Result<()>;
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

    fn encode(&self, full_pn: PacketNumber, len: PacketNumberLen, buf: &mut [u8]) -> Result<()> {
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

    // ==========================================================================
    // PacketNumberLen Tests
    // ==========================================================================

    #[test]
    fn test_packet_number_len_values() {
        assert_eq!(PacketNumberLen::One as usize, 1);
        assert_eq!(PacketNumberLen::Two as usize, 2);
        assert_eq!(PacketNumberLen::Three as usize, 3);
        assert_eq!(PacketNumberLen::Four as usize, 4);
    }

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
    fn test_packet_number_len_len() {
        assert_eq!(PacketNumberLen::One.len(), 1);
        assert_eq!(PacketNumberLen::Two.len(), 2);
        assert_eq!(PacketNumberLen::Three.len(), 3);
        assert_eq!(PacketNumberLen::Four.len(), 4);
    }

    #[test]
    fn test_packet_number_len_roundtrip() {
        for bits in 0..4 {
            let len = PacketNumberLen::from_bits(bits).unwrap();
            assert_eq!(len.to_bits(), bits);
        }
    }

    // ==========================================================================
    // DefaultPacketNumberDecoder Tests - RFC 9000 Appendix A.3
    // ==========================================================================

    #[test]
    fn test_decode_simple_case() {
        let decoder = DefaultPacketNumberDecoder;
        // When largest_pn is 0 and we receive truncated 1, decode should return 1
        let result = decoder.decode(0, 1, 8);
        assert_eq!(result, 1);
    }

    #[test]
    fn test_decode_sequential_packets() {
        let decoder = DefaultPacketNumberDecoder;
        // Receiving packets in sequence
        let pn1 = decoder.decode(0, 1, 8);
        assert_eq!(pn1, 1);
        
        let pn2 = decoder.decode(1, 2, 8);
        assert_eq!(pn2, 2);
        
        let pn3 = decoder.decode(2, 3, 8);
        assert_eq!(pn3, 3);
    }

    #[test]
    fn test_decode_wrap_around_1byte() {
        let decoder = DefaultPacketNumberDecoder;
        // After 255, next packet is 256
        // But truncated to 1 byte shows as 0
        let result = decoder.decode(255, 0, 8);
        assert_eq!(result, 256);
    }

    #[test]
    fn test_decode_wrap_around_2bytes() {
        let decoder = DefaultPacketNumberDecoder;
        // After 65535, truncated 2-byte PN wraps
        let result = decoder.decode(65535, 0, 16);
        assert_eq!(result, 65536);
    }

    #[test]
    fn test_decode_large_gap_within_window() {
        let decoder = DefaultPacketNumberDecoder;
        // Gap within the decoding window
        let result = decoder.decode(100, 110, 8);
        assert_eq!(result, 110);
    }

    #[test]
    fn test_decode_rfc_example() {
        // RFC 9000 Appendix A.3 example
        let decoder = DefaultPacketNumberDecoder;
        
        // If largest_pn = 0xa82f30ea, truncated_pn = 0x9b32 (16 bits)
        // expected_pn = 0xa82f30eb
        // candidate_pn = (0xa82f30eb & ~0xffff) | 0x9b32 = 0xa82f9b32
        let result = decoder.decode(0xa82f30ea, 0x9b32, 16);
        assert_eq!(result, 0xa82f9b32);
    }

    #[test]
    fn test_parse_bytes_1byte() {
        let decoder = DefaultPacketNumberDecoder;
        let result = decoder.parse_bytes(&[0x42], PacketNumberLen::One).unwrap();
        assert_eq!(result, 0x42);
    }

    #[test]
    fn test_parse_bytes_2bytes() {
        let decoder = DefaultPacketNumberDecoder;
        let result = decoder.parse_bytes(&[0x12, 0x34], PacketNumberLen::Two).unwrap();
        assert_eq!(result, 0x1234);
    }

    #[test]
    fn test_parse_bytes_3bytes() {
        let decoder = DefaultPacketNumberDecoder;
        let result = decoder.parse_bytes(&[0x12, 0x34, 0x56], PacketNumberLen::Three).unwrap();
        assert_eq!(result, 0x123456);
    }

    #[test]
    fn test_parse_bytes_4bytes() {
        let decoder = DefaultPacketNumberDecoder;
        let result = decoder.parse_bytes(&[0x12, 0x34, 0x56, 0x78], PacketNumberLen::Four).unwrap();
        assert_eq!(result, 0x12345678);
    }

    #[test]
    fn test_parse_bytes_truncated() {
        let decoder = DefaultPacketNumberDecoder;
        let result = decoder.parse_bytes(&[0x12], PacketNumberLen::Two);
        assert!(result.is_err());
    }

    // ==========================================================================
    // DefaultPacketNumberEncoder Tests - RFC 9000 Appendix A.2
    // ==========================================================================

    #[test]
    fn test_compute_length_small_gap() {
        let encoder = DefaultPacketNumberEncoder;
        // Gap < 128 needs only 1 byte
        let len = encoder.compute_length(10, 5);
        assert_eq!(len, PacketNumberLen::One);
    }

    #[test]
    fn test_compute_length_medium_gap() {
        let encoder = DefaultPacketNumberEncoder;
        // Gap >= 128 but < 32768 needs 2 bytes
        let len = encoder.compute_length(200, 5);
        assert_eq!(len, PacketNumberLen::Two);
    }

    #[test]
    fn test_compute_length_large_gap() {
        let encoder = DefaultPacketNumberEncoder;
        // Gap >= 32768 but < 8388608 needs 3 bytes
        let len = encoder.compute_length(50000, 5);
        assert_eq!(len, PacketNumberLen::Three);
    }

    #[test]
    fn test_compute_length_very_large_gap() {
        let encoder = DefaultPacketNumberEncoder;
        // Gap >= 8388608 needs 4 bytes
        let len = encoder.compute_length(10_000_000, 5);
        assert_eq!(len, PacketNumberLen::Four);
    }

    #[test]
    fn test_compute_length_zero_gap() {
        let encoder = DefaultPacketNumberEncoder;
        // Gap of 0 (retransmit) needs only 1 byte
        let len = encoder.compute_length(5, 5);
        assert_eq!(len, PacketNumberLen::One);
    }

    #[test]
    fn test_encode_1byte() {
        let encoder = DefaultPacketNumberEncoder;
        let mut buf = [0u8; 4];
        encoder.encode(0x42, PacketNumberLen::One, &mut buf).unwrap();
        assert_eq!(buf[0], 0x42);
    }

    #[test]
    fn test_encode_2bytes() {
        let encoder = DefaultPacketNumberEncoder;
        let mut buf = [0u8; 4];
        encoder.encode(0x1234, PacketNumberLen::Two, &mut buf).unwrap();
        assert_eq!(&buf[0..2], &[0x12, 0x34]);
    }

    #[test]
    fn test_encode_3bytes() {
        let encoder = DefaultPacketNumberEncoder;
        let mut buf = [0u8; 4];
        encoder.encode(0x123456, PacketNumberLen::Three, &mut buf).unwrap();
        assert_eq!(&buf[0..3], &[0x12, 0x34, 0x56]);
    }

    #[test]
    fn test_encode_4bytes() {
        let encoder = DefaultPacketNumberEncoder;
        let mut buf = [0u8; 4];
        encoder.encode(0x12345678, PacketNumberLen::Four, &mut buf).unwrap();
        assert_eq!(&buf[..], &[0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn test_encode_buffer_too_small() {
        let encoder = DefaultPacketNumberEncoder;
        let mut buf = [0u8; 1];
        let result = encoder.encode(0x1234, PacketNumberLen::Two, &mut buf);
        assert!(result.is_err());
    }

    // ==========================================================================
    // Roundtrip Tests
    // ==========================================================================

    #[test]
    fn test_encode_decode_roundtrip_1byte() {
        let encoder = DefaultPacketNumberEncoder;
        let decoder = DefaultPacketNumberDecoder;
        
        let full_pn = 42u64;
        let largest_acked = 40u64;
        
        let len = encoder.compute_length(full_pn, largest_acked);
        assert_eq!(len, PacketNumberLen::One);
        
        let mut buf = [0u8; 4];
        encoder.encode(full_pn, len, &mut buf).unwrap();
        
        let truncated = decoder.parse_bytes(&buf, len).unwrap();
        let decoded = decoder.decode(largest_acked, truncated, len.len() * 8);
        
        assert_eq!(decoded, full_pn);
    }

    #[test]
    fn test_encode_decode_roundtrip_large() {
        let encoder = DefaultPacketNumberEncoder;
        let decoder = DefaultPacketNumberDecoder;
        
        let full_pn = 1_000_000u64;
        let largest_acked = 999_950u64;
        
        let len = encoder.compute_length(full_pn, largest_acked);
        
        let mut buf = [0u8; 4];
        encoder.encode(full_pn, len, &mut buf).unwrap();
        
        let truncated = decoder.parse_bytes(&buf, len).unwrap();
        let decoded = decoder.decode(largest_acked, truncated, len.len() * 8);
        
        assert_eq!(decoded, full_pn);
    }
}