//! # QUIC Packet Header Parsing and Types (RFC 9000 Section 17, RFC 8999)
//!
//! Zero-copy packet header parsing with lifetime-bound return types.
//! Supports both Long Header (handshake) and Short Header (1-RTT) formats.

#![forbid(unsafe_code)]

use crate::error::{Error, Result, TransportError};
use crate::types::VarInt;

// ============================================================================
// Header Form Constants (RFC 8999 Section 5.1, RFC 9000 Section 17)
// ============================================================================

/// Header Form Bit (most significant bit)
/// 1 = Long Header, 0 = Short Header
pub const HEADER_FORM_BIT: u8 = 0x80;

/// Fixed Bit (second most significant bit)
/// MUST be set to 1 in all QUIC packets
pub const FIXED_BIT: u8 = 0x40;

/// Long Packet Type Mask (bits 4-5)
pub const LONG_PACKET_TYPE_MASK: u8 = 0x30;

/// Long Packet Type Values
pub const LONG_PACKET_TYPE_INITIAL: u8 = 0x00;
pub const LONG_PACKET_TYPE_0RTT: u8 = 0x10;
pub const LONG_PACKET_TYPE_HANDSHAKE: u8 = 0x20;
pub const LONG_PACKET_TYPE_RETRY: u8 = 0x30;

/// Spin Bit (Short Header, bit 5)
pub const SPIN_BIT: u8 = 0x20;

/// Key Phase Bit (Short Header, bit 2)
pub const KEY_PHASE_BIT: u8 = 0x04;

/// Packet Number Length Mask (bottom 2 bits)
/// Encodes (packet_number_length - 1)
pub const PACKET_NUMBER_LENGTH_MASK: u8 = 0x03;

// ============================================================================
// Packet Type Enumeration
// ============================================================================

pub use crate::packet::types::PacketType;

// ============================================================================
// Header Structures (Zero-Copy, Lifetime-Bound)
// ============================================================================

/// Long Header (RFC 9000 Section 17.2)
///
/// Used during connection establishment. Contains version field and
/// both source and destination connection IDs.
#[derive(Debug, Clone)]
pub struct LongHeader<'a> {
    /// Packet type (Initial, 0-RTT, Handshake, Retry, VersionNegotiation)
    pub packet_type: PacketType,

    /// QUIC version (or 0x00000000 for Version Negotiation)
    pub version: u32,

    /// Destination Connection ID
    pub dcid: &'a [u8],

    /// Source Connection ID
    pub scid: &'a [u8],

    /// Token (only present in Initial and Retry packets)
    pub token: Option<&'a [u8]>,

    /// Length of payload + packet number (only in Initial, 0-RTT, Handshake)
    pub length: Option<VarInt>,

    /// Encoded packet number (1-4 bytes, still protected)
    /// Not present in Retry or Version Negotiation packets
    pub packet_number: Option<&'a [u8]>,
}

/// Short Header (RFC 9000 Section 17.3)
///
/// Used for 1-RTT packets after handshake completes. Omits version
/// and source connection ID for efficiency.
#[derive(Debug, Clone)]
pub struct ShortHeader<'a> {
    /// Spin bit (for latency measurement)
    pub spin: bool,

    /// Key phase bit (for key updates)
    pub key_phase: bool,

    /// Destination Connection ID
    pub dcid: &'a [u8],

    /// Encoded packet number (1-4 bytes, still protected)
    pub packet_number: &'a [u8],
}

/// Parsed Packet Header (unifies Long and Short headers)
#[derive(Debug, Clone)]
pub enum Header<'a> {
    /// Long header packet
    Long(LongHeader<'a>),

    /// Short header packet
    Short(ShortHeader<'a>),
}

impl<'a> Header<'a> {
    /// Get the packet type
    pub fn packet_type(&self) -> PacketType {
        match self {
            Header::Long(h) => h.packet_type,
            Header::Short(_) => PacketType::OneRtt,
        }
    }

    /// Get destination connection ID
    pub fn dcid(&self) -> &'a [u8] {
        match self {
            Header::Long(h) => h.dcid,
            Header::Short(h) => h.dcid,
        }
    }

    /// Get source connection ID (only available in Long Header)
    pub fn scid(&self) -> Option<&'a [u8]> {
        match self {
            Header::Long(h) => Some(h.scid),
            Header::Short(_) => None,
        }
    }

    /// Get the version (only available in Long Header)
    pub fn version(&self) -> Option<u32> {
        match self {
            Header::Long(h) => Some(h.version),
            Header::Short(_) => None,
        }
    }

    /// Get the encoded (protected) packet number bytes
    pub fn protected_packet_number(&self) -> Option<&'a [u8]> {
        match self {
            Header::Long(h) => h.packet_number,
            Header::Short(h) => Some(h.packet_number),
        }
    }
}

// ============================================================================
// Packet Parser Trait (Zero-Copy, Lifetime-Bound)
// ============================================================================

/// Zero-Copy Packet Parser (RFC 9000 Section 17)
///
/// Parses QUIC packet headers without copying data. All returned
/// references borrow from the input buffer.
///
/// **Design Rationale**:
/// - Lifetime parameter 'a binds all returned data to input buffer
/// - No heap allocations during parsing
/// - Returns slices into original packet for zero-copy processing
pub trait PacketParser: Send + Sync {
    /// Parse packet header from bytes
    ///
    /// Returns parsed header and offset to payload.
    /// Header references borrow from input buffer 'a.
    ///
    /// **Note**: Packet number is still protected at this stage.
    /// Call `remove_header_protection()` before decoding.
    fn parse_header<'a>(&self, packet: &'a [u8]) -> Result<(Header<'a>, usize)>;

    /// Parse only the first byte to determine header form
    ///
    /// Fast path for routing decisions without full parsing.
    fn peek_header_form(&self, packet: &[u8]) -> Result<HeaderForm>;

    /// Extract destination CID without full parsing
    ///
    /// Used for connection demultiplexing. Faster than full parse.
    fn extract_dcid<'a>(&self, packet: &'a [u8], dcid_len: Option<usize>) -> Result<&'a [u8]>;
}

/// Header Form (Long vs Short)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderForm {
    /// Long Header (handshake packets)
    Long,
    /// Short Header (1-RTT packets)
    Short,
}

// ============================================================================
// Default Parser Implementation Skeleton
// ============================================================================

/// Default zero-copy packet header parser
pub struct DefaultHeaderParser;

impl PacketParser for DefaultHeaderParser {
    fn parse_header<'a>(&self, packet: &'a [u8]) -> Result<(Header<'a>, usize)> {
        if packet.is_empty() {
            return Err(Error::Transport(TransportError::FrameEncodingError));
        }

        let first_byte = packet[0];

        // Validate Fixed Bit (RFC 9000 Section 17.2)
        if (first_byte & FIXED_BIT) == 0 {
            return Err(Error::Transport(TransportError::ProtocolViolation));
        }

        // Check header form
        if (first_byte & HEADER_FORM_BIT) != 0 {
            // Long Header
            self.parse_long_header(packet)
        } else {
            // Short Header
            self.parse_short_header(packet)
        }
    }

    fn peek_header_form(&self, packet: &[u8]) -> Result<HeaderForm> {
        if packet.is_empty() {
            return Err(Error::Transport(TransportError::FrameEncodingError));
        }

        if (packet[0] & HEADER_FORM_BIT) != 0 {
            Ok(HeaderForm::Long)
        } else {
            Ok(HeaderForm::Short)
        }
    }

    fn extract_dcid<'a>(&self, packet: &'a [u8], dcid_len: Option<usize>) -> Result<&'a [u8]> {
        if packet.is_empty() {
            return Err(Error::Transport(TransportError::FrameEncodingError));
        }

        let first_byte = packet[0];

        if (first_byte & HEADER_FORM_BIT) != 0 {
            // Long Header: DCID starts at byte 6
            if packet.len() < 6 {
                return Err(Error::Transport(TransportError::FrameEncodingError));
            }

            let dcid_len = packet[5] as usize;
            if packet.len() < 6 + dcid_len {
                return Err(Error::Transport(TransportError::FrameEncodingError));
            }

            Ok(&packet[6..6 + dcid_len])
        } else {
            // Short Header: DCID starts at byte 1
            let dcid_len = dcid_len.ok_or(Error::Transport(TransportError::FrameEncodingError))?;
            if packet.len() < 1 + dcid_len {
                return Err(Error::Transport(TransportError::FrameEncodingError));
            }

            Ok(&packet[1..1 + dcid_len])
        }
    }
}

impl DefaultHeaderParser {
    /// Parse Long Header (RFC 9000 Section 17.2)
    fn parse_long_header<'a>(&self, packet: &'a [u8]) -> Result<(Header<'a>, usize)> {
        use crate::types::VarIntCodec;

        if packet.len() < 5 {
            return Err(Error::Transport(TransportError::FrameEncodingError));
        }

        let first_byte = packet[0];
        let mut offset = 1;

        // Parse Version (4 bytes)
        let version = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);
        offset += 4;

        // Parse DCID Length + DCID
        let dcid_len = packet[offset] as usize;
        offset += 1;

        if dcid_len > 20 {
            return Err(Error::Transport(TransportError::ProtocolViolation));
        }

        if packet.len() < offset + dcid_len {
            return Err(Error::Transport(TransportError::FrameEncodingError));
        }

        let dcid = &packet[offset..offset + dcid_len];
        offset += dcid_len;

        // Parse SCID Length + SCID
        if packet.len() < offset + 1 {
            return Err(Error::Transport(TransportError::FrameEncodingError));
        }

        let scid_len = packet[offset] as usize;
        offset += 1;

        if scid_len > 20 {
            return Err(Error::Transport(TransportError::ProtocolViolation));
        }

        if packet.len() < offset + scid_len {
            return Err(Error::Transport(TransportError::FrameEncodingError));
        }

        let scid = &packet[offset..offset + scid_len];
        offset += scid_len;

        // Version Negotiation packet check
        if version == 0x00000000 {
            return Ok((
                Header::Long(LongHeader {
                    packet_type: PacketType::VersionNegotiation,
                    version,
                    dcid,
                    scid,
                    token: None,
                    length: None,
                    packet_number: None,
                }),
                offset,
            ));
        }

        // Determine packet type
        let packet_type_bits = first_byte & LONG_PACKET_TYPE_MASK;
        let packet_type = match packet_type_bits {
            LONG_PACKET_TYPE_INITIAL => PacketType::Initial,
            LONG_PACKET_TYPE_0RTT => PacketType::ZeroRtt,
            LONG_PACKET_TYPE_HANDSHAKE => PacketType::Handshake,
            LONG_PACKET_TYPE_RETRY => PacketType::Retry,
            _ => return Err(Error::Transport(TransportError::ProtocolViolation)),
        };

        // Parse token (Initial and Retry packets)
        let token = if matches!(packet_type, PacketType::Initial) {
            let (token_length, consumed) = VarIntCodec::decode(&packet[offset..])
                .ok_or(Error::Transport(TransportError::FrameEncodingError))?;
            offset += consumed;

            if token_length > (packet.len() - offset) as u64 {
                return Err(Error::Transport(TransportError::FrameEncodingError));
            }

            let token_data = &packet[offset..offset + token_length as usize];
            offset += token_length as usize;
            Some(token_data)
        } else if matches!(packet_type, PacketType::Retry) {
            // Retry has token at end (all remaining bytes except 16-byte integrity tag)
            if packet.len() < offset + 16 {
                return Err(Error::Transport(TransportError::FrameEncodingError));
            }
            let token_data = &packet[offset..packet.len() - 16];
            return Ok((
                Header::Long(LongHeader {
                    packet_type,
                    version,
                    dcid,
                    scid,
                    token: Some(token_data),
                    length: None,
                    packet_number: None,
                }),
                packet.len(),
            ));
        } else {
            None
        };

        // Parse Length + Packet Number (not in Retry packets)
        let (length, consumed) = VarIntCodec::decode(&packet[offset..])
            .ok_or(Error::Transport(TransportError::FrameEncodingError))?;
        offset += consumed;

        // Packet Number Length from first byte (bottom 2 bits)
        let pn_len = ((first_byte & PACKET_NUMBER_LENGTH_MASK) as usize) + 1;

        if packet.len() < offset + pn_len {
            return Err(Error::Transport(TransportError::FrameEncodingError));
        }

        let packet_number = &packet[offset..offset + pn_len];
        offset += pn_len;

        Ok((
            Header::Long(LongHeader {
                packet_type,
                version,
                dcid,
                scid,
                token,
                length: Some(length),
                packet_number: Some(packet_number),
            }),
            offset,
        ))
    }

    /// Parse Short Header (RFC 9000 Section 17.3)
    fn parse_short_header<'a>(&self, packet: &'a [u8]) -> Result<(Header<'a>, usize)> {
        if packet.is_empty() {
            return Err(Error::Transport(TransportError::FrameEncodingError));
        }

        let first_byte = packet[0];
        let mut offset = 1;

        // Extract flags
        let spin = (first_byte & SPIN_BIT) != 0;
        let key_phase = (first_byte & KEY_PHASE_BIT) != 0;

        // Packet Number Length from first byte (bottom 2 bits)
        let pn_len = ((first_byte & PACKET_NUMBER_LENGTH_MASK) as usize) + 1;

        // DCID: Variable length, must be known from connection state
        // For parsing, we'll read until we have enough for packet number
        // In real implementation, DCID length is tracked per connection

        // Simplified: Assume zero-length DCID for now
        // Real implementation needs connection context
        let dcid = &packet[offset..offset]; // Empty slice

        // Packet Number
        if packet.len() < offset + pn_len {
            return Err(Error::Transport(TransportError::FrameEncodingError));
        }

        let packet_number = &packet[offset..offset + pn_len];
        offset += pn_len;

        Ok((
            Header::Short(ShortHeader {
                spin,
                key_phase,
                dcid,
                packet_number,
            }),
            offset,
        ))
    }
}

// ============================================================================
// Header Protection Removal (RFC 9001 Section 5.4)
// ============================================================================

/// Header Protection Operations
///
/// RFC 9001 Section 5.4: Packet number and certain header bits are
/// protected using a sample from the packet payload.
///
/// **Critical Design**: This trait enables in-place modification of
/// packet buffers for header protection removal without allocation.
pub trait HeaderProtectionRemover {
    /// Remove header protection from a packet
    ///
    /// Modifies the packet buffer in-place to reveal:
    /// - Actual packet number length (bottom 2 bits of first byte)
    /// - Packet number bytes
    ///
    /// **Parameters**:
    /// - `packet`: Mutable buffer containing protected packet
    /// - `header_len`: Length of fixed header before packet number
    /// - `sample`: 16-byte sample from packet payload
    ///
    /// **Returns**: Length of packet number (1-4 bytes)
    fn remove_protection(
        &self,
        packet: &mut [u8],
        header_len: usize,
        sample: &[u8; 16],
    ) -> Result<usize>;

    /// Apply header protection to a packet
    ///
    /// Inverse operation for outgoing packets.
    fn apply_protection(
        &self,
        packet: &mut [u8],
        header_len: usize,
        sample: &[u8; 16],
    ) -> Result<()>;
}
// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ==========================================================================
    // Constants Tests
    // ==========================================================================

    #[test]
    fn test_header_form_bit() {
        assert_eq!(HEADER_FORM_BIT, 0x80);
        // Bit 7 (MSB) indicates Long Header
    }

    #[test]
    fn test_fixed_bit() {
        assert_eq!(FIXED_BIT, 0x40);
        // Bit 6 MUST be 1 in all QUIC packets (RFC 9000)
    }

    #[test]
    fn test_long_packet_type_values() {
        assert_eq!(LONG_PACKET_TYPE_INITIAL, 0x00);
        assert_eq!(LONG_PACKET_TYPE_0RTT, 0x10);
        assert_eq!(LONG_PACKET_TYPE_HANDSHAKE, 0x20);
        assert_eq!(LONG_PACKET_TYPE_RETRY, 0x30);
    }

    #[test]
    fn test_packet_number_length_mask() {
        assert_eq!(PACKET_NUMBER_LENGTH_MASK, 0x03);
        // Bottom 2 bits encode (pn_length - 1)
    }

    // ==========================================================================
    // HeaderForm Tests
    // ==========================================================================

    #[test]
    fn test_header_form_enum() {
        assert_ne!(HeaderForm::Long, HeaderForm::Short);
    }

    // ==========================================================================
    // DefaultHeaderParser - Long Header Tests
    // ==========================================================================

    #[test]
    fn test_parse_header_empty_packet() {
        let parser = DefaultHeaderParser;
        let result = parser.parse_header(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_header_missing_fixed_bit() {
        let parser = DefaultHeaderParser;
        // First byte with Fixed Bit = 0 (invalid)
        let packet = [0x80]; // Long header form but Fixed Bit not set
        let result = parser.parse_header(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_long_header_version_negotiation() {
        let parser = DefaultHeaderParser;
        // Build Version Negotiation packet
        let mut packet = Vec::new();
        packet.push(0xC0); // Long Header, Fixed Bit set
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Version = 0
        packet.push(4); // DCID length
        packet.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // DCID
        packet.push(4); // SCID length
        packet.extend_from_slice(&[0x05, 0x06, 0x07, 0x08]); // SCID

        let (header, offset) = parser.parse_header(&packet).unwrap();
        match header {
            Header::Long(h) => {
                assert_eq!(h.packet_type, PacketType::VersionNegotiation);
                assert_eq!(h.version, 0x00000000);
                assert_eq!(h.dcid, &[0x01, 0x02, 0x03, 0x04]);
                assert_eq!(h.scid, &[0x05, 0x06, 0x07, 0x08]);
                assert!(h.token.is_none());
                assert!(h.length.is_none());
                assert!(h.packet_number.is_none());
            }
            _ => panic!("Expected Long header"),
        }
        // Offset: 1 (first byte) + 4 (version) + 1 (dcid len) + 4 (dcid) + 1 (scid len) + 4 (scid) = 15
        assert_eq!(offset, 15);
    }

    #[test]
    fn test_parse_long_header_initial() {
        let parser = DefaultHeaderParser;
        // Build Initial packet
        let mut packet = Vec::new();
        packet.push(0xC0); // Long Header, Fixed Bit, Type = Initial (00), PN len = 1
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Version 1
        packet.push(4); // DCID length
        packet.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // DCID
        packet.push(4); // SCID length
        packet.extend_from_slice(&[0x05, 0x06, 0x07, 0x08]); // SCID
        packet.push(0x00); // Token length = 0 (varint)
        packet.push(0x10); // Length = 16 (varint)
        packet.push(0x00); // Packet number (1 byte, protected)
        // Remaining payload...

        let (header, offset) = parser.parse_header(&packet).unwrap();
        match header {
            Header::Long(h) => {
                assert_eq!(h.packet_type, PacketType::Initial);
                assert_eq!(h.version, 0x00000001);
                assert_eq!(h.dcid, &[0x01, 0x02, 0x03, 0x04]);
                assert_eq!(h.scid, &[0x05, 0x06, 0x07, 0x08]);
                assert_eq!(h.token, Some(&[][..])); // Empty token
                assert_eq!(h.length, Some(0x10));
                assert!(h.packet_number.is_some());
            }
            _ => panic!("Expected Long header"),
        }
    }

    #[test]
    fn test_parse_long_header_initial_with_token() {
        let parser = DefaultHeaderParser;
        let mut packet = Vec::new();
        packet.push(0xC0); // Long Header, Fixed Bit, Type = Initial, PN len = 1
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Version 1
        packet.push(4); // DCID length
        packet.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // DCID
        packet.push(4); // SCID length
        packet.extend_from_slice(&[0x05, 0x06, 0x07, 0x08]); // SCID
        packet.push(0x05); // Token length = 5 (varint)
        packet.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]); // Token
        packet.push(0x10); // Length = 16 (varint)
        packet.push(0x00); // Packet number

        let (header, _) = parser.parse_header(&packet).unwrap();
        match header {
            Header::Long(h) => {
                assert_eq!(h.token, Some(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE][..]));
            }
            _ => panic!("Expected Long header"),
        }
    }

    #[test]
    fn test_parse_long_header_handshake() {
        let parser = DefaultHeaderParser;
        let mut packet = Vec::new();
        packet.push(0xE0); // Long Header, Fixed Bit, Type = Handshake (10), PN len = 1
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Version 1
        packet.push(4); // DCID length
        packet.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // DCID
        packet.push(0); // SCID length = 0
        packet.push(0x10); // Length (varint)
        packet.push(0x00); // Packet number

        let (header, _) = parser.parse_header(&packet).unwrap();
        match header {
            Header::Long(h) => {
                assert_eq!(h.packet_type, PacketType::Handshake);
                assert!(h.token.is_none());
            }
            _ => panic!("Expected Long header"),
        }
    }

    #[test]
    fn test_parse_long_header_0rtt() {
        let parser = DefaultHeaderParser;
        let mut packet = Vec::new();
        packet.push(0xD0); // Long Header, Fixed Bit, Type = 0-RTT (01), PN len = 1
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Version 1
        packet.push(4); // DCID length
        packet.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // DCID
        packet.push(4); // SCID length
        packet.extend_from_slice(&[0x05, 0x06, 0x07, 0x08]); // SCID
        packet.push(0x10); // Length (varint)
        packet.push(0x00); // Packet number

        let (header, _) = parser.parse_header(&packet).unwrap();
        match header {
            Header::Long(h) => {
                assert_eq!(h.packet_type, PacketType::ZeroRtt);
                assert!(h.token.is_none());
            }
            _ => panic!("Expected Long header"),
        }
    }

    #[test]
    fn test_parse_long_header_retry() {
        let parser = DefaultHeaderParser;
        let mut packet = Vec::new();
        packet.push(0xF0); // Long Header, Fixed Bit, Type = Retry (11), PN len = 1
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Version 1
        packet.push(4); // DCID length
        packet.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]); // DCID
        packet.push(4); // SCID length
        packet.extend_from_slice(&[0x05, 0x06, 0x07, 0x08]); // SCID
        // Retry token (variable)
        packet.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        // Integrity tag (16 bytes)
        packet.extend_from_slice(&[0; 16]);

        let (header, offset) = parser.parse_header(&packet).unwrap();
        match header {
            Header::Long(h) => {
                assert_eq!(h.packet_type, PacketType::Retry);
                assert_eq!(h.token, Some(&[0xAA, 0xBB, 0xCC][..]));
                assert!(h.packet_number.is_none());
            }
            _ => panic!("Expected Long header"),
        }
        assert_eq!(offset, packet.len()); // Retry consumes entire packet
    }

    #[test]
    fn test_parse_long_header_dcid_too_long() {
        let parser = DefaultHeaderParser;
        let mut packet = Vec::new();
        packet.push(0xC0); // Long Header
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Version
        packet.push(21); // DCID length > 20 (invalid per RFC 9000)
        packet.extend_from_slice(&[0; 21]); // DCID

        let result = parser.parse_header(&packet);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_long_header_truncated() {
        let parser = DefaultHeaderParser;
        // Truncated header - just 4 bytes
        let packet = [0xC0, 0x00, 0x00, 0x00];
        let result = parser.parse_header(&packet);
        assert!(result.is_err());
    }

    // ==========================================================================
    // DefaultHeaderParser - Short Header Tests
    // ==========================================================================

    #[test]
    fn test_parse_short_header() {
        let parser = DefaultHeaderParser;
        // Short header: 0x40 (Fixed Bit, no spin, no key phase, PN len = 1)
        let packet = [0x40, 0x42]; // First byte + 1-byte packet number

        let (header, offset) = parser.parse_header(&packet).unwrap();
        match header {
            Header::Short(h) => {
                assert!(!h.spin);
                assert!(!h.key_phase);
                assert_eq!(h.packet_number, &[0x42]);
            }
            _ => panic!("Expected Short header"),
        }
        assert_eq!(offset, 2);
    }

    #[test]
    fn test_parse_short_header_with_spin() {
        let parser = DefaultHeaderParser;
        // Short header with spin bit set
        let packet = [0x60, 0x42]; // 0x60 = 0x40 | 0x20 (spin)

        let (header, _) = parser.parse_header(&packet).unwrap();
        match header {
            Header::Short(h) => {
                assert!(h.spin);
                assert!(!h.key_phase);
            }
            _ => panic!("Expected Short header"),
        }
    }

    #[test]
    fn test_parse_short_header_with_key_phase() {
        let parser = DefaultHeaderParser;
        // Short header with key phase bit set
        let packet = [0x44, 0x42]; // 0x44 = 0x40 | 0x04 (key phase)

        let (header, _) = parser.parse_header(&packet).unwrap();
        match header {
            Header::Short(h) => {
                assert!(!h.spin);
                assert!(h.key_phase);
            }
            _ => panic!("Expected Short header"),
        }
    }

    #[test]
    fn test_parse_short_header_4byte_pn() {
        let parser = DefaultHeaderParser;
        // Short header with 4-byte packet number (PN length bits = 0x03)
        let packet = [0x43, 0x01, 0x02, 0x03, 0x04];

        let (header, offset) = parser.parse_header(&packet).unwrap();
        match header {
            Header::Short(h) => {
                assert_eq!(h.packet_number, &[0x01, 0x02, 0x03, 0x04]);
            }
            _ => panic!("Expected Short header"),
        }
        assert_eq!(offset, 5); // 1 first byte + 4 PN bytes
    }

    // ==========================================================================
    // peek_header_form Tests
    // ==========================================================================

    #[test]
    fn test_peek_header_form_long() {
        let parser = DefaultHeaderParser;
        let packet = [0xC0, 0x00, 0x00, 0x00, 0x01];
        assert_eq!(parser.peek_header_form(&packet).unwrap(), HeaderForm::Long);
    }

    #[test]
    fn test_peek_header_form_short() {
        let parser = DefaultHeaderParser;
        let packet = [0x40, 0x00];
        assert_eq!(parser.peek_header_form(&packet).unwrap(), HeaderForm::Short);
    }

    #[test]
    fn test_peek_header_form_empty() {
        let parser = DefaultHeaderParser;
        let result = parser.peek_header_form(&[]);
        assert!(result.is_err());
    }

    // ==========================================================================
    // extract_dcid Tests
    // ==========================================================================

    #[test]
    fn test_extract_dcid_long_header() {
        let parser = DefaultHeaderParser;
        let mut packet = Vec::new();
        packet.push(0xC0); // Long Header
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Version
        packet.push(4); // DCID length
        packet.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // DCID
        packet.push(0); // SCID length

        let dcid = parser.extract_dcid(&packet, None).unwrap();
        assert_eq!(dcid, &[0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_extract_dcid_short_header() {
        let parser = DefaultHeaderParser;
        // Short header: DCID starts at byte 1
        let packet = [0x40, 0x01, 0x02, 0x03, 0x04, 0x00];

        let dcid = parser.extract_dcid(&packet, Some(4)).unwrap();
        assert_eq!(dcid, &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_extract_dcid_short_header_no_len() {
        let parser = DefaultHeaderParser;
        let packet = [0x40, 0x01];

        // Short header requires dcid_len parameter
        let result = parser.extract_dcid(&packet, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_dcid_truncated() {
        let parser = DefaultHeaderParser;
        // Long header but truncated
        let packet = [0xC0, 0x00, 0x00, 0x00, 0x01];
        let result = parser.extract_dcid(&packet, None);
        assert!(result.is_err());
    }

    // ==========================================================================
    // Header Methods Tests
    // ==========================================================================

    #[test]
    fn test_header_packet_type_long() {
        let header = Header::Long(LongHeader {
            packet_type: PacketType::Initial,
            version: 1,
            dcid: &[],
            scid: &[],
            token: None,
            length: None,
            packet_number: None,
        });
        assert_eq!(header.packet_type(), PacketType::Initial);
    }

    #[test]
    fn test_header_packet_type_short() {
        let header = Header::Short(ShortHeader {
            spin: false,
            key_phase: false,
            dcid: &[],
            packet_number: &[0x00],
        });
        assert_eq!(header.packet_type(), PacketType::OneRtt);
    }

    #[test]
    fn test_header_dcid() {
        let dcid_bytes = [0x01, 0x02, 0x03];
        let header = Header::Long(LongHeader {
            packet_type: PacketType::Handshake,
            version: 1,
            dcid: &dcid_bytes,
            scid: &[],
            token: None,
            length: None,
            packet_number: None,
        });
        assert_eq!(header.dcid(), &dcid_bytes);
    }

    #[test]
    fn test_header_scid_long() {
        let scid_bytes = [0x04, 0x05, 0x06];
        let header = Header::Long(LongHeader {
            packet_type: PacketType::Handshake,
            version: 1,
            dcid: &[],
            scid: &scid_bytes,
            token: None,
            length: None,
            packet_number: None,
        });
        assert_eq!(header.scid(), Some(&scid_bytes[..]));
    }

    #[test]
    fn test_header_scid_short() {
        let header = Header::Short(ShortHeader {
            spin: false,
            key_phase: false,
            dcid: &[],
            packet_number: &[0x00],
        });
        assert!(header.scid().is_none());
    }

    #[test]
    fn test_header_version_long() {
        let header = Header::Long(LongHeader {
            packet_type: PacketType::Initial,
            version: 0x00000001,
            dcid: &[],
            scid: &[],
            token: None,
            length: None,
            packet_number: None,
        });
        assert_eq!(header.version(), Some(0x00000001));
    }

    #[test]
    fn test_header_version_short() {
        let header = Header::Short(ShortHeader {
            spin: false,
            key_phase: false,
            dcid: &[],
            packet_number: &[0x00],
        });
        assert!(header.version().is_none());
    }

    #[test]
    fn test_header_protected_packet_number_long() {
        let pn_bytes = [0x01, 0x02];
        let header = Header::Long(LongHeader {
            packet_type: PacketType::Handshake,
            version: 1,
            dcid: &[],
            scid: &[],
            token: None,
            length: Some(100),
            packet_number: Some(&pn_bytes),
        });
        assert_eq!(header.protected_packet_number(), Some(&pn_bytes[..]));
    }

    #[test]
    fn test_header_protected_packet_number_short() {
        let pn_bytes = [0x42];
        let header = Header::Short(ShortHeader {
            spin: false,
            key_phase: false,
            dcid: &[],
            packet_number: &pn_bytes,
        });
        assert_eq!(header.protected_packet_number(), Some(&pn_bytes[..]));
    }
}