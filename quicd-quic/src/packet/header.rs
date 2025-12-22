//! # QUIC Packet Header Parsing and Types (RFC 9000 Section 17, RFC 8999)
//!
//! Zero-copy packet header parsing with lifetime-bound return types.
//! Supports both Long Header (handshake) and Short Header (1-RTT) formats.

#![forbid(unsafe_code)]

use crate::error::{Error, Result, TransportError};
use crate::types::{ConnectionId, PacketNumber, VarInt};
use bytes::Bytes;
use core::fmt;

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

/// Packet Type (RFC 9000 Section 17)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    /// Initial packet (Long Header, type 0x0)
    Initial,
    /// 0-RTT packet (Long Header, type 0x1)
    ZeroRtt,
    /// Handshake packet (Long Header, type 0x2)
    Handshake,
    /// Retry packet (Long Header, type 0x3)
    Retry,
    /// 1-RTT packet (Short Header)
    OneRtt,
    /// Version Negotiation packet (special Long Header)
    VersionNegotiation,
}

impl PacketType {
    /// Returns true if this is a long header packet type
    pub fn is_long_header(&self) -> bool {
        !matches!(self, PacketType::OneRtt)
    }

    /// Returns true if this packet type carries an ACK-eliciting payload
    pub fn is_ack_eliciting_type(&self) -> bool {
        !matches!(
            self,
            PacketType::Retry | PacketType::VersionNegotiation
        )
    }

    /// Get the packet number space for this packet type
    pub fn packet_number_space(&self) -> Option<crate::types::PacketNumberSpace> {
        use crate::types::PacketNumberSpace;
        match self {
            PacketType::Initial => Some(PacketNumberSpace::Initial),
            PacketType::Handshake => Some(PacketNumberSpace::Handshake),
            PacketType::ZeroRtt | PacketType::OneRtt => {
                Some(PacketNumberSpace::ApplicationData)
            }
            PacketType::Retry | PacketType::VersionNegotiation => None,
        }
    }
}

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
    fn extract_dcid<'a>(
        &self,
        packet: &'a [u8],
        dcid_len: Option<usize>,
    ) -> Result<&'a [u8]>;
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
        unimplemented!("Skeleton - no implementation required")
    }

    fn peek_header_form(&self, packet: &[u8]) -> Result<HeaderForm> {
        unimplemented!("Skeleton - no implementation required")
    }

    fn extract_dcid<'a>(
        &self,
        packet: &'a [u8],
        dcid_len: Option<usize>,
    ) -> Result<&'a [u8]> {
        unimplemented!("Skeleton - no implementation required")
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
