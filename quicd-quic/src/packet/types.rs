//! # Packet Type Definitions (RFC 9000 Section 17)
//!
//! Defines all QUIC packet types and header structures.

extern crate alloc;

use crate::error::*;
use crate::types::*;
use bytes::Bytes;

/// QUIC Protocol Version (RFC 9000 Section 15)
pub type Version = u32;

/// QUIC Version 1 (RFC 9000)
pub const VERSION_1: Version = 0x00000001;

/// Version used for Version Negotiation packets
pub const VERSION_NEGOTIATION: Version = 0x00000000;

pub use crate::types::Token;

/// Header Form (RFC 9000 Section 17.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderForm {
    /// Long Header - Fixed bit set, remaining bits determine packet type
    Long,
    /// Short Header - 1-RTT packets
    Short,
}

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
    /// Parse from first byte bits (for Long Header packets)
    pub fn from_first_byte(first_byte: u8) -> Option<Self> {
        let type_bits = (first_byte >> 4) & 0x03;
        match type_bits {
            0x00 => Some(PacketType::Initial),
            0x01 => Some(PacketType::ZeroRtt),
            0x02 => Some(PacketType::Handshake),
            0x03 => Some(PacketType::Retry),
            _ => None,
        }
    }

    /// Returns true if this is a long header packet type
    pub fn is_long_header(&self) -> bool {
        !matches!(self, PacketType::OneRtt)
    }

    /// Returns true if this packet type carries an ACK-eliciting payload
    pub fn is_ack_eliciting_type(&self) -> bool {
        !matches!(self, PacketType::Retry | PacketType::VersionNegotiation)
    }

    /// Get the packet number space for this packet type
    pub fn packet_number_space(&self) -> Option<PacketNumberSpace> {
        match self {
            PacketType::Initial => Some(PacketNumberSpace::Initial),
            PacketType::Handshake => Some(PacketNumberSpace::Handshake),
            PacketType::ZeroRtt | PacketType::OneRtt => Some(PacketNumberSpace::ApplicationData),
            PacketType::Retry | PacketType::VersionNegotiation => None,
        }
    }
}

/// Long Header Packet (RFC 9000 Section 17.2)
///
/// Used during connection establishment. Contains version and connection IDs.
#[derive(Debug, Clone)]
pub struct LongHeader {
    /// Packet type
    pub packet_type: PacketType,

    /// QUIC version
    pub version: Version,

    /// Destination Connection ID
    pub dcid: ConnectionId,

    /// Source Connection ID
    pub scid: ConnectionId,

    /// Packet number (not present in Retry packets)
    ///
    /// This is the decoded packet number after header protection removal.
    pub packet_number: Option<PacketNumber>,

    /// Packet number length (1-4 bytes)
    pub pn_length: Option<u8>,

    /// Token (only for Initial packets)
    pub token: Option<Token>,

    /// Length field (payload + packet number)
    pub length: VarInt,
}

/// Short Header Packet (RFC 9000 Section 17.3)
///
/// Used for 1-RTT protected packets. Minimal overhead.
#[derive(Debug, Clone)]
pub struct ShortHeader {
    /// Spin bit (RFC 9000 Section 17.3.1)
    pub spin_bit: bool,

    /// Key phase bit (RFC 9001 Section 6)
    pub key_phase: bool,

    /// Destination Connection ID
    pub dcid: ConnectionId,

    /// Packet number
    ///
    /// This is the decoded packet number after header protection removal.
    pub packet_number: PacketNumber,

    /// Packet number length (1-4 bytes)
    pub pn_length: u8,
}

/// Parsed QUIC Packet Header
#[derive(Debug, Clone)]
pub enum PacketHeader {
    /// Long header packet
    Long(LongHeader),

    /// Short header packet
    Short(ShortHeader),

    /// Version Negotiation packet (no version negotiation in v1)
    VersionNegotiation {
        dcid: ConnectionId,
        scid: ConnectionId,
        supported_versions: alloc::vec::Vec<Version>,
    },
}

impl PacketHeader {
    /// Get the destination connection ID
    pub fn dcid(&self) -> &ConnectionId {
        match self {
            PacketHeader::Long(h) => &h.dcid,
            PacketHeader::Short(h) => &h.dcid,
            PacketHeader::VersionNegotiation { dcid, .. } => dcid,
        }
    }

    /// Get the source connection ID (if present)
    pub fn scid(&self) -> Option<&ConnectionId> {
        match self {
            PacketHeader::Long(h) => Some(&h.scid),
            PacketHeader::Short(_) => None,
            PacketHeader::VersionNegotiation { scid, .. } => Some(scid),
        }
    }

    /// Get the packet number (if present)
    pub fn packet_number(&self) -> Option<PacketNumber> {
        match self {
            PacketHeader::Long(h) => h.packet_number,
            PacketHeader::Short(h) => Some(h.packet_number),
            PacketHeader::VersionNegotiation { .. } => None,
        }
    }

    /// Get the packet number space (if applicable)
    pub fn packet_number_space(&self) -> Option<PacketNumberSpace> {
        match self {
            PacketHeader::Long(h) => h.packet_type.packet_number_space(),
            PacketHeader::Short(_) => Some(PacketNumberSpace::ApplicationData),
            _ => None,
        }
    }
}

/// Parsed QUIC Packet with borrowed payload
///
/// The payload reference has lifetime 'a bound to the original datagram buffer.
#[derive(Debug)]
pub struct ParsedPacket<'a> {
    /// Packet header
    pub header: PacketHeader,

    /// Encrypted payload (frames + authentication tag)
    ///
    /// For Initial/Handshake/1-RTT packets, this is AEAD-protected.
    /// For 0-RTT packets, this is 0-RTT protected.
    /// For Retry packets, this includes the retry token and integrity tag.
    pub payload: &'a [u8],

    /// Header length in bytes
    pub header_len: usize,
}

/// Datagram input for packet processing
///
/// Contains the received UDP datagram and metadata.
pub struct DatagramInput {
    /// Raw UDP payload (may contain multiple QUIC packets)
    pub data: Bytes,

    /// Reception timestamp
    pub recv_time: Instant,
}

/// Datagram output for packet sending
///
/// Contains the serialized packet ready for UDP transmission.
pub struct DatagramOutput {
    /// Serialized packet bytes
    pub data: Bytes,

    /// Transmission timestamp (for RTT calculation)
    pub send_time: Instant,
}
