//! # Packet Type Definitions (RFC 9000 Section 17)
//!
//! Defines all QUIC packet types and header structures.

extern crate alloc;

use crate::types::*;
use crate::error::*;
use bytes::Bytes;

/// QUIC Protocol Version (RFC 9000 Section 15)
pub type Version = u32;

/// QUIC Version 1 (RFC 9000)
pub const VERSION_1: Version = 0x00000001;

/// Version used for Version Negotiation packets
pub const VERSION_NEGOTIATION: Version = 0x00000000;

/// Token (RFC 9000 Section 8)
///
/// Opaque blob used for address validation.
pub type Token = Bytes;

/// Header Form (RFC 9000 Section 17.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderForm {
    /// Long Header - Fixed bit set, remaining bits determine packet type
    Long,
    /// Short Header - 1-RTT packets
    Short,
}

/// Long Packet Type (RFC 9000 Section 17.2)
///
/// Encoded in bits 4-5 of the first byte for long header packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LongPacketType {
    /// Initial packet (0x00)
    Initial = 0x00,
    /// 0-RTT packet (0x01)
    ZeroRtt = 0x01,
    /// Handshake packet (0x02)
    Handshake = 0x02,
    /// Retry packet (0x03)
    Retry = 0x03,
}

impl LongPacketType {
    /// Parse from first byte bits
    pub fn from_first_byte(first_byte: u8) -> Option<Self> {
        let type_bits = (first_byte >> 4) & 0x03;
        match type_bits {
            0x00 => Some(LongPacketType::Initial),
            0x01 => Some(LongPacketType::ZeroRtt),
            0x02 => Some(LongPacketType::Handshake),
            0x03 => Some(LongPacketType::Retry),
            _ => None,
        }
    }

    /// Get packet number space for this packet type
    pub fn packet_number_space(self) -> PacketNumberSpace {
        match self {
            LongPacketType::Initial => PacketNumberSpace::Initial,
            LongPacketType::ZeroRtt => PacketNumberSpace::ApplicationData,
            LongPacketType::Handshake => PacketNumberSpace::Handshake,
            LongPacketType::Retry => panic!("Retry packets do not have packet numbers"),
        }
    }
}

/// Long Header Packet (RFC 9000 Section 17.2)
///
/// Used during connection establishment. Contains version and connection IDs.
#[derive(Debug, Clone)]
pub struct LongHeader {
    /// Packet type
    pub packet_type: LongPacketType,
    
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
            PacketHeader::Long(h) if h.packet_type != LongPacketType::Retry => {
                Some(h.packet_type.packet_number_space())
            }
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
