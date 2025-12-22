//! # Packet Header Types (RFC 9000 Section 17, RFC 8999)
//!
//! This module defines the packet header format and parsing traits.
//! QUIC has two header forms: Long Header and Short Header.
//!
//! ## Long Header (RFC 9000 Section 17.2)
//! Used during handshake (Initial, 0-RTT, Handshake, Retry).
//! Contains version field and full connection IDs.
//!
//! ## Short Header (RFC 9000 Section 17.3)
//! Used for 1-RTT packets after handshake completes.
//! Omits version and SCID for efficiency.

#![forbid(unsafe_code)]

use crate::error::{Error, Result};
use crate::types::{ConnectionId, PacketNumber, VarInt};
use bytes::Bytes;

/// Header Form Bit (RFC 8999 Section 5.1)
///
/// The most significant bit of the first byte indicates header form:
/// - 1: Long Header
/// - 0: Short Header
pub const HEADER_FORM_BIT: u8 = 0x80;

/// Fixed Bit (RFC 9000 Section 17.2)
///
/// The second most significant bit MUST be set to 1.
/// Packets with this bit cleared are not valid QUIC packets.
pub const FIXED_BIT: u8 = 0x40;

/// Long Packet Type Mask (RFC 9000 Section 17.2)
///
/// Bits 4-5 of the first byte encode the long packet type.
pub const LONG_PACKET_TYPE_MASK: u8 = 0x30;

/// Long Packet Type: Initial (0x00)
pub const LONG_PACKET_TYPE_INITIAL: u8 = 0x00;

/// Long Packet Type: 0-RTT (0x10)
pub const LONG_PACKET_TYPE_0RTT: u8 = 0x10;

/// Long Packet Type: Handshake (0x20)
pub const LONG_PACKET_TYPE_HANDSHAKE: u8 = 0x20;

/// Long Packet Type: Retry (0x30)
pub const LONG_PACKET_TYPE_RETRY: u8 = 0x30;

/// Spin Bit (RFC 9000 Section 17.3.1)
///
/// Used for latency measurement. Third most significant bit in short header.
pub const SPIN_BIT: u8 = 0x20;

/// Key Phase Bit (RFC 9000 Section 17.3.1)
///
/// Indicates which key phase is in use. Fourth most significant bit.
pub const KEY_PHASE_BIT: u8 = 0x04;

/// Packet Number Length Mask (RFC 9000 Section 17.2)
///
/// Bottom 2 bits encode packet number length - 1 (0=1 byte, 1=2 bytes, etc.)
pub const PACKET_NUMBER_LENGTH_MASK: u8 = 0x03;

/// Packet Type (RFC 9000 Section 17)
///
/// Distinguishes between different packet types in the QUIC protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    /// Initial packet (Long Header, type 0x0)
    /// Used for client's first flight and crypto handshake
    Initial,

    /// 0-RTT packet (Long Header, type 0x1)
    /// Contains early application data before handshake completes
    ZeroRtt,

    /// Handshake packet (Long Header, type 0x2)
    /// Used for crypto handshake after Initial keys derived
    Handshake,

    /// Retry packet (Long Header, type 0x3)
    /// Sent by server to perform stateless retry
    Retry,

    /// 1-RTT packet (Short Header)
    /// Used for application data after handshake completes
    OneRtt,

    /// Version Negotiation packet (Long Header with version 0x00000000)
    /// Sent when server doesn't support client's version
    VersionNegotiation,
}

impl PacketType {
    /// Returns true if this is a long header packet type
    pub fn is_long_header(&self) -> bool {
        !matches!(self, PacketType::OneRtt)
    }

    /// Returns true if this is a short header packet type
    pub fn is_short_header(&self) -> bool {
        matches!(self, PacketType::OneRtt)
    }

    /// Returns true if this packet type carries an ACK-eliciting payload
    pub fn is_ack_eliciting(&self) -> bool {
        // Version Negotiation and Retry are not ACK-eliciting
        !matches!(self, PacketType::VersionNegotiation | PacketType::Retry)
    }
}

/// Long Packet Header (RFC 9000 Section 17.2)
///
/// Used for Initial, 0-RTT, Handshake, and Retry packets.
/// Contains full version and connection ID information.
#[derive(Debug, Clone)]
pub struct LongHeader {
    /// Packet type (Initial, 0-RTT, Handshake, Retry)
    pub packet_type: PacketType,

    /// QUIC version (4 bytes)
    pub version: u32,

    /// Destination Connection ID
    pub dcid: ConnectionId,

    /// Source Connection ID
    pub scid: ConnectionId,

    /// Token (only for Initial and Retry packets)
    pub token: Option<Bytes>,

    /// Packet Number (not present in Retry packets)
    /// Encoded length varies (1-4 bytes)
    pub packet_number: Option<PacketNumber>,

    /// Packet Number Length in bytes (1-4)
    /// Derived from the 2 least significant bits of first byte
    pub packet_number_length: u8,

    /// Length of the payload (variable-length integer)
    /// Includes packet number and encrypted payload
    pub length: VarInt,
}

/// Short Packet Header (RFC 9000 Section 17.3)
///
/// Used for 1-RTT packets after handshake completion.
/// More compact than long header, omits version and SCID.
#[derive(Debug, Clone)]
pub struct ShortHeader {
    /// Destination Connection ID
    /// Length determined by initial handshake
    pub dcid: ConnectionId,

    /// Packet Number (1-4 bytes)
    pub packet_number: PacketNumber,

    /// Packet Number Length in bytes (1-4)
    pub packet_number_length: u8,

    /// Spin bit value (for latency measurement)
    pub spin_bit: bool,

    /// Key phase bit (indicates current key phase)
    pub key_phase: bool,
}

/// Unified Packet Header (RFC 9000 Section 17)
///
/// Discriminated union of Long and Short headers.
#[derive(Debug, Clone)]
pub enum PacketHeader {
    /// Long header packet
    Long(LongHeader),

    /// Short header packet
    Short(ShortHeader),
}

impl PacketHeader {
    /// Get the packet type
    pub fn packet_type(&self) -> PacketType {
        match self {
            PacketHeader::Long(h) => h.packet_type,
            PacketHeader::Short(_) => PacketType::OneRtt,
        }
    }

    /// Get the destination connection ID
    pub fn dcid(&self) -> &ConnectionId {
        match self {
            PacketHeader::Long(h) => &h.dcid,
            PacketHeader::Short(h) => &h.dcid,
        }
    }

    /// Get the packet number (if present)
    pub fn packet_number(&self) -> Option<PacketNumber> {
        match self {
            PacketHeader::Long(h) => h.packet_number,
            PacketHeader::Short(h) => Some(h.packet_number),
        }
    }
}

/// Parsed Packet (Zero-Copy)
///
/// Represents a parsed QUIC packet with lifetime-bound payload reference.
/// The payload slice points into the original datagram buffer.
#[derive(Debug)]
pub struct ParsedPacket<'a> {
    /// Parsed header
    pub header: PacketHeader,

    /// Encrypted payload (references original buffer)
    /// Does NOT include packet number - that's in the header
    pub payload: &'a [u8],

    /// Header bytes (for header protection removal)
    /// References the exact header bytes from original buffer
    pub header_bytes: &'a [u8],
}

/// Packet Parser Trait (Zero-Copy)
///
/// Defines the interface for parsing QUIC packets from UDP datagrams.
/// All parsing is done in-place without allocations.
///
/// ## Implementation Note:
/// The parser must handle:
/// 1. Version-independent header parsing (RFC 8999)
/// 2. Variable-length integer decoding
/// 3. Connection ID extraction
/// 4. Packet number recovery (RFC 9000 Section A.3)
pub trait PacketParser {
    /// Parse a QUIC packet from a datagram buffer.
    ///
    /// Returns a ParsedPacket with lifetime-bound references to the input buffer.
    /// The payload is still encrypted at this stage.
    ///
    /// # Errors
    /// Returns Error::ProtocolViolation if the packet is malformed.
    fn parse<'a>(&self, datagram: &'a [u8]) -> Result<ParsedPacket<'a>>;

    /// Decode a variable-length integer from a buffer.
    ///
    /// Returns (value, bytes_consumed) on success.
    ///
    /// # RFC 9000 Section 16
    /// Variable-length integers use the first 2 bits to encode length:
    /// - 00: 1 byte (6-bit value)
    /// - 01: 2 bytes (14-bit value)
    /// - 10: 4 bytes (30-bit value)
    /// - 11: 8 bytes (62-bit value)
    fn decode_varint(&self, buf: &[u8]) -> Result<(VarInt, usize)>;

    /// Recover the full packet number from a truncated packet number.
    ///
    /// # RFC 9000 Section A.3
    /// Packet numbers are transmitted in truncated form (1-4 bytes).
    /// The receiver reconstructs the full value using the largest
    /// acknowledged packet number.
    fn recover_packet_number(
        &self,
        truncated_pn: u64,
        pn_nbits: usize,
        expected_pn: PacketNumber,
    ) -> PacketNumber;
}

/// Packet Builder Trait (Zero-Allocation)
///
/// Defines the interface for constructing QUIC packets.
/// The caller provides a pre-allocated buffer.
///
/// ## Implementation Note:
/// The builder writes directly into the provided buffer.
/// Encryption is handled separately by the CryptoBackend.
pub trait PacketBuilder {
    /// Build a long header packet into the provided buffer.
    ///
    /// Returns the number of bytes written on success.
    ///
    /// # Errors
    /// Returns Error::InternalError if buffer is too small.
    fn build_long_header(
        &self,
        buf: &mut [u8],
        header: &LongHeader,
        payload: &[u8],
    ) -> Result<usize>;

    /// Build a short header packet into the provided buffer.
    ///
    /// Returns the number of bytes written on success.
    fn build_short_header(
        &self,
        buf: &mut [u8],
        header: &ShortHeader,
        payload: &[u8],
    ) -> Result<usize>;

    /// Encode a variable-length integer into the buffer.
    ///
    /// Returns the number of bytes written.
    fn encode_varint(&self, buf: &mut [u8], value: VarInt) -> Result<usize>;

    /// Calculate the required size for encoding a VarInt
    fn varint_size(&self, value: VarInt) -> usize;
}
