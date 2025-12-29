//! # Zero-Copy Packet Parser (RFC 9000 Section 17)
//!
//! Provides traits and implementations for parsing QUIC packets without
//! copying the underlying buffer. All parsed structures borrow from the
//! original datagram buffer.

extern crate alloc;

use crate::error::*;
use crate::packet::header::HeaderForm;
use crate::packet::types::*;
use crate::types::*;
use bytes::BytesMut;

/// Zero-Copy Packet Parser Trait
///
/// Parses QUIC packets from borrowed buffers. The returned ParsedPacket
/// contains references with lifetime 'a bound to the input buffer.
///
/// # Header Protection
///
/// This parser works on packets BEFORE header protection removal. The caller
/// must use HeaderProtectionRemover trait to decrypt the packet number field.
pub trait PacketParser: Send + Sync {
    /// Parse a single QUIC packet from the beginning of a buffer
    ///
    /// Returns the parsed packet and the number of bytes consumed.
    /// If the buffer contains multiple QUIC packets (coalescing), only the
    /// first packet is parsed. The caller must parse subsequent packets by
    /// advancing the buffer.
    ///
    /// # Errors
    ///
    /// - `FrameEncodingError`: Malformed packet header
    /// - `ProtocolViolation`: Invalid packet structure
    fn parse_packet<'a>(&self, buf: &'a [u8]) -> Result<(ParsedPacket<'a>, usize)>;

    /// Parse the first byte to determine packet type
    ///
    /// This is used for fast dispatch without full parsing.
    fn parse_first_byte(&self, first_byte: u8) -> Result<HeaderForm>;

    /// Parse only the destination connection ID
    ///
    /// Used for demultiplexing before full packet parsing.
    /// Returns (dcid, bytes_consumed)
    fn parse_dcid<'a>(&self, buf: &'a [u8]) -> Result<(ConnectionId, usize)>;
}

/// Header Protection Remover Trait (RFC 9001 Section 5.4)
///
/// Removes header protection in-place for a parsed packet.
/// This requires the packet payload to be decrypted to extract the sample.
///
/// # In-Place Operation
///
/// Header protection removal modifies the packet buffer in-place:
/// 1. Extract a 16-byte sample from the packet payload
/// 2. Apply XOR mask to the first byte and packet number bytes
/// 3. Decode the packet number using the unmasked length
///
/// The buffer MUST be mutable for in-place modification.
pub trait HeaderProtectionRemover {
    /// Remove header protection from a long header packet
    ///
    /// # Arguments
    ///
    /// - `buf`: Mutable buffer containing the packet (header + payload)
    /// - `header_len`: Length of the protected header (before PN)
    /// - `pn_offset`: Offset to the packet number field
    /// - `sample_offset`: Offset to the 16-byte sample in payload
    ///
    /// Returns the decoded packet number and packet number length.
    fn remove_long_header_protection(
        &mut self,
        buf: &mut [u8],
        header_len: usize,
        pn_offset: usize,
        sample_offset: usize,
    ) -> Result<(PacketNumber, u8)>;

    /// Remove header protection from a short header packet
    ///
    /// Same as long header but also extracts the key phase bit.
    fn remove_short_header_protection(
        &mut self,
        buf: &mut [u8],
        header_len: usize,
        pn_offset: usize,
        sample_offset: usize,
    ) -> Result<(PacketNumber, u8, bool)>;
}

/// Packet Number Decoder Trait (RFC 9000 Section 17.1)
///
/// Decodes truncated packet numbers from the wire format using the
/// expected packet number algorithm (RFC 9000 Section A.3).
pub trait PacketNumberDecoder {
    /// Decode a truncated packet number
    ///
    /// # Arguments
    ///
    /// - `truncated_pn`: The truncated packet number from the wire (1-4 bytes)
    /// - `pn_length`: Number of bytes in the truncated PN
    /// - `expected_pn`: The next expected packet number
    ///
    /// Returns the full 62-bit packet number.
    fn decode_packet_number(
        &self,
        truncated_pn: u64,
        pn_length: u8,
        expected_pn: PacketNumber,
    ) -> PacketNumber;
}

/// Packet Number Encoder Trait (RFC 9000 Section 17.1)
///
/// Encodes packet numbers in truncated form for transmission.
pub trait PacketNumberEncoder {
    /// Encode a packet number with minimal bytes
    ///
    /// # Arguments
    ///
    /// - `pn`: The full packet number to encode
    /// - `largest_acked`: The largest acknowledged packet number
    ///
    /// Returns (encoded_bytes, length)
    fn encode_packet_number(&self, pn: PacketNumber, largest_acked: PacketNumber) -> (u32, u8);
}

/// Packet Serializer Trait
///
/// Serializes QUIC packets into caller-provided BytesMut buffers.
/// This enables zero-allocation packet construction using the buffer
/// injection pattern.
pub trait PacketSerializer {
    /// Serialize a long header packet
    ///
    /// The caller provides the buffer and header/payload data.
    /// The serializer writes the packet structure and returns the number
    /// of bytes written.
    fn serialize_long_header(
        &mut self,
        buf: &mut BytesMut,
        header: &LongHeader,
        payload: &[u8],
    ) -> Result<usize>;

    /// Serialize a short header packet
    fn serialize_short_header(
        &mut self,
        buf: &mut BytesMut,
        header: &ShortHeader,
        payload: &[u8],
    ) -> Result<usize>;

    /// Serialize a Version Negotiation packet
    fn serialize_version_negotiation(
        &mut self,
        buf: &mut BytesMut,
        dcid: &ConnectionId,
        scid: &ConnectionId,
        supported_versions: &[Version],
    ) -> Result<usize>;
}

/// Packet Coalescing Helper
///
/// QUIC allows multiple packets in a single UDP datagram (RFC 9000 Section 12.2).
/// This trait helps parse and construct coalesced packets.
pub trait PacketCoalescer {
    /// Parse all packets from a datagram
    ///
    /// Returns a vector of parsed packets. The lifetime 'a is bound to the
    /// input buffer.
    fn parse_coalesced<'a>(&self, buf: &'a [u8]) -> Result<alloc::vec::Vec<ParsedPacket<'a>>>;

    /// Check if a buffer has room for additional packets
    ///
    /// Returns the remaining capacity after the current packet.
    fn coalesce_capacity(&self, buf: &BytesMut, current_len: usize) -> usize;
}

/// Default packet parser implementation
pub struct DefaultPacketParser {
    /// Maximum packet size to accept
    max_packet_size: usize,
}

impl DefaultPacketParser {
    /// Create a new packet parser
    pub fn new(max_packet_size: usize) -> Self {
        Self { max_packet_size }
    }
}

impl PacketParser for DefaultPacketParser {
    fn parse_packet<'a>(&self, _buf: &'a [u8]) -> Result<(ParsedPacket<'a>, usize)> {
        // TODO: Implement packet parsing
        Err(Error::Transport(TransportError::ProtocolViolation))
    }

    fn parse_first_byte(&self, _first_byte: u8) -> Result<HeaderForm> {
        // TODO: Implement first byte parsing
        Err(Error::Transport(TransportError::ProtocolViolation))
    }

    fn parse_dcid<'a>(&self, _buf: &'a [u8]) -> Result<(ConnectionId, usize)> {
        // TODO: Implement DCID extraction
        Err(Error::Transport(TransportError::ProtocolViolation))
    }
}

// Implementation would go in separate file
// This is just the trait definition skeleton
