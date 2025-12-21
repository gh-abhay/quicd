//! # QUIC Packet Parsing (RFC 9000 Section 12, 17)
//!
//! This module handles packet headers, packet numbers, and packet number spaces.
//!
//! ## Packet Number Spaces (RFC 9000 Section 12.3)
//!
//! QUIC uses three separate packet number spaces, each with independent packet numbering:
//! - **Initial**: For Initial packets during handshake
//! - **Handshake**: For Handshake packets during handshake  
//! - **ApplicationData**: For 0-RTT and 1-RTT packets (application data)
//!
//! ## Packet Numbers (RFC 9000 Section 12.3, 17.1)
//!
//! Packet numbers are 62-bit integers that increase monotonically within a packet number space.
//! They are encoded using variable-length encoding (1-4 bytes) in packet headers.

#![forbid(unsafe_code)]

use crate::error::{Error, Result};

pub mod number;
pub mod space;

// ============================================================================
// Core Packet Types
// ============================================================================

/// Packet Number (RFC 9000 Section 12.3)
///
/// Packet numbers are 62-bit integers that increase monotonically within
/// a packet number space. They are encoded variably in packet headers.
///
/// **Encoding**: Packet numbers use truncated encoding (1-4 bytes) to save space.
/// The decoder must track the highest received packet number to reconstruct the full value.
pub type PacketNumber = u64;

/// Packet Number Space (RFC 9000 Section 12.3)
///
/// QUIC uses three separate packet number spaces to avoid conflicts between
/// different packet types during the handshake and application data phases.
///
/// Each space:
/// - Has independent packet number allocation starting from 0
/// - Has independent ACK state (ACK frames only acknowledge packets in the same space)
/// - Has independent loss detection timers
///
/// **Rationale**: Separation prevents ambiguity when packets are reordered across
/// different encryption levels during the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketNumberSpace {
    /// Initial packet number space (Initial packets)
    ///
    /// Used during the initial phase of the handshake.
    /// Uses Initial keys derived from the destination connection ID.
    Initial,
    
    /// Handshake packet number space (Handshake packets)
    ///
    /// Used during the cryptographic handshake.
    /// Uses Handshake keys derived from the TLS handshake.
    Handshake,
    
    /// Application Data packet number space (0-RTT and 1-RTT packets)
    ///
    /// Used for all application data after the handshake.
    /// Includes both 0-RTT (early data) and 1-RTT (protected) packets.
    ApplicationData,
}

impl PacketNumberSpace {
    /// Get the encryption level associated with this packet number space
    pub fn encryption_level(&self) -> crate::crypto::EncryptionLevel {
        match self {
            PacketNumberSpace::Initial => crate::crypto::EncryptionLevel::Initial,
            PacketNumberSpace::Handshake => crate::crypto::EncryptionLevel::Handshake,
            PacketNumberSpace::ApplicationData => crate::crypto::EncryptionLevel::ApplicationData,
        }
    }
}

// ============================================================================
// Packet Types (RFC 9000 Section 17)
// ============================================================================

/// QUIC Packet Type (RFC 9000 Section 17)
///
/// QUIC defines two packet header formats:
/// - **Long Header**: Used during handshake (Initial, 0-RTT, Handshake, Retry)
/// - **Short Header**: Used for application data (1-RTT)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    /// Initial packet (Long Header, type 0x00)
    ///
    /// Used for the first packets of a connection. Contains CRYPTO frames
    /// with TLS ClientHello or ServerHello.
    Initial,
    
    /// 0-RTT packet (Long Header, type 0x01)
    ///
    /// Client-only. Contains early data before the handshake completes.
    ZeroRtt,
    
    /// Handshake packet (Long Header, type 0x02)
    ///
    /// Contains CRYPTO frames with remaining TLS handshake messages.
    Handshake,
    
    /// Retry packet (Long Header, type 0x03)
    ///
    /// Server-only. Performs address validation before allocating state.
    Retry,
    
    /// 1-RTT packet (Short Header)
    ///
    /// Application data packets after handshake completes. Most common type.
    OneRtt,
    
    /// Version Negotiation packet (Long Header with Version 0)
    ///
    /// Server response when client version is not supported.
    VersionNegotiation,
}

impl PacketType {
    /// Check if this packet type uses a long header
    pub fn is_long_header(&self) -> bool {
        !matches!(self, PacketType::OneRtt)
    }
    
    /// Check if this packet type uses a short header
    pub fn is_short_header(&self) -> bool {
        matches!(self, PacketType::OneRtt)
    }
    
    /// Get the packet number space for this packet type
    pub fn packet_number_space(&self) -> Option<PacketNumberSpace> {
        match self {
            PacketType::Initial => Some(PacketNumberSpace::Initial),
            PacketType::ZeroRtt | PacketType::OneRtt => Some(PacketNumberSpace::ApplicationData),
            PacketType::Handshake => Some(PacketNumberSpace::Handshake),
            PacketType::Retry | PacketType::VersionNegotiation => None,
        }
    }
}

// ============================================================================
// Packet Header Structures
// ============================================================================

/// Parsed Packet Header (zero-copy)
///
/// This structure holds references to the original packet buffer for zero-copy parsing.
/// It represents the decoded header information without copying payload data.
#[derive(Debug, Clone, Copy)]
pub struct PacketHeader<'a> {
    /// Packet type
    pub packet_type: PacketType,
    
    /// QUIC version (for long headers)
    pub version: Option<u32>,
    
    /// Destination Connection ID
    pub dcid: &'a [u8],
    
    /// Source Connection ID (for long headers)
    pub scid: Option<&'a [u8]>,
    
    /// Packet number (decoded, not truncated)
    pub packet_number: PacketNumber,
    
    /// Packet number length in bytes (1-4)
    pub packet_number_length: usize,
    
    /// Token (for Initial and Retry packets)
    pub token: Option<&'a [u8]>,
    
    /// Key phase bit (for 1-RTT packets only)
    pub key_phase: Option<bool>,
    
    /// Length of the packet payload (for long headers)
    pub length: Option<usize>,
}

// ============================================================================
// Trait: Packet Parser (Zero-Copy)
// ============================================================================

/// Packet Parser Trait
///
/// Provides zero-copy parsing of QUIC packet headers from raw datagram bytes.
///
/// **Design**: All parsing methods return structures with lifetime `'a` bound to
/// the input slice, ensuring zero-copy semantics.
///
/// **Usage Pattern**:
/// ```rust,ignore
/// let datagram: &[u8] = /* received UDP payload */;
/// let parser = /* concrete implementation */;
///
/// let (header, payload) = parser.parse_header(datagram)?;
/// // `header.dcid` is a reference into `datagram`, not a copy
/// ```
pub trait PacketParser {
    /// Parse a packet header from a datagram
    ///
    /// # Arguments
    /// * `data` - Raw datagram bytes (may contain multiple coalesced packets)
    ///
    /// # Returns
    /// A tuple of (header, remaining_bytes):
    /// - `header`: Parsed packet header information
    /// - `remaining_bytes`: The encrypted payload + any coalesced packets
    ///
    /// # Errors
    /// Returns `Error::InvalidPacket` if the header is malformed.
    ///
    /// **Zero-Copy**: Header fields reference slices of the input `data`.
    fn parse_header<'a>(&self, data: &'a [u8]) -> Result<(PacketHeader<'a>, &'a [u8])>;
    
    /// Decode a truncated packet number (RFC 9000 Section 17.1)
    ///
    /// Packet numbers in headers are truncated (1-4 bytes) to save space.
    /// The full 62-bit value must be reconstructed using the highest received
    /// packet number in the same packet number space.
    ///
    /// # Arguments
    /// * `truncated_pn` - The truncated packet number from the header
    /// * `pn_length` - Number of bytes used to encode the packet number (1-4)
    /// * `largest_pn` - The largest packet number received in this space
    ///
    /// # Returns
    /// The full 62-bit packet number.
    ///
    /// **RFC 9000 Appendix A**: The algorithm finds the value closest to
    /// `largest_pn + 1` that has the same low bits as `truncated_pn`.
    fn decode_packet_number(
        &self,
        truncated_pn: u64,
        pn_length: usize,
        largest_pn: PacketNumber,
    ) -> PacketNumber;
}

// ============================================================================
// Trait: Packet Serializer (Zero-Copy)
// ============================================================================

/// Packet Serializer Trait
///
/// Serializes QUIC packet headers and frames into caller-provided buffers.
///
/// **Zero-Copy**: Frames are serialized directly into the output buffer
/// without intermediate allocations.
pub trait PacketSerializer {
    /// Serialize a packet header into a buffer
    ///
    /// # Arguments
    /// * `header` - The header to serialize
    /// * `buffer` - Pre-allocated buffer to write into
    ///
    /// # Returns
    /// The number of bytes written.
    ///
    /// **Note**: Does NOT include packet number or length fields, which are
    /// added later after determining the payload size.
    fn serialize_header(
        &self,
        header: &PacketHeader,
        buffer: &mut [u8],
    ) -> Result<usize>;
    
    /// Encode a packet number (RFC 9000 Section 17.1)
    ///
    /// Truncates the packet number to the minimum number of bytes (1-4)
    /// needed to unambiguously represent it relative to the largest
    /// acknowledged packet number.
    ///
    /// # Arguments
    /// * `packet_number` - The full 62-bit packet number
    /// * `largest_acked` - The largest packet number acknowledged by the peer
    ///
    /// # Returns
    /// A tuple of (encoded_bytes, length):
    /// - `encoded_bytes`: The packet number in big-endian format
    /// - `length`: Number of significant bytes (1-4)
    fn encode_packet_number(
        &self,
        packet_number: PacketNumber,
        largest_acked: PacketNumber,
    ) -> ([u8; 4], usize);
}

// ============================================================================
// Constants
// ============================================================================

/// QUIC Version 1 (RFC 9000)
pub const VERSION_1: u32 = 0x00000001;

/// Reserved version for version negotiation forcing
pub const VERSION_NEGOTIATION: u32 = 0x00000000;

/// Minimum packet size for Initial packets (RFC 9000 Section 14.1)
///
/// Initial packets must be padded to at least this size to provide PMTU
/// defense against amplification attacks.
pub const MIN_INITIAL_PACKET_SIZE: usize = 1200;

/// Maximum connection ID length (RFC 9000 Section 17.2)
pub const MAX_CID_LEN: usize = 20;

