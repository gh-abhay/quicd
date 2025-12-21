//! # QUIC Version Negotiation and Invariants (RFC 8999, RFC 9000 Section 6)
//!
//! This module handles QUIC version negotiation and defines version-independent
//! properties that remain constant across all QUIC versions.
//!
//! ## RFC 8999: Version-Independent Properties
//!
//! Certain packet format elements must remain invariant across QUIC versions
//! to allow intermediaries (like load balancers) to process QUIC packets
//! without understanding the specific version.
//!
//! ### Invariants:
//! 1. **Header Format**: First byte has a header form bit (0x80)
//! 2. **Long Header**: Contains Version field, DCID length, DCID, SCID length, SCID
//! 3. **Short Header**: Contains DCID (length established during handshake)
//! 4. **Version Negotiation**: Uses version 0x00000000
//!
//! ## Version Negotiation Process (RFC 9000 Section 6)
//!
//! 1. Client sends Initial packet with chosen version
//! 2. Server doesn't support that version → sends Version Negotiation packet
//! 3. Client retries with a version from the server's list
//! 4. If no common version, connection fails

#![forbid(unsafe_code)]

use crate::error::{Error, Result};

// ============================================================================
// QUIC Version Constants
// ============================================================================

/// QUIC Version 1 (RFC 9000)
///
/// The first standardized version of QUIC.
pub const VERSION_1: u32 = 0x00000001;

/// Version used in Version Negotiation packets (RFC 9000 Section 6)
///
/// This value (0x00000000) indicates that the packet is a Version Negotiation
/// packet and does not represent an actual QUIC version.
pub const VERSION_NEGOTIATION: u32 = 0x00000000;

/// Version 2 (RFC 9369)
///
/// An alias for Version 1 with different packet protection to detect middlebox
/// ossification. Functionally identical to Version 1.
pub const VERSION_2: u32 = 0x6b3343cf;

/// Reserved versions for version negotiation forcing (RFC 9000 Section 6.3)
///
/// These versions have the form 0x?a?a?a?a (where ? is any hex digit).
/// They are used to ensure version negotiation is working correctly.
///
/// **Example**: 0x0a0a0a0a, 0x1a1a1a1a, 0xfafafafa
pub fn is_reserved_version(version: u32) -> bool {
    (version & 0x0f0f0f0f) == 0x0a0a0a0a
}

// ============================================================================
// Version Negotiation Traits
// ============================================================================

/// QUIC Version Trait
///
/// Represents a specific QUIC version with its associated behavior.
pub trait QuicVersion {
    /// Get the version number
    fn version(&self) -> u32;
    
    /// Get the Initial salt for key derivation (RFC 9001 Section 5.2)
    ///
    /// Different versions may use different salts for Initial packet protection.
    fn initial_salt(&self) -> &'static [u8];
    
    /// Check if this version supports a specific feature
    fn supports_feature(&self, feature: VersionFeature) -> bool;
}

/// Version-Specific Features
///
/// Features that may vary between QUIC versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionFeature {
    /// Support for DATAGRAM frames (RFC 9221)
    Datagrams,
    
    /// Support for Greasing (RFC 9287)
    Greasing,
    
    /// Support for Version Negotiation (RFC 9368)
    CompatibleVersionNegotiation,
    
    /// Support for Acknowledgment Frequency (draft-ietf-quic-ack-frequency)
    AckFrequency,
}

// ============================================================================
// Version Negotiation State Machine
// ============================================================================

/// Version Negotiation Handler
///
/// Manages the version negotiation process for a connection.
pub trait VersionNegotiator {
    /// Handle an incoming Version Negotiation packet
    ///
    /// # Arguments
    /// * `supported_versions` - List of versions advertised by the server
    /// * `original_version` - The version used in the client's Initial packet
    ///
    /// # Returns
    /// The version to use for the next connection attempt, or `None` if
    /// no compatible version is found.
    ///
    /// **RFC 9000 Section 6.2**: The client must validate that:
    /// 1. The original version is not in the supported list
    /// 2. A reserved version is in the list (greasing check)
    fn negotiate_version(
        &self,
        supported_versions: &[u32],
        original_version: u32,
    ) -> Option<u32>;
    
    /// Generate a Version Negotiation packet
    ///
    /// # Arguments
    /// * `buffer` - Pre-allocated buffer to write the packet
    /// * `dcid` - Destination Connection ID (from client's Initial packet)
    /// * `scid` - Source Connection ID (server-generated)
    /// * `supported_versions` - List of versions supported by the server
    ///
    /// # Returns
    /// The number of bytes written to the buffer.
    ///
    /// **RFC 9000 Section 17.2.1**: Version Negotiation packet format:
    /// ```text
    /// Version Negotiation Packet {
    ///   Header Form (1) = 1,
    ///   Unused (7),
    ///   Version (32) = 0,
    ///   Destination Connection ID Length (8),
    ///   Destination Connection ID (0..2040),
    ///   Source Connection ID Length (8),
    ///   Source Connection ID (0..2040),
    ///   Supported Version (32) ...,
    /// }
    /// ```
    fn generate_version_negotiation(
        &self,
        buffer: &mut [u8],
        dcid: &[u8],
        scid: &[u8],
        supported_versions: &[u32],
    ) -> Result<usize>;
}

// ============================================================================
// Invariant Properties (RFC 8999)
// ============================================================================

/// QUIC Packet Header Invariants
///
/// Properties that MUST remain consistent across all QUIC versions.
/// These are relied upon by middleboxes and load balancers.
pub struct PacketInvariants;

impl PacketInvariants {
    /// Check if a packet has the long header form
    ///
    /// **Invariant**: The first bit (0x80) indicates header form.
    /// - `1`: Long header
    /// - `0`: Short header
    pub fn is_long_header(first_byte: u8) -> bool {
        (first_byte & 0x80) == 0x80
    }
    
    /// Check if a packet has the fixed bit set
    ///
    /// **Invariant (RFC 9000 Section 17.2)**: The second bit (0x40) is the
    /// fixed bit and MUST be set to 1 in all QUIC packets (except Version
    /// Negotiation). Packets with this bit unset are not QUIC packets.
    ///
    /// **Purpose**: Allows distinguishing QUIC from other protocols on the
    /// same port (e.g., DTLS).
    pub fn has_fixed_bit(first_byte: u8) -> bool {
        (first_byte & 0x40) == 0x40
    }
    
    /// Extract the version field from a long header packet
    ///
    /// **Invariant**: The version field is at bytes 1-4 (big-endian u32)
    /// for all long header packets.
    ///
    /// **Returns**: `None` if the buffer is too short or not a long header.
    pub fn extract_version(packet: &[u8]) -> Option<u32> {
        if packet.len() < 5 || !Self::is_long_header(packet[0]) {
            return None;
        }
        
        Some(u32::from_be_bytes([
            packet[1],
            packet[2],
            packet[3],
            packet[4],
        ]))
    }
    
    /// Extract destination connection ID length from a long header
    ///
    /// **Invariant**: The DCID length field is at byte 5 for long headers.
    pub fn extract_dcid_length(packet: &[u8]) -> Option<usize> {
        if packet.len() < 6 || !Self::is_long_header(packet[0]) {
            return None;
        }
        
        Some(packet[5] as usize)
    }
    
    /// Extract destination connection ID from a packet
    ///
    /// **Invariant**: For long headers, DCID follows the length field.
    /// For short headers, DCID starts at byte 1 (length established during handshake).
    pub fn extract_dcid<'a>(packet: &'a [u8], dcid_len: usize) -> Option<&'a [u8]> {
        if Self::is_long_header(packet[0]) {
            // Long header: DCID starts at byte 6
            if packet.len() < 6 + dcid_len {
                return None;
            }
            Some(&packet[6..6 + dcid_len])
        } else {
            // Short header: DCID starts at byte 1
            if packet.len() < 1 + dcid_len {
                return None;
            }
            Some(&packet[1..1 + dcid_len])
        }
    }
    
    /// Validate packet against version-independent properties
    ///
    /// Returns `Ok(())` if the packet adheres to invariants, otherwise an error.
    pub fn validate_packet(packet: &[u8]) -> Result<()> {
        if packet.is_empty() {
            return Err(Error::InvalidPacket);
        }
        
        let first_byte = packet[0];
        
        // Check fixed bit (except for Version Negotiation packets)
        if Self::is_long_header(first_byte) {
            if let Some(version) = Self::extract_version(packet) {
                if version != VERSION_NEGOTIATION && !Self::has_fixed_bit(first_byte) {
                    return Err(Error::InvalidPacket);
                }
            }
        } else {
            // Short header must have fixed bit set
            if !Self::has_fixed_bit(first_byte) {
                return Err(Error::InvalidPacket);
            }
        }
        
        Ok(())
    }
}

// ============================================================================
// Version Selection Strategy
// ============================================================================

/// Version Selection Strategy
///
/// Defines the policy for selecting a QUIC version when multiple are available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionSelectionStrategy {
    /// Prefer the highest mutually supported version
    PreferLatest,
    
    /// Prefer Version 1 (most widely deployed)
    PreferV1,
    
    /// Use a specific version (for testing)
    UseSpecific(u32),
}

impl VersionSelectionStrategy {
    /// Select a version from the available list
    ///
    /// # Arguments
    /// * `available` - List of versions supported by both endpoints
    ///
    /// # Returns
    /// The selected version, or `None` if no compatible version exists.
    pub fn select(&self, available: &[u32]) -> Option<u32> {
        match self {
            VersionSelectionStrategy::PreferLatest => {
                available.iter().copied().max()
            }
            VersionSelectionStrategy::PreferV1 => {
                if available.contains(&VERSION_1) {
                    Some(VERSION_1)
                } else {
                    available.first().copied()
                }
            }
            VersionSelectionStrategy::UseSpecific(version) => {
                if available.contains(version) {
                    Some(*version)
                } else {
                    None
                }
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_reserved_version() {
        assert!(is_reserved_version(0x0a0a0a0a));
        assert!(is_reserved_version(0x1a1a1a1a));
        assert!(is_reserved_version(0xfafafafa));
        assert!(!is_reserved_version(VERSION_1));
        assert!(!is_reserved_version(VERSION_NEGOTIATION));
    }
    
    #[test]
    fn test_header_invariants() {
        // Long header packet (Initial)
        let long_header = [0xc0, 0x00, 0x00, 0x00, 0x01, 0x08];
        assert!(PacketInvariants::is_long_header(long_header[0]));
        assert!(PacketInvariants::has_fixed_bit(long_header[0]));
        assert_eq!(PacketInvariants::extract_version(&long_header), Some(VERSION_1));
        
        // Short header packet
        let short_header = [0x40];
        assert!(!PacketInvariants::is_long_header(short_header[0]));
        assert!(PacketInvariants::has_fixed_bit(short_header[0]));
    }
}
