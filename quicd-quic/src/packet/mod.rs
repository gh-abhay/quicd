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

