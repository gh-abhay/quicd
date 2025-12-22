//! # Core QUIC Types (RFC 8999, RFC 9000)
//!
//! This module defines fundamental QUIC types used throughout the protocol.
//! All types are designed for zero-copy operations and no_std compatibility.

#![forbid(unsafe_code)]

use bytes::{Bytes, BytesMut};
use core::fmt;
use core::time::Duration;

/// Variable-Length Integer (RFC 9000 Section 16)
///
/// QUIC uses a variable-length encoding for integers. The first two bits
/// indicate the length: 00=1 byte, 01=2 bytes, 10=4 bytes, 11=8 bytes.
/// Maximum value: 2^62 - 1
pub type VarInt = u64;

/// Maximum value for VarInt (2^62 - 1)
pub const VARINT_MAX: u64 = (1u64 << 62) - 1;

/// Connection ID (RFC 9000 Section 5.1, RFC 8999 Section 5.3)
///
/// Opaque identifier for a connection. Length: 0-20 bytes.
/// Used for routing packets to the correct connection context.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionId {
    bytes: tinyvec::TinyVec<[u8; 20]>,
}

impl ConnectionId {
    /// Maximum Connection ID length in bytes (RFC 9000 Section 17.2)
    pub const MAX_LENGTH: usize = 20;

    /// Create a new Connection ID from a byte slice.
    /// Returns None if length > 20 bytes.
    pub fn new(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > Self::MAX_LENGTH {
            return None;
        }
        let mut vec = tinyvec::TinyVec::new();
        vec.extend_from_slice(bytes);
        Some(Self { bytes: vec })
    }

    /// Returns the byte slice of this Connection ID
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the length in bytes
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns true if the Connection ID is zero-length
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Packet Number (RFC 9000 Section 12.3)
///
/// 62-bit packet number. Encoded in 1-4 bytes in packet headers.
/// Monotonically increasing per packet number space.
pub type PacketNumber = u64;

/// Maximum Packet Number value (2^62 - 1)
pub const PACKET_NUMBER_MAX: u64 = VARINT_MAX;

/// Stream ID (RFC 9000 Section 2.1)
///
/// 62-bit identifier for streams. Lower 2 bits encode:
/// - Bit 0: Client-initiated (0) or Server-initiated (1)
/// - Bit 1: Bidirectional (0) or Unidirectional (1)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(pub u64);

impl StreamId {
    /// Extract the initiator from a stream ID
    pub fn initiator(self) -> StreamInitiator {
        if self.0 & 0x01 == 0 {
            StreamInitiator::Client
        } else {
            StreamInitiator::Server
        }
    }

    /// Extract the direction from a stream ID
    pub fn direction(self) -> StreamDirection {
        if self.0 & 0x02 == 0 {
            StreamDirection::Bidirectional
        } else {
            StreamDirection::Unidirectional
        }
    }

    /// Check if this stream ID is for a bidirectional stream
    pub fn is_bidirectional(self) -> bool {
        matches!(self.direction(), StreamDirection::Bidirectional)
    }

    /// Check if this stream ID is for a unidirectional stream
    pub fn is_unidirectional(self) -> bool {
        matches!(self.direction(), StreamDirection::Unidirectional)
    }

    /// Check if this stream was initiated by the client
    pub fn is_client_initiated(self) -> bool {
        matches!(self.initiator(), StreamInitiator::Client)
    }

    /// Check if this stream was initiated by the server
    pub fn is_server_initiated(self) -> bool {
        matches!(self.initiator(), StreamInitiator::Server)
    }

    /// Get the inner u64 value
    pub fn into_inner(self) -> u64 {
        self.0
    }
}

/// Stream Offset (RFC 9000 Section 2.2)
///
/// Byte offset within a stream. Used in STREAM frames.
pub type StreamOffset = u64;

/// Packet Number Space (RFC 9000 Section 12.1)
///
/// QUIC has three distinct packet number spaces, each with independent
/// packet number sequences:
/// - Initial: Used for initial handshake packets
/// - Handshake: Used after Initial keys are available
/// - ApplicationData: Used for 0-RTT and 1-RTT packets
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketNumberSpace {
    /// Initial packet number space
    Initial,
    /// Handshake packet number space
    Handshake,
    /// Application data packet number space (0-RTT and 1-RTT)
    ApplicationData,
}

/// Instant in time (monotonic clock)
///
/// Used for tracking packet send/receive times, timeouts, etc.
/// Intentionally opaque - implementation provides this via poll().
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant {
    /// Nanoseconds since an arbitrary epoch
    nanos: u64,
}

impl Instant {
    /// Create a new instant from nanoseconds
    pub fn from_nanos(nanos: u64) -> Self {
        Self { nanos }
    }

    /// Get nanoseconds since epoch
    pub fn as_nanos(&self) -> u64 {
        self.nanos
    }

    /// Calculate duration since another instant
    pub fn duration_since(&self, earlier: Instant) -> Duration {
        Duration::from_nanos(self.nanos.saturating_sub(earlier.nanos))
    }

    /// Add a duration to this instant
    pub fn checked_add(&self, duration: Duration) -> Option<Self> {
        self.nanos
            .checked_add(duration.as_nanos() as u64)
            .map(|nanos| Self { nanos })
    }
}

/// Side of the connection (RFC 9000 Section 3)
///
/// Distinguishes between client and server roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// Client initiated the connection
    Client,
    /// Server accepted the connection
    Server,
}

impl Side {
    /// Returns true if this side initiates streams with even IDs
    pub fn initiates_even_streams(&self) -> bool {
        matches!(self, Side::Client)
    }

    /// Returns true if this is the client side
    pub fn is_client(&self) -> bool {
        matches!(self, Side::Client)
    }

    /// Returns true if this is the server side
    pub fn is_server(&self) -> bool {
        matches!(self, Side::Server)
    }
}

/// Stream Direction (RFC 9000 Section 2.1)
///
/// Indicates whether a stream is bidirectional or unidirectional.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamDirection {
    /// Bidirectional stream - both endpoints can send data
    Bidirectional,
    /// Unidirectional stream - only initiator can send data
    Unidirectional,
}

/// Stream Initiator (RFC 9000 Section 2.1)
///
/// Indicates which side initiated the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamInitiator {
    /// Client-initiated stream
    Client,
    /// Server-initiated stream
    Server,
}



/// Token (RFC 9000 Section 8.1)
///
/// Opaque blob used for address validation and stateless retry.
/// - Retry Token: Sent in Retry packets
/// - NEW_TOKEN: Sent in NEW_TOKEN frames for future connections
pub type Token = Bytes;

/// Stateless Reset Token (RFC 9000 Section 10.3)
///
/// 16-byte token used to reset a connection without per-connection state.
pub type StatelessResetToken = [u8; 16];

/// Maximum UDP payload size (bytes)
///
/// RFC 9000 Section 14: Initial packets must be at least 1200 bytes.
/// IPv6 minimum MTU is 1280 bytes, leaving room for UDP/IP headers.
pub const MIN_INITIAL_PACKET_SIZE: usize = 1200;

/// Maximum QUIC packet size (without considering MTU)
pub const MAX_PACKET_SIZE: usize = 65527; // Max UDP payload for IPv6

/// Default maximum datagram size
pub const DEFAULT_MAX_DATAGRAM_SIZE: usize = 1200;

/// Error Code (generic)
///
/// Used in RESET_STREAM and STOP_SENDING frames.
pub type ErrorCode = u64;
