//! # Core QUIC Types (RFC 8999, RFC 9000)
//!
//! This module defines fundamental QUIC types used throughout the protocol.
//! All types are designed for zero-copy operations and no_std compatibility.

#![forbid(unsafe_code)]

extern crate alloc;

use bytes::Bytes;
use core::time::Duration;

// ============================================================================
// Variable-Length Integer Encoding (RFC 9000 Section 16)
// ============================================================================

/// Variable-Length Integer (RFC 9000 Section 16)
///
/// QUIC uses a variable-length encoding for integers. The first two bits
/// indicate the length: 00=1 byte, 01=2 bytes, 10=4 bytes, 11=8 bytes.
/// Maximum value: 2^62 - 1
pub type VarInt = u64;

/// Maximum value for VarInt (2^62 - 1)
pub const VARINT_MAX: u64 = (1u64 << 62) - 1;

/// VarInt encoding and decoding utilities
pub struct VarIntCodec;

impl VarIntCodec {
    /// Decode a VarInt from a byte slice, returning (value, bytes_consumed)
    ///
    /// Returns None if buffer is too short or value exceeds VARINT_MAX
    pub fn decode(buf: &[u8]) -> Option<(VarInt, usize)> {
        if buf.is_empty() {
            return None;
        }

        let first = buf[0];
        let tag = first >> 6;

        match tag {
            0b00 => {
                // 1-byte encoding
                Some((first as u64 & 0x3f, 1))
            }
            0b01 => {
                // 2-byte encoding
                if buf.len() < 2 {
                    return None;
                }
                let value = ((first as u64 & 0x3f) << 8) | buf[1] as u64;
                Some((value, 2))
            }
            0b10 => {
                // 4-byte encoding
                if buf.len() < 4 {
                    return None;
                }
                let value = ((first as u64 & 0x3f) << 24)
                    | ((buf[1] as u64) << 16)
                    | ((buf[2] as u64) << 8)
                    | (buf[3] as u64);
                Some((value, 4))
            }
            0b11 => {
                // 8-byte encoding
                if buf.len() < 8 {
                    return None;
                }
                let value = ((first as u64 & 0x3f) << 56)
                    | ((buf[1] as u64) << 48)
                    | ((buf[2] as u64) << 40)
                    | ((buf[3] as u64) << 32)
                    | ((buf[4] as u64) << 24)
                    | ((buf[5] as u64) << 16)
                    | ((buf[6] as u64) << 8)
                    | (buf[7] as u64);
                Some((value, 8))
            }
            _ => unreachable!(),
        }
    }

    /// Encode a VarInt into a buffer, returning bytes written
    ///
    /// Returns None if value exceeds VARINT_MAX or buffer is too small
    pub fn encode(value: VarInt, buf: &mut [u8]) -> Option<usize> {
        if value > VARINT_MAX {
            return None;
        }

        if value < 0x40 {
            // 1-byte encoding
            if buf.is_empty() {
                return None;
            }
            buf[0] = value as u8;
            Some(1)
        } else if value < 0x4000 {
            // 2-byte encoding
            if buf.len() < 2 {
                return None;
            }
            buf[0] = 0x40 | ((value >> 8) as u8);
            buf[1] = value as u8;
            Some(2)
        } else if value < 0x40000000 {
            // 4-byte encoding
            if buf.len() < 4 {
                return None;
            }
            buf[0] = 0x80 | ((value >> 24) as u8);
            buf[1] = (value >> 16) as u8;
            buf[2] = (value >> 8) as u8;
            buf[3] = value as u8;
            Some(4)
        } else {
            // 8-byte encoding
            if buf.len() < 8 {
                return None;
            }
            buf[0] = 0xc0 | ((value >> 56) as u8);
            buf[1] = (value >> 48) as u8;
            buf[2] = (value >> 40) as u8;
            buf[3] = (value >> 32) as u8;
            buf[4] = (value >> 24) as u8;
            buf[5] = (value >> 16) as u8;
            buf[6] = (value >> 8) as u8;
            buf[7] = value as u8;
            Some(8)
        }
    }

    /// Calculate the encoded size for a given value
    pub fn size(value: VarInt) -> usize {
        if value < 0x40 {
            1
        } else if value < 0x4000 {
            2
        } else if value < 0x40000000 {
            4
        } else {
            8
        }
    }
}

// ============================================================================
// Connection ID (RFC 9000 Section 5.1, RFC 8999 Section 5.3)
// ============================================================================

/// Maximum length of a Connection ID (20 bytes per RFC 9000)
pub const MAX_CID_LENGTH: usize = 20;

/// Connection ID - Version-independent identifier (RFC 8999 Section 5.3)
///
/// Connection IDs are opaque byte sequences chosen by endpoints.
/// Zero-length CIDs are permitted.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnectionId {
    bytes: Bytes,
}

impl ConnectionId {
    /// Create a new ConnectionId from bytes
    ///
    /// Returns None if length exceeds MAX_CID_LENGTH
    pub fn new(bytes: Bytes) -> Option<Self> {
        if bytes.len() > MAX_CID_LENGTH {
            return None;
        }
        Some(Self { bytes })
    }

    /// Create from a borrowed slice (copies data)
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() > MAX_CID_LENGTH {
            return None;
        }
        Some(Self {
            bytes: Bytes::copy_from_slice(slice),
        })
    }

    /// Access the underlying bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Length of the connection ID
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if this is a zero-length connection ID
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Create an empty (zero-length) connection ID
    pub fn empty() -> Self {
        Self {
            bytes: Bytes::new(),
        }
    }
}

impl core::fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ConnectionId({:02x?})", &self.bytes[..])
    }
}

impl core::fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in &self.bytes[..] {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

// ============================================================================
// Packet Number (RFC 9000 Section 12.3)
// ============================================================================

/// Packet Number - Monotonically increasing per packet number space
///
/// Packet numbers are 62-bit integers (0 to 2^62-1) that increase
/// monotonically within each packet number space.
pub type PacketNumber = u64;

/// Maximum packet number value (2^62 - 1)
pub const MAX_PACKET_NUMBER: u64 = (1u64 << 62) - 1;

/// Packet Number Space (RFC 9000 Section 12.3)
///
/// QUIC uses three separate packet number spaces to avoid ambiguity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketNumberSpace {
    /// Initial packet space (Initial packets)
    Initial = 0,
    /// Handshake packet space (Handshake packets)
    Handshake = 1,
    /// Application data packet space (0-RTT and 1-RTT packets)
    ApplicationData = 2,
}

// ============================================================================
// Stream ID (RFC 9000 Section 2.1)
// ============================================================================

/// Stream ID - Identifies a bidirectional or unidirectional stream
///
/// The two least significant bits encode stream type and initiator:
/// - Bit 0: Direction (0=bidirectional, 1=unidirectional)
/// - Bit 1: Initiator (0=client, 1=server)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(pub u64);

impl StreamId {
    /// Create a new StreamId
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// Get the raw value
    pub fn value(&self) -> u64 {
        self.0
    }

    /// Construct StreamId from raw u64 (alias for new())
    pub fn from_raw(id: u64) -> Self {
        Self(id)
    }

    /// Convert StreamId into raw u64
    pub fn into_inner(self) -> u64 {
        self.0
    }

    /// Check if this stream is bidirectional
    pub fn is_bidirectional(&self) -> bool {
        (self.0 & 0x02) == 0
    }

    /// Check if this stream is unidirectional
    pub fn is_unidirectional(&self) -> bool {
        (self.0 & 0x02) != 0
    }
}

// Implement BitAnd for StreamId to support bitwise operations
impl core::ops::BitAnd<u64> for StreamId {
    type Output = u64;

    fn bitand(self, rhs: u64) -> u64 {
        self.0 & rhs
    }
}

// Implement PartialEq<u64> for StreamId comparisons
impl PartialEq<u64> for StreamId {
    fn eq(&self, other: &u64) -> bool {
        self.0 == *other
    }
}

/// Maximum Stream ID value (2^62 - 1)
pub const MAX_STREAM_ID: u64 = VARINT_MAX;

/// Stream Type - Encodes directionality and initiator
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamType {
    /// Client-initiated bidirectional stream
    ClientBidirectional = 0x00,
    /// Server-initiated bidirectional stream
    ServerBidirectional = 0x01,
    /// Client-initiated unidirectional stream
    ClientUnidirectional = 0x02,
    /// Server-initiated unidirectional stream
    ServerUnidirectional = 0x03,
}

impl StreamType {
    /// Extract stream type from stream ID
    pub fn from_stream_id(id: StreamId) -> Self {
        match id.0 & 0x03 {
            0x00 => StreamType::ClientBidirectional,
            0x01 => StreamType::ServerBidirectional,
            0x02 => StreamType::ClientUnidirectional,
            0x03 => StreamType::ServerUnidirectional,
            _ => unreachable!(),
        }
    }

    /// Check if this stream type is bidirectional
    pub fn is_bidirectional(self) -> bool {
        matches!(
            self,
            StreamType::ClientBidirectional | StreamType::ServerBidirectional
        )
    }

    /// Check if this stream type is unidirectional
    pub fn is_unidirectional(self) -> bool {
        !self.is_bidirectional()
    }

    /// Check if client initiated this stream type
    pub fn is_client_initiated(self) -> bool {
        matches!(
            self,
            StreamType::ClientBidirectional | StreamType::ClientUnidirectional
        )
    }

    /// Check if server initiated this stream type
    pub fn is_server_initiated(self) -> bool {
        !self.is_client_initiated()
    }
}

/// Stream Offset - Byte offset within a stream
pub type StreamOffset = u64;

// ============================================================================
// Side (Client vs Server)
// ============================================================================

/// Connection endpoint side
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// Client endpoint
    Client,
    /// Server endpoint
    Server,
}

impl Side {
    /// Check if this side is the client
    pub fn is_client(self) -> bool {
        matches!(self, Side::Client)
    }

    /// Check if this side is the server
    pub fn is_server(self) -> bool {
        matches!(self, Side::Server)
    }

    /// Get the opposite side
    pub fn opposite(self) -> Side {
        match self {
            Side::Client => Side::Server,
            Side::Server => Side::Client,
        }
    }
}

// ============================================================================
// Time Abstraction (no_std compatible)
// ============================================================================

/// Monotonic timestamp for QUIC timing operations
///
/// This abstraction allows no_std usage. The caller must provide
/// a monotonic clock source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant {
    /// Nanoseconds since an arbitrary epoch
    nanos: u64,
}

impl Instant {
    /// Create an Instant from nanoseconds since epoch
    pub fn from_nanos(nanos: u64) -> Self {
        Self { nanos }
    }

    /// Get nanoseconds since epoch
    pub fn as_nanos(&self) -> u64 {
        self.nanos
    }

    /// Calculate duration since another instant
    ///
    /// Returns None if other is later than self
    pub fn duration_since(&self, other: Instant) -> Option<Duration> {
        if self.nanos >= other.nanos {
            Some(Duration::from_nanos(self.nanos - other.nanos))
        } else {
            None
        }
    }

    /// Calculate duration until another instant
    pub fn duration_until(&self, other: Instant) -> Option<Duration> {
        other.duration_since(*self)
    }

    /// Add a duration to this instant
    pub fn checked_add(&self, duration: Duration) -> Option<Instant> {
        let nanos = duration.as_nanos();
        if nanos > u64::MAX as u128 {
            return None;
        }
        self.nanos
            .checked_add(nanos as u64)
            .map(|n| Instant { nanos: n })
    }

    /// Subtract a duration from this instant
    pub fn checked_sub(&self, duration: Duration) -> Option<Instant> {
        let nanos = duration.as_nanos();
        if nanos > u64::MAX as u128 {
            return None;
        }
        self.nanos
            .checked_sub(nanos as u64)
            .map(|n| Instant { nanos: n })
    }
}

// ============================================================================
// Token (RFC 9000 Section 8.1)
// ============================================================================

/// Address Validation Token
///
/// Opaque blob issued by servers for address validation.
/// Clients echo these in subsequent Initial packets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    bytes: Bytes,
}

impl Token {
    /// Create a new token from bytes
    pub fn new(bytes: Bytes) -> Self {
        Self { bytes }
    }

    /// Create token from slice (copies data)
    pub fn from_slice(slice: &[u8]) -> Self {
        Self {
            bytes: Bytes::copy_from_slice(slice),
        }
    }

    /// Access the underlying bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Length of the token
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if token is empty
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

// ============================================================================
// Constants from RFC 9000
// ============================================================================

/// Default UDP payload size (1200 bytes per RFC 9000 Section 14.1)
pub const DEFAULT_MAX_UDP_PAYLOAD_SIZE: usize = 1200;

/// Minimum Initial packet size (1200 bytes per RFC 9000 Section 14.1)
pub const MIN_INITIAL_PACKET_SIZE: usize = 1200;

/// Maximum UDP payload size for IPv4 (65527 bytes)
pub const MAX_UDP_PAYLOAD_SIZE_IPV4: usize = 65527;

/// Maximum UDP payload size for IPv6 (65535 bytes)
pub const MAX_UDP_PAYLOAD_SIZE_IPV6: usize = 65535;

/// Default idle timeout (30 seconds)
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum idle timeout (600 seconds per RFC 9000)
pub const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(600);

/// Default maximum number of bidirectional streams
pub const DEFAULT_MAX_STREAMS_BIDI: u64 = 100;

/// Default maximum number of unidirectional streams
pub const DEFAULT_MAX_STREAMS_UNI: u64 = 100;

/// Default initial maximum data (15 MB)
pub const DEFAULT_INITIAL_MAX_DATA: u64 = 15 * 1024 * 1024;

/// Default initial maximum stream data for bidirectional streams (6 MB)
pub const DEFAULT_INITIAL_MAX_STREAM_DATA_BIDI: u64 = 6 * 1024 * 1024;

/// Default initial maximum stream data for unidirectional streams (6 MB)
pub const DEFAULT_INITIAL_MAX_STREAM_DATA_UNI: u64 = 6 * 1024 * 1024;

// Additional types needed by the crate
pub type StatelessResetToken = [u8; 16];

/// Stream Direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamDirection {
    Bidirectional,
    Unidirectional,
}

/// Stream Initiator
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamInitiator {
    Client,
    Server,
}

// ============================================================================
// StreamId Helper Functions
// ============================================================================

/// Helper functions for StreamId operations
pub mod stream_id_helpers {
    use super::*;

    /// Create a StreamId from raw u64 value
    #[inline]
    pub fn from_raw(id: u64) -> StreamId {
        StreamId::from_raw(id)
    }

    /// Get the raw u64 value from StreamId
    #[inline]
    pub fn into_inner(id: StreamId) -> u64 {
        id.into_inner()
    }

    /// Get the initiator of a stream
    #[inline]
    pub fn initiator(id: StreamId) -> StreamInitiator {
        if (id & 0x01) == 0 {
            StreamInitiator::Client
        } else {
            StreamInitiator::Server
        }
    }

    /// Get the direction of a stream
    #[inline]
    pub fn direction(id: StreamId) -> StreamDirection {
        if (id & 0x02) == 0 {
            StreamDirection::Bidirectional
        } else {
            StreamDirection::Unidirectional
        }
    }

    /// Check if stream is client-initiated
    #[inline]
    pub fn is_client_initiated(id: StreamId) -> bool {
        (id & 0x01) == 0
    }

    /// Check if stream is server-initiated
    #[inline]
    pub fn is_server_initiated(id: StreamId) -> bool {
        (id & 0x01) == 1
    }

    /// Check if stream is bidirectional
    #[inline]
    pub fn is_bidirectional(id: StreamId) -> bool {
        (id & 0x02) == 0
    }

    /// Check if stream is unidirectional
    #[inline]
    pub fn is_unidirectional(id: StreamId) -> bool {
        (id & 0x02) != 0
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // VarInt Tests (RFC 9000 Section 16)
    // ========================================================================

    mod varint_tests {
        use super::*;

        #[test]
        fn test_varint_decode_1byte_minimum() {
            // RFC 9000 Section 16: 1-byte encoding for 0-63
            let buf = [0x00];
            let (value, consumed) = VarIntCodec::decode(&buf).unwrap();
            assert_eq!(value, 0);
            assert_eq!(consumed, 1);
        }

        #[test]
        fn test_varint_decode_1byte_maximum() {
            // RFC 9000 Section 16: 1-byte max is 63 (0x3f)
            let buf = [0x3f];
            let (value, consumed) = VarIntCodec::decode(&buf).unwrap();
            assert_eq!(value, 63);
            assert_eq!(consumed, 1);
        }

        #[test]
        fn test_varint_decode_2byte_minimum() {
            // RFC 9000 Section 16: 2-byte encoding starts at 64 (0x4040)
            let buf = [0x40, 0x40];
            let (value, consumed) = VarIntCodec::decode(&buf).unwrap();
            assert_eq!(value, 64);
            assert_eq!(consumed, 2);
        }

        #[test]
        fn test_varint_decode_2byte_maximum() {
            // RFC 9000 Section 16: 2-byte max is 16383 (0x7fff)
            let buf = [0x7f, 0xff];
            let (value, consumed) = VarIntCodec::decode(&buf).unwrap();
            assert_eq!(value, 16383);
            assert_eq!(consumed, 2);
        }

        #[test]
        fn test_varint_decode_4byte_minimum() {
            // RFC 9000 Section 16: 4-byte encoding starts at 16384 (0x80004000)
            let buf = [0x80, 0x00, 0x40, 0x00];
            let (value, consumed) = VarIntCodec::decode(&buf).unwrap();
            assert_eq!(value, 16384);
            assert_eq!(consumed, 4);
        }

        #[test]
        fn test_varint_decode_4byte_maximum() {
            // RFC 9000 Section 16: 4-byte max is 1073741823 (0xbfffffff)
            let buf = [0xbf, 0xff, 0xff, 0xff];
            let (value, consumed) = VarIntCodec::decode(&buf).unwrap();
            assert_eq!(value, 1073741823);
            assert_eq!(consumed, 4);
        }

        #[test]
        fn test_varint_decode_8byte_minimum() {
            // RFC 9000 Section 16: 8-byte encoding starts at 1073741824
            let buf = [0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00];
            let (value, consumed) = VarIntCodec::decode(&buf).unwrap();
            assert_eq!(value, 1073741824);
            assert_eq!(consumed, 8);
        }

        #[test]
        fn test_varint_decode_8byte_maximum() {
            // RFC 9000 Section 16: Max VarInt is 2^62 - 1
            let buf = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
            let (value, consumed) = VarIntCodec::decode(&buf).unwrap();
            assert_eq!(value, VARINT_MAX);
            assert_eq!(consumed, 8);
        }

        #[test]
        fn test_varint_decode_empty_buffer() {
            // Empty buffer should return None
            let buf: [u8; 0] = [];
            assert!(VarIntCodec::decode(&buf).is_none());
        }

        #[test]
        fn test_varint_decode_truncated_2byte() {
            // 2-byte encoding with only 1 byte available
            let buf = [0x40];
            assert!(VarIntCodec::decode(&buf).is_none());
        }

        #[test]
        fn test_varint_decode_truncated_4byte() {
            // 4-byte encoding with only 3 bytes available
            let buf = [0x80, 0x00, 0x00];
            assert!(VarIntCodec::decode(&buf).is_none());
        }

        #[test]
        fn test_varint_decode_truncated_8byte() {
            // 8-byte encoding with only 7 bytes available
            let buf = [0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            assert!(VarIntCodec::decode(&buf).is_none());
        }

        #[test]
        fn test_varint_encode_1byte() {
            let mut buf = [0u8; 8];
            let written = VarIntCodec::encode(37, &mut buf).unwrap();
            assert_eq!(written, 1);
            assert_eq!(buf[0], 0x25); // 37 = 0x25
        }

        #[test]
        fn test_varint_encode_2byte() {
            let mut buf = [0u8; 8];
            let written = VarIntCodec::encode(494, &mut buf).unwrap();
            assert_eq!(written, 2);
            assert_eq!(buf[0], 0x41); // 0x40 | (494 >> 8)
            assert_eq!(buf[1], 0xee); // 494 & 0xff
        }

        #[test]
        fn test_varint_encode_4byte() {
            let mut buf = [0u8; 8];
            let written = VarIntCodec::encode(494878333, &mut buf).unwrap();
            assert_eq!(written, 4);
            assert_eq!(&buf[..4], &[0x9d, 0x7f, 0x3e, 0x7d]);
        }

        #[test]
        fn test_varint_encode_8byte() {
            let mut buf = [0u8; 8];
            let written = VarIntCodec::encode(151288809941952652, &mut buf).unwrap();
            assert_eq!(written, 8);
            assert_eq!(&buf, &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]);
        }

        #[test]
        fn test_varint_encode_exceeds_max() {
            let mut buf = [0u8; 8];
            // Value larger than 2^62 - 1 should fail
            assert!(VarIntCodec::encode(VARINT_MAX + 1, &mut buf).is_none());
        }

        #[test]
        fn test_varint_encode_buffer_too_small() {
            let mut buf = [0u8; 1];
            // 2-byte value in 1-byte buffer should fail
            assert!(VarIntCodec::encode(100, &mut buf).is_none());
        }

        #[test]
        fn test_varint_roundtrip() {
            // Test encode-decode roundtrip for various values
            let test_values = [
                0,
                1,
                63,
                64,
                16383,
                16384,
                1073741823,
                1073741824,
                VARINT_MAX,
            ];

            for &value in &test_values {
                let mut buf = [0u8; 8];
                let written = VarIntCodec::encode(value, &mut buf).unwrap();
                let (decoded, consumed) = VarIntCodec::decode(&buf[..written]).unwrap();
                assert_eq!(decoded, value, "Roundtrip failed for {}", value);
                assert_eq!(consumed, written);
            }
        }

        #[test]
        fn test_varint_size() {
            assert_eq!(VarIntCodec::size(0), 1);
            assert_eq!(VarIntCodec::size(63), 1);
            assert_eq!(VarIntCodec::size(64), 2);
            assert_eq!(VarIntCodec::size(16383), 2);
            assert_eq!(VarIntCodec::size(16384), 4);
            assert_eq!(VarIntCodec::size(1073741823), 4);
            assert_eq!(VarIntCodec::size(1073741824), 8);
            assert_eq!(VarIntCodec::size(VARINT_MAX), 8);
        }

        #[test]
        fn test_varint_rfc_examples() {
            // RFC 9000 Section 16 - Sample Varints table
            // Example from A.1: 494 = 0x41ee (2 bytes)
            let mut buf = [0u8; 8];
            VarIntCodec::encode(494, &mut buf).unwrap();
            assert_eq!(&buf[..2], &[0x41, 0xee]);

            // Decode the example
            let (value, _) = VarIntCodec::decode(&[0x41, 0xee]).unwrap();
            assert_eq!(value, 494);
        }
    }

    // ========================================================================
    // ConnectionId Tests (RFC 9000 Section 5.1, RFC 8999 Section 5.3)
    // ========================================================================

    mod connection_id_tests {
        use super::*;

        #[test]
        fn test_connection_id_from_slice_valid() {
            let bytes = [0x01, 0x02, 0x03, 0x04];
            let cid = ConnectionId::from_slice(&bytes).unwrap();
            assert_eq!(cid.len(), 4);
            assert_eq!(cid.as_bytes(), &bytes);
        }

        #[test]
        fn test_connection_id_max_length() {
            // RFC 9000 Section 5.1: Maximum CID length is 20 bytes
            let bytes = [0xab; MAX_CID_LENGTH];
            let cid = ConnectionId::from_slice(&bytes).unwrap();
            assert_eq!(cid.len(), MAX_CID_LENGTH);
        }

        #[test]
        fn test_connection_id_exceeds_max_length() {
            // RFC 9000 Section 5.1: CID > 20 bytes is invalid
            let bytes = [0xab; MAX_CID_LENGTH + 1];
            assert!(ConnectionId::from_slice(&bytes).is_none());
        }

        #[test]
        fn test_connection_id_empty() {
            // RFC 9000: Zero-length CIDs are permitted
            let cid = ConnectionId::empty();
            assert!(cid.is_empty());
            assert_eq!(cid.len(), 0);
        }

        #[test]
        fn test_connection_id_equality() {
            let cid1 = ConnectionId::from_slice(&[0x01, 0x02, 0x03]).unwrap();
            let cid2 = ConnectionId::from_slice(&[0x01, 0x02, 0x03]).unwrap();
            let cid3 = ConnectionId::from_slice(&[0x01, 0x02, 0x04]).unwrap();

            assert_eq!(cid1, cid2);
            assert_ne!(cid1, cid3);
        }

        #[test]
        fn test_connection_id_hash() {
            use std::collections::HashSet;

            let cid1 = ConnectionId::from_slice(&[0x01, 0x02, 0x03]).unwrap();
            let cid2 = ConnectionId::from_slice(&[0x01, 0x02, 0x03]).unwrap();

            let mut set = HashSet::new();
            set.insert(cid1.clone());

            // Same CID should already be in set
            assert!(set.contains(&cid2));
        }

        #[test]
        fn test_connection_id_ordering() {
            let cid1 = ConnectionId::from_slice(&[0x01]).unwrap();
            let cid2 = ConnectionId::from_slice(&[0x02]).unwrap();

            assert!(cid1 < cid2);
        }

        #[test]
        fn test_connection_id_debug_format() {
            let cid = ConnectionId::from_slice(&[0xab, 0xcd]).unwrap();
            let debug = format!("{:?}", cid);
            assert!(debug.contains("ConnectionId"));
        }

        #[test]
        fn test_connection_id_display_format() {
            let cid = ConnectionId::from_slice(&[0xab, 0xcd]).unwrap();
            let display = format!("{}", cid);
            assert_eq!(display, "abcd");
        }

        #[test]
        fn test_connection_id_new_with_bytes() {
            let bytes = Bytes::from_static(&[0x11, 0x22, 0x33]);
            let cid = ConnectionId::new(bytes).unwrap();
            assert_eq!(cid.as_bytes(), &[0x11, 0x22, 0x33]);
        }

        #[test]
        fn test_connection_id_new_exceeds_max() {
            let bytes = Bytes::from(vec![0xffu8; MAX_CID_LENGTH + 1]);
            assert!(ConnectionId::new(bytes).is_none());
        }
    }

    // ========================================================================
    // PacketNumber Tests (RFC 9000 Section 12.3)
    // ========================================================================

    mod packet_number_tests {
        use super::*;

        #[test]
        fn test_packet_number_space_values() {
            assert_eq!(PacketNumberSpace::Initial as usize, 0);
            assert_eq!(PacketNumberSpace::Handshake as usize, 1);
            assert_eq!(PacketNumberSpace::ApplicationData as usize, 2);
        }

        #[test]
        fn test_max_packet_number() {
            // RFC 9000: Packet numbers are 62-bit
            assert_eq!(MAX_PACKET_NUMBER, (1u64 << 62) - 1);
        }

        #[test]
        fn test_packet_number_space_equality() {
            assert_eq!(PacketNumberSpace::Initial, PacketNumberSpace::Initial);
            assert_ne!(PacketNumberSpace::Initial, PacketNumberSpace::Handshake);
        }

        #[test]
        fn test_packet_number_space_hash() {
            use std::collections::HashMap;

            let mut map = HashMap::new();
            map.insert(PacketNumberSpace::Initial, 1);
            map.insert(PacketNumberSpace::Handshake, 2);
            map.insert(PacketNumberSpace::ApplicationData, 3);

            assert_eq!(map.get(&PacketNumberSpace::Initial), Some(&1));
            assert_eq!(map.get(&PacketNumberSpace::Handshake), Some(&2));
            assert_eq!(map.get(&PacketNumberSpace::ApplicationData), Some(&3));
        }
    }

    // ========================================================================
    // StreamId Tests (RFC 9000 Section 2.1)
    // ========================================================================

    mod stream_id_tests {
        use super::*;

        #[test]
        fn test_stream_id_client_bidi() {
            // RFC 9000 Section 2.1: Client bidi streams have low 2 bits = 0x00
            let id = StreamId::new(0); // First client bidi
            assert!(id.is_bidirectional());
            assert!(!id.is_unidirectional());
            assert_eq!(StreamType::from_stream_id(id), StreamType::ClientBidirectional);
        }

        #[test]
        fn test_stream_id_server_bidi() {
            // RFC 9000 Section 2.1: Server bidi streams have low 2 bits = 0x01
            let id = StreamId::new(1); // First server bidi
            assert!(id.is_bidirectional());
            assert_eq!(StreamType::from_stream_id(id), StreamType::ServerBidirectional);
        }

        #[test]
        fn test_stream_id_client_uni() {
            // RFC 9000 Section 2.1: Client uni streams have low 2 bits = 0x02
            let id = StreamId::new(2); // First client uni
            assert!(id.is_unidirectional());
            assert_eq!(StreamType::from_stream_id(id), StreamType::ClientUnidirectional);
        }

        #[test]
        fn test_stream_id_server_uni() {
            // RFC 9000 Section 2.1: Server uni streams have low 2 bits = 0x03
            let id = StreamId::new(3); // First server uni
            assert!(id.is_unidirectional());
            assert_eq!(StreamType::from_stream_id(id), StreamType::ServerUnidirectional);
        }

        #[test]
        fn test_stream_id_sequence() {
            // RFC 9000: Stream IDs increase by 4 within same type
            let client_bidi_0 = StreamId::new(0);
            let client_bidi_1 = StreamId::new(4);
            let client_bidi_2 = StreamId::new(8);

            assert_eq!(StreamType::from_stream_id(client_bidi_0), StreamType::ClientBidirectional);
            assert_eq!(StreamType::from_stream_id(client_bidi_1), StreamType::ClientBidirectional);
            assert_eq!(StreamType::from_stream_id(client_bidi_2), StreamType::ClientBidirectional);
        }

        #[test]
        fn test_stream_id_value() {
            let id = StreamId::new(42);
            assert_eq!(id.value(), 42);
            assert_eq!(id.into_inner(), 42);
        }

        #[test]
        fn test_stream_id_from_raw() {
            let id = StreamId::from_raw(100);
            assert_eq!(id.value(), 100);
        }

        #[test]
        fn test_stream_id_bitand() {
            let id = StreamId::new(0b11111111);
            assert_eq!(id & 0x03, 0x03);
        }

        #[test]
        fn test_stream_id_partial_eq_u64() {
            let id = StreamId::new(42);
            assert_eq!(id, 42u64);
            assert!(id != 43u64);
        }

        #[test]
        fn test_stream_type_is_bidirectional() {
            assert!(StreamType::ClientBidirectional.is_bidirectional());
            assert!(StreamType::ServerBidirectional.is_bidirectional());
            assert!(!StreamType::ClientUnidirectional.is_bidirectional());
            assert!(!StreamType::ServerUnidirectional.is_bidirectional());
        }

        #[test]
        fn test_stream_type_is_client_initiated() {
            assert!(StreamType::ClientBidirectional.is_client_initiated());
            assert!(StreamType::ClientUnidirectional.is_client_initiated());
            assert!(!StreamType::ServerBidirectional.is_client_initiated());
            assert!(!StreamType::ServerUnidirectional.is_client_initiated());
        }

        #[test]
        fn test_stream_id_helpers_initiator() {
            assert_eq!(stream_id_helpers::initiator(StreamId::new(0)), StreamInitiator::Client);
            assert_eq!(stream_id_helpers::initiator(StreamId::new(1)), StreamInitiator::Server);
            assert_eq!(stream_id_helpers::initiator(StreamId::new(2)), StreamInitiator::Client);
            assert_eq!(stream_id_helpers::initiator(StreamId::new(3)), StreamInitiator::Server);
        }

        #[test]
        fn test_stream_id_helpers_direction() {
            assert_eq!(stream_id_helpers::direction(StreamId::new(0)), StreamDirection::Bidirectional);
            assert_eq!(stream_id_helpers::direction(StreamId::new(1)), StreamDirection::Bidirectional);
            assert_eq!(stream_id_helpers::direction(StreamId::new(2)), StreamDirection::Unidirectional);
            assert_eq!(stream_id_helpers::direction(StreamId::new(3)), StreamDirection::Unidirectional);
        }
    }

    // ========================================================================
    // Side Tests
    // ========================================================================

    mod side_tests {
        use super::*;

        #[test]
        fn test_side_is_client() {
            assert!(Side::Client.is_client());
            assert!(!Side::Server.is_client());
        }

        #[test]
        fn test_side_is_server() {
            assert!(Side::Server.is_server());
            assert!(!Side::Client.is_server());
        }

        #[test]
        fn test_side_opposite() {
            assert_eq!(Side::Client.opposite(), Side::Server);
            assert_eq!(Side::Server.opposite(), Side::Client);
        }
    }

    // ========================================================================
    // Instant Tests
    // ========================================================================

    mod instant_tests {
        use super::*;

        #[test]
        fn test_instant_from_nanos() {
            let instant = Instant::from_nanos(1_000_000_000);
            assert_eq!(instant.as_nanos(), 1_000_000_000);
        }

        #[test]
        fn test_instant_duration_since() {
            let t1 = Instant::from_nanos(1_000_000);
            let t2 = Instant::from_nanos(2_000_000);

            let duration = t2.duration_since(t1).unwrap();
            assert_eq!(duration, Duration::from_nanos(1_000_000));
        }

        #[test]
        fn test_instant_duration_since_earlier() {
            let t1 = Instant::from_nanos(2_000_000);
            let t2 = Instant::from_nanos(1_000_000);

            // t2 < t1, so this returns None
            assert!(t2.duration_since(t1).is_none());
        }

        #[test]
        fn test_instant_duration_until() {
            let t1 = Instant::from_nanos(1_000_000);
            let t2 = Instant::from_nanos(2_000_000);

            let duration = t1.duration_until(t2).unwrap();
            assert_eq!(duration, Duration::from_nanos(1_000_000));
        }

        #[test]
        fn test_instant_checked_add() {
            let t = Instant::from_nanos(1_000_000);
            let duration = Duration::from_nanos(500_000);

            let result = t.checked_add(duration).unwrap();
            assert_eq!(result.as_nanos(), 1_500_000);
        }

        #[test]
        fn test_instant_checked_add_overflow() {
            let t = Instant::from_nanos(u64::MAX);
            let duration = Duration::from_nanos(1);

            assert!(t.checked_add(duration).is_none());
        }

        #[test]
        fn test_instant_checked_sub() {
            let t = Instant::from_nanos(1_500_000);
            let duration = Duration::from_nanos(500_000);

            let result = t.checked_sub(duration).unwrap();
            assert_eq!(result.as_nanos(), 1_000_000);
        }

        #[test]
        fn test_instant_checked_sub_underflow() {
            let t = Instant::from_nanos(100);
            let duration = Duration::from_nanos(200);

            assert!(t.checked_sub(duration).is_none());
        }

        #[test]
        fn test_instant_ordering() {
            let t1 = Instant::from_nanos(100);
            let t2 = Instant::from_nanos(200);
            let t3 = Instant::from_nanos(100);

            assert!(t1 < t2);
            assert!(t2 > t1);
            assert_eq!(t1, t3);
        }
    }

    // ========================================================================
    // Token Tests (RFC 9000 Section 8.1)
    // ========================================================================

    mod token_tests {
        use super::*;

        #[test]
        fn test_token_from_slice() {
            let bytes = [0x01, 0x02, 0x03, 0x04];
            let token = Token::from_slice(&bytes);
            assert_eq!(token.as_bytes(), &bytes);
            assert_eq!(token.len(), 4);
        }

        #[test]
        fn test_token_new_with_bytes() {
            let bytes = Bytes::from_static(&[0xaa, 0xbb, 0xcc]);
            let token = Token::new(bytes);
            assert_eq!(token.as_bytes(), &[0xaa, 0xbb, 0xcc]);
        }

        #[test]
        fn test_token_empty() {
            let token = Token::from_slice(&[]);
            assert!(token.is_empty());
            assert_eq!(token.len(), 0);
        }

        #[test]
        fn test_token_equality() {
            let token1 = Token::from_slice(&[0x01, 0x02]);
            let token2 = Token::from_slice(&[0x01, 0x02]);
            let token3 = Token::from_slice(&[0x01, 0x03]);

            assert_eq!(token1, token2);
            assert_ne!(token1, token3);
        }
    }

    // ========================================================================
    // Constants Tests (RFC 9000)
    // ========================================================================

    mod constants_tests {
        use super::*;

        #[test]
        fn test_default_max_udp_payload_size() {
            // RFC 9000 Section 14.1: Default is 1200 bytes
            assert_eq!(DEFAULT_MAX_UDP_PAYLOAD_SIZE, 1200);
        }

        #[test]
        fn test_min_initial_packet_size() {
            // RFC 9000 Section 14.1: Initial packets must be at least 1200 bytes
            assert_eq!(MIN_INITIAL_PACKET_SIZE, 1200);
        }

        #[test]
        fn test_max_udp_payload_ipv4() {
            // Maximum UDP payload for IPv4
            assert_eq!(MAX_UDP_PAYLOAD_SIZE_IPV4, 65527);
        }

        #[test]
        fn test_max_udp_payload_ipv6() {
            // Maximum UDP payload for IPv6
            assert_eq!(MAX_UDP_PAYLOAD_SIZE_IPV6, 65535);
        }

        #[test]
        fn test_default_idle_timeout() {
            assert_eq!(DEFAULT_IDLE_TIMEOUT, Duration::from_secs(30));
        }

        #[test]
        fn test_max_idle_timeout() {
            // RFC 9000: Max idle timeout is 600 seconds
            assert_eq!(MAX_IDLE_TIMEOUT, Duration::from_secs(600));
        }

        #[test]
        fn test_varint_max_equals_max_stream_id() {
            // Both are 2^62 - 1
            assert_eq!(VARINT_MAX, MAX_STREAM_ID);
        }
    }
}
