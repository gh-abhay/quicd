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
        Self { bytes: Bytes::new() }
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
        matches!(self, StreamType::ClientBidirectional | StreamType::ServerBidirectional)
    }

    /// Check if this stream type is unidirectional
    pub fn is_unidirectional(self) -> bool {
        !self.is_bidirectional()
    }

    /// Check if client initiated this stream type
    pub fn is_client_initiated(self) -> bool {
        matches!(self, StreamType::ClientBidirectional | StreamType::ClientUnidirectional)
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
        self.nanos.checked_add(nanos as u64).map(|n| Instant { nanos: n })
    }

    /// Subtract a duration from this instant
    pub fn checked_sub(&self, duration: Duration) -> Option<Instant> {
        let nanos = duration.as_nanos();
        if nanos > u64::MAX as u128 {
            return None;
        }
        self.nanos.checked_sub(nanos as u64).map(|n| Instant { nanos: n })
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

    // VarInt Tests
    #[test]
    fn test_varint_1byte_encoding() {
        let mut buf = [0u8; 8];
        // Test boundary values for 1-byte encoding (0 to 63)
        assert_eq!(VarIntCodec::encode(0, &mut buf), Some(1));
        assert_eq!(buf[0], 0x00);
        
        assert_eq!(VarIntCodec::encode(37, &mut buf), Some(1));
        assert_eq!(buf[0], 37);
        
        assert_eq!(VarIntCodec::encode(63, &mut buf), Some(1));
        assert_eq!(buf[0], 63);
    }

    #[test]
    fn test_varint_2byte_encoding() {
        let mut buf = [0u8; 8];
        // Test boundary for 2-byte encoding (64 to 16383)
        assert_eq!(VarIntCodec::encode(64, &mut buf), Some(2));
        assert_eq!(buf[0], 0x40);
        assert_eq!(buf[1], 0x40);
        
        assert_eq!(VarIntCodec::encode(151_288_809_941_952_652, &mut buf), Some(8));
        
        assert_eq!(VarIntCodec::encode(16383, &mut buf), Some(2));
        assert_eq!(buf[0], 0x7f);
        assert_eq!(buf[1], 0xff);
    }

    #[test]
    fn test_varint_4byte_encoding() {
        let mut buf = [0u8; 8];
        // Test boundary for 4-byte encoding (16384 to 1073741823)
        assert_eq!(VarIntCodec::encode(16384, &mut buf), Some(4));
        assert_eq!(buf[0], 0x80);
        assert_eq!(buf[1], 0x00);
        assert_eq!(buf[2], 0x40);
        assert_eq!(buf[3], 0x00);
        
        assert_eq!(VarIntCodec::encode(1_073_741_823, &mut buf), Some(4));
        assert_eq!(buf[0], 0xbf);
        assert_eq!(buf[1], 0xff);
        assert_eq!(buf[2], 0xff);
        assert_eq!(buf[3], 0xff);
    }

    #[test]
    fn test_varint_8byte_encoding() {
        let mut buf = [0u8; 8];
        // Test 8-byte encoding (1073741824 to 2^62-1)
        assert_eq!(VarIntCodec::encode(1_073_741_824, &mut buf), Some(8));
        assert_eq!(buf[0], 0xc0);
        assert_eq!(buf[1], 0x00);
        assert_eq!(buf[2], 0x00);
        assert_eq!(buf[3], 0x00);
        assert_eq!(buf[4], 0x40);
        assert_eq!(buf[5], 0x00);
        assert_eq!(buf[6], 0x00);
        assert_eq!(buf[7], 0x00);
        
        // Test max value
        assert_eq!(VarIntCodec::encode(VARINT_MAX, &mut buf), Some(8));
        assert_eq!(buf[0], 0xff);
        assert_eq!(buf[1], 0xff);
        assert_eq!(buf[2], 0xff);
        assert_eq!(buf[3], 0xff);
        assert_eq!(buf[4], 0xff);
        assert_eq!(buf[5], 0xff);
        assert_eq!(buf[6], 0xff);
        assert_eq!(buf[7], 0xff);
    }

    #[test]
    fn test_varint_decode_1byte() {
        let buf = [0x25];
        assert_eq!(VarIntCodec::decode(&buf), Some((37, 1)));
        
        let buf = [0x3f];
        assert_eq!(VarIntCodec::decode(&buf), Some((63, 1)));
    }

    #[test]
    fn test_varint_decode_2byte() {
        let buf = [0x7b, 0xbd];
        assert_eq!(VarIntCodec::decode(&buf), Some((15293, 2)));
        
        let buf = [0x7f, 0xff];
        assert_eq!(VarIntCodec::decode(&buf), Some((16383, 2)));
    }

    #[test]
    fn test_varint_decode_4byte() {
        let buf = [0x9d, 0x7f, 0x3e, 0x7d];
        assert_eq!(VarIntCodec::decode(&buf), Some((494878333, 4)));
        
        let buf = [0xbf, 0xff, 0xff, 0xff];
        assert_eq!(VarIntCodec::decode(&buf), Some((1_073_741_823, 4)));
    }

    #[test]
    fn test_varint_decode_8byte() {
        let buf = [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c];
        assert_eq!(VarIntCodec::decode(&buf), Some((151_288_809_941_952_652, 8)));
        
        let buf = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(VarIntCodec::decode(&buf), Some((VARINT_MAX, 8)));
    }

    #[test]
    fn test_varint_roundtrip() {
        let test_values = vec![
            0u64, 1, 37, 63,
            64, 151, 16383,
            16384, 494878333, 1_073_741_823,
            1_073_741_824, 151_288_809_941_952_652, VARINT_MAX,
        ];
        
        for value in test_values {
            let mut buf = [0u8; 8];
            let encoded_len = VarIntCodec::encode(value, &mut buf).expect("encode failed");
            let (decoded_value, decoded_len) = VarIntCodec::decode(&buf).expect("decode failed");
            assert_eq!(value, decoded_value);
            assert_eq!(encoded_len, decoded_len);
        }
    }

    #[test]
    fn test_varint_buffer_too_short() {
        // Empty buffer
        assert_eq!(VarIntCodec::decode(&[]), None);
        
        // 2-byte value with only 1 byte
        assert_eq!(VarIntCodec::decode(&[0x40]), None);
        
        // 4-byte value with only 3 bytes
        assert_eq!(VarIntCodec::decode(&[0x80, 0x00, 0x40]), None);
        
        // 8-byte value with only 7 bytes
        assert_eq!(VarIntCodec::decode(&[0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), None);
    }

    #[test]
    fn test_varint_encode_exceeds_max() {
        let mut buf = [0u8; 8];
        // Value exceeds VARINT_MAX (2^62 - 1)
        assert_eq!(VarIntCodec::encode(VARINT_MAX + 1, &mut buf), None);
        assert_eq!(VarIntCodec::encode(u64::MAX, &mut buf), None);
    }

    #[test]
    fn test_varint_encode_buffer_too_small() {
        let mut buf = [0u8; 1];
        // Try to encode 2-byte value into 1-byte buffer
        assert_eq!(VarIntCodec::encode(64, &mut buf), None);
        
        let mut buf = [0u8; 3];
        // Try to encode 4-byte value into 3-byte buffer
        assert_eq!(VarIntCodec::encode(16384, &mut buf), None);
    }

    #[test]
    fn test_varint_size() {
        assert_eq!(VarIntCodec::size(0), 1);
        assert_eq!(VarIntCodec::size(63), 1);
        assert_eq!(VarIntCodec::size(64), 2);
        assert_eq!(VarIntCodec::size(16383), 2);
        assert_eq!(VarIntCodec::size(16384), 4);
        assert_eq!(VarIntCodec::size(1_073_741_823), 4);
        assert_eq!(VarIntCodec::size(1_073_741_824), 8);
        assert_eq!(VarIntCodec::size(VARINT_MAX), 8);
    }

    // ConnectionId Tests
    #[test]
    fn test_connection_id_creation() {
        let bytes = Bytes::from_static(b"\x01\x02\x03\x04");
        let cid = ConnectionId::new(bytes.clone()).unwrap();
        assert_eq!(cid.len(), 4);
        assert_eq!(cid.as_bytes(), &[1, 2, 3, 4]);
        assert!(!cid.is_empty());
    }

    #[test]
    fn test_connection_id_max_length() {
        let bytes = Bytes::from(vec![0xffu8; MAX_CID_LENGTH]);
        assert!(ConnectionId::new(bytes).is_some());
        
        let bytes = Bytes::from(vec![0xffu8; MAX_CID_LENGTH + 1]);
        assert!(ConnectionId::new(bytes).is_none());
    }

    #[test]
    fn test_connection_id_zero_length() {
        let cid = ConnectionId::from_slice(&[]).unwrap();
        assert!(cid.is_empty());
        assert_eq!(cid.len(), 0);
    }

    // Instant Tests
    #[test]
    fn test_instant_duration_since() {
        let t1 = Instant::from_nanos(1_000_000_000);
        let t2 = Instant::from_nanos(2_000_000_000);
        
        let duration = t2.duration_since(t1).unwrap();
        assert_eq!(duration.as_nanos(), 1_000_000_000);
        
        assert!(t1.duration_since(t2).is_none());
    }

    #[test]
    fn test_instant_checked_add() {
        let t = Instant::from_nanos(1_000_000_000);
        let t2 = t.checked_add(Duration::from_nanos(500_000_000)).unwrap();
        assert_eq!(t2.as_nanos(), 1_500_000_000);
    }

    #[test]
    fn test_instant_checked_sub() {
        let t = Instant::from_nanos(1_500_000_000);
        let t2 = t.checked_sub(Duration::from_nanos(500_000_000)).unwrap();
        assert_eq!(t2.as_nanos(), 1_000_000_000);
        
        // Underflow
        assert!(t2.checked_sub(Duration::from_nanos(2_000_000_000)).is_none());
    }

    // StreamType Tests
    #[test]
    fn test_stream_type_from_id() {
        assert_eq!(StreamType::from_stream_id(StreamId::new(0)), StreamType::ClientBidirectional);
        assert_eq!(StreamType::from_stream_id(StreamId::new(1)), StreamType::ServerBidirectional);
        assert_eq!(StreamType::from_stream_id(StreamId::new(2)), StreamType::ClientUnidirectional);
        assert_eq!(StreamType::from_stream_id(StreamId::new(3)), StreamType::ServerUnidirectional);
        assert_eq!(StreamType::from_stream_id(StreamId::new(4)), StreamType::ClientBidirectional);
        assert_eq!(StreamType::from_stream_id(StreamId::new(7)), StreamType::ServerUnidirectional);
    }

    #[test]
    fn test_stream_type_properties() {
        assert!(StreamType::ClientBidirectional.is_bidirectional());
        assert!(StreamType::ClientBidirectional.is_client_initiated());
        
        assert!(StreamType::ServerUnidirectional.is_unidirectional());
        assert!(StreamType::ServerUnidirectional.is_server_initiated());
    }

    // Side Tests
    #[test]
    fn test_side_properties() {
        assert!(Side::Client.is_client());
        assert!(!Side::Client.is_server());
        assert!(Side::Server.is_server());
        assert!(!Side::Server.is_client());
    }

    #[test]
    fn test_side_opposite() {
        assert_eq!(Side::Client.opposite(), Side::Server);
        assert_eq!(Side::Server.opposite(), Side::Client);
    }

    // Token Tests
    #[test]
    fn test_token_creation() {
        let token = Token::from_slice(b"test_token");
        assert_eq!(token.len(), 10);
        assert_eq!(token.as_bytes(), b"test_token");
        assert!(!token.is_empty());
    }

    #[test]
    fn test_empty_token() {
        let token = Token::from_slice(&[]);
        assert!(token.is_empty());
        assert_eq!(token.len(), 0);
    }
}
