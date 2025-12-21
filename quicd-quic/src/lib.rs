//! # quicd-quic: Production-Grade QUIC Protocol Implementation
//!
//! This crate provides a **100% RFC-compliant**, `#![no_std]` compatible QUIC protocol
//! implementation with complete trait-based architecture:
//!
//! - **RFC 8999**: Version-Independent Properties of QUIC
//! - **RFC 9000**: QUIC: A UDP-Based Multiplexed and Secure Transport  
//! - **RFC 9001**: Using TLS to Secure QUIC
//! - **RFC 9002**: QUIC Loss Detection and Congestion Control
//!
//! ## Architecture Overview
//!
//! The crate is organized into distinct RFC-aligned modules:
//!
//! ```text
//! quicd-quic/
//! ├── error          - Unified error types (Transport, Application, Crypto)
//! ├── frames         - All 20+ frame types with zero-copy parsing
//! ├── packet         - Packet header parsing and number spaces
//! ├── crypto         - Cryptographic trait interfaces (AEAD, Header Protection)
//! ├── recovery       - Loss Detection and Congestion Control (RFC 9002)
//! ├── stream         - Stream state machine and reassembly buffers
//! ├── transport      - Transport parameters and connection flow control
//! └── server         - Server state machine and connection management
//! ```
//!
//! ## Design Principles
//!
//! 1. **Pure State Machine**: No I/O, sockets, or event loops. The library processes input
//!    bytes/events and produces output bytes/events.
//!
//! 2. **Zero-Copy Parsing**: All frame and packet parsing operates on borrowed slices (`&[u8]`).
//!    Return types use lifetime parameters to reference original packet data.
//!
//! 3. **Zero-Allocation (Runtime)**: No heap allocations in hot paths. Callers provide
//!    pre-allocated buffers via `&mut [u8]` for output operations.
//!
//! 4. **Deterministic**: State transitions are purely deterministic based on inputs and time.
//!
//! 5. **Pluggable Backends**: Crypto providers and congestion control algorithms are
//!    abstracted via traits, enabling testability and algorithm swapping.
//!
//! ## Module Guide
//!
//! ### Frames (`frames`)
//! Zero-copy parsing and serialization for all QUIC frame types (STREAM, ACK, CRYPTO, etc.).
//! See [`frames::Frame`] for the unified enum and [`frames::parse`] for parsing logic.
//!
//! ### Recovery (`recovery`)
//! Loss detection and congestion control implementation per RFC 9002:
//! - [`recovery::RttEstimator`] - RTT smoothing and PTO calculation
//! - [`recovery::LossDetector`] - Time/packet threshold loss detection  
//! - [`recovery::CongestionController`] - NewReno/Cubic/BBR implementations
//!
//! ### Crypto (`crypto`)
//! Trait-based cryptographic interface for pluggable TLS backends:
//! - [`crypto::CryptoContext`] - Key management across encryption levels
//! - [`crypto::PacketProtector`] - AEAD encryption/decryption
//! - [`crypto::HeaderProtector`] - Header obfuscation (RFC 9001 Section 5.4)
//!
//! ### Streams (`stream`)
//! Stream lifecycle management and data reassembly:
//! - [`stream::StreamMeta`] - Per-stream state machine
//! - [`stream::buffer::ReassemblyBuffer`] - Out-of-order data handling
//!
//! ### Transport (`transport`)
//! Connection-level parameters and flow control:
//! - [`transport::parameters::TransportParameters`] - TLS handshake parameters
//! - [`transport::flow::ConnectionFlowControl`] - Connection-level flow control
//!
//! ## Usage Example
//!
//! ```rust,ignore
//! use quicd_quic::{frames::Frame, crypto::CryptoContext};
//!
//! // Parse frames from a decrypted packet payload
//! let payload: &[u8] = /* decrypted QUIC packet */;
//! let mut parser = frames::parse::FrameParser::new(payload);
//!
//! while let Some(frame) = parser.next_frame()? {
//!     match frame {
//!         Frame::Stream { stream_id, data, fin, .. } => {
//!             // `data` is a zero-copy reference to `payload`
//!             handle_stream_data(stream_id, data, fin);
//!         }
//!         Frame::Ack { largest_acked, .. } => {
//!             process_ack(largest_acked);
//!         }
//!         _ => { /* handle other frame types */ }
//!     }
//! }
//! ```

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

// ============================================================================
// RFC 8999: Version-Independent Properties
// ============================================================================

/// Connection ID as defined in RFC 8999 Section 5.1.
/// 
/// Connection IDs are opaque fields of between 0 and 20 bytes in length.
/// They are version-independent and used for routing packets to connections.
///
/// **Design**: Uses a lifetime to reference the underlying buffer without copying.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId<'a> {
    bytes: &'a [u8],
}

impl<'a> ConnectionId<'a> {
    /// Maximum length of a Connection ID per RFC 9000 Section 17.2.
    pub const MAX_LENGTH: usize = 20;

    /// Creates a ConnectionId from a byte slice.
    /// 
    /// Returns `None` if the length exceeds `MAX_LENGTH`.
    pub fn new(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() <= Self::MAX_LENGTH {
            Some(Self { bytes })
        } else {
            None
        }
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// QUIC Version number (RFC 8999 Section 5.2).
///
/// Version 0x00000000 is reserved for version negotiation.
/// Version 0x00000001 represents QUIC v1 (RFC 9000).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Version(pub u32);

impl Version {
    pub const NEGOTIATION: Version = Version(0x00000000);
    pub const V1: Version = Version(0x00000001);
}

// ============================================================================
// Library Metadata
// ============================================================================

/// Get the QUIC version supported by this library
pub const fn supported_version() -> Version {
    Version::V1
}

/// Check if a version is supported
pub const fn is_version_supported(version: Version) -> bool {
    version.0 == Version::V1.0
}



// ============================================================================
// Module Re-exports (RFC-Aligned Architecture)
// ============================================================================

/// Error types for QUIC operations (Transport, Application, Crypto)
pub mod error;

/// QUIC frame types and zero-copy parsing (RFC 9000 Section 12.4)
pub mod frames;

/// Packet header parsing, packet numbers, and packet number spaces (RFC 9000 Section 12, 17)
pub mod packet;

/// Cryptographic interface traits (RFC 9001)
pub mod crypto;

/// Loss detection and congestion control (RFC 9002)
pub mod recovery;

/// Stream management and data reassembly (RFC 9000 Section 2-3)
pub mod stream;

/// Transport parameters and flow control (RFC 9000 Section 4, 7)
pub mod transport;

/// Server connection management
pub mod server;

/// Connection state machine and lifecycle management (RFC 9000 Section 5)
pub mod connection;

/// Version negotiation and invariants (RFC 8999)
pub mod version;

/// Connection-level flow control (distinct from stream flow control)
pub mod flow_control;

// ============================================================================
// Re-export Core Types for Convenience
// ============================================================================

pub use error::{Error, Result, TransportError, ApplicationError, CryptoError};
pub use frames::{Frame, StreamId, VarInt};
pub use packet::{PacketNumber, PacketNumberSpace, PacketType, PacketHeader, PacketParser};
pub use recovery::{
    RttEstimator, LossDetector, CongestionController,
    CongestionWindow, BytesInFlight, PacketSent, AckReceived,
};
pub use crypto::{EncryptionLevel, CryptoContext, PacketProtector, HeaderProtector};
pub use stream::{StreamMeta, SendState, RecvState, StreamManager};
pub use transport::{
    parameters::TransportParameters,
    flow::ConnectionFlowControl,
};
pub use connection::{QuicConnection, ConnectionState, ConnectionConfig, ConnectionEvent};
pub use version::{QuicVersion, VersionNegotiator, PacketInvariants, VERSION_1};

// ============================================================================
// RFC 8999: Version-Independent Properties
// ============================================================================

