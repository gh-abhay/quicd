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
//! ├── types          - Core QUIC types (ConnectionId, VarInt, Instant, etc.)
//! ├── version        - Version negotiation (RFC 8999)
//! ├── error          - Unified error types (Transport, Application, Crypto)
//! ├── frames         - All 20+ frame types with zero-copy parsing
//! ├── packet         - Packet header parsing and number spaces
//! ├── crypto         - Cryptographic trait interfaces (AEAD, Header Protection)
//! ├── recovery       - Loss Detection and Congestion Control (RFC 9002)
//! ├── stream         - Stream state machine and reassembly buffers
//! ├── flow_control   - Connection and stream-level flow control
//! ├── transport      - Transport parameters and configuration
//! ├── connection     - Top-level connection state machine
//! └── server         - Server state machine and connection management
//! ```
//!
//! ## Design Principles
//!
//! ### 1. Pure State Machine
//!
//! No I/O, sockets, or event loops. The library processes input bytes/events
//! and produces output bytes/events:
//!
//! ```rust,ignore
//! // Process incoming UDP datagram
//! connection.process_datagram(DatagramInput {
//!     data: received_bytes,
//!     recv_time: Instant::now(),
//! })?;
//!
//! // Poll for outgoing datagrams
//! while let Some(dgram) = connection.poll_send(&mut send_buf, now) {
//!     udp_socket.send(&dgram.data)?;
//! }
//! ```
//!
//! ### 2. Zero-Copy Parsing
//!
//! All frame and packet parsing operates on borrowed slices (`&[u8]`).
//! Return types use lifetime parameters to reference original packet data:
//!
//! ```rust,ignore
//! // Frame references borrow from original packet
//! pub struct StreamFrame<'a> {
//!     pub stream_id: StreamId,
//!     pub offset: StreamOffset,
//!     pub data: &'a [u8],  // Zero-copy reference
//!     pub fin: bool,
//! }
//! ```
//!
//! ### 3. Buffer Injection Pattern
//!
//! Output methods accept caller-provided `bytes::BytesMut` to avoid internal
//! allocations:
//!
//! ```rust,ignore
//! let mut send_buf = BytesMut::with_capacity(1500);
//! if let Some(datagram) = connection.poll_send(&mut send_buf, now) {
//!     // send_buf contains serialized packet
//! }
//! ```
//!
//! ### 4. Pluggable Cryptography
//!
//! Crypto providers and congestion control algorithms are abstracted via traits:
//!
//! ```rust,ignore
//! pub trait CryptoBackend: Send + Sync {
//!     fn create_aead(&self, cipher_suite: u16) -> Result<Box<dyn AeadProvider>>;
//!     fn create_header_protection(&self, cipher_suite: u16) -> Result<Box<dyn HeaderProtectionProvider>>;
//!     fn create_tls_session(&self, side: Side) -> Result<Box<dyn TlsSession>>;
//! }
//! ```
//!
//! ### 5. Deterministic Behavior
//!
//! State transitions are purely deterministic based on inputs and time.
//! No randomness except in cryptographic operations.
//!
//! ## Usage Example
//!
//! ```rust,ignore
//! use quicd_quic::*;
//!
//! // Create connection
//! let config = ConnectionConfig {
//!     local_params: TransportParameters::default_client(),
//!     idle_timeout: Duration::from_secs(30),
//!     max_packet_size: 1200,
//! };
//!
//! let mut conn = QuicConnection::new(
//!     Side::Client,
//!     source_cid,
//!     dest_cid,
//!     None,  // original_dcid only used by servers
//!     config,
//! );
//!
//! // Process received datagram
//! conn.process_datagram(DatagramInput {
//!     data: udp_payload,
//!     recv_time: Instant::from_nanos(monotonic_time),
//! })?;
//!
//! // Open stream and send data
//! let stream_id = conn.open_stream(StreamDirection::Bidirectional)?;
//! conn.write_stream(stream_id, Bytes::from("Hello QUIC"), true)?;
//!
//! // Poll for output
//! let mut buf = BytesMut::with_capacity(1500);
//! while let Some(dgram) = conn.poll_send(&mut buf, now) {
//!     udp_socket.send(&dgram.data)?;
//!     buf.clear();
//! }
//!
//! // Poll for events
//! while let Some(event) = conn.poll_event() {
//!     match event {
//!         ConnectionEvent::StreamData { stream_id, data, fin } => {
//!             println!("Received data on stream {}: {:?}", stream_id.0, data);
//!         }
//!         ConnectionEvent::HandshakeComplete => {
//!             println!("Handshake complete!");
//!         }
//!         _ => {}
//!     }
//! }
//! ```
//!
//! ## Module Organization
//!
//! ### Core Types (`types`)
//! - `VarInt`, `ConnectionId`, `StreamId`, `PacketNumber`
//! - `Instant` (monotonic time abstraction)
//! - `Side`, `StreamDirection`, `PacketNumberSpace`
//!
//! ### Packet Layer (`packet`)
//! - Zero-copy packet header parsing (`PacketParser` trait)
//! - Packet number encoding/decoding (RFC 9000 Appendix A)
//! - Packet number space management
//!
//! ### Frame Layer (`frames`)
//! - All 22+ QUIC frame types with zero-copy parsing
//! - `FrameParser` and `FrameSerializer` traits
//! - Iterator-based frame processing
//!
//! ### Cryptography (`crypto`)
//! - `CryptoBackend` trait for pluggable TLS providers
//! - `AeadProvider`, `HeaderProtectionProvider` traits
//! - `TlsSession` trait for handshake state machine
//!
//! ### Loss Recovery (`recovery`)
//! - `LossDetector` trait (RFC 9002 Section 6)
//! - `CongestionController` trait (pluggable algorithms)
//! - `RttEstimator` for RTT calculation
//!
//! ### Streams (`stream`)
//! - Stream state machine (RFC 9000 Section 3)
//! - `ReceiveBuffer` and `SendBuffer` for reassembly
//! - `StreamController` trait for zero-copy I/O
//!
//! ### Flow Control (`flow_control`)
//! - Connection and stream-level flow control
//! - Credit tracking and window updates
//!
//! ### Transport Parameters (`transport`)
//! - Encoding/decoding of transport parameters (RFC 9000 Section 18)
//! - Parameter validation and negotiation
//!
//! ### Connection (`connection`)
//! - `Connection` trait (top-level state machine)
//! - Event-driven interface with `poll_send()` and `poll_event()`
//! - Connection statistics and lifecycle management
//!
//! ### Server (`server`)
//! - `QuicServer` trait for connection acceptance
//! - Version negotiation (RFC 9000 Section 6)
//! - Retry logic for address validation (RFC 9000 Section 8)
//!
//! ## Testing Strategy
//!
//! The trait-based architecture enables comprehensive testing:
//!
//! - **Unit Tests**: Mock crypto backends, predictable packet parsing
//! - **Interop Tests**: RFC compliance validation against other implementations
//! - **Fuzzing**: Zero-copy parsing is fuzz-safe (no panics on invalid input)

#![cfg_attr(not(feature = "std"), no_std)]
// #![forbid(unsafe_code)]

extern crate alloc;

// Core types and error handling
pub mod error;
pub mod types;
pub mod version;

// Protocol layers
pub mod crypto;
pub mod frames;
pub mod packet;
pub mod tls;

// Transport subsystems
pub mod flow_control;
pub mod recovery;
pub mod stream;
pub mod transport;

// Connection management
pub mod connection;
pub mod server;

// Re-export commonly used types
pub use types::{
    ConnectionId, Instant, PacketNumber, PacketNumberSpace, Side, StatelessResetToken, StreamId,
    StreamOffset, VarInt, VarIntCodec, VARINT_MAX,
};

pub use error::{ApplicationError, CryptoError, Error, Result, TransportError};

pub use version::{QuicVersion, VERSION_1, VERSION_NEGOTIATION};

// Re-export primary traits for library consumers
pub use connection::state::{
    Connection, ConnectionConfig, ConnectionEvent, ConnectionState, ConnectionStats, DatagramInput,
    DatagramOutput, QuicConnection,
};
pub use crypto::backend::{
    AeadProvider, CryptoBackend, CryptoLevel, HeaderProtectionProvider, KeySchedule, TlsEvent,
    TlsSession,
};
pub use frames::parse::{DefaultFrameParser, DefaultFrameSerializer, FrameSerializer};
pub use frames::{Frame, FrameParser};
pub use packet::api::{Packet, PacketHeaderWrapper, ParseContext};
pub use packet::header::{
    DefaultHeaderParser, Header, HeaderForm, LongHeader, PacketType, ShortHeader,
};
pub use packet::number::{
    DefaultPacketNumberDecoder, DefaultPacketNumberEncoder, PacketNumberDecoder,
    PacketNumberEncoder, PacketNumberLen,
};
pub use packet::parser::PacketParser as PacketParserTrait;
pub use packet::types::{ParsedPacket, Token};
pub use recovery::{CongestionController, LossDetector, RttEstimator};
pub use stream::{StreamController, StreamManager};
pub use transport::TransportParameters;

// ConnectionIdGenerator trait - for CID routing logic
pub trait ConnectionIdGenerator: Send + Sync {
    fn generate(&self, len: usize) -> ConnectionId;
}

// Type alias for EncryptionLevel (renamed to CryptoLevel in backend)
pub use crypto::backend::CryptoLevel as EncryptionLevel;

// Re-export sub-modules for convenience
pub mod cid {
    pub use crate::types::ConnectionId;
    pub use crate::ConnectionIdGenerator;
    pub const MAX_CID_LENGTH: usize = 20;
}

pub mod frame {
    pub use crate::frames::Frame;
}
