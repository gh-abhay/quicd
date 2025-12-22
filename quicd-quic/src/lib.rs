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
//! 1. **Pure State Machine**: No I/O, sockets, or event loops. The library processes input
//!    bytes/events and produces output bytes/events.
//!
//! 2. **Zero-Copy Parsing**: All frame and packet parsing operates on borrowed slices (`&[u8]`).
//!    Return types use lifetime parameters to reference original packet data.
//!
//! 3. **Zero-Allocation (Runtime)**: No heap allocations in hot paths. Callers provide
//!    pre-allocated buffers via `bytes::BytesMut` for output operations.
//!
//! 4. **Deterministic**: State transitions are purely deterministic based on inputs and time.
//!
//! 5. **Pluggable Backends**: Crypto providers and congestion control algorithms are
//!    abstracted via traits, enabling testability and algorithm swapping.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

// Core types and error handling
pub mod types;
pub mod error;
pub mod version;

// Protocol layers
pub mod frames;
pub mod packet;
pub mod crypto;

// Transport subsystems
pub mod stream;
pub mod flow_control;
pub mod transport;
pub mod recovery;

// Connection management
pub mod connection;
pub mod server;

// Re-export commonly used types
pub use types::{
    ConnectionId, Instant, PacketNumber, PacketNumberSpace, Side, StreamDirection, StreamId,
    StreamInitiator, StreamOffset, VarInt, VARINT_MAX,
};

pub use error::{ApplicationError, CryptoError, Error, Result, TransportError};

pub use version::{VERSION_1, VERSION_2, VERSION_NEGOTIATION};

