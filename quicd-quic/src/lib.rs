//! quicd-quic: RFC-Compliant QUIC Transport Implementation
//!
//! This crate provides a complete implementation of the QUIC transport protocol
//! as specified in RFC 9000, RFC 9001, RFC 9002, and RFC 8999.
//!
//! # Architecture
//!
//! - **Zero-contention design**: All state is thread-local, no shared mutexes
//! - **Zero-copy parsing**: Operate on borrowed slices, use `bytes::Bytes` for payloads
//! - **Single-task per connection**: All connection state managed in one Tokio task
//! - **Modular congestion control**: Pluggable algorithms (NewReno default)
//! - **Crypto-agnostic**: TLS trait interface with rustls/BoringSSL adapters
//!
//! # RFC Compliance
//!
//! - **RFC 9000**: QUIC transport protocol (packets, frames, streams, flow control)
//! - **RFC 9001**: Using TLS to secure QUIC (key derivation, handshake)
//! - **RFC 9002**: Loss detection and congestion control (PTO, NewReno)
//! - **RFC 8999**: Version-independent properties (version negotiation) - **100% COMPLIANT**
//!
//! ## RFC 8999 Compliance Details
//!
//! This implementation achieves 100% compliance with RFC 8999 requirements:
//!
//! - ✅ Long Header Format: Correctly parses header form, version, DCID/SCID lengths and values
//! - ✅ Short Header Format: Context-aware parsing with learned DCID length
//! - ✅ Connection ID Properties: Supports 0..255 bytes for Version Negotiation, 0..20 for QUIC v1
//! - ✅ Version Negotiation: Proper packet generation, CID echoing, and payload validation
//! - ✅ Unused Bits: Correctly ignores lower 7 bits in Version Negotiation first byte
//! - ✅ Payload Validation: Rejects empty or truncated Supported Version fields
//!
//! # Module Organization
//!
//! - `packet`: Packet parsing and serialization
//! - `frame`: Frame parsing and handling
//! - `connection`: Connection state machine
//! - `stream`: Stream state management
//! - `crypto`: TLS integration and key derivation
//! - `recovery`: Loss detection and congestion control
//! - `cid`: Connection ID lifecycle management

pub mod packet;
pub mod frame;
pub mod connection;
pub mod stream;
pub mod crypto;
pub mod recovery;
pub mod cid;
pub mod varint;
pub mod error;
pub mod params;

// Re-export key types
pub use connection::{Connection, ConnectionConfig, ConnectionError, ConnectionState};
pub use packet::{Packet, PacketType, Header, ParseContext};
pub use frame::Frame;
pub use stream::{Stream, StreamId, StreamError};
pub use crypto::{TlsSession, KeySchedule};
pub use recovery::{CongestionController, LossDetector};
pub use cid::ConnectionId;
pub use error::Error;
pub use params::TransportParams;
