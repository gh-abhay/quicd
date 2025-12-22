//! # Connection State Machine (RFC 9000 Section 4)
//!
//! This module defines the connection state machine and the top-level
//! QUIC connection interface (the "Driver").
//!
//! ## RFC 9000 Section 4: Connection Lifecycle
//!
//! States: Idle → Initial → Handshake → Active → Draining → Closed
//!
//! ## Design:
//! The Connection is the top-level state machine that coordinates:
//! - Packet parsing and encryption
//! - Stream management
//! - Flow control
//! - Loss recovery
//! - Crypto handshake

#![forbid(unsafe_code)]

use crate::crypto::backend::{CryptoBackend, EncryptionLevel};
use crate::error::{Error, Result};
use crate::frames::types::Frame;
use crate::packet::header::{PacketHeader, PacketParser, PacketBuilder};
use crate::recovery::traits::{RecoveryManager};
use crate::stream::manager::{StreamManager};
use crate::transport::params::TransportParameters;
use crate::types::{ConnectionId, Instant, PacketNumber, PacketNumberSpace, Side};
use bytes::{Bytes, BytesMut};

/// Connection State (RFC 9000 Section 4)
///
/// Tracks the lifecycle state of a QUIC connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Initial state before any packets sent/received
    Idle,

    /// Initial packet exchange in progress
    Initial,

    /// Handshake in progress
    Handshake,

    /// Handshake complete, active data transfer
    Active,

    /// Closing: CONNECTION_CLOSE sent, waiting for ACK or timeout
    Closing,

    /// Draining: CONNECTION_CLOSE received, waiting for timeout
    Draining,

    /// Connection closed
    Closed,
}

/// Connection Event
///
/// Events produced by the connection that must be handled by the application.
#[derive(Debug)]
pub enum ConnectionEvent {
    /// Handshake completed successfully
    HandshakeComplete,

    /// New stream created by peer
    StreamOpened {
        stream_id: u64,
    },

    /// Stream data available to read
    StreamReadable {
        stream_id: u64,
    },

    /// Stream writable (flow control window increased)
    StreamWritable {
        stream_id: u64,
    },

    /// Stream closed by peer
    StreamClosed {
        stream_id: u64,
        error_code: u64,
    },

    /// Connection closing
    Closing {
        error_code: u64,
        reason: Bytes,
    },

    /// Connection closed
    Closed,

    /// Datagram received (RFC 9221 - DATAGRAM extension)
    DatagramReceived {
        data: Bytes,
    },
}

/// Datagram to Send
///
/// Represents a UDP datagram ready to be sent.
#[derive(Debug)]
pub struct Datagram {
    /// Destination Connection ID
    pub dcid: ConnectionId,

    /// Source Connection ID
    pub scid: Option<ConnectionId>,

    /// Serialized packet bytes
    pub data: Bytes,
}

/// Connection Configuration
///
/// Configuration options for a QUIC connection.
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    /// Local transport parameters
    pub local_transport_params: TransportParameters,

    /// Connection role (Client or Server)
    pub side: Side,

    /// Initial destination Connection ID
    pub initial_dcid: ConnectionId,

    /// Initial source Connection ID
    pub initial_scid: ConnectionId,

    /// ALPN protocols to negotiate
    pub alpn_protocols: tinyvec::TinyVec<[Bytes; 4]>,

    /// Maximum UDP payload size
    pub max_udp_payload_size: usize,

    /// Enable DATAGRAM extension (RFC 9221)
    pub enable_datagram: bool,
}

/// QUIC Connection Trait (Main State Machine)
///
/// This is the top-level interface for a QUIC connection.
/// It's a pure state machine: accepts bytes/events, returns bytes/events.
///
/// ## Zero-Copy Design:
/// - Input: References to UDP datagram buffers (&[u8])
/// - Output: Caller-provided buffers (BytesMut) or Bytes
///
/// ## No I/O:
/// The connection doesn't perform any I/O. The caller is responsible for:
/// - Receiving UDP datagrams and passing them to `handle_datagram()`
/// - Calling `poll()` to get outgoing datagrams
/// - Managing timers and calling `handle_timeout()`
pub trait Connection {
    /// Process an incoming UDP datagram.
    ///
    /// Parses packets, decrypts, processes frames, updates state.
    ///
    /// # Arguments
    /// - `datagram`: Raw UDP payload bytes
    /// - `now`: Current time
    ///
    /// # Returns
    /// List of connection events produced by processing this datagram
    fn handle_datagram(&mut self, datagram: &[u8], now: Instant) -> Result<Vec<ConnectionEvent>>;

    /// Poll the connection for outgoing datagrams and events.
    ///
    /// Caller should call this repeatedly until it returns None or buffer is full.
    ///
    /// # Arguments
    /// - `buf`: Buffer to write outgoing datagram into
    /// - `now`: Current time
    ///
    /// # Returns
    /// Number of bytes written, or None if no data to send
    fn poll(&mut self, buf: &mut BytesMut, now: Instant) -> Result<Option<usize>>;

    /// Handle a timeout event.
    ///
    /// Should be called when the timer returned by `get_timeout()` expires.
    ///
    /// # Arguments
    /// - `now`: Current time
    fn handle_timeout(&mut self, now: Instant) -> Result<Vec<ConnectionEvent>>;

    /// Get the next timeout deadline.
    ///
    /// Caller must implement timer management and call `handle_timeout()`
    /// when this deadline is reached.
    ///
    /// # Returns
    /// Next timeout instant, or None if no timers active
    fn get_timeout(&self) -> Option<Instant>;

    /// Get the current connection state
    fn state(&self) -> ConnectionState;

    /// Check if the connection is established (handshake complete)
    fn is_established(&self) -> bool;

    /// Check if the connection is closed
    fn is_closed(&self) -> bool;

    /// Close the connection gracefully.
    ///
    /// Sends CONNECTION_CLOSE frame and transitions to Closing state.
    ///
    /// # Arguments
    /// - `error_code`: Application error code
    /// - `reason`: Human-readable reason (UTF-8)
    fn close(&mut self, error_code: u64, reason: &[u8]) -> Result<()>;

    // Note: streams() method removed - implementations should provide their own typed access

    /// Get peer's transport parameters
    fn peer_transport_params(&self) -> Option<&TransportParameters>;

    /// Get negotiated ALPN protocol
    fn alpn(&self) -> Option<&[u8]>;

    /// Send a datagram (RFC 9221 - DATAGRAM extension)
    ///
    /// # Errors
    /// Returns Error if DATAGRAM extension not negotiated or datagram too large
    fn send_datagram(&mut self, data: Bytes) -> Result<()>;

    /// Get connection statistics
    fn stats(&self) -> ConnectionStats;
}

/// Connection Statistics
///
/// Metrics for monitoring connection health and performance.
#[derive(Debug, Clone, Copy, Default)]
pub struct ConnectionStats {
    /// Total packets sent
    pub packets_sent: u64,

    /// Total packets received
    pub packets_received: u64,

    /// Total bytes sent
    pub bytes_sent: u64,

    /// Total bytes received
    pub bytes_received: u64,

    /// Packets lost
    pub packets_lost: u64,

    /// Current congestion window (bytes)
    pub cwnd: u64,

    /// Current bytes in flight
    pub bytes_in_flight: u64,

    /// Smoothed RTT (microseconds)
    pub smoothed_rtt_us: u64,

    /// Minimum RTT (microseconds)
    pub min_rtt_us: u64,

    /// Latest RTT (microseconds)
    pub latest_rtt_us: u64,
}

/// Connection ID Manager Trait
///
/// Manages Connection IDs for a connection (RFC 9000 Section 5.1).
/// QUIC connections can have multiple Connection IDs for migration.
pub trait ConnectionIdManager {
    /// Get the current destination Connection ID
    fn current_dcid(&self) -> &ConnectionId;

    /// Get the current source Connection ID
    fn current_scid(&self) -> &ConnectionId;

    /// Add a new Connection ID (from NEW_CONNECTION_ID frame)
    fn add_connection_id(&mut self, cid: ConnectionId, sequence: u64, token: [u8; 16]) -> Result<()>;

    /// Retire a Connection ID (from RETIRE_CONNECTION_ID frame)
    fn retire_connection_id(&mut self, sequence: u64) -> Result<()>;

    /// Generate a new Connection ID for the peer to use
    fn generate_new_cid(&mut self) -> Result<(ConnectionId, [u8; 16])>;

    /// Get the number of active Connection IDs
    fn active_cid_count(&self) -> usize;
}

/// Packet Space Manager
///
/// Manages per-packet-number-space state (Initial, Handshake, ApplicationData).
///
/// ## RFC 9000 Section 12.1:
/// QUIC has three packet number spaces with independent packet numbers and ACKs.
pub trait PacketSpaceManager {
    /// Get the next packet number for a packet number space
    fn next_packet_number(&mut self, space: PacketNumberSpace) -> PacketNumber;

    /// Get the largest acknowledged packet number
    fn largest_acked(&self, space: PacketNumberSpace) -> Option<PacketNumber>;

    /// Update largest acknowledged packet number
    fn update_largest_acked(&mut self, space: PacketNumberSpace, pn: PacketNumber);

    /// Check if a packet number has been acknowledged
    fn is_acked(&self, space: PacketNumberSpace, pn: PacketNumber) -> bool;

    /// Get the largest sent packet number
    fn largest_sent(&self, space: PacketNumberSpace) -> Option<PacketNumber>;
}

/// Connection Context Builder
///
/// Builder pattern for creating connection contexts.
pub trait ConnectionBuilder {
    /// Set the connection role (client or server)
    fn with_side(self, side: Side) -> Self;

    /// Set initial destination Connection ID
    fn with_initial_dcid(self, dcid: ConnectionId) -> Self;

    /// Set initial source Connection ID
    fn with_initial_scid(self, scid: ConnectionId) -> Self;

    /// Set transport parameters
    fn with_transport_params(self, params: TransportParameters) -> Self;

    /// Set ALPN protocols
    fn with_alpn(self, alpn: Vec<Bytes>) -> Self;

    /// Set crypto backend
    fn with_crypto_backend(self, backend: Box<dyn CryptoBackend>) -> Self;

    /// Build the connection
    fn build(self) -> Result<Box<dyn Connection>>;
}
