//! # QUIC Connection State Machine (RFC 9000)
//!
//! This module defines the **top-level connection state machine** that orchestrates
//! all QUIC subsystems: crypto, streams, recovery, flow control, and packet processing.
//!
//! ## Pure State Machine Design
//!
//! The connection is a **pure state machine** with **no I/O dependencies**:
//! - **Input**: Accepts incoming datagrams (`&[u8]`) and time (`Instant`)
//! - **Output**: Produces outgoing datagrams via caller-provided buffers (`&mut [u8]`)
//! - **Deterministic**: State transitions depend only on inputs and time
//!
//! ## Architecture
//!
//! ```text
//! ┌────────────────────────────────────────────────────────┐
//! │               QuicConnection (Main State Machine)       │
//! ├────────────────────────────────────────────────────────┤
//! │ • Connection State (Handshaking, Active, Closing, etc.) │
//! │ • Connection ID Management                              │
//! │ • Timer Management (Idle, PTO, Close, etc.)             │
//! │ • Orchestrates all subsystems                           │
//! └────────┬───────────┬──────────┬──────────┬─────────────┘
//!          │           │          │          │
//!          ▼           ▼          ▼          ▼
//!    ┌────────┐  ┌────────┐  ┌──────┐  ┌─────────┐
//!    │ Crypto │  │Recovery│  │Stream│  │Transport│
//!    │ Module │  │ Module │  │Module│  │  Params │
//!    └────────┘  └────────┘  └──────┘  └─────────┘
//! ```
//!
//! ## Connection Lifecycle (RFC 9000 Section 5)
//!
//! ```text
//! Client:
//!   Initial → Handshaking → Active → Closing → Draining → Closed
//!
//! Server:
//!   Listen → Handshaking → Active → Closing → Draining → Closed
//! ```

#![forbid(unsafe_code)]

use crate::crypto::{CryptoContext, EncryptionLevel};
use crate::error::{Error, Result};
use crate::frames::Frame;
use crate::packet::{PacketNumber, PacketNumberSpace};
use crate::recovery::{CongestionController, LossDetector, RttEstimator};
use crate::stream::StreamManager;
use crate::transport::parameters::TransportParameters;
use alloc::vec::Vec;
use core::time::Duration;

/// Type alias for time tracking (no_std compatible)
pub type Instant = Duration;

// ============================================================================
// Connection State (RFC 9000 Section 5)
// ============================================================================

/// Connection State (RFC 9000 Section 5)
///
/// Represents the high-level lifecycle state of a QUIC connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Initial state before handshake begins (client only)
    Initial,
    
    /// Handshake in progress (crypto handshake not yet complete)
    ///
    /// Transitions:
    /// - To `Active` when handshake completes
    /// - To `Closing` on error or CONNECTION_CLOSE frame
    Handshaking,
    
    /// Connection established and active
    ///
    /// Normal data transfer occurs in this state.
    /// Transitions:
    /// - To `Closing` when initiating connection close
    /// - To `Draining` when receiving CONNECTION_CLOSE
    Active,
    
    /// Closing: Sent CONNECTION_CLOSE, waiting for peer acknowledgment
    ///
    /// In this state:
    /// - No new streams can be created
    /// - Only CONNECTION_CLOSE frames are sent
    /// - Waits for 3 * PTO before transitioning to Draining
    Closing,
    
    /// Draining: Received CONNECTION_CLOSE, silent period before cleanup
    ///
    /// In this state:
    /// - No packets are sent (including CONNECTION_CLOSE)
    /// - Waits for 3 * PTO before transitioning to Closed
    /// - Discards all incoming packets
    Draining,
    
    /// Closed: Connection terminated, all resources released
    ///
    /// This is a terminal state. The connection object should be destroyed.
    Closed,
}

// ============================================================================
// Connection Trait: The Main Interface
// ============================================================================

/// QuicConnection - The Top-Level QUIC State Machine
///
/// This trait defines the interface for a QUIC connection. It orchestrates
/// all subsystems and provides the main entry points for:
/// - Processing incoming packets
/// - Generating outgoing packets
/// - Managing timers
/// - Handling stream operations
///
/// ## Usage Pattern
///
/// ```rust,ignore
/// // Create connection (client or server)
/// let mut conn = QuicConnection::new(config, crypto_provider);
///
/// // Event loop
/// loop {
///     // 1. Process incoming datagrams
///     if let Some(dgram) = recv_udp() {
///         conn.on_datagram(&dgram, now())?;
///     }
///
///     // 2. Check timers
///     if let Some(timeout) = conn.next_timeout() {
///         if now() >= timeout {
///             conn.on_timeout(now())?;
///         }
///     }
///
///     // 3. Send outgoing datagrams
///     let mut buf = [0u8; 1500];
///     while let Some(len) = conn.send_datagram(&mut buf, now())? {
///         send_udp(&buf[..len]);
///     }
/// }
/// ```
pub trait QuicConnection {
    /// Process an incoming datagram
    ///
    /// **Parameters**:
    /// - `datagram`: The UDP payload bytes (may contain multiple coalesced QUIC packets)
    /// - `now`: Current time (monotonic)
    ///
    /// **Lifecycle**: Zero-copy parsing. The datagram is parsed and processed
    /// without heap allocation. Frame payloads reference the input slice.
    ///
    /// **Returns**:
    /// - `Ok(())` if datagram was processed (may still contain protocol errors)
    /// - `Err(Error)` if datagram was malformed and connection should close
    fn on_datagram(&mut self, datagram: &[u8], now: Instant) -> Result<()>;
    
    /// Generate an outgoing datagram
    ///
    /// **Parameters**:
    /// - `buffer`: Pre-allocated buffer to write the datagram into (typically MTU-sized)
    /// - `now`: Current time (monotonic)
    ///
    /// **Returns**:
    /// - `Ok(Some(len))` if a datagram was written to `buffer[..len]`
    /// - `Ok(None)` if no datagram is ready to send
    /// - `Err(Error)` if an error occurred
    ///
    /// **Zero-Copy**: Frames are serialized directly into the provided buffer.
    /// The caller is responsible for sending the datagram via UDP.
    ///
    /// **Note**: May coalesce multiple QUIC packets into a single datagram.
    fn send_datagram(&mut self, buffer: &mut [u8], now: Instant) -> Result<Option<usize>>;
    
    /// Get the next timeout deadline
    ///
    /// Returns the earliest time at which `on_timeout()` should be called.
    /// This includes:
    /// - Idle timeout
    /// - PTO (Probe Timeout)
    /// - Close timeout
    /// - ACK delay timeout
    ///
    /// **Returns**:
    /// - `Some(instant)` if there is a pending timer
    /// - `None` if no timers are active (e.g., connection is closed)
    fn next_timeout(&self) -> Option<Instant>;
    
    /// Handle timeout event
    ///
    /// Called when the deadline returned by `next_timeout()` expires.
    /// This triggers:
    /// - Probe Timeout (PTO) - retransmit or send probe
    /// - Idle timeout - close connection
    /// - Close/Draining timeout - transition to Closed state
    fn on_timeout(&mut self, now: Instant) -> Result<()>;
    
    /// Get the current connection state
    fn state(&self) -> ConnectionState;
    
    /// Check if the connection is established (handshake complete)
    fn is_established(&self) -> bool {
        matches!(self.state(), ConnectionState::Active)
    }
    
    /// Check if the connection is closed
    fn is_closed(&self) -> bool {
        matches!(self.state(), ConnectionState::Closed)
    }
    
    /// Close the connection with an error code
    ///
    /// Initiates connection termination by sending CONNECTION_CLOSE frames.
    /// The connection enters the Closing state.
    ///
    /// **Parameters**:
    /// - `error_code`: Application or transport error code
    /// - `reason`: Human-readable reason phrase
    fn close(&mut self, error_code: u64, reason: &[u8]) -> Result<()>;
}

// ============================================================================
// Connection ID Management (RFC 9000 Section 5.1)
// ============================================================================

/// Connection ID (RFC 9000 Section 5.1)
///
/// Connection IDs are variable-length identifiers (0-20 bytes) used to
/// route packets to the correct connection. They enable connection migration
/// and load balancing.
///
/// **Zero-Copy**: Represented as a slice reference during parsing.
pub type ConnectionId<'a> = &'a [u8];

/// Connection ID Sequence Number
///
/// Each connection ID has a sequence number for management and retirement.
pub type ConnectionIdSequence = u64;

/// Stateless Reset Token (RFC 9000 Section 10.3)
///
/// A 16-byte cryptographic token that allows a peer to immediately close
/// a connection without state (e.g., after server restart).
pub type StatelessResetToken = [u8; 16];

// ============================================================================
// Timer Types
// ============================================================================

/// Timer Types for Connection Management
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerType {
    /// Idle timeout (RFC 9000 Section 10.1)
    ///
    /// Connection closes if no activity for `max_idle_timeout` period.
    Idle,
    
    /// Probe Timeout (PTO) - RFC 9002 Section 6.2
    ///
    /// Triggers retransmission when ACKs are not received.
    Pto,
    
    /// ACK Delay Timer (RFC 9000 Section 13.2.1)
    ///
    /// Ensures ACKs are sent within `max_ack_delay`.
    AckDelay,
    
    /// Close/Draining Timeout (RFC 9000 Section 10.2)
    ///
    /// Time to wait in Closing/Draining states before transitioning to Closed.
    Close,
}

// ============================================================================
// Connection Configuration
// ============================================================================

/// Connection Configuration
///
/// Parameters for creating a new QUIC connection.
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    /// Local transport parameters (RFC 9000 Section 7.4)
    pub local_transport_parameters: TransportParameters,
    
    /// Maximum UDP payload size (MTU)
    ///
    /// Typically 1200 bytes initially, can increase after PMTU discovery.
    pub max_udp_payload_size: usize,
    
    /// Whether this is a client or server connection
    pub is_client: bool,
    
    /// Initial source connection ID (for clients)
    pub initial_scid: Option<Vec<u8>>,
    
    /// Initial destination connection ID (for clients)
    pub initial_dcid: Option<Vec<u8>>,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            local_transport_parameters: TransportParameters::default(),
            max_udp_payload_size: 1200,
            is_client: false,
            initial_scid: None,
            initial_dcid: None,
        }
    }
}

// ============================================================================
// Connection Statistics
// ============================================================================

/// Connection Statistics
///
/// Metrics for monitoring connection health and performance.
#[derive(Debug, Clone, Copy, Default)]
pub struct ConnectionStats {
    /// Total packets sent
    pub packets_sent: u64,
    
    /// Total packets received
    pub packets_received: u64,
    
    /// Total bytes sent (UDP payload)
    pub bytes_sent: u64,
    
    /// Total bytes received (UDP payload)
    pub bytes_received: u64,
    
    /// Total packets lost (detected by loss detection)
    pub packets_lost: u64,
    
    /// Total stream data bytes sent
    pub stream_bytes_sent: u64,
    
    /// Total stream data bytes received
    pub stream_bytes_received: u64,
    
    /// Smoothed RTT (microseconds)
    pub smoothed_rtt: Duration,
    
    /// Current congestion window (bytes)
    pub cwnd: u64,
    
    /// Current bytes in flight
    pub bytes_in_flight: u64,
}

// ============================================================================
// Connection Events (Outbound to Application)
// ============================================================================

/// Connection Events
///
/// Events that the connection generates for the application layer.
/// These are consumed via a polling interface or callback.
#[derive(Debug, Clone)]
pub enum ConnectionEvent {
    /// Handshake completed, connection is now established
    HandshakeComplete,
    
    /// New bidirectional stream opened by peer
    StreamOpened {
        stream_id: u64,
        is_bidirectional: bool,
    },
    
    /// Stream data received
    StreamData {
        stream_id: u64,
        offset: u64,
        fin: bool,
    },
    
    /// Stream reset by peer
    StreamReset {
        stream_id: u64,
        error_code: u64,
        final_size: u64,
    },
    
    /// Peer requested to stop sending on stream
    StreamStopSending {
        stream_id: u64,
        error_code: u64,
    },
    
    /// Datagram received (RFC 9221)
    DatagramReceived,
    
    /// Connection is closing
    Closing {
        error_code: u64,
        reason: Vec<u8>,
    },
    
    /// Connection is closed
    Closed,
}
