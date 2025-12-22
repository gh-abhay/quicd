//! # Connection State Machine (RFC 9000 Section 5, 10)
//!
//! Pure state machine - accepts datagrams and time, produces datagrams and events.

#![forbid(unsafe_code)]

use crate::crypto::{CryptoBackend, CryptoLevel, TlsSession};
use crate::error::{Error, Result};
use crate::flow_control::ConnectionFlowControl;
use crate::frames::Frame;
use crate::packet::{Header, PacketParserTrait};
use crate::packet::space::PacketNumberSpaceManager;
use crate::recovery::{CongestionController, LossDetector, RttEstimator};
use crate::stream::{StreamController, StreamManager};
use crate::transport::TransportParameters;
use crate::types::{ConnectionId, Instant, PacketNumber, Side, StreamId};
use bytes::{Bytes, BytesMut};
use core::time::Duration;

/// Connection State (RFC 9000 Section 5)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Handshake in progress
    Handshaking,

    /// Handshake complete, connection active
    Active,

    /// Draining - waiting after sending CONNECTION_CLOSE
    Draining,

    /// Closing - sending CONNECTION_CLOSE
    Closing,

    /// Connection closed
    Closed,
}

/// Connection Configuration
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    /// Local transport parameters
    pub local_params: TransportParameters,

    /// Idle timeout
    pub idle_timeout: Duration,

    /// Maximum packet size to send
    pub max_packet_size: usize,
}

/// Connection Input (Datagram)
///
/// **Zero-Copy**: Bytes references the received UDP datagram.
#[derive(Debug, Clone)]
pub struct DatagramInput {
    /// Datagram payload (entire UDP payload)
    pub data: Bytes,

    /// Time received
    pub recv_time: Instant,
}

/// Connection Output (Datagram)
///
/// **Buffer Injection**: Connection writes into provided BytesMut.
#[derive(Debug)]
pub struct DatagramOutput {
    /// Datagram payload to send
    pub data: BytesMut,

    /// When to send (for pacing, or immediate if None)
    pub send_time: Option<Instant>,
}

/// Connection Event (Application Notifications)
#[derive(Debug, Clone)]
pub enum ConnectionEvent {
    /// Handshake completed
    HandshakeComplete,

    /// Stream data available
    StreamData {
        stream_id: StreamId,
        data: Bytes,
        fin: bool,
    },

    /// Stream opened by peer
    StreamOpened { stream_id: StreamId },

    /// Stream finished (FIN received)
    StreamFinished { stream_id: StreamId },

    /// Stream reset by peer
    StreamReset {
        stream_id: StreamId,
        error_code: u64,
    },

    /// Datagram received (DATAGRAM frame)
    DatagramReceived { data: Bytes },

    /// Connection closing
    ConnectionClosing {
        error_code: u64,
        reason: Bytes,
    },

    /// Connection closed
    ConnectionClosed,
}

/// QUIC Connection (Top-Level State Machine)
///
/// **Pure State Machine Design**:
/// - No I/O - accepts bytes via `process_datagram()`
/// - No timers - accepts time via `process_timeout()`
/// - Returns bytes via `poll_send()`
/// - Returns events via `poll_event()`
///
/// **Zero-Copy + Buffer Injection**:
/// - Input: `Bytes` (zero-copy reference to received datagram)
/// - Output: Writes into caller-provided `BytesMut`
///
/// **Deterministic**: Same inputs produce same outputs (no randomness except crypto).
pub trait Connection: Send {
    /// Process incoming datagram
    ///
    /// Parses packets, processes frames, updates state.
    ///
    /// **Zero-Copy**: Input borrows from datagram buffer.
    fn process_datagram(&mut self, datagram: DatagramInput) -> Result<()>;

    /// Process timeout (called at or after deadline from `next_timeout()`)
    ///
    /// Handles PTO, idle timeout, draining timeout, etc.
    fn process_timeout(&mut self, now: Instant) -> Result<()>;

    /// Poll for outgoing datagram
    ///
    /// **Buffer Injection**: Writes into provided `buf`.
    ///
    /// Returns None if nothing to send.
    fn poll_send(&mut self, buf: &mut BytesMut, now: Instant) -> Option<DatagramOutput>;

    /// Poll for application events
    ///
    /// Returns None if no events pending.
    fn poll_event(&mut self) -> Option<ConnectionEvent>;

    /// Get next timeout deadline
    ///
    /// Returns None if no timeout pending (connection idle).
    fn next_timeout(&self) -> Option<Instant>;

    /// Get connection state
    fn state(&self) -> ConnectionState;

    /// Send datagram (DATAGRAM frame)
    fn send_datagram(&mut self, data: Bytes) -> Result<()>;

    /// Open new stream
    fn open_stream(
        &mut self,
        direction: crate::types::StreamDirection,
    ) -> Result<StreamId>;

    /// Write data to stream
    fn write_stream(&mut self, stream_id: StreamId, data: Bytes, fin: bool) -> Result<()>;

    /// Read data from stream
    fn read_stream(&mut self, stream_id: StreamId) -> Result<Option<Bytes>>;

    /// Reset stream (send RESET_STREAM)
    fn reset_stream(&mut self, stream_id: StreamId, error_code: u64) -> Result<()>;

    /// Close connection gracefully
    fn close(&mut self, error_code: u64, reason: &[u8]);

    /// Get connection statistics
    fn stats(&self) -> ConnectionStats;

    /// Get source connection ID
    fn source_cid(&self) -> &ConnectionId;

    /// Get destination connection ID
    fn destination_cid(&self) -> &ConnectionId;
}

/// Connection Statistics
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    /// Packets sent
    pub packets_sent: u64,

    /// Packets received
    pub packets_received: u64,

    /// Bytes sent
    pub bytes_sent: u64,

    /// Bytes received
    pub bytes_received: u64,

    /// Packets lost
    pub packets_lost: u64,

    /// Smoothed RTT
    pub smoothed_rtt: Duration,

    /// Congestion window
    pub congestion_window: usize,

    /// Bytes in flight
    pub bytes_in_flight: usize,
}

/// Connection Implementation Skeleton
///
/// Real implementation would contain:
/// - Packet parser
/// - Frame parser
/// - Crypto backend
/// - Stream manager
/// - Flow control
/// - Loss detector
/// - Congestion controller
/// - Packet number space manager
pub struct QuicConnection {
    /// Connection side (Client or Server)
    side: Side,

    /// Connection state
    state: ConnectionState,

    /// Source Connection ID
    scid: ConnectionId,

    /// Destination Connection ID
    dcid: ConnectionId,

    /// Configuration
    config: ConnectionConfig,

    /// Statistics
    stats: ConnectionStats,

    // Internal components (would be fully implemented):
    // packet_parser: Box<dyn PacketParser>,
    // crypto: Box<dyn CryptoBackend>,
    // tls_session: Box<dyn TlsSession>,
    // streams: StreamManager,
    // flow_control: ConnectionFlowControl,
    // loss_detector: Box<dyn LossDetector>,
    // congestion_controller: Box<dyn CongestionController>,
    // pn_spaces: PacketNumberSpaceManager,
}

impl QuicConnection {
    /// Create new connection
    pub fn new(
        side: Side,
        scid: ConnectionId,
        dcid: ConnectionId,
        config: ConnectionConfig,
    ) -> Self {
        Self {
            side,
            state: ConnectionState::Handshaking,
            scid,
            dcid,
            config,
            stats: ConnectionStats::default(),
        }
    }
}

impl Connection for QuicConnection {
    fn process_datagram(&mut self, datagram: DatagramInput) -> Result<()> {
        unimplemented!("Skeleton - no implementation required")
    }

    fn process_timeout(&mut self, now: Instant) -> Result<()> {
        unimplemented!("Skeleton")
    }

    fn poll_send(&mut self, buf: &mut BytesMut, now: Instant) -> Option<DatagramOutput> {
        unimplemented!("Skeleton")
    }

    fn poll_event(&mut self) -> Option<ConnectionEvent> {
        unimplemented!("Skeleton")
    }

    fn next_timeout(&self) -> Option<Instant> {
        unimplemented!("Skeleton")
    }

    fn state(&self) -> ConnectionState {
        self.state
    }

    fn send_datagram(&mut self, data: Bytes) -> Result<()> {
        unimplemented!("Skeleton")
    }

    fn open_stream(
        &mut self,
        direction: crate::types::StreamDirection,
    ) -> Result<StreamId> {
        unimplemented!("Skeleton")
    }

    fn write_stream(&mut self, stream_id: StreamId, data: Bytes, fin: bool) -> Result<()> {
        unimplemented!("Skeleton")
    }

    fn read_stream(&mut self, stream_id: StreamId) -> Result<Option<Bytes>> {
        unimplemented!("Skeleton")
    }

    fn reset_stream(&mut self, stream_id: StreamId, error_code: u64) -> Result<()> {
        unimplemented!("Skeleton")
    }

    fn close(&mut self, error_code: u64, reason: &[u8]) {
        unimplemented!("Skeleton")
    }

    fn stats(&self) -> ConnectionStats {
        self.stats.clone()
    }

    fn source_cid(&self) -> &ConnectionId {
        &self.scid
    }

    fn destination_cid(&self) -> &ConnectionId {
        &self.dcid
    }
}
