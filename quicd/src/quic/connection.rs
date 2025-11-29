//! QUIC connection wrapper.
//!
//! Wraps a Quiche connection and provides:
//! - Connection state management
//! - Stream handling
//! - Send/receive buffer management
//! - Timeout tracking

use quiche::ConnectionId;
use std::net::SocketAddr;
use std::time::Instant;
use tokio::sync::{mpsc, oneshot};

/// Convert a quiche ConnectionId to a quicd-x ConnectionId (u128).
///
/// We take the first 16 bytes of the scid and convert to u128.
/// If scid is shorter, we pad with zeros.
fn scid_to_connection_id(scid: &ConnectionId) -> quicd_x::ConnectionId {
    let bytes = scid.as_ref();
    let mut buf = [0u8; 16];
    let len = bytes.len().min(16);
    buf[..len].copy_from_slice(&bytes[..len]);
    u128::from_be_bytes(buf)
}

/// Wrapper around a Quiche connection
pub struct QuicConnection {
    /// The underlying Quiche connection
    pub conn: quiche::Connection,

    /// Peer address (source IP:port)
    pub peer_addr: SocketAddr,

    /// Connection ID for routing (Destination Connection ID from client perspective)
    pub scid: ConnectionId<'static>,

    /// Alternate Destination Connection IDs observed for this connection.
    ///
    /// The QUIC client may use multiple destination connection IDs over the
    /// lifetime of the connection (e.g. during Initial packets, migrations or
    /// as part of connection ID retirement). We track the set of DCIDs we have
    /// seen so the worker can route future packets correctly and clean up the
    /// alias map when the connection is dropped.
    pub dcid_aliases: Vec<ConnectionId<'static>>,

    /// Last time we received a packet from this connection
    pub last_active: Instant,

    /// Connection statistics (updated periodically)
    pub stats: ConnectionStats,

    /// Channel for sending events to the application task (ingress from worker to app)
    pub ingress_tx: Option<mpsc::Sender<quicd_x::AppEvent>>,

    /// Handle to the application task (for tracking and cleanup)
    pub app_task_handle: Option<tokio::task::JoinHandle<()>>,

    /// Unique connection ID for quicd-x handle (derived from scid)
    pub connection_id: quicd_x::ConnectionId,

    /// Stream manager for handling stream lifecycle and data flow
    pub stream_manager: Option<crate::worker::streams::StreamManager>,

    /// Shutdown signal sender (used to notify app task when connection closes)
    pub shutdown_tx: Option<oneshot::Sender<()>>,

    /// Stream ID generator for this connection
    pub stream_id_gen: StreamIdGenerator,
}

/// Connection statistics
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    /// Total packets received
    pub packets_recv: u64,
    /// Total packets sent
    pub packets_sent: u64,
    /// Total bytes received (application data)
    pub bytes_recv: u64,
    /// Total bytes sent (application data)
    pub bytes_sent: u64,
    /// Number of active streams
    pub active_streams: usize,
}

/// Stream ID counters for a connection.
///
/// QUIC stream IDs follow this pattern:
/// - Client-initiated bidirectional: 0, 4, 8, 12, ... (id % 4 == 0)
/// - Client-initiated unidirectional: 2, 6, 10, 14, ... (id % 4 == 2)
/// - Server-initiated bidirectional: 1, 5, 9, 13, ... (id % 4 == 1)
/// - Server-initiated unidirectional: 3, 7, 11, 15, ... (id % 4 == 3)
///
/// Each connection maintains its own stream ID counters, and stream IDs
/// are unique only within a single connection (not globally).
#[derive(Debug, Clone)]
pub struct StreamIdGenerator {
    /// Next server-initiated bidirectional stream ID
    next_bidi: u64,
    /// Next server-initiated unidirectional stream ID
    next_uni: u64,
    /// Highest stream ID observed on this connection (both directions)
    max_stream_id: u64,
}

impl Default for StreamIdGenerator {
    fn default() -> Self {
        Self {
            // Server-initiated bidirectional streams start at 1
            next_bidi: 1,
            // Server-initiated unidirectional streams start at 3
            next_uni: 3,
            // No streams observed yet
            max_stream_id: 0,
        }
    }
}

impl StreamIdGenerator {
    /// Generate next server-initiated bidirectional stream ID.
    ///
    /// Returns stream IDs: 1, 5, 9, 13, ...
    pub fn next_bidi(&mut self) -> u64 {
        let id = self.next_bidi;
        self.next_bidi += 4;
        self.max_stream_id = self.max_stream_id.max(id);
        id
    }

    /// Generate next server-initiated unidirectional stream ID.
    ///
    /// Returns stream IDs: 3, 7, 11, 15, ...
    pub fn next_uni(&mut self) -> u64 {
        let id = self.next_uni;
        self.next_uni += 4;
        self.max_stream_id = self.max_stream_id.max(id);
        id
    }

    /// Update max stream ID when observing a client-initiated stream.
    /// Should be called when processing readable/writable streams from quiche.
    pub fn observe_stream_id(&mut self, stream_id: u64) {
        self.max_stream_id = self.max_stream_id.max(stream_id);
    }

    /// Get the highest stream ID observed on this connection.
    pub fn max_stream_id(&self) -> u64 {
        self.max_stream_id
    }
}

impl QuicConnection {
    /// Create a new QUIC connection
    pub fn new(
        conn: quiche::Connection,
        peer_addr: SocketAddr,
        scid: ConnectionId<'static>,
    ) -> Self {
        // Generate a stable connection ID for quicd-x from the scid
        let connection_id = scid_to_connection_id(&scid);

        Self {
            conn,
            peer_addr,
            scid,
            dcid_aliases: Vec::new(),
            last_active: Instant::now(),
            stats: ConnectionStats::default(),
            ingress_tx: None,
            app_task_handle: None,
            connection_id,
            stream_manager: None,
            shutdown_tx: None,
            stream_id_gen: StreamIdGenerator::default(),
        }
    }

    /// Process an incoming packet
    ///
    /// Returns the number of bytes processed, or error if packet is invalid.
    pub fn recv(&mut self, buf: &mut [u8], info: quiche::RecvInfo) -> Result<usize, quiche::Error> {
        self.last_active = Instant::now();
        self.stats.packets_recv += 1;

        self.conn.recv(buf, info)
    }

    /// Generate packets to send
    ///
    /// Writes packets into the provided buffer and returns the size and destination.
    /// Returns `Done` when there are no more packets to send.
    pub fn send(&mut self, out: &mut [u8]) -> Result<(usize, quiche::SendInfo), quiche::Error> {
        match self.conn.send(out) {
            Ok((written, send_info)) => {
                self.stats.packets_sent += 1;
                Ok((written, send_info))
            }
            Err(e) => Err(e),
        }
    }

    /// Check if connection is established (handshake complete)
    #[inline]
    pub fn is_established(&self) -> bool {
        self.conn.is_established()
    }

    /// Check if connection is closed
    #[inline]
    pub fn is_closed(&self) -> bool {
        self.conn.is_closed()
    }

    /// Check if connection is in early data state (0-RTT)
    #[inline]
    pub fn is_in_early_data(&self) -> bool {
        self.conn.is_in_early_data()
    }

    /// Get connection timeout
    ///
    /// Returns the duration until the next timeout event (retransmission, idle, etc.)
    #[inline]
    pub fn timeout(&self) -> Option<std::time::Duration> {
        self.conn.timeout()
    }

    /// Handle connection timeout
    ///
    /// Must be called when the timeout duration returned by `timeout()` expires.
    pub fn on_timeout(&mut self) {
        self.conn.on_timeout();
    }

    /// Get readable stream IDs
    ///
    /// Returns an iterator over stream IDs that have data ready to read.
    pub fn readable(&self) -> impl Iterator<Item = u64> + '_ {
        self.conn.readable()
    }

    /// Get writable stream IDs
    ///
    /// Returns an iterator over stream IDs that are ready to accept data.
    pub fn writable(&self) -> impl Iterator<Item = u64> + '_ {
        self.conn.writable()
    }

    /// Read from a stream
    ///
    /// Reads application data from the specified stream into the buffer.
    /// Returns the number of bytes read and whether the stream is finished.
    pub fn stream_recv(
        &mut self,
        stream_id: u64,
        out: &mut [u8],
    ) -> Result<(usize, bool), quiche::Error> {
        let (read, fin) = self.conn.stream_recv(stream_id, out)?;
        self.stats.bytes_recv += read as u64;
        Ok((read, fin))
    }

    /// Write to a stream
    ///
    /// Writes application data to the specified stream.
    /// Returns the number of bytes written.
    pub fn stream_send(
        &mut self,
        stream_id: u64,
        buf: &[u8],
        fin: bool,
    ) -> Result<usize, quiche::Error> {
        let written = self.conn.stream_send(stream_id, buf, fin)?;
        self.stats.bytes_sent += written as u64;
        Ok(written)
    }

    /// Close the connection with an error code
    pub fn close(&mut self, app: bool, err: u64, reason: &[u8]) -> Result<(), quiche::Error> {
        self.conn.close(app, err, reason)
    }

    /// Update connection statistics from Quiche stats
    pub fn update_stats(&mut self) {
        let stats = self.conn.stats();
        // Update from quiche stats
        self.stats.packets_recv = stats.recv as u64;
        self.stats.packets_sent = stats.sent as u64;

        // Count active streams
        let mut active = 0;
        for _stream_id in self.conn.readable() {
            active += 1;
        }
        for _stream_id in self.conn.writable() {
            active += 1;
        }
        self.stats.active_streams = active;
    }

    /// Get path statistics
    pub fn path_stats(&self) -> Option<quiche::PathStats> {
        self.conn.path_stats().next()
    }

    /// Get next path event (connection migration, path validation)
    ///
    /// Returns the next path event if any are pending.
    /// Should be called after processing received packets to handle
    /// connection migration and path validation events.
    pub fn path_event_next(&mut self) -> Option<quiche::PathEvent> {
        self.conn.path_event_next()
    }

    /// Send DATAGRAM
    ///
    /// Sends an unreliable datagram over the connection (RFC 9221).
    /// Requires DATAGRAM extension to be enabled.
    pub fn dgram_send(&mut self, buf: &[u8]) -> Result<(), quiche::Error> {
        self.conn.dgram_send(buf)
    }

    /// Receive DATAGRAM
    ///
    /// Receives an unreliable datagram from the connection.
    pub fn dgram_recv(&mut self, buf: &mut [u8]) -> Result<usize, quiche::Error> {
        self.conn.dgram_recv(buf)
    }

    /// Get connection trace ID for logging
    pub fn trace_id(&self) -> &str {
        self.conn.trace_id()
    }
}

impl std::fmt::Debug for QuicConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicConnection")
            .field("peer_addr", &self.peer_addr)
            .field("scid", &self.scid)
            .field("is_established", &self.is_established())
            .field("is_closed", &self.is_closed())
            .field("stats", &self.stats)
            .finish()
    }
}
