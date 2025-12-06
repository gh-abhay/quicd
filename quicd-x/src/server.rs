use std::net::SocketAddr;

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};

use crate::error::ConnectionError;
use crate::handle::{ConnectionHandle, ConnectionId, RecvStream, SendStream, StreamData, StreamId};

/// Commands the application sends back to the worker for egress operations.
///
/// These are non-blocking; the worker processes them as part of its main event loop.
/// If a command cannot be processed immediately (e.g., stream not open), the worker
/// generates a response event.
#[derive(Debug)]
pub enum EgressCommand {
    /// Request to open a new bidirectional stream.
    ///
    /// Response: `AppEvent::StreamOpened`
    OpenBi {
        request_id: u64,
        connection_id: ConnectionId,
    },

    /// Request to open a new unidirectional stream.
    ///
    /// Response: `AppEvent::UniStreamOpened`
    OpenUni {
        request_id: u64,
        connection_id: ConnectionId,
    },

    /// Request to send an unreliable datagram.
    ///
    /// Datagrams are independent; loss of one doesn't affect others.
    /// Response: `AppEvent::DatagramSent`
    SendDatagram {
        request_id: u64,
        connection_id: ConnectionId,
        data: Bytes,
    },

    /// Request to reset (close) a stream with an error code.
    ///
    /// Response: `AppEvent::StreamReset`
    ResetStream {
        request_id: u64,
        connection_id: ConnectionId,
        stream_id: StreamId,
        error_code: u64,
    },

    /// Request to gracefully close the entire connection.
    ///
    /// No response; connection will close and `AppEvent::ConnectionClosing` will be sent.
    Close {
        connection_id: ConnectionId,
        error_code: u64,
        reason: Option<Bytes>,
    },

    /// Request connection-level statistics.
    ///
    /// Response: `AppEvent::StatsReceived`
    RequestStats {
        request_id: u64,
        connection_id: ConnectionId,
    },

    /// Query connection state (e.g., is_in_early_data).
    ///
    /// Response delivered via oneshot channel
    QueryConnectionState {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<ConnectionState>,
    },

    /// Request connection migration to new local address (RFC 9000 §9).
    ///
    /// The worker will initiate path validation automatically.
    MigrateTo {
        connection_id: ConnectionId,
        new_local_addr: SocketAddr,
    },

    /// Request path validation for specific address (RFC 9000 §8.2).
    ///
    /// Response: TransportEvent::PathValidated or PathValidationFailed
    ValidatePath {
        connection_id: ConnectionId,
        peer_addr: SocketAddr,
    },

    /// Set stream priority using RFC 9218 extensible priority scheme.
    ///
    /// No explicit response; priority changes reflected in stream behavior.
    SetStreamPriority {
        connection_id: ConnectionId,
        stream_id: StreamId,
        urgency: u8,
        incremental: bool,
    },

    /// Send STOP_SENDING frame to peer (RFC 9000 §3.5).
    ///
    /// Requests peer to stop sending on this stream.
    StopSending {
        connection_id: ConnectionId,
        stream_id: StreamId,
        error_code: u64,
    },

    /// Query maximum datagram size (RFC 9221 §3).
    ///
    /// Returns the maximum size of datagram that can be sent.
    /// Response delivered via oneshot channel.
    GetMaxDatagramSize {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<Option<usize>>,
    },

    /// Query remaining stream credits (RFC 9000 §4.6).
    ///
    /// Returns how many more streams can be opened.
    /// Response delivered via oneshot channel.
    GetStreamCredits {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<StreamCredits>,
    },

    /// Query stream send capacity (RFC 9000 §4.1).
    ///
    /// Returns how many bytes can be sent on this stream without being
    /// blocked by flow control. Applications can use this to implement
    /// adaptive sending strategies.
    /// Response delivered via oneshot channel.
    QueryStreamCapacity {
        connection_id: ConnectionId,
        stream_id: StreamId,
        reply: tokio::sync::oneshot::Sender<Result<u64, ConnectionError>>,
    },

    /// Query connection-level send capacity (RFC 9000 §4.1).
    ///
    /// Returns total bytes available for sending across all streams,
    /// limited by the peer's MAX_DATA frame.
    /// Response delivered via oneshot channel.
    QueryConnectionCapacity {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<u64>,
    },

    /// Query if stream has data ready to read (RFC 9000 §2.2).
    ///
    /// Returns true if stream has buffered receive data available.
    /// Response delivered via oneshot channel.
    QueryStreamReadable {
        connection_id: ConnectionId,
        stream_id: StreamId,
        reply: tokio::sync::oneshot::Sender<bool>,
    },

    /// Query if stream can accept data for sending (RFC 9000 §2.2).
    ///
    /// Returns true if stream has send buffer space and flow control capacity.
    /// Response delivered via oneshot channel.
    QueryStreamWritable {
        connection_id: ConnectionId,
        stream_id: StreamId,
        reply: tokio::sync::oneshot::Sender<bool>,
    },

    /// Query if stream is finished (RFC 9000 §2.2).
    ///
    /// Returns true if peer sent FIN and all data has been read.
    /// Response delivered via oneshot channel.
    QueryStreamFinished {
        connection_id: ConnectionId,
        stream_id: StreamId,
        reply: tokio::sync::oneshot::Sender<bool>,
    },

    /// Gracefully shutdown send side of stream (RFC 9000 §3.1).
    ///
    /// Sends FIN flag but doesn't reset the stream. The peer can still
    /// send data on their side (for bidirectional streams).
    ShutdownStream {
        connection_id: ConnectionId,
        stream_id: StreamId,
        /// Application error code (0 for graceful close)
        error_code: u64,
        reply: tokio::sync::oneshot::Sender<Result<(), ConnectionError>>,
    },

    /// Request to retire a connection ID (RFC 9000 §5.1).
    ///
    /// The worker will send RETIRE_CONNECTION_ID frame to peer.
    RetireConnectionId {
        connection_id: ConnectionId,
        /// Sequence number of CID to retire
        sequence: u64,
    },

    /// Request new connection ID from peer (RFC 9000 §5.1).
    ///
    /// Triggers NEW_CONNECTION_ID frame request. Response delivered
    /// via TransportEvent::NewConnectionId.
    RequestNewConnectionId {
        connection_id: ConnectionId,
    },

    /// Probe path by sending PATH_CHALLENGE (RFC 9000 §8.2).
    ///
    /// Used for path validation or active probing.
    ProbePath {
        connection_id: ConnectionId,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        /// Challenge data (variable length, typically 8 bytes)
        data: bytes::Bytes,
    },

    /// Set maximum stream data limit for specific stream (RFC 9000 §4.1).
    ///
    /// Manually override flow control window. Typically used for
    /// custom backpressure strategies.
    SetStreamMaxData {
        connection_id: ConnectionId,
        stream_id: StreamId,
        max_data: u64,
    },

    /// Set connection-level maximum data limit (RFC 9000 §4.1).
    ///
    /// Manually override connection flow control window.
    SetConnectionMaxData {
        connection_id: ConnectionId,
        max_data: u64,
    },

    /// Request key update (RFC 9001 §6).
    ///
    /// Initiates TLS key rotation. The worker will trigger the key update
    /// and notify via TransportEvent::KeyUpdateInitiated.
    UpdateKeys {
        connection_id: ConnectionId,
    },

    /// Query if connection can send 0-RTT data (RFC 9001 §4.6).
    ///
    /// Checks if early data is available for sending.
    CanSendEarlyData {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<bool>,
    },

    /// Query peer's transport parameters (RFC 9000 §7.4).
    ///
    /// Returns the negotiated parameters from the peer.
    GetPeerTransportParams {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<Option<PeerTransportParams>>,
    },

    /// Set DATAGRAM send priority (implementation-specific).
    ///
    /// Higher priority datagrams are sent before lower priority ones.
    SetDatagramPriority {
        connection_id: ConnectionId,
        priority: u8,
    },

    /// Query current path MTU (RFC 9000 §14).
    ///
    /// Returns the effective MTU for the active path.
    GetPathMtu {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<usize>,
    },

    /// Query all active paths (for multipath/migration scenarios).
    ///
    /// Returns list of validated network paths.
    GetActivePaths {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<Vec<PathInfo>>,
    },

    /// Set stream send order (HTTP/3 priority, RFC 9218).
    ///
    /// Controls scheduler ordering for stream transmission.
    SetStreamSendOrder {
        connection_id: ConnectionId,
        stream_id: StreamId,
        /// Send order value (higher = earlier transmission)
        send_order: i64,
    },

    // ============ Stream Iterator Queries (RFC 9000 §2) ============
    
    /// Poll all currently readable streams (triggers edge-triggered event).
    ///
    /// Worker responds with ReadableStreamsUpdated event containing
    /// the set of streams with pending receive data.
    PollReadableStreams {
        connection_id: ConnectionId,
    },

    /// Poll all currently writable streams (triggers edge-triggered event).
    ///
    /// Worker responds with WritableStreamsUpdated event containing
    /// the set of streams with available send capacity.
    PollWritableStreams {
        connection_id: ConnectionId,
    },

    /// Get next readable stream (iterator-style access).
    ///
    /// Worker responds with NextReadableStream event. Returns None
    /// when no readable streams remain.
    GetNextReadableStream {
        connection_id: ConnectionId,
        request_id: u64,
    },

    /// Get next writable stream (iterator-style access).
    ///
    /// Worker responds with NextWritableStream event. Returns None
    /// when no writable streams remain.
    GetNextWritableStream {
        connection_id: ConnectionId,
        request_id: u64,
    },

    // ============ Connection ID Management Queries (RFC 9000 §5.1) ============
    
    /// Issue new source connection ID (RFC 9000 §5.1.1).
    ///
    /// Generates a NEW_CONNECTION_ID frame with a new SCID for path migration
    /// or connection ID rotation. Worker responds with SourceConnectionIdIssued event.
    IssueNewScid {
        connection_id: ConnectionId,
        request_id: u64,
        /// Optional: specific connection ID to use (if None, auto-generated)
        scid: Option<Vec<u8>>,
    },

    /// Enumerate all source connection IDs (RFC 9000 §5.1).
    ///
    /// Worker responds with SourceConnectionIds event containing all
    /// active SCIDs with their sequence numbers and reset tokens.
    GetSourceConnectionIds {
        connection_id: ConnectionId,
        request_id: u64,
    },

    // ============ Multipath Commands (P0 Gap #3, #4) ============
    
    /// Get statistics for all active paths (RFC 9000 §9).
    ///
    /// Worker responds with AllPathStats event containing detailed
    /// statistics (RTT, cwnd, bytes in flight, etc.) for each path.
    GetAllPathStats {
        connection_id: ConnectionId,
        request_id: u64,
    },

    /// Send stream data on a specific path (multipath QUIC).
    ///
    /// Allows explicit path selection for stream transmission. Useful for
    /// load balancing or path-specific optimization.
    ///
    /// NOTE: Quiche 0.24.6 does not expose send_on_path() in public API.
    /// This command returns NotImplemented until Quiche adds multipath support.
    SendOnPath {
        connection_id: ConnectionId,
        stream_id: StreamId,
        data: bytes::Bytes,
        fin: bool,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        reply: tokio::sync::oneshot::Sender<Result<usize, ConnectionError>>,
    },

    QuerySourceId {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<Vec<u8>>,
    },

    QueryDestinationId {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<Vec<u8>>,
    },

    QueryAvailableDcids {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<usize>,
    },

    QueryScidsLeft {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<usize>,
    },

    // ============ Timeout Management Queries (RFC 9000 §10.1) ============
    
    QueryTimeout {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<Option<std::time::Duration>>,
    },

    OnTimeout {
        connection_id: ConnectionId,
    },

    // ============ TLS Session Queries (RFC 8446) ============
    
    QuerySession {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<Option<Vec<u8>>>,
    },

    QueryServerName {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<Option<String>>,
    },

    QueryPeerCert {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<Option<Vec<u8>>>,
    },

    QueryPeerCertChain {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<Option<Vec<Vec<u8>>>>,
    },

    // ============ Connection State Queries (RFC 9000) ============
    
    QueryIsEstablished {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<bool>,
    },

    QueryIsResumed {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<bool>,
    },

    QueryIsInEarlyData {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<bool>,
    },

    QueryIsClosed {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<bool>,
    },

    QueryIsDraining {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<bool>,
    },

    QueryIsTimedOut {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<bool>,
    },

    /// Query peer-initiated connection close error (RFC 9000 §10.2).
    ///
    /// Returns the error code and reason sent by peer in CONNECTION_CLOSE frame,
    /// or None if the connection was closed locally or is still open.
    QueryPeerError {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<Option<(u64, Vec<u8>)>>,
    },

    /// Query local-initiated connection close error (RFC 9000 §10.2).
    ///
    /// Returns the error code and reason that we sent to peer in CONNECTION_CLOSE frame,
    /// or None if the connection was closed by peer or is still open.
    QueryLocalError {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<Option<(u64, Vec<u8>)>>,
    },

    /// Query active Source Connection IDs (RFC 9000 §5.1).
    ///
    /// Returns all currently active SCIDs as (sequence, cid_bytes) tuples.
    QueryActiveScids {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<Vec<(u64, Vec<u8>)>>,
    },

    /// Query send quantum for pacing (RFC 9002 §7.7).
    ///
    /// Returns the maximum number of bytes that should be sent in a single burst.
    QuerySendQuantum {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<usize>,
    },

    // ============ DATAGRAM Queries (RFC 9221) ============
    
    /// Purge all unsent DATAGRAMs from send queue (RFC 9221 §5).
    ///
    /// Clears all datagrams waiting to be sent. Useful for real-time applications
    /// that want to drop stale data.
    DgramPurgeOutgoing {
        connection_id: ConnectionId,
    },
    
    QueryDgramMaxWritableLen {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<Option<usize>>,
    },

    QueryDgramSendQueueLen {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<usize>,
    },

    QueryDgramRecvQueueLen {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<usize>,
    },

    QueryDgramRecvQueueByteSize {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<usize>,
    },

    QueryDgramSendQueueByteSize {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<usize>,
    },

    // ============ Path Management Queries (RFC 9000 §4.6, §8.1) ============
    
    QueryPeerStreamsLeftBidi {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<u64>,
    },

    QueryPeerStreamsLeftUni {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<u64>,
    },

    QueryPeerVerifiedAddress {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<bool>,
    },

    // ============ Statistics Query (RFC 9000) ============
    
    QueryStats {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<crate::ConnectionStats>,
    },

    // ============ P0 Critical Additions ============

    /// Send ACK_FREQUENCY frame (RFC 9330).
    ///
    /// Request the peer to adjust their ACK generation frequency.
    /// Used for latency-sensitive applications.
    SendAckFrequency {
        connection_id: ConnectionId,
        /// Packet tolerance before sending ACK
        ack_eliciting_threshold: u64,
        /// Maximum ACK delay in microseconds
        request_max_ack_delay: u64,
        /// Whether to ignore packet ordering
        ignore_order: bool,
    },

    /// Query available send window synchronously (P0 #5).
    ///
    /// Returns connection-level bytes available for immediate sending.
    /// Response: AppEvent::AvailableSendWindow
    QueryAvailableSendWindow {
        connection_id: ConnectionId,
        request_id: u64,
    },

    /// Query if this is a server-side connection (P0/P2 #9).
    ///
    /// Response: AppEvent::IsServer
    QueryIsServer {
        connection_id: ConnectionId,
        request_id: u64,
    },

    /// Request next path event for frame-level introspection (P0 #3).
    ///
    /// Provides detailed PATH_CHALLENGE/RESPONSE events.
    /// Response: AppEvent::PathEvent or None if no events pending
    GetNextPathEvent {
        connection_id: ConnectionId,
        request_id: u64,
    },

    /// Shutdown stream in specific direction (P1 #6).
    ///
    /// Extended version supporting read/write/both directions.
    ShutdownStreamDirection {
        connection_id: ConnectionId,
        stream_id: StreamId,
        direction: StreamShutdownDirection,
        error_code: u64,
        reply: tokio::sync::oneshot::Sender<Result<(), ConnectionError>>,
    },

    /// Enable or disable PMTU discovery at runtime (P2 #15).
    SetPmtuDiscovery {
        connection_id: ConnectionId,
        enabled: bool,
    },

    /// Set maximum pacing rate at runtime (P2 #14).
    SetMaxPacingRate {
        connection_id: ConnectionId,
        /// Bytes per second (None = unlimited)
        rate_bps: Option<u64>,
    },

    /// Query active source connection ID (P2 #12).
    QueryActiveScid {
        connection_id: ConnectionId,
        reply: tokio::sync::oneshot::Sender<Vec<u8>>,
    },
}

/// Direction for stream shutdown (RFC 9000 §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamShutdownDirection {
    /// Shutdown read side (send STOP_SENDING)
    Read,
    /// Shutdown write side (send FIN or RESET_STREAM)
    Write,
    /// Shutdown both directions
    Both,
}

/// Stream credit information (RFC 9000 §4.6).
#[derive(Debug, Clone, Copy)]
pub struct StreamCredits {
    /// Remaining bidirectional streams that can be opened
    pub bidi: u64,
    /// Remaining unidirectional streams that can be opened
    pub uni: u64,
}

/// Connection state information for queries.
#[derive(Debug, Clone)]
pub struct ConnectionState {
    /// Whether the connection is currently in early data (0-RTT) state
    pub is_in_early_data: bool,
}

/// Peer transport parameters (RFC 9000 §7.4).
#[derive(Debug, Clone)]
pub struct PeerTransportParams {
    /// Peer's max idle timeout (milliseconds)
    pub max_idle_timeout: u64,
    /// Peer's initial max data (connection-level flow control)
    pub initial_max_data: u64,
    /// Peer's initial max stream data (bidirectional local)
    pub initial_max_stream_data_bidi_local: u64,
    /// Peer's initial max stream data (bidirectional remote)
    pub initial_max_stream_data_bidi_remote: u64,
    /// Peer's initial max stream data (unidirectional)
    pub initial_max_stream_data_uni: u64,
    /// Peer's max bidirectional streams limit
    pub max_streams_bidi: u64,
    /// Peer's max unidirectional streams limit
    pub max_streams_uni: u64,
    /// Peer's ACK delay exponent
    pub ack_delay_exponent: u64,
    /// Peer's max ACK delay (milliseconds)
    pub max_ack_delay: u64,
    /// Peer's active connection ID limit
    pub active_connection_id_limit: u64,
    /// Whether peer disabled active migration
    pub disable_active_migration: bool,
    /// Peer's max UDP payload size
    pub max_udp_payload_size: u64,
}

/// Information about a network path.
#[derive(Debug, Clone)]
pub struct PathInfo {
    /// Local socket address
    pub local_addr: SocketAddr,
    /// Peer socket address
    pub peer_addr: SocketAddr,
    /// Whether path is validated
    pub validated: bool,
    /// Whether this is the active path
    pub active: bool,
    /// Current RTT estimate (microseconds)
    pub rtt_us: u64,
}

/// Low-level stream write command consumed by the worker side of a send stream.
///
/// This is the transport mechanism for stream data from app to worker.
/// The worker writes this data to the QUIC layer for transmission.
/// The `reply` channel is used to send back acknowledgment (or error).
#[derive(Debug)]
pub struct StreamWriteCmd {
    /// Data payload (zero-copy)
    pub data: Bytes,
    /// True to send a FIN (end-of-stream) flag
    pub fin: bool,
    /// Channel to reply with the result (bytes written or error)
    pub reply: oneshot::Sender<Result<usize, ConnectionError>>,
}

/// Helper for worker code to create a [`ConnectionHandle`].
pub fn new_connection_handle(
    connection_id: ConnectionId,
    egress_tx: mpsc::Sender<EgressCommand>,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
) -> ConnectionHandle {
    ConnectionHandle::new(connection_id, egress_tx, local_addr, peer_addr)
}

/// Helper for worker code to create a [`SendStream`].
pub fn new_send_stream(stream_id: StreamId, tx: mpsc::Sender<StreamWriteCmd>) -> SendStream {
    SendStream::new(stream_id, tx)
}

/// Helper for worker code to create a [`RecvStream`].
pub fn new_recv_stream(stream_id: StreamId, rx: mpsc::Receiver<StreamData>) -> RecvStream {
    RecvStream::new(stream_id, rx)
}
