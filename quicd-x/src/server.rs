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
