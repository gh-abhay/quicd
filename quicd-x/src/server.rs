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
