use std::net::SocketAddr;

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};

use crate::error::ConnectionError;
use crate::handle::{
    ConnectionHandle, ConnectionId, ConnectionStats, RecvStream, SendStream, StreamId,
};

/// Commands the application sends back to the worker for egress operations.
#[derive(Debug)]
pub enum EgressCommand {
    OpenBi {
        reply: oneshot::Sender<Result<(SendStream, RecvStream), ConnectionError>>,
    },
    OpenUni {
        reply: oneshot::Sender<Result<SendStream, ConnectionError>>,
    },
    SendDatagram {
        data: Bytes,
        reply: oneshot::Sender<Result<usize, ConnectionError>>,
    },
    ResetStream {
        stream_id: StreamId,
        error_code: u64,
        reply: oneshot::Sender<Result<(), ConnectionError>>,
    },
    Close {
        error_code: u64,
        reason: Option<Bytes>,
    },
    RequestStats {
        reply: oneshot::Sender<Result<ConnectionStats, ConnectionError>>,
    },
}

/// Low-level stream write command consumed by the worker side of a send stream.
#[derive(Debug)]
pub struct StreamWriteCmd {
    pub data: Bytes,
    pub fin: bool,
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
pub fn new_recv_stream(stream_id: StreamId, rx: mpsc::Receiver<Bytes>) -> RecvStream {
    RecvStream::new(stream_id, rx)
}
