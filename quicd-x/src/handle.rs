use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};

use crate::error::ConnectionError;
use crate::server::{EgressCommand, StreamWriteCmd};

/// Identifier for a QUIC stream.
pub type StreamId = u64;
/// Identifier for a QUIC connection.
pub type ConnectionId = u128;

/// Shared handle exposed to applications for connection-scoped operations.
#[derive(Clone)]
pub struct ConnectionHandle {
    connection_id: ConnectionId,
    egress_tx: mpsc::Sender<EgressCommand>,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
}

impl ConnectionHandle {
    pub(crate) fn new(
        connection_id: ConnectionId,
        egress_tx: mpsc::Sender<EgressCommand>,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
    ) -> Self {
        Self {
            connection_id,
            egress_tx,
            local_addr,
            peer_addr,
        }
    }

    /// Returns the identifier for this connection.
    pub fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    /// Returns the local socket address in use for this connection.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns the peer socket address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Opens a new bi-directional stream.
    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream), ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.egress_tx
            .send(EgressCommand::OpenBi { reply: reply_tx })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable".into()))?;
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable".into()))?
    }

    /// Opens a new uni-directional stream.
    pub async fn open_uni(&self) -> Result<SendStream, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.egress_tx
            .send(EgressCommand::OpenUni { reply: reply_tx })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable".into()))?;
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable".into()))?
    }

    /// Sends an unreliable datagram.
    pub async fn send_datagram(&self, data: Bytes) -> Result<usize, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.egress_tx
            .send(EgressCommand::SendDatagram {
                data,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable".into()))?;
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable".into()))?
    }

    /// Resets a stream.
    pub async fn reset_stream(
        &self,
        stream_id: StreamId,
        error_code: u64,
    ) -> Result<(), ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.egress_tx
            .send(EgressCommand::ResetStream {
                stream_id,
                error_code,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable".into()))?;
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable".into()))?
    }

    /// Gracefully closes the connection.
    pub async fn close(
        &self,
        error_code: u64,
        reason: Option<Bytes>,
    ) -> Result<(), ConnectionError> {
        self.egress_tx
            .send(EgressCommand::Close { error_code, reason })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable".into()))
    }

    /// Requests latest transport statistics for this connection.
    pub async fn stats(&self) -> Result<ConnectionStats, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.egress_tx
            .send(EgressCommand::RequestStats { reply: reply_tx })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable".into()))?;
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable".into()))?
    }
}

/// Handle allowing the application to send stream data.
#[derive(Clone)]
pub struct SendStream {
    pub stream_id: StreamId,
    inner: Arc<SendStreamInner>,
}

impl fmt::Debug for SendStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SendStream")
            .field("stream_id", &self.stream_id)
            .finish()
    }
}

impl SendStream {
    pub(crate) fn new(stream_id: StreamId, tx: mpsc::Sender<StreamWriteCmd>) -> Self {
        Self {
            stream_id,
            inner: Arc::new(SendStreamInner { tx }),
        }
    }

    /// Write a data chunk to the stream. `fin` finalises the stream when true.
    pub async fn write(&self, data: Bytes, fin: bool) -> Result<usize, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.inner
            .tx
            .send(StreamWriteCmd {
                data,
                fin,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable".into()))?;
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable".into()))?
    }

    /// Convenience helper to finish the stream with an empty FIN frame.
    pub async fn finish(&self) -> Result<(), ConnectionError> {
        self.write(Bytes::new(), true).await.map(|_| ())
    }
}

struct SendStreamInner {
    tx: mpsc::Sender<StreamWriteCmd>,
}

/// Handle allowing the application to read stream data.
pub struct RecvStream {
    pub stream_id: StreamId,
    rx: mpsc::Receiver<Bytes>,
}

impl fmt::Debug for RecvStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecvStream")
            .field("stream_id", &self.stream_id)
            .finish()
    }
}

impl RecvStream {
    pub(crate) fn new(stream_id: StreamId, rx: mpsc::Receiver<Bytes>) -> Self {
        Self { stream_id, rx }
    }

    /// Reads the next chunk of data. `Ok(None)` signals FIN.
    pub async fn read(&mut self) -> Result<Option<Bytes>, ConnectionError> {
        Ok(self.rx.recv().await)
    }
}

/// Transport controls negotiated for the connection.
#[derive(Debug, Clone, Default)]
pub struct TransportControls {
    pub enable_datagrams: bool,
    pub max_datagram_size: usize,
}

/// Snapshot of connection statistics useful to applications.
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    pub rtt_estimate_ms: Option<u32>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub active_streams: usize,
    pub congestion_state: Option<String>,
}
