use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};

use crate::error::ConnectionError;
use crate::server::{EgressCommand, StreamWriteCmd};

/// Identifier for a QUIC stream.
pub type StreamId = u64;
/// Identifier for a QUIC connection.
pub type ConnectionId = u128;

/// Zero-copy stream data container.
///
/// This enum allows the worker to send either data references or FIN signals
/// to applications without copying data.
#[derive(Debug)]
pub enum StreamData {
    /// Stream data chunk with owned buffer
    Data(bytes::Bytes),
    /// Stream finished (FIN received)
    Fin,
}

/// Shared handle exposed to applications for connection-scoped operations.
#[derive(Clone)]
pub struct ConnectionHandle {
    connection_id: ConnectionId,
    egress_tx: mpsc::Sender<EgressCommand>,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    next_request_id: Arc<AtomicU64>,
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
            next_request_id: Arc::new(AtomicU64::new(0)),
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
    ///
    /// The result will be delivered as an AppEvent::StreamOpened.
    /// Returns the request ID which will be used to correlate the response.
    ///
    /// # Errors
    ///
    /// Returns `ConnectionError::Closed` if the worker thread is unavailable.
    pub fn open_bi(&self) -> Result<u64, ConnectionError> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        self.egress_tx
            .try_send(EgressCommand::OpenBi {
                request_id,
                connection_id: self.connection_id,
            })
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        Ok(request_id)
    }

    /// Opens a new uni-directional stream.
    ///
    /// The result will be delivered as an AppEvent::UniStreamOpened.
    /// Returns the request ID which will be used to correlate the response.
    ///
    /// # Errors
    ///
    /// Returns `ConnectionError::Closed` if the worker thread is unavailable.
    pub fn open_uni(&self) -> Result<u64, ConnectionError> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        self.egress_tx
            .try_send(EgressCommand::OpenUni {
                request_id,
                connection_id: self.connection_id,
            })
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        Ok(request_id)
    }

    /// Sends an unreliable datagram.
    ///
    /// Datagrams are independent packets that are not guaranteed delivery.
    /// The result will be delivered as an AppEvent::DatagramSent.
    /// Returns the request ID which will be used to correlate the response.
    ///
    /// # Errors
    ///
    /// Returns `ConnectionError::Closed` if the worker thread is unavailable.
    pub fn send_datagram(&self, data: Bytes) -> Result<u64, ConnectionError> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        self.egress_tx
            .try_send(EgressCommand::SendDatagram {
                request_id,
                connection_id: self.connection_id,
                data,
            })
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        Ok(request_id)
    }

    /// Resets a stream with an error code.
    ///
    /// The result will be delivered as an AppEvent::StreamReset.
    /// Returns the request ID which will be used to correlate the response.
    ///
    /// # Errors
    ///
    /// Returns `ConnectionError::Closed` if the worker thread is unavailable.
    pub fn reset_stream(
        &self,
        stream_id: StreamId,
        error_code: u64,
    ) -> Result<u64, ConnectionError> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        self.egress_tx
            .try_send(EgressCommand::ResetStream {
                request_id,
                connection_id: self.connection_id,
                stream_id,
                error_code,
            })
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        Ok(request_id)
    }

    /// Gracefully closes the connection.
    ///
    /// Sends a QUIC CONNECTION_CLOSE frame with the specified error code and optional reason.
    /// After sending, the connection will transition to closed state.
    ///
    /// # Errors
    ///
    /// Returns `ConnectionError::Closed` if the worker thread is unavailable.
    pub fn close(&self, error_code: u64, reason: Option<Bytes>) -> Result<(), ConnectionError> {
        self.egress_tx
            .try_send(EgressCommand::Close {
                connection_id: self.connection_id,
                error_code,
                reason,
            })
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))
    }

    /// Requests latest transport statistics for this connection.
    ///
    /// The result will be delivered as an AppEvent::StatsReceived.
    /// Returns the request ID which will be used to correlate the response.
    ///
    /// # Errors
    ///
    /// Returns `ConnectionError::Closed` if the worker thread is unavailable.
    pub fn stats(&self) -> Result<u64, ConnectionError> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        self.egress_tx
            .try_send(EgressCommand::RequestStats {
                request_id,
                connection_id: self.connection_id,
            })
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        Ok(request_id)
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

    /// Write a data chunk to the stream.
    ///
    /// # Arguments
    ///
    /// - `data`: Bytes to send (zero-copy via Bytes reference counting)
    /// - `fin`: If true, sets the FIN flag to indicate end-of-stream
    ///
    /// # Returns
    ///
    /// The number of bytes actually written to the QUIC stream buffer.
    /// This may be less than `data.len()` if the stream buffer is full.
    /// The application can retry with the remaining data.
    ///
    /// # Errors
    ///
    /// Returns `ConnectionError::Closed` if the worker thread becomes unavailable
    /// or the connection is closed.
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
    ///
    /// This sends a FIN signal with zero bytes of data, indicating that no more
    /// data will be sent on this stream.
    pub async fn finish(&self) -> Result<(), ConnectionError> {
        self.write(Bytes::new(), true).await.map(|_| ())
    }

    /// Creates a fluent builder for sending data with optional FIN.
    ///
    /// This enables ergonomic patterns like:
    /// ```ignore
    /// send_stream.send_data(data).with_fin(true).await?;
    /// ```
    ///
    /// This is particularly useful for HTTP/3 patterns where you send
    /// HEADERS + DATA + FIN in one logical operation.
    pub fn send_data(&self, data: Bytes) -> SendDataBuilder {
        SendDataBuilder {
            stream: self.clone(),
            data,
            fin: false,
        }
    }
}

/// Fluent builder for sending stream data with optional FIN flag.
///
/// Created by `SendStream::send_data()`. Provides ergonomic method chaining
/// for common patterns like HTTP/3 request/response finalization.
///
/// # Example
///
/// ```ignore
/// // Send data with FIN in one fluent call
/// send_stream.send_data(body).with_fin(true).send().await?;
///
/// // Or split for clarity
/// let builder = send_stream.send_data(headers);
/// let written = builder.with_fin(false).send().await?;
/// ```
pub struct SendDataBuilder {
    stream: SendStream,
    data: Bytes,
    fin: bool,
}

impl SendDataBuilder {
    /// Sets the FIN flag to indicate end-of-stream after this data.
    ///
    /// Returns self for method chaining.
    pub fn with_fin(mut self, fin: bool) -> Self {
        self.fin = fin;
        self
    }

    /// Sends the data with the configured flags.
    ///
    /// Returns the number of bytes written to the stream buffer.
    pub async fn send(self) -> Result<usize, ConnectionError> {
        self.stream.write(self.data, self.fin).await
    }
}

struct SendStreamInner {
    tx: mpsc::Sender<StreamWriteCmd>,
}

/// Handle allowing the application to read stream data.
pub struct RecvStream {
    pub stream_id: StreamId,
    rx: mpsc::Receiver<StreamData>,
}

impl fmt::Debug for RecvStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecvStream")
            .field("stream_id", &self.stream_id)
            .finish()
    }
}

impl RecvStream {
    pub(crate) fn new(stream_id: StreamId, rx: mpsc::Receiver<StreamData>) -> Self {
        Self { stream_id, rx }
    }

    /// Reads the next chunk of data from the stream.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(StreamData::Data(bytes)))` - Data chunk received (zero-copy via Bytes)
    /// - `Ok(Some(StreamData::Fin))` - FIN received, no more data will arrive
    /// - `Ok(None)` - Channel closed (equivalent to FIN)
    /// - `Err(...)` - Connection error
    ///
    /// # Zero-Copy
    ///
    /// The returned `StreamData::Data(bytes)` uses `Bytes` which provides cheap
    /// cloning without copying the underlying buffer. This is zero-copy relative
    /// to the worker thread's buffer pool.
    pub async fn read(&mut self) -> Result<Option<StreamData>, ConnectionError> {
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
///
/// These are informational metrics that applications can use to adapt their
/// behavior (e.g., adaptive bitrate based on RTT, backpressure handling, etc.).
///
/// # Fields
///
/// - `rtt_estimate_ms`: Estimated round-trip time in milliseconds
/// - `bytes_sent`: Total application data bytes sent on this connection
/// - `bytes_received`: Total application data bytes received on this connection
/// - `active_streams`: Number of currently open streams
/// - `congestion_state`: Current congestion control state (e.g., "slow_start", "congestion_avoidance")
/// - `packets_sent`: Total QUIC packets transmitted
/// - `packets_received`: Total QUIC packets received
/// - `max_stream_id`: The highest stream ID processed on this connection
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    pub rtt_estimate_ms: Option<u32>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub active_streams: usize,
    pub congestion_state: Option<String>,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub max_stream_id: u64,
}
