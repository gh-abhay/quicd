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

    /// Query available send capacity for a stream (RFC 9000 §4.1).
    ///
    /// Returns the number of bytes that can be sent on this stream without
    /// blocking due to flow control. Applications can use this to implement
    /// adaptive sending strategies.
    ///
    /// # Returns
    ///
    /// - `Ok(capacity)`: Number of bytes available to send
    /// - `Err(ConnectionError::StreamNotFound)`: Stream doesn't exist
    /// - `Err(ConnectionError::Closed)`: Connection closed
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example(handle: quicd_x::ConnectionHandle, stream_id: u64) {
    /// let capacity = handle.stream_send_capacity(stream_id).await.unwrap();
    /// if capacity > 0 {
    ///     // Safe to send up to 'capacity' bytes
    /// }
    /// # }
    /// ```
    pub async fn stream_send_capacity(&self, stream_id: StreamId) -> Result<u64, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();

        self.egress_tx
            .send(EgressCommand::QueryStreamCapacity {
                connection_id: self.connection_id,
                stream_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;

        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))?
    }

    /// Query connection-level send capacity (RFC 9000 §4.1).
    ///
    /// Returns the total number of bytes that can be sent on the connection
    /// across all streams, limited by the peer's MAX_DATA flow control.
    ///
    /// # Returns
    ///
    /// - `Ok(capacity)`: Connection-wide bytes available to send
    /// - `Err(ConnectionError::Closed)`: Connection closed
    pub async fn connection_send_capacity(&self) -> Result<u64, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();

        self.egress_tx
            .send(EgressCommand::QueryConnectionCapacity {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;

        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable".into()))
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

    /// Checks whether the connection is currently in early data (0-RTT) state.
    ///
    /// This is used for HTTP/3 0-RTT settings validation per RFC 9114 Section 7.2.4.2.
    ///
    /// # Errors
    ///
    /// Returns `ConnectionError::Closed` if the worker thread is unavailable.
    pub async fn is_in_early_data(&self) -> Result<bool, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.egress_tx
            .send(EgressCommand::QueryConnectionState {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;

        let state = reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable".into()))?;

        Ok(state.is_in_early_data)
    }

    /// Initiate connection migration to a new local address (RFC 9000 §9).
    ///
    /// This is used when the client wants to migrate to a different network interface
    /// or IP address. The worker will initiate path validation automatically.
    ///
    /// # Arguments
    ///
    /// * `new_local_addr` - The new local socket address to migrate to
    ///
    /// # Errors
    ///
    /// Returns `ConnectionError::Closed` if the worker thread is unavailable.
    pub fn migrate_to(&self, new_local_addr: SocketAddr) -> Result<(), ConnectionError> {
        self.egress_tx
            .try_send(EgressCommand::MigrateTo {
                connection_id: self.connection_id,
                new_local_addr,
            })
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        Ok(())
    }

    /// Request path validation for a specific address (RFC 9000 §8.2).
    ///
    /// This sends PATH_CHALLENGE frames to validate that a path is working.
    /// The result will be delivered via TransportEvent::PathValidated or PathValidationFailed.
    ///
    /// # Arguments
    ///
    /// * `peer_addr` - The peer address to validate
    ///
    /// # Errors
    ///
    /// Returns `ConnectionError::Closed` if the worker thread is unavailable.
    pub fn validate_path(&self, peer_addr: SocketAddr) -> Result<(), ConnectionError> {
        self.egress_tx
            .try_send(EgressCommand::ValidatePath {
                connection_id: self.connection_id,
                peer_addr,
            })
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        Ok(())
    }

    /// Set stream priority using RFC 9218 extensible priority scheme.
    ///
    /// # Arguments
    ///
    /// * `stream_id` - The stream to set priority for
    /// * `urgency` - Priority urgency (0-7, where 0 is highest priority)
    /// * `incremental` - Whether this stream should be sent incrementally
    ///
    /// # Errors
    ///
    /// Returns `ConnectionError::Closed` if the worker thread is unavailable.
    pub fn set_stream_priority(
        &self,
        stream_id: StreamId,
        urgency: u8,
        incremental: bool,
    ) -> Result<(), ConnectionError> {
        self.egress_tx
            .try_send(EgressCommand::SetStreamPriority {
                connection_id: self.connection_id,
                stream_id,
                urgency,
                incremental,
            })
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        Ok(())
    }

    /// Send STOP_SENDING to peer for a stream (RFC 9000 §3.5).
    ///
    /// This requests that the peer stop sending data on the specified stream.
    ///
    /// # Arguments
    ///
    /// * `stream_id` - The stream to stop
    /// * `error_code` - Application error code
    ///
    /// # Errors
    ///
    /// Returns `ConnectionError::Closed` if the worker thread is unavailable.
    pub fn stop_sending(
        &self,
        stream_id: StreamId,
        error_code: u64,
    ) -> Result<(), ConnectionError> {
        self.egress_tx
            .try_send(EgressCommand::StopSending {
                connection_id: self.connection_id,
                stream_id,
                error_code,
            })
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        Ok(())
    }

    /// Get maximum datagram size that can be sent (RFC 9221 §3).
    ///
    /// Returns None if datagrams are not supported by the peer.
    /// The size includes QUIC and UDP overhead.
    ///
    /// # Errors
    ///
    /// Returns `ConnectionError::Closed` if the worker thread is unavailable.
    pub async fn max_datagram_size(&self) -> Result<Option<usize>, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.egress_tx
            .send(EgressCommand::GetMaxDatagramSize {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;

        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable".into()))
    }

    /// Query remaining stream credits (RFC 9000 §4.6).
    ///
    /// Returns the number of bidirectional and unidirectional streams
    /// that can still be opened before hitting the peer's limit.
    ///
    /// # Errors
    ///
    /// Returns `ConnectionError::Closed` if the worker thread is unavailable.
    pub async fn stream_credits(&self) -> Result<crate::server::StreamCredits, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.egress_tx
            .send(EgressCommand::GetStreamCredits {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;

        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable".into()))
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

    /// Non-blocking write: attempts to write data without blocking.
    ///
    /// This is the key method for non-blocking HTTP/3 implementations.
    /// It attempts to send data immediately without blocking the task.
    ///
    /// # Arguments
    ///
    /// - `data`: Bytes to send (zero-copy via Bytes reference counting)
    /// - `fin`: If true, sets the FIN flag to indicate end-of-stream
    ///
    /// # Returns
    ///
    /// - `Ok(usize)` - Number of bytes written (may be 0 if buffer is full)
    /// - `Err(ConnectionError::WouldBlock)` - Send buffer full, retry when writable
    /// - `Err(ConnectionError::Closed)` - Connection closed
    ///
    /// # Non-Blocking Pattern
    ///
    /// Applications should:
    /// 1. Call `try_write()` to send data
    /// 2. If `WouldBlock` is returned, queue data in application buffer
    /// 3. Wait for `StreamWritable` event before retrying
    /// 4. Applications must implement their own buffering for partial writes
    ///
    /// # Example
    ///
    /// ```ignore
    /// match send_stream.try_write(data, false) {
    ///     Ok(n) if n == data.len() => {
    ///         // All data written
    ///     }
    ///     Ok(n) => {
    ///         // Partial write, queue remaining data
    ///         pending_data = data.slice(n..);
    ///     }
    ///     Err(ConnectionError::WouldBlock) => {
    ///         // Buffer full, queue all data for later
    ///         pending_data = data;
    ///     }
    ///     Err(e) => return Err(e),
    /// }
    /// ```
    pub fn try_write(&self, data: Bytes, fin: bool) -> Result<usize, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        // Try to send without blocking
        self.inner
            .tx
            .try_send(StreamWriteCmd {
                data,
                fin,
                reply: reply_tx,
            })
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => ConnectionError::WouldBlock,
                mpsc::error::TrySendError::Closed(_) => {
                    ConnectionError::Closed("worker unavailable".into())
                }
            })?;

        // Wait for reply (this is fast, just getting the result from worker)
        // The worker has already accepted the write command, so this won't block
        match reply_rx.blocking_recv() {
            Ok(result) => result,
            Err(_) => Err(ConnectionError::Closed("worker unavailable".into())),
        }
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

    /// Non-blocking read: attempts to read data without blocking.
    ///
    /// This is the key method for non-blocking, event-driven HTTP/3 implementations.
    /// It checks if data is immediately available without blocking the task.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(StreamData::Data(bytes)))` - Data chunk received (zero-copy)
    /// - `Ok(Some(StreamData::Fin))` - FIN received, no more data will arrive
    /// - `Ok(None)` - Channel closed (equivalent to FIN)
    /// - `Err(ConnectionError::WouldBlock)` - No data available, retry when readable
    ///
    /// # Non-Blocking Pattern
    ///
    /// Applications should:
    /// 1. Call `try_read()` when receiving a `StreamReadable` event
    /// 2. Process data until `WouldBlock` is returned
    /// 3. Wait for the next `StreamReadable` event before retrying
    ///
    /// # Example
    ///
    /// ```ignore
    /// loop {
    ///     match recv_stream.try_read() {
    ///         Ok(Some(StreamData::Data(bytes))) => {
    ///             // Process data
    ///         }
    ///         Ok(Some(StreamData::Fin)) => {
    ///             // Stream finished
    ///             break;
    ///         }
    ///         Ok(None) => {
    ///             // Channel closed
    ///             break;
    ///         }
    ///         Err(ConnectionError::WouldBlock) => {
    ///             // No more data available, wait for next event
    ///             break;
    ///         }
    ///         Err(e) => return Err(e),
    ///     }
    /// }
    /// ```
    pub fn try_read(&mut self) -> Result<Option<StreamData>, ConnectionError> {
        match self.rx.try_recv() {
            Ok(data) => Ok(Some(data)),
            Err(mpsc::error::TryRecvError::Empty) => Err(ConnectionError::WouldBlock),
            Err(mpsc::error::TryRecvError::Disconnected) => Ok(None),
        }
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
/// All metrics are sourced from the underlying quiche connection state and
/// represent the current snapshot at query time.
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    // === RFC 9002 Loss Detection and Congestion Control ===
    /// Smoothed round-trip time in microseconds (RFC 9002 §5.3).
    pub srtt_us: Option<u64>,

    /// Minimum RTT observed in microseconds (RFC 9002 §5.2).
    pub min_rtt_us: Option<u64>,

    /// RTT variance in microseconds (RFC 9002 §5.3).
    pub rttvar_us: Option<u64>,

    /// Latest RTT sample in microseconds.
    pub latest_rtt_us: Option<u64>,

    /// Probe timeout value in milliseconds (RFC 9002 §6.2).
    pub pto_ms: Option<u64>,

    /// Congestion window in bytes (RFC 9002 §7).
    pub cwnd: u64,

    /// Bytes currently in flight (unacknowledged).
    pub bytes_in_flight: u64,

    /// Slow start threshold in bytes (RFC 9002 §7.3.2).
    pub ssthresh: Option<u64>,

    /// Pacing rate in bytes per second (if available).
    pub pacing_rate_bps: Option<u64>,

    // === RFC 9000 Flow Control ===
    /// Maximum data that can be sent (connection-level flow control).
    pub max_data: u64,

    /// Data sent so far on this connection.
    pub data_sent: u64,

    /// Maximum data that can be received.
    pub max_data_recv: u64,

    /// Data received so far on this connection.
    pub data_received: u64,

    /// Maximum bidirectional streams that can be opened.
    pub max_streams_bidi: u64,

    /// Maximum unidirectional streams that can be opened.
    pub max_streams_uni: u64,

    // === Connection Statistics ===
    /// Total application data bytes sent.
    pub bytes_sent: u64,

    /// Total application data bytes received.
    pub bytes_received: u64,

    /// Number of currently open streams.
    pub active_streams: usize,

    /// Total QUIC packets transmitted.
    pub packets_sent: u64,

    /// Total QUIC packets received.
    pub packets_received: u64,

    /// Total packets declared lost (RFC 9002 §6).
    pub packets_lost: u64,

    /// Total packets retransmitted.
    pub packets_retransmitted: u64,

    /// Highest stream ID processed.
    pub max_stream_id: u64,

    // === ECN Statistics (RFC 9000 §13.4) ===
    /// ECT(0) marked packets received.
    pub ecn_ect0_count: u64,

    /// ECT(1) marked packets received.
    pub ecn_ect1_count: u64,

    /// ECN-CE (congestion experienced) marked packets received.
    pub ecn_ce_count: u64,

    // === Path Information ===
    /// Current path MTU in bytes.
    pub path_mtu: usize,

    /// Whether the connection is in early data (0-RTT) state.
    pub is_in_early_data: bool,

    /// Whether the connection handshake is complete.
    pub is_established: bool,

    /// Whether the connection is closing or closed.
    pub is_closed: bool,

    /// Number of successful path validations.
    pub path_validations_completed: u64,

    /// Number of failed path validations.
    pub path_validations_failed: u64,
}
