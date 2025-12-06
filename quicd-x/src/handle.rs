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

    /// Check if stream has data available to read (RFC 9000 §2.2).
    ///
    /// Returns true if stream has received data that hasn't been consumed yet.
    ///
    /// # Returns
    ///
    /// - `Ok(true)`: Stream has data ready to read
    /// - `Ok(false)`: No data available or stream doesn't exist
    /// - `Err(ConnectionError::Closed)`: Connection closed
    pub async fn stream_readable(&self, stream_id: StreamId) -> Result<bool, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();

        self.egress_tx
            .send(EgressCommand::QueryStreamReadable {
                connection_id: self.connection_id,
                stream_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;

        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))
    }

    /// Check if stream can accept more data for sending (RFC 9000 §2.2).
    ///
    /// Returns true if stream has buffer space and flow control window.
    ///
    /// # Returns
    ///
    /// - `Ok(true)`: Stream can accept data to send
    /// - `Ok(false)`: Stream blocked or doesn't exist
    /// - `Err(ConnectionError::Closed)`: Connection closed
    pub async fn stream_writable(&self, stream_id: StreamId) -> Result<bool, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();

        self.egress_tx
            .send(EgressCommand::QueryStreamWritable {
                connection_id: self.connection_id,
                stream_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;

        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))
    }

    /// Check if stream has received FIN and all data consumed (RFC 9000 §2.2).
    ///
    /// Returns true when peer sent FIN and application read all data.
    ///
    /// # Returns
    ///
    /// - `Ok(true)`: Stream fully finished (FIN received and consumed)
    /// - `Ok(false)`: Stream still active
    /// - `Err(ConnectionError::Closed)`: Connection closed
    pub async fn stream_finished(&self, stream_id: StreamId) -> Result<bool, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();

        self.egress_tx
            .send(EgressCommand::QueryStreamFinished {
                connection_id: self.connection_id,
                stream_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;

        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))
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

    /// Gracefully shutdown send side of stream (RFC 9000 §3.1).
    ///
    /// Sends FIN flag but doesn't reset the stream. The peer can still
    /// send data on their side (for bidirectional streams).
    ///
    /// # Errors
    ///
    /// Returns `ConnectionError::Closed` if the worker thread is unavailable.
    pub async fn shutdown_stream(
        &self,
        stream_id: StreamId,
        error_code: u64,
    ) -> Result<(), ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.egress_tx
            .send(EgressCommand::ShutdownStream {
                connection_id: self.connection_id,
                stream_id,
                error_code,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;

        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable".into()))?
    }

    /// Retire a connection ID (RFC 9000 §5.1).
    ///
    /// Informs the peer that a previously issued connection ID is no longer in use.
    ///
    /// # Errors
    ///
    /// Returns `ConnectionError::Closed` if the worker thread is unavailable.
    pub fn retire_connection_id(&self, sequence: u64) -> Result<(), ConnectionError> {
        self.egress_tx
            .try_send(EgressCommand::RetireConnectionId {
                connection_id: self.connection_id,
                sequence,
            })
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        Ok(())
    }

    /// Request new connection ID from peer (RFC 9000 §5.1).
    ///
    /// Triggers NEW_CONNECTION_ID frame request. Response delivered
    /// via TransportEvent::NewConnectionId.
    ///
    /// # Errors
    ///
    /// Returns `ConnectionError::Closed` if the worker thread is unavailable.
    pub fn request_new_connection_id(&self) -> Result<(), ConnectionError> {
        self.egress_tx
            .try_send(EgressCommand::RequestNewConnectionId {
                connection_id: self.connection_id,
            })
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        Ok(())
    }

    /// Probe path by sending PATH_CHALLENGE (RFC 9000 §8.2).
    ///
    /// Used for path validation or active probing.
    ///
    /// # Errors
    ///
    /// Returns `ConnectionError::Closed` if the worker thread is unavailable.
    pub fn probe_path(
        &self,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        data: &[u8],
    ) -> Result<(), ConnectionError> {
        self.egress_tx
            .try_send(EgressCommand::ProbePath {
                connection_id: self.connection_id,
                local_addr,
                peer_addr,
                data: bytes::Bytes::copy_from_slice(data),
            })
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        Ok(())
    }

    /// Get source connection ID (SCID) for this connection (RFC 9000 §5.1).
    ///
    /// Returns the connection ID used by local endpoint to identify this connection.
    pub async fn source_id(&self) -> Result<Vec<u8>, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        self.egress_tx
            .send(EgressCommand::QuerySourceId {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))
    }

    /// Get destination connection ID (DCID) for this connection (RFC 9000 §5.1).
    ///
    /// Returns the connection ID used by peer to identify this connection.
    pub async fn destination_id(&self) -> Result<Vec<u8>, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        self.egress_tx
            .send(EgressCommand::QueryDestinationId {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))
    }

    /// Get number of available source connection IDs (RFC 9000 §5.1).
    ///
    /// Returns count of SCIDs that can be advertised to peer.
    pub async fn available_dcids(&self) -> Result<usize, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        self.egress_tx
            .send(EgressCommand::QueryAvailableDcids {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))
    }

    /// Get number of spare connection IDs available (RFC 9000 §5.1).
    ///
    /// Returns count of unused SCIDs in the local pool.
    pub async fn scids_left(&self) -> Result<usize, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        self.egress_tx
            .send(EgressCommand::QueryScidsLeft {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))
    }

    /// Issue a new source connection ID (RFC 9000 §5.1.1).
    ///
    /// Generates and advertises a NEW_CONNECTION_ID frame to the peer.
    /// The peer can use this new connection ID for path migration or load balancing.
    ///
    /// # Arguments
    ///
    /// * `scid` - Optional specific connection ID to use. If None, auto-generated.
    ///
    /// # Returns
    ///
    /// Returns the request ID. Listen for `AppEvent::SourceConnectionIdIssued` 
    /// in the event stream for the result containing the actual SCID used,
    /// sequence number, and reset token.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example(handle: quicd_x::ConnectionHandle) {
    /// let request_id = handle.issue_new_scid(None).await.unwrap();
    /// // Wait for AppEvent::SourceConnectionIdIssued { request_id, result }
    /// # }
    /// ```
    pub async fn issue_new_scid(&self, scid: Option<Vec<u8>>) -> Result<u64, ConnectionError> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        
        self.egress_tx
            .send(EgressCommand::IssueNewScid {
                connection_id: self.connection_id,
                request_id,
                scid,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        Ok(request_id)
    }

    /// Get all source connection IDs (RFC 9000 §5.1).
    ///
    /// Enumerates all active SCIDs for this connection, including their
    /// sequence numbers and reset tokens.
    ///
    /// # Returns
    ///
    /// Returns the request ID. Listen for `AppEvent::SourceConnectionIds` 
    /// in the event stream for the vector of `SourceConnectionIdInfo`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example(handle: quicd_x::ConnectionHandle) {
    /// let request_id = handle.source_connection_ids().await.unwrap();
    /// // Wait for AppEvent::SourceConnectionIds { request_id, scids }
    /// # }
    /// ```
    pub async fn source_connection_ids(&self) -> Result<u64, ConnectionError> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        
        self.egress_tx
            .send(EgressCommand::GetSourceConnectionIds {
                connection_id: self.connection_id,
                request_id,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        Ok(request_id)
    }

    /// Poll all currently readable streams (RFC 9000 §2).
    ///
    /// Triggers an edge-triggered event containing all streams with pending data.
    /// This is the event-driven equivalent of Quiche's `Connection::readable()` iterator.
    ///
    /// The worker will emit `AppEvent::ReadableStreamsUpdated` with the set of
    /// stream IDs that have data available to read.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example(handle: quicd_x::ConnectionHandle) {
    /// handle.poll_readable_streams().await.unwrap();
    /// // Wait for AppEvent::ReadableStreamsUpdated { stream_ids }
    /// # }
    /// ```
    pub async fn poll_readable_streams(&self) -> Result<(), ConnectionError> {
        self.egress_tx
            .send(EgressCommand::PollReadableStreams {
                connection_id: self.connection_id,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        Ok(())
    }

    /// Poll all currently writable streams (RFC 9000 §2).
    ///
    /// Triggers an edge-triggered event containing all streams with available send capacity.
    /// This is the event-driven equivalent of Quiche's `Connection::writable()` iterator.
    ///
    /// The worker will emit `AppEvent::WritableStreamsUpdated` with the set of
    /// stream IDs that have space in their send windows.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example(handle: quicd_x::ConnectionHandle) {
    /// handle.poll_writable_streams().await.unwrap();
    /// // Wait for AppEvent::WritableStreamsUpdated { stream_ids }
    /// # }
    /// ```
    pub async fn poll_writable_streams(&self) -> Result<(), ConnectionError> {
        self.egress_tx
            .send(EgressCommand::PollWritableStreams {
                connection_id: self.connection_id,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        Ok(())
    }

    /// Get next readable stream in iterator-style access (RFC 9000 §2).
    ///
    /// Returns the next stream with pending receive data, if any.
    /// Calling this repeatedly will iterate through all readable streams.
    ///
    /// # Returns
    ///
    /// Returns the request ID. Listen for `AppEvent::NextReadableStream` 
    /// in the event stream. The event will contain `Some(stream_id)` if a
    /// readable stream exists, or `None` if no more readable streams remain.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example(handle: quicd_x::ConnectionHandle) {
    /// let request_id = handle.next_readable_stream().await.unwrap();
    /// // Wait for AppEvent::NextReadableStream { request_id, stream_id }
    /// # }
    /// ```
    pub async fn next_readable_stream(&self) -> Result<u64, ConnectionError> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        
        self.egress_tx
            .send(EgressCommand::GetNextReadableStream {
                connection_id: self.connection_id,
                request_id,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        Ok(request_id)
    }

    /// Get next writable stream in iterator-style access (RFC 9000 §2).
    ///
    /// Returns the next stream with available send capacity, if any.
    /// Calling this repeatedly will iterate through all writable streams.
    ///
    /// # Returns
    ///
    /// Returns the request ID. Listen for `AppEvent::NextWritableStream` 
    /// in the event stream. The event will contain `Some(stream_id)` if a
    /// writable stream exists, or `None` if no more writable streams remain.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example(handle: quicd_x::ConnectionHandle) {
    /// let request_id = handle.next_writable_stream().await.unwrap();
    /// // Wait for AppEvent::NextWritableStream { request_id, stream_id }
    /// # }
    /// ```
    pub async fn next_writable_stream(&self) -> Result<u64, ConnectionError> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        
        self.egress_tx
            .send(EgressCommand::GetNextWritableStream {
                connection_id: self.connection_id,
                request_id,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        Ok(request_id)
    }

    /// Get statistics for all active paths (RFC 9000 §9).
    ///
    /// Returns detailed statistics for each network path including RTT, congestion window,
    /// bytes in flight, and validation status. Useful for multipath QUIC implementations
    /// and connection migration decisions.
    ///
    /// # Returns
    ///
    /// Returns the request ID. Listen for `AppEvent::AllPathStats` in the event stream
    /// for the vector of `PathStats`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example(handle: quicd_x::ConnectionHandle) {
    /// let request_id = handle.all_path_stats().await.unwrap();
    /// // Wait for AppEvent::AllPathStats { request_id, paths }
    /// # }
    /// ```
    pub async fn all_path_stats(&self) -> Result<u64, ConnectionError> {
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        
        self.egress_tx
            .send(EgressCommand::GetAllPathStats {
                connection_id: self.connection_id,
                request_id,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        Ok(request_id)
    }

    /// Send stream data on a specific network path (multipath QUIC).
    ///
    /// Allows explicit path selection for stream data transmission. This enables
    /// load balancing across multiple paths or path-specific optimizations.
    ///
    /// # Arguments
    ///
    /// * `stream_id` - The stream to send data on
    /// * `data` - Data bytes to send (zero-copy)
    /// * `fin` - Whether to set the FIN flag (end of stream)
    /// * `local_addr` - Local address for the path
    /// * `peer_addr` - Peer address for the path
    ///
    /// # Returns
    ///
    /// Number of bytes written to the stream.
    ///
    /// # Errors
    ///
    /// - `ConnectionError::Transport`: Quiche 0.24.6 does not expose send_on_path() yet
    /// - `ConnectionError::StreamNotFound`: Stream doesn't exist
    /// - `ConnectionError::Closed`: Connection closed
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example(handle: quicd_x::ConnectionHandle, stream_id: u64, data: bytes::Bytes) {
    /// use std::net::SocketAddr;
    /// let local: SocketAddr = "192.168.1.1:4433".parse().unwrap();
    /// let peer: SocketAddr = "192.168.1.2:5000".parse().unwrap();
    /// let written = handle.send_on_path(stream_id, data, false, local, peer).await.unwrap();
    /// # }
    /// ```
    ///
    /// # Note
    ///
    /// Quiche 0.24.6 does not yet expose `send_on_path()` in its public API.
    /// This method returns `NotImplemented` error until Quiche adds multipath support.
    /// The QuicD-X interface is ready and will work once Quiche exposes this functionality.
    pub async fn send_on_path(
        &self,
        stream_id: StreamId,
        data: bytes::Bytes,
        fin: bool,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
    ) -> Result<usize, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        self.egress_tx
            .send(EgressCommand::SendOnPath {
                connection_id: self.connection_id,
                stream_id,
                data,
                fin,
                local_addr,
                peer_addr,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))?
    }

    /// Get QUIC idle timeout for this connection (RFC 9000 §10.1).
    ///
    /// Returns the negotiated idle timeout duration, or None if no timeout.
    pub async fn timeout(&self) -> Result<Option<std::time::Duration>, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        self.egress_tx
            .send(EgressCommand::QueryTimeout {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))
    }

    /// Call connection timeout handler (RFC 9000 §10.1).
    ///
    /// Triggers timeout processing. Should be called when timeout expires.
    pub fn on_timeout(&self) -> Result<(), ConnectionError> {
        self.egress_tx
            .try_send(EgressCommand::OnTimeout {
                connection_id: self.connection_id,
            })
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        Ok(())
    }

    /// Get TLS session data for 0-RTT resumption (RFC 8446 §4.6.1, RFC 9001 Appendix A).
    ///
    /// Returns the serialized TLS session ticket that can be saved and used for
    /// resuming this connection in the future. This enables 0-RTT (zero round-trip time)
    /// data transmission on subsequent connections.
    ///
    /// # 0-RTT Architecture
    ///
    /// **QuicD Server Context**: QuicD operates as a QUIC server. For server-accepted connections:
    /// - Clients initiate 0-RTT by calling `set_session()` when creating connections
    /// - Servers cannot use `set_session()` on accepted connections (too late in handshake)
    /// - This `session()` method is useful for:
    ///   1. Applications that also act as QUIC clients to other services
    ///   2. Session ticket observability/logging
    ///   3. Custom session management systems
    ///
    /// **Client Implementation Pattern**:
    /// ```ignore
    /// // 1. After successful connection, retrieve and save session
    /// if let Some(session_data) = connection.session().await? {
    ///     storage.save("server.example.com:443", &session_data)?;
    /// }
    ///
    /// // 2. On reconnection, load session and apply BEFORE processing packets
    /// let mut conn = quiche::connect(...)?;
    /// if let Some(saved) = storage.load("server.example.com:443")? {
    ///     conn.set_session(&saved)?;  // Enables 0-RTT
    /// }
    /// ```
    ///
    /// # Returns
    ///
    /// - `Ok(Some(session_data))` - Session ticket available (TLS 1.3 handshake complete)
    /// - `Ok(None)` - No session (handshake incomplete or tickets unsupported)
    ///
    /// # RFC Compliance
    ///
    /// - **RFC 9001 Appendix A**: 0-RTT data can be sent by clients using resumed sessions
    /// - **RFC 8446 §4.6.1**: Session tickets enable session resumption across connections
    /// - **Security Note**: 0-RTT data is NOT forward-secret and can be replayed
    pub async fn session(&self) -> Result<Option<Vec<u8>>, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        self.egress_tx
            .send(EgressCommand::QuerySession {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))
    }

    /// Get Server Name Indication (SNI) from TLS handshake.
    ///
    /// RFC 6066 §3: SNI extension allows the client to indicate the hostname
    /// it's attempting to connect to. Available only on server-side connections
    /// after handshake. Returns None for client connections or if SNI not provided.
    pub async fn sni(&self) -> Result<Option<String>, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        self.egress_tx
            .send(EgressCommand::QueryServerName {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))
    }

    /// Get peer's TLS certificate (RFC 8446 §4.4.2).
    ///
    /// Returns DER-encoded X.509 certificate, or None if not available.
    pub async fn peer_cert(&self) -> Result<Option<Vec<u8>>, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        self.egress_tx
            .send(EgressCommand::QueryPeerCert {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))
    }

    /// Get peer's TLS certificate chain (RFC 8446 §4.4.2).
    ///
    /// Returns vector of DER-encoded X.509 certificates from peer.
    pub async fn peer_cert_chain(&self) -> Result<Option<Vec<Vec<u8>>>, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        self.egress_tx
            .send(EgressCommand::QueryPeerCertChain {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))
    }

    /// Check if connection is established (RFC 9000 §5).
    ///
    /// Returns true if handshake completed and connection is ready.
    pub async fn is_established(&self) -> Result<bool, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        self.egress_tx
            .send(EgressCommand::QueryIsEstablished {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))
    }

    /// Check if connection used TLS session resumption (RFC 8446 §2.2).
    ///
    /// Returns true if this connection resumed a previous session.
    pub async fn is_resumed(&self) -> Result<bool, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        self.egress_tx
            .send(EgressCommand::QueryIsResumed {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))
    }

    /// Check if connection is closed (RFC 9000 §10).
    ///
    /// Returns true if connection closed (graceful or error).
    pub async fn is_closed(&self) -> Result<bool, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        self.egress_tx
            .send(EgressCommand::QueryIsClosed {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))
    }

    /// Check if connection is draining (RFC 9000 §10.2).
    ///
    /// Returns true if connection in draining state (waiting for peer ACK).
    pub async fn is_draining(&self) -> Result<bool, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        self.egress_tx
            .send(EgressCommand::QueryIsDraining {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))
    }

    /// Check if connection timed out (RFC 9000 §10.1).
    ///
    /// Returns true if idle timeout expired.
    pub async fn is_timed_out(&self) -> Result<bool, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        self.egress_tx
            .send(EgressCommand::QueryIsTimedOut {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))
    }

    /// Get peer-initiated connection close error (RFC 9000 §10.2).
    ///
    /// Returns the error code and reason sent by the peer in a CONNECTION_CLOSE frame,
    /// or `None` if:
    /// - The connection is still open
    /// - The connection was closed locally (not by peer)
    /// - No error information is available
    ///
    /// # Returns
    ///
    /// - `Ok(Some((error_code, reason)))` - Peer closed with error
    ///   - `error_code`: QUIC transport error code (RFC 9000 §20) or application error
    ///   - `reason`: UTF-8 encoded human-readable error description (may be empty)
    /// - `Ok(None)` - Connection open or closed locally
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use quicd_x::ConnectionHandle;
    /// # async fn example(handle: ConnectionHandle) -> Result<(), Box<dyn std::error::Error>> {
    /// if let Some((code, reason)) = handle.peer_error().await? {
    ///     let reason_str = String::from_utf8_lossy(&reason);
    ///     eprintln!("Peer closed connection with error {}: {}", code, reason_str);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn peer_error(&self) -> Result<Option<(u64, Vec<u8>)>, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        self.egress_tx
            .send(EgressCommand::QueryPeerError {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))
    }

    /// Get local-initiated connection close error (RFC 9000 §10.2).
    ///
    /// Returns the error code and reason that we sent to the peer in a CONNECTION_CLOSE frame,
    /// or `None` if:
    /// - The connection is still open
    /// - The connection was closed by peer (not locally)
    /// - No error information is available
    ///
    /// # Returns
    ///
    /// - `Ok(Some((error_code, reason)))` - We closed with error
    ///   - `error_code`: QUIC transport error code (RFC 9000 §20) or application error
    ///   - `reason`: UTF-8 encoded human-readable error description (may be empty)
    /// - `Ok(None)` - Connection open or closed by peer
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use quicd_x::ConnectionHandle;
    /// # async fn example(handle: ConnectionHandle) -> Result<(), Box<dyn std::error::Error>> {
    /// if let Some((code, reason)) = handle.local_error().await? {
    ///     let reason_str = String::from_utf8_lossy(&reason);
    ///     eprintln!("We closed connection with error {}: {}", code, reason_str);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn local_error(&self) -> Result<Option<(u64, Vec<u8>)>, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        self.egress_tx
            .send(EgressCommand::QueryLocalError {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))
    }

    /// Get all active Source Connection IDs (RFC 9000 §5.1).
    ///
    /// Returns a vector of all currently active Source Connection IDs that we're
    /// advertising to the peer. Each entry is a tuple of (sequence_number, connection_id_bytes).
    ///
    /// Source Connection IDs are used by the peer to send packets to us. The sequence
    /// numbers allow tracking which CIDs are active and which have been retired.
    ///
    /// # Returns
    ///
    /// Vector of `(sequence, cid_bytes)` tuples, one for each active SCID:
    /// - `sequence`: Sequence number for this CID (RFC 9000 §5.1.1)
    /// - `cid_bytes`: The actual Connection ID bytes
    ///
    /// Returns empty vector if no active SCIDs (shouldn't happen for valid connections).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use quicd_x::ConnectionHandle;
    /// # async fn example(handle: ConnectionHandle) -> Result<(), Box<dyn std::error::Error>> {
    /// let scids = handle.active_scids().await?;
    /// for (seq, cid) in scids {
    ///     println!("Active SCID #{}: {:?}", seq, cid);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn active_scids(&self) -> Result<Vec<(u64, Vec<u8>)>, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        self.egress_tx
            .send(EgressCommand::QueryActiveScids {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))
    }

    /// Get send quantum for pacing (RFC 9002 §7.7).
    ///
    /// Returns the maximum number of bytes that should be sent in a single burst
    /// to avoid overwhelming the network. This is used by the congestion controller
    /// for packet pacing.
    ///
    /// Applications generally don't need this - it's used internally by the QUIC
    /// stack for send scheduling. Exposed for observability and advanced tuning.
    ///
    /// # Returns
    ///
    /// Maximum bytes to send in one burst (typically based on CWND and RTT).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use quicd_x::ConnectionHandle;
    /// # async fn example(handle: ConnectionHandle) -> Result<(), Box<dyn std::error::Error>> {
    /// let quantum = handle.send_quantum().await?;
    /// println!("Can send {} bytes in next burst", quantum);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send_quantum(&self) -> Result<usize, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        self.egress_tx
            .send(EgressCommand::QuerySendQuantum {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))
    }

    /// Get TLS session data for 0-RTT resumption (RFC 9001 Appendix A).
    ///
    /// Returns the serialized TLS session ticket that can be saved and used for
    /// resuming this connection in the future. This enables 0-RTT (zero round-trip time)
    /// data transmission on subsequent connections.
    ///
    /// # 0-RTT Architecture Note
    ///
    /// **QuicD Server Context**: QuicD operates as a QUIC server, accepting incoming
    /// connections. For server-side connections:
    /// - Clients initiate 0-RTT by providing session data via `set_session()` when creating connections
    /// - Servers cannot use `set_session()` on accepted connections (too late - handshake already started)
    /// - This `session()` method is primarily useful for:
    ///   1. Server applications that also act as QUIC clients to other services
    ///   2. Observability/logging of session tickets
    ///   3. Custom session management systems
    ///
    /// **Client Implementation**: Applications acting as QUIC clients should:
    /// 1. Call `session()` after successful handshake completion
    /// 2. Store the returned session data persistently (file, database, cache)
    /// 3. When reconnecting to the same server:
    ///    - Create new connection with quiche::connect()
    ///    - Immediately call `connection.set_session(&saved_data)` before any packet processing
    ///    - This enables 0-RTT data transmission in the initial flight
    ///
    /// # Returns
    ///
    /// - `Ok(Some(session_data))` - Session ticket available (connection established with TLS 1.3)
    /// - `Ok(None)` - No session available (handshake not complete, or session tickets not supported)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use quicd_x::ConnectionHandle;
    /// # async fn example(handle: ConnectionHandle) -> Result<(), Box<dyn std::error::Error>> {
    /// // After handshake completes, save session for future 0-RTT
    /// if let Some(session_data) = handle.session().await? {
    ///     // Store in cache/database keyed by server address
    ///     save_session("server.example.com:443", &session_data).await?;
    /// }
    /// # Ok(())
    /// # }
    /// # async fn save_session(key: &str, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> { Ok(()) }
    /// ```

    /// Purge all unsent DATAGRAMs from send queue (RFC 9221 §5).
    ///
    /// Removes all datagrams that are queued for sending but haven't been transmitted yet.
    /// This is useful for real-time applications (gaming, live video) where stale data
    /// is worthless and should be discarded rather than sent late.
    ///
    /// **Note**: Only affects unsent datagrams. DATAGRAMs already in flight cannot be recalled.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use quicd_x::ConnectionHandle;
    /// # async fn example(handle: ConnectionHandle) -> Result<(), Box<dyn std::error::Error>> {
    /// // Drop all queued video frames when switching scenes
    /// handle.dgram_purge_outgoing().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn dgram_purge_outgoing(&self) -> Result<(), ConnectionError> {
        self.egress_tx
            .send(EgressCommand::DgramPurgeOutgoing {
                connection_id: self.connection_id,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))
    }

    /// Get maximum writable DATAGRAM length (RFC 9221 §5).
    ///
    /// Returns max bytes for next datagram, or None if DATAGRAMs not supported.
    pub async fn dgram_max_writable_len(&self) -> Result<Option<usize>, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        self.egress_tx
            .send(EgressCommand::QueryDgramMaxWritableLen {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))
    }

    /// Get DATAGRAM send queue length (RFC 9221).
    ///
    /// Returns number of datagrams waiting to be sent.
    pub async fn dgram_send_queue_len(&self) -> Result<usize, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        self.egress_tx
            .send(EgressCommand::QueryDgramSendQueueLen {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))
    }

    /// Get DATAGRAM receive queue length (RFC 9221).
    ///
    /// Returns number of received datagrams waiting to be read.
    pub async fn dgram_recv_queue_len(&self) -> Result<usize, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        self.egress_tx
            .send(EgressCommand::QueryDgramRecvQueueLen {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))
    }

    /// Get DATAGRAM receive queue byte size (RFC 9221).
    ///
    /// Returns total bytes in receive queue.
    pub async fn dgram_recv_queue_byte_size(&self) -> Result<usize, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        self.egress_tx
            .send(EgressCommand::QueryDgramRecvQueueByteSize {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))
    }

    /// Get DATAGRAM send queue byte size (RFC 9221).
    ///
    /// Returns total bytes in send queue.
    pub async fn dgram_send_queue_byte_size(&self) -> Result<usize, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        self.egress_tx
            .send(EgressCommand::QueryDgramSendQueueByteSize {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))
    }

    /// Get number of peer's remaining bidi stream credits (RFC 9000 §4.6).
    ///
    /// Returns how many more bidi streams peer can open.
    pub async fn peer_streams_left_bidi(&self) -> Result<u64, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        self.egress_tx
            .send(EgressCommand::QueryPeerStreamsLeftBidi {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))
    }

    /// Get number of peer's remaining uni stream credits (RFC 9000 §4.6).
    ///
    /// Returns how many more uni streams peer can open.
    pub async fn peer_streams_left_uni(&self) -> Result<u64, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        self.egress_tx
            .send(EgressCommand::QueryPeerStreamsLeftUni {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))
    }

    /// Check if peer's address has been validated (RFC 9000 §8.1).
    ///
    /// Returns true if anti-amplification limit no longer applies.
    pub async fn peer_verified_address(&self) -> Result<bool, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        self.egress_tx
            .send(EgressCommand::QueryPeerVerifiedAddress {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))
    }

    /// Query connection statistics directly (RFC 9000).
    ///
    /// Returns detailed stats including RTT, cwnd, bytes transferred, packet loss, etc.
    /// Unlike stats(), this returns the full ConnectionStats synchronously via query.
    pub async fn query_stats(&self) -> Result<crate::ConnectionStats, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        self.egress_tx
            .send(EgressCommand::QueryStats {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))
    }

    // ============ P0 Critical Additions ============

    /// Send ACK_FREQUENCY frame to peer (RFC 9330).
    ///
    /// Requests the peer to adjust their ACK generation frequency. Useful for
    /// latency-sensitive applications that need more frequent acknowledgments.
    ///
    /// # Arguments
    ///
    /// * `ack_eliciting_threshold` - Number of ACK-eliciting packets before sending ACK
    /// * `request_max_ack_delay` - Maximum ACK delay in microseconds
    /// * `ignore_order` - Whether to ignore packet reordering when sending ACKs
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example(handle: quicd_x::ConnectionHandle) -> Result<(), quicd_x::ConnectionError> {
    /// // Request ACKs every 2 packets with 10ms max delay
    /// handle.send_ack_frequency(2, 10_000, false)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn send_ack_frequency(
        &self,
        ack_eliciting_threshold: u64,
        request_max_ack_delay: u64,
        ignore_order: bool,
    ) -> Result<(), ConnectionError> {
        self.egress_tx
            .try_send(EgressCommand::SendAckFrequency {
                connection_id: self.connection_id,
                ack_eliciting_threshold,
                request_max_ack_delay,
                ignore_order,
            })
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        Ok(())
    }

    /// Query available send window synchronously (P0 #5).
    ///
    /// Returns connection-level bytes available for immediate sending without blocking.
    /// This is synchronous - the result comes via AppEvent::AvailableSendWindow.
    ///
    /// # Returns
    ///
    /// Request ID for matching the AppEvent response.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example(handle: quicd_x::ConnectionHandle) -> Result<(), quicd_x::ConnectionError> {
    /// let request_id = handle.query_available_send_window()?;
    /// // Wait for AppEvent::AvailableSendWindow { request_id, window }
    /// # Ok(())
    /// # }
    /// ```
    pub fn query_available_send_window(&self) -> Result<u64, ConnectionError> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static REQUEST_ID_COUNTER: AtomicU64 = AtomicU64::new(1);
        
        let request_id = REQUEST_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        
        self.egress_tx
            .try_send(EgressCommand::QueryAvailableSendWindow {
                connection_id: self.connection_id,
                request_id,
            })
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        Ok(request_id)
    }

    /// Query if this is a server-side connection (P2 #9).
    ///
    /// Returns via AppEvent::IsServer whether this connection was initiated by
    /// the local endpoint (client) or accepted from a remote peer (server).
    ///
    /// # Returns
    ///
    /// Request ID for matching the AppEvent response.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example(handle: quicd_x::ConnectionHandle) -> Result<(), quicd_x::ConnectionError> {
    /// let request_id = handle.query_is_server()?;
    /// // Wait for AppEvent::IsServer { request_id, is_server }
    /// # Ok(())
    /// # }
    /// ```
    pub fn query_is_server(&self) -> Result<u64, ConnectionError> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static REQUEST_ID_COUNTER: AtomicU64 = AtomicU64::new(1);
        
        let request_id = REQUEST_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        
        self.egress_tx
            .try_send(EgressCommand::QueryIsServer {
                connection_id: self.connection_id,
                request_id,
            })
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        Ok(request_id)
    }

    /// Request next path event for frame-level introspection (P0 #3).
    ///
    /// Provides detailed PATH_CHALLENGE/RESPONSE frame events for debugging
    /// and path validation monitoring. Returns via AppEvent::PathEvent.
    ///
    /// # Returns
    ///
    /// Request ID for matching the AppEvent response (or None if no events pending).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example(handle: quicd_x::ConnectionHandle) -> Result<(), quicd_x::ConnectionError> {
    /// let request_id = handle.get_next_path_event()?;
    /// // Wait for AppEvent::PathEvent { event: PathEventType::... }
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_next_path_event(&self) -> Result<u64, ConnectionError> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static REQUEST_ID_COUNTER: AtomicU64 = AtomicU64::new(1);
        
        let request_id = REQUEST_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        
        self.egress_tx
            .try_send(EgressCommand::GetNextPathEvent {
                connection_id: self.connection_id,
                request_id,
            })
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        Ok(request_id)
    }

    /// Shutdown stream in specific direction (P1 #6).
    ///
    /// Extended version of shutdown_stream() supporting read/write/both directions
    /// per RFC 9000 §3.1. Read shutdown sends STOP_SENDING, write shutdown sends
    /// RESET_STREAM or FIN depending on data buffered.
    ///
    /// # Arguments
    ///
    /// * `stream_id` - Stream to shutdown
    /// * `direction` - Which direction(s) to shutdown
    /// * `error_code` - Application error code (0 = graceful)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example(handle: quicd_x::ConnectionHandle) -> Result<(), quicd_x::ConnectionError> {
    /// use quicd_x::StreamShutdownDirection;
    /// // Shutdown write side only (send FIN)
    /// handle.shutdown_stream_direction(4, StreamShutdownDirection::Write, 0).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn shutdown_stream_direction(
        &self,
        stream_id: StreamId,
        direction: crate::server::StreamShutdownDirection,
        error_code: u64,
    ) -> Result<(), ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        self.egress_tx
            .send(EgressCommand::ShutdownStreamDirection {
                connection_id: self.connection_id,
                stream_id,
                direction,
                error_code,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))?
    }

    /// Enable or disable PMTU discovery at runtime (P2 #15).
    ///
    /// Allows dynamic control of Path MTU Discovery after connection establishment.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example(handle: quicd_x::ConnectionHandle) -> Result<(), quicd_x::ConnectionError> {
    /// // Enable PMTU discovery for better throughput
    /// handle.set_pmtu_discovery(true)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_pmtu_discovery(&self, enabled: bool) -> Result<(), ConnectionError> {
        self.egress_tx
            .try_send(EgressCommand::SetPmtuDiscovery {
                connection_id: self.connection_id,
                enabled,
            })
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        Ok(())
    }

    /// Set maximum pacing rate at runtime (P2 #14).
    ///
    /// Controls packet pacing to avoid bursts that could cause packet loss.
    ///
    /// # Arguments
    ///
    /// * `rate_bps` - Maximum sending rate in bytes per second (None = unlimited)
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example(handle: quicd_x::ConnectionHandle) -> Result<(), quicd_x::ConnectionError> {
    /// // Limit to 10 Mbps
    /// handle.set_max_pacing_rate(Some(10_000_000 / 8))?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_max_pacing_rate(&self, rate_bps: Option<u64>) -> Result<(), ConnectionError> {
        self.egress_tx
            .try_send(EgressCommand::SetMaxPacingRate {
                connection_id: self.connection_id,
                rate_bps,
            })
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        Ok(())
    }

    /// Query active source connection ID (P2 #12).
    ///
    /// Returns the current SCID being used by this endpoint.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example(handle: quicd_x::ConnectionHandle) -> Result<(), quicd_x::ConnectionError> {
    /// let scid = handle.query_active_scid().await?;
    /// println!("Active SCID: {:?}", scid);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn query_active_scid(&self) -> Result<Vec<u8>, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        
        self.egress_tx
            .send(EgressCommand::QueryActiveScid {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        
        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker dropped response".into()))
    }

    /// Manually set maximum stream data limit (RFC 9000 §4.1).
    ///
    /// Overrides automatic flow control window for specific stream.
    ///
    /// # Errors
    ///
    /// Returns `ConnectionError::Closed` if the worker thread is unavailable.
    pub fn set_stream_max_data(
        &self,
        stream_id: StreamId,
        max_data: u64,
    ) -> Result<(), ConnectionError> {
        self.egress_tx
            .try_send(EgressCommand::SetStreamMaxData {
                connection_id: self.connection_id,
                stream_id,
                max_data,
            })
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        Ok(())
    }

    /// Manually set connection-level maximum data limit (RFC 9000 §4.1).
    ///
    /// Overrides automatic connection flow control window.
    ///
    /// # Errors
    ///
    /// Returns `ConnectionError::Closed` if the worker thread is unavailable.
    pub fn set_connection_max_data(&self, max_data: u64) -> Result<(), ConnectionError> {
        self.egress_tx
            .try_send(EgressCommand::SetConnectionMaxData {
                connection_id: self.connection_id,
                max_data,
            })
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        Ok(())
    }

    /// Request TLS key update (RFC 9001 §6).
    ///
    /// Initiates key rotation for forward secrecy.
    ///
    /// # Errors
    ///
    /// Returns `ConnectionError::Closed` if the worker thread is unavailable.
    pub fn update_keys(&self) -> Result<(), ConnectionError> {
        self.egress_tx
            .try_send(EgressCommand::UpdateKeys {
                connection_id: self.connection_id,
            })
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        Ok(())
    }

    /// Query if connection can send 0-RTT data (RFC 9001 §4.6).
    ///
    /// # Errors
    ///
    /// Returns `ConnectionError::Closed` if the worker thread is unavailable.
    pub async fn can_send_early_data(&self) -> Result<bool, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.egress_tx
            .send(EgressCommand::CanSendEarlyData {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;

        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable".into()))
    }

    /// Get peer's transport parameters (RFC 9000 §7.4).
    ///
    /// Returns None if handshake not yet complete.
    ///
    /// # Errors
    ///
    /// Returns `ConnectionError::Closed` if the worker thread is unavailable.
    pub async fn peer_transport_params(
        &self,
    ) -> Result<Option<crate::server::PeerTransportParams>, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.egress_tx
            .send(EgressCommand::GetPeerTransportParams {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;

        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable".into()))
    }

    /// Set DATAGRAM send priority (implementation-specific).
    ///
    /// Higher priority datagrams sent before lower priority ones.
    ///
    /// # Errors
    ///
    /// Returns `ConnectionError::Closed` if the worker thread is unavailable.
    pub fn set_datagram_priority(&self, priority: u8) -> Result<(), ConnectionError> {
        self.egress_tx
            .try_send(EgressCommand::SetDatagramPriority {
                connection_id: self.connection_id,
                priority,
            })
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        Ok(())
    }

    /// Query current path MTU (RFC 9000 §14).
    ///
    /// # Errors
    ///
    /// Returns `ConnectionError::Closed` if the worker thread is unavailable.
    pub async fn path_mtu(&self) -> Result<usize, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.egress_tx
            .send(EgressCommand::GetPathMtu {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;

        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable".into()))
    }

    /// Query all active paths.
    ///
    /// # Errors
    ///
    /// Returns `ConnectionError::Closed` if the worker thread is unavailable.
    pub async fn active_paths(&self) -> Result<Vec<crate::server::PathInfo>, ConnectionError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.egress_tx
            .send(EgressCommand::GetActivePaths {
                connection_id: self.connection_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;

        reply_rx
            .await
            .map_err(|_| ConnectionError::Closed("worker unavailable".into()))
    }

    /// Set stream send order for scheduler (RFC 9218).
    ///
    /// Higher values transmitted earlier.
    ///
    /// # Errors
    ///
    /// Returns `ConnectionError::Closed` if the worker thread is unavailable.
    pub fn set_stream_send_order(
        &self,
        stream_id: StreamId,
        send_order: i64,
    ) -> Result<(), ConnectionError> {
        self.egress_tx
            .try_send(EgressCommand::SetStreamSendOrder {
                connection_id: self.connection_id,
                stream_id,
                send_order,
            })
            .map_err(|_| ConnectionError::Closed("worker unavailable or overloaded".into()))?;
        Ok(())
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

    /// Gracefully stop reading from this stream (RFC 9000 §3.5).
    ///
    /// Sends STOP_SENDING frame to the peer with error_code=0, indicating graceful
    /// termination without error. This is the read-side equivalent of sending FIN.
    ///
    /// This implements `Shutdown::Read` semantics from the QUIC specification.
    /// The peer will receive the signal and should stop sending data on this stream.
    ///
    /// # Arguments
    ///
    /// * `handle` - ConnectionHandle to send the STOP_SENDING frame
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example(mut recv_stream: quicd_x::RecvStream, handle: quicd_x::ConnectionHandle) {
    /// // Stop reading gracefully (no error)
    /// recv_stream.stop_reading(&handle).unwrap();
    /// # }
    /// ```
    pub fn stop_reading(&self, handle: &ConnectionHandle) -> Result<(), ConnectionError> {
        handle.stop_sending(self.stream_id, 0)
    }

    /// Stop reading from this stream with an error code (RFC 9000 §3.5).
    ///
    /// Sends STOP_SENDING frame to the peer with the specified application error code.
    /// Use this when terminating the stream due to an error condition.
    ///
    /// For graceful termination without error, use `stop_reading()` instead.
    ///
    /// # Arguments
    ///
    /// * `handle` - ConnectionHandle to send the STOP_SENDING frame
    /// * `error_code` - Application-specific error code
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example(mut recv_stream: quicd_x::RecvStream, handle: quicd_x::ConnectionHandle) {
    /// // Stop reading due to protocol error
    /// const PROTOCOL_ERROR: u64 = 1;
    /// recv_stream.stop_reading_with_error(&handle, PROTOCOL_ERROR).unwrap();
    /// # }
    /// ```
    pub fn stop_reading_with_error(
        &self,
        handle: &ConnectionHandle,
        error_code: u64,
    ) -> Result<(), ConnectionError> {
        handle.stop_sending(self.stream_id, error_code)
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
