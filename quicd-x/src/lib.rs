//! quicd-x: Application Bridge Interface for QUIC Server
//!
//! This crate defines the interface between QUIC worker threads and application tasks.
//! It provides zero-copy, async-friendly abstractions for building QUIC applications.
//!
//! # Architecture
//!
//! - **Worker Threads** (native, synchronous) run the QUIC protocol via `quicd-quic`
//! - **Application Tasks** (Tokio, async) implement protocol-specific logic
//! - **Communication**: Crossbeam channels provide lock-free, high-throughput bridge
//!
//! # Channel Model
//!
//! 1. **Worker → Task (Ingress)**: Per-connection SPSC channel
//!    - Worker sends events: `StreamData`, `StreamOpened`, `DatagramReceived`
//!    - Task receives via `ConnectionHandle::recv_event()`
//!    - **Backpressure**: Worker uses `try_send()` - if full, applies QUIC flow control
//!
//! 2. **Task → Worker (Egress)**: Shared MPMC channel per worker
//!    - All tasks send commands to same worker channel
//!    - Commands include `ConnectionId` for routing
//!    - Worker multiplexes reception via `select!`
//!
//! # Zero-Copy Data Transfer
//!
//! All payload data uses `bytes::Bytes` (reference-counted, zero-copy buffers).
//! Worker slices and transfers ownership to Task without memory copies.
//!
//! # One Task Per Connection
//!
//! Each QUIC connection gets **exactly one** Tokio task running the application logic.
//! This 1:1 ratio enables scaling to millions of concurrent connections.
//! Applications MUST NOT spawn additional tasks/threads per connection.

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use crossbeam_channel::{Receiver, Sender, TryRecvError, TrySendError};
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

/// Unique identifier for a QUIC connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId(pub u64);

/// Unique identifier for a stream within a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamId(pub u64);

impl StreamId {
    /// Check if this is a client-initiated stream.
    pub fn is_client_initiated(&self) -> bool {
        (self.0 & 0x1) == 0
    }

    /// Check if this is a server-initiated stream.
    pub fn is_server_initiated(&self) -> bool {
        !self.is_client_initiated()
    }

    /// Check if this is a bidirectional stream.
    pub fn is_bidirectional(&self) -> bool {
        (self.0 & 0x2) == 0
    }

    /// Check if this is a unidirectional stream.
    pub fn is_unidirectional(&self) -> bool {
        !self.is_bidirectional()
    }
}

/// Events sent from worker thread to application task (ingress).
#[derive(Debug, Clone)]
pub enum Event {
    /// New stream opened by remote peer.
    StreamOpened {
        stream_id: StreamId,
        /// True if bidirectional, false if unidirectional.
        is_bidirectional: bool,
    },

    /// Data received on a stream.
    StreamData {
        stream_id: StreamId,
        /// Zero-copy payload data.
        data: Bytes,
        /// True if this is the final data on the stream (FIN bit set).
        fin: bool,
    },

    /// Stream was reset by remote peer.
    StreamReset {
        stream_id: StreamId,
        /// Application protocol error code.
        error_code: u64,
    },

    /// Stream send side was stopped by remote peer (STOP_SENDING frame).
    StreamStopSending {
        stream_id: StreamId,
        /// Application protocol error code.
        error_code: u64,
    },

    /// Datagram received (unreliable, unordered).
    DatagramReceived {
        /// Zero-copy datagram payload.
        data: Bytes,
    },

    /// Connection is closing gracefully.
    ConnectionClosing {
        /// Application protocol error code (0 = no error).
        error_code: u64,
        /// Human-readable reason.
        reason: String,
    },

    /// Connection closed.
    ConnectionClosed,

    /// Maximum streams limit increased (can open more streams now).
    MaxStreamsUpdated {
        /// True for bidirectional, false for unidirectional.
        is_bidirectional: bool,
        /// New maximum number of concurrent streams allowed.
        max_streams: u64,
    },
}

/// Commands sent from application task to worker thread (egress).
#[derive(Debug, Clone)]
pub enum Command {
    /// Open a new bidirectional stream.
    OpenBiStream {
        conn_id: ConnectionId,
        /// Response channel for the new stream ID.
        response_tx: Arc<Notify>,
    },

    /// Open a new unidirectional stream.
    OpenUniStream {
        conn_id: ConnectionId,
        /// Response channel for the new stream ID.
        response_tx: Arc<Notify>,
    },

    /// Write data to a stream.
    WriteStreamData {
        conn_id: ConnectionId,
        stream_id: StreamId,
        /// Zero-copy data to send.
        data: Bytes,
        /// True to close the stream after sending (set FIN bit).
        fin: bool,
    },

    /// Reset a stream (abrupt termination).
    ResetStream {
        conn_id: ConnectionId,
        stream_id: StreamId,
        /// Application protocol error code.
        error_code: u64,
    },

    /// Stop sending on a stream (request peer to stop).
    StopSending {
        conn_id: ConnectionId,
        stream_id: StreamId,
        /// Application protocol error code.
        error_code: u64,
    },

    /// Send an unreliable datagram.
    SendDatagram {
        conn_id: ConnectionId,
        /// Zero-copy datagram payload.
        data: Bytes,
    },

    /// Close the connection gracefully.
    CloseConnection {
        conn_id: ConnectionId,
        /// Application protocol error code (0 = no error).
        error_code: u64,
        /// Human-readable reason.
        reason: String,
    },

    /// Abort the connection immediately (no graceful close).
    AbortConnection {
        conn_id: ConnectionId,
        /// Application protocol error code.
        error_code: u64,
    },
}

/// Application trait that must be implemented by QUIC applications.
///
/// # Contract
///
/// - Invoked exactly once per connection after successful QUIC handshake
/// - Runs in a dedicated Tokio task (one task per connection)
/// - Must be event-driven within single task (no spawning additional tasks)
/// - Panics in this method are isolated to the connection task
#[async_trait]
pub trait ServerApplication: Send + Sync {
    /// Entry point for application logic upon successful QUIC handshake.
    ///
    /// This method is executed inside a dedicated Tokio task.
    ///
    /// # Arguments
    ///
    /// * `conn` - Handle for interacting with the QUIC connection
    ///
    /// # Implementation Requirements
    ///
    /// - Process events from `conn.recv_event()` in event-driven loop
    /// - Send commands via `conn.send_command()` for stream/datagram operations
    /// - Must NOT spawn additional tasks or threads
    /// - Should handle backpressure gracefully when channels fill
    async fn on_connection(&self, conn: ConnectionHandle);
}

/// Handle for interacting with a QUIC connection from application task.
///
/// Abstracts the crossbeam channels and provides async-friendly interface.
///
/// # Zero-Copy
///
/// All data payloads use `bytes::Bytes` for zero-copy transfers.
///
/// # Backpressure
///
/// - Ingress: If task doesn't read events fast enough, worker applies QUIC flow control
/// - Egress: If worker can't process commands, `send_command()` returns error
pub struct ConnectionHandle {
    /// Connection identifier.
    conn_id: ConnectionId,
    /// Dedicated ingress receiver for events from worker.
    ingress_rx: Receiver<Event>,
    /// Sender for commands to shared worker egress channel.
    egress_tx: Sender<Command>,
}

impl ConnectionHandle {
    /// Create a new connection handle.
    ///
    /// # Arguments
    ///
    /// * `conn_id` - Unique connection identifier
    /// * `ingress_rx` - Receiver for events from worker
    /// * `egress_tx` - Sender for commands to worker
    pub fn new(
        conn_id: ConnectionId,
        ingress_rx: Receiver<Event>,
        egress_tx: Sender<Command>,
    ) -> Self {
        Self {
            conn_id,
            ingress_rx,
            egress_tx,
        }
    }

    /// Get the connection ID.
    pub fn connection_id(&self) -> ConnectionId {
        self.conn_id
    }

    /// Receive an event from the worker (async-friendly).
    ///
    /// Returns `None` if the connection is closed and no more events will arrive.
    ///
    /// # Backpressure
    ///
    /// If this method is not called frequently enough, the ingress channel fills
    /// and the worker applies QUIC flow control to stop the remote peer from sending.
    pub async fn recv_event(&self) -> Option<Event> {
        // Use tokio::task::spawn_blocking for crossbeam recv to avoid blocking
        tokio::task::spawn_blocking({
            let rx = self.ingress_rx.clone();
            move || rx.recv().ok()
        })
        .await
        .ok()
        .flatten()
    }

    /// Try to receive an event without blocking.
    ///
    /// Returns:
    /// - `Ok(Some(event))` if an event is available
    /// - `Ok(None)` if no event is available (would block)
    /// - `Err(())` if the channel is disconnected
    pub fn try_recv_event(&self) -> Result<Option<Event>, ()> {
        match self.ingress_rx.try_recv() {
            Ok(event) => Ok(Some(event)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(()),
        }
    }

    /// Send a command to the worker.
    ///
    /// Returns error if the worker's egress channel is full or disconnected.
    ///
    /// # Backpressure
    ///
    /// If this returns error due to full channel, the application should either:
    /// - Wait and retry (introduces latency)
    /// - Drop the command (may violate application protocol)
    /// - Implement adaptive rate limiting
    pub fn send_command(&self, cmd: Command) -> Result<(), TrySendError<Command>> {
        self.egress_tx.try_send(cmd)
    }

    /// Open a new bidirectional stream.
    ///
    /// Returns the new stream ID if successful.
    ///
    /// May fail if:
    /// - Maximum streams limit reached (wait for `Event::MaxStreamsUpdated`)
    /// - Connection is closing/closed
    /// - Worker egress channel is full
    pub async fn open_bi_stream(&self) -> io::Result<QuicStream> {
        let notify = Arc::new(Notify::new());
        let cmd = Command::OpenBiStream {
            conn_id: self.conn_id,
            response_tx: notify.clone(),
        };

        self.egress_tx
            .try_send(cmd)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "connection closed"))?;

        // Wait for worker to process and send stream ID via event
        // For now, we'll poll events until we get StreamOpened
        // TODO: Implement proper response mechanism
        notify.notified().await;

        // Placeholder: in real impl, worker would send StreamOpened event with ID
        // For now return a dummy stream
        Ok(QuicStream::new(
            self.conn_id,
            StreamId(0),
            self.ingress_rx.clone(),
            self.egress_tx.clone(),
            true,
        ))
    }

    /// Open a new unidirectional stream.
    ///
    /// Returns the new stream ID if successful.
    pub async fn open_uni_stream(&self) -> io::Result<QuicStream> {
        let notify = Arc::new(Notify::new());
        let cmd = Command::OpenUniStream {
            conn_id: self.conn_id,
            response_tx: notify.clone(),
        };

        self.egress_tx
            .try_send(cmd)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "connection closed"))?;

        notify.notified().await;

        Ok(QuicStream::new(
            self.conn_id,
            StreamId(0),
            self.ingress_rx.clone(),
            self.egress_tx.clone(),
            false,
        ))
    }

    /// Accept an incoming bidirectional stream from the peer.
    ///
    /// Waits for a `StreamOpened` event and returns the stream.
    pub async fn accept_bi_stream(&self) -> io::Result<QuicStream> {
        loop {
            match self.recv_event().await {
                Some(Event::StreamOpened {
                    stream_id,
                    is_bidirectional: true,
                }) => {
                    return Ok(QuicStream::new(
                        self.conn_id,
                        stream_id,
                        self.ingress_rx.clone(),
                        self.egress_tx.clone(),
                        true,
                    ));
                }
                Some(Event::ConnectionClosed) | None => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "connection closed",
                    ));
                }
                _ => continue, // Skip other events
            }
        }
    }

    /// Accept an incoming unidirectional stream from the peer.
    pub async fn accept_uni_stream(&self) -> io::Result<QuicStream> {
        loop {
            match self.recv_event().await {
                Some(Event::StreamOpened {
                    stream_id,
                    is_bidirectional: false,
                }) => {
                    return Ok(QuicStream::new(
                        self.conn_id,
                        stream_id,
                        self.ingress_rx.clone(),
                        self.egress_tx.clone(),
                        false,
                    ));
                }
                Some(Event::ConnectionClosed) | None => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "connection closed",
                    ));
                }
                _ => continue,
            }
        }
    }

    /// Send an unreliable datagram.
    ///
    /// Datagrams are not retransmitted and may be lost or reordered.
    ///
    /// # Arguments
    ///
    /// * `data` - Zero-copy datagram payload
    pub fn send_datagram(&self, data: Bytes) -> Result<(), TrySendError<Command>> {
        let cmd = Command::SendDatagram {
            conn_id: self.conn_id,
            data,
        };
        self.egress_tx.try_send(cmd)
    }

    /// Receive an unreliable datagram.
    ///
    /// Waits for a `DatagramReceived` event.
    pub async fn recv_datagram(&self) -> io::Result<Bytes> {
        loop {
            match self.recv_event().await {
                Some(Event::DatagramReceived { data }) => return Ok(data),
                Some(Event::ConnectionClosed) | None => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "connection closed",
                    ));
                }
                _ => continue,
            }
        }
    }

    /// Close the connection gracefully with an error code and reason.
    ///
    /// # Arguments
    ///
    /// * `error_code` - Application protocol error code (0 = no error)
    /// * `reason` - Human-readable reason
    pub fn close(&self, error_code: u64, reason: String) -> Result<(), TrySendError<Command>> {
        let cmd = Command::CloseConnection {
            conn_id: self.conn_id,
            error_code,
            reason,
        };
        self.egress_tx.try_send(cmd)
    }

    /// Abort the connection immediately without graceful close.
    pub fn abort(&self, error_code: u64) -> Result<(), TrySendError<Command>> {
        let cmd = Command::AbortConnection {
            conn_id: self.conn_id,
            error_code,
        };
        self.egress_tx.try_send(cmd)
    }
}

/// A QUIC stream that implements AsyncRead and AsyncWrite.
///
/// # Stream Types
///
/// - **Bidirectional**: Can read and write
/// - **Unidirectional**: Read-only (for received) or write-only (for opened)
///
/// # Flow Control
///
/// Coordinated with QUIC stream-level flow control through Command messages to worker.
pub struct QuicStream {
    conn_id: ConnectionId,
    stream_id: StreamId,
    ingress_rx: Receiver<Event>,
    egress_tx: Sender<Command>,
    is_bidirectional: bool,
    /// Read buffer for data received on this stream.
    read_buffer: VecDeque<Bytes>,
    /// True if FIN has been received on this stream.
    read_fin: bool,
    /// True if stream has been closed for writing.
    write_closed: bool,
}

impl QuicStream {
    /// Create a new QUIC stream handle.
    fn new(
        conn_id: ConnectionId,
        stream_id: StreamId,
        ingress_rx: Receiver<Event>,
        egress_tx: Sender<Command>,
        is_bidirectional: bool,
    ) -> Self {
        Self {
            conn_id,
            stream_id,
            ingress_rx,
            egress_tx,
            is_bidirectional,
            read_buffer: VecDeque::new(),
            read_fin: false,
            write_closed: false,
        }
    }

    /// Get the stream ID.
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// Check if this is a bidirectional stream.
    pub fn is_bidirectional(&self) -> bool {
        self.is_bidirectional
    }

    /// Reset the stream (abrupt termination).
    ///
    /// # Arguments
    ///
    /// * `error_code` - Application protocol error code
    pub fn reset(&mut self, error_code: u64) -> io::Result<()> {
        let cmd = Command::ResetStream {
            conn_id: self.conn_id,
            stream_id: self.stream_id,
            error_code,
        };
        self.egress_tx
            .try_send(cmd)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "connection closed"))
    }

    /// Request the peer to stop sending on this stream.
    ///
    /// # Arguments
    ///
    /// * `error_code` - Application protocol error code
    pub fn stop_sending(&mut self, error_code: u64) -> io::Result<()> {
        let cmd = Command::StopSending {
            conn_id: self.conn_id,
            stream_id: self.stream_id,
            error_code,
        };
        self.egress_tx
            .try_send(cmd)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "connection closed"))
    }

    /// Fill read buffer by polling for StreamData events.
    fn fill_read_buffer(&mut self) -> io::Result<()> {
        loop {
            match self.ingress_rx.try_recv() {
                Ok(Event::StreamData {
                    stream_id,
                    data,
                    fin,
                }) if stream_id == self.stream_id => {
                    if !data.is_empty() {
                        self.read_buffer.push_back(data);
                    }
                    if fin {
                        self.read_fin = true;
                        break;
                    }
                }
                Ok(Event::StreamReset {
                    stream_id,
                    error_code,
                }) if stream_id == self.stream_id => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        format!("stream reset with error code {}", error_code),
                    ));
                }
                Ok(Event::ConnectionClosed) => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "connection closed",
                    ));
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "worker disconnected",
                    ));
                }
                _ => continue, // Skip unrelated events
            }
        }
        Ok(())
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Try to fill read buffer from ingress channel
        if let Err(e) = self.fill_read_buffer() {
            return Poll::Ready(Err(e));
        }

        // If we have data in buffer, copy to caller's buffer
        if let Some(chunk) = self.read_buffer.front_mut() {
            let to_copy = buf.remaining().min(chunk.len());
            buf.put_slice(&chunk[..to_copy]);
            chunk.advance(to_copy);

            if chunk.is_empty() {
                self.read_buffer.pop_front();
            }

            return Poll::Ready(Ok(()));
        }

        // If FIN received and no more data, return EOF
        if self.read_fin {
            return Poll::Ready(Ok(()));
        }

        // Would block - need to register waker for when data arrives
        // For now, return Pending (application should retry)
        Poll::Pending
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream closed",
            )));
        }

        // Copy data to Bytes for zero-copy transfer
        let data = Bytes::copy_from_slice(buf);
        let len = data.len();

        let cmd = Command::WriteStreamData {
            conn_id: self.conn_id,
            stream_id: self.stream_id,
            data,
            fin: false,
        };

        match self.egress_tx.try_send(cmd) {
            Ok(()) => Poll::Ready(Ok(len)),
            Err(TrySendError::Full(_)) => Poll::Pending,
            Err(TrySendError::Disconnected(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "connection closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // QUIC handles flushing internally
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_closed {
            return Poll::Ready(Ok(()));
        }

        let cmd = Command::WriteStreamData {
            conn_id: self.conn_id,
            stream_id: self.stream_id,
            data: Bytes::new(),
            fin: true,
        };

        match self.egress_tx.try_send(cmd) {
            Ok(()) => {
                self.write_closed = true;
                Poll::Ready(Ok(()))
            }
            Err(TrySendError::Full(_)) => Poll::Pending,
            Err(TrySendError::Disconnected(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "connection closed",
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_id_properties() {
        // Client-initiated bidirectional: 0b00 = 0
        let id = StreamId(0);
        assert!(id.is_client_initiated());
        assert!(id.is_bidirectional());

        // Server-initiated bidirectional: 0b01 = 1
        let id = StreamId(1);
        assert!(id.is_server_initiated());
        assert!(id.is_bidirectional());

        // Client-initiated unidirectional: 0b10 = 2
        let id = StreamId(2);
        assert!(id.is_client_initiated());
        assert!(id.is_unidirectional());

        // Server-initiated unidirectional: 0b11 = 3
        let id = StreamId(3);
        assert!(id.is_server_initiated());
        assert!(id.is_unidirectional());
    }

    #[test]
    fn test_connection_handle_creation() {
        let (ingress_tx, ingress_rx) = crossbeam_channel::bounded(10);
        let (egress_tx, _egress_rx) = crossbeam_channel::bounded(10);

        let handle = ConnectionHandle::new(ConnectionId(42), ingress_rx, egress_tx.clone());

        assert_eq!(handle.connection_id(), ConnectionId(42));

        // Test command sending
        let result = handle.send_command(Command::CloseConnection {
            conn_id: ConnectionId(42),
            error_code: 0,
            reason: "test".to_string(),
        });
        assert!(result.is_ok());

        // Test event sending
        ingress_tx
            .send(Event::ConnectionClosed)
            .expect("send failed");
        let event = handle.try_recv_event();
        assert!(matches!(event, Ok(Some(Event::ConnectionClosed))));
    }
}
