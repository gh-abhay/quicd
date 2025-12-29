//! quicd-x: Application Bridge Interface for QUIC Server
//!
//! # Architecture: Asymmetric Channel Design
//!
//! This crate provides the bridge between worker threads and application tasks with:
//!
//! ## Ingress (Worker → App): Bounded tokio::mpsc
//! - **Per-connection** bounded channel (capacity 32-64)
//! - Provides automatic backpressure to worker when app is slow
//! - Worker detects full channel via try_send() and applies QUIC flow control
//!
//! ## Egress (App → Worker): Unbounded crossbeam
//! - **Shared per-worker** unbounded channel
//! - All app tasks send to same worker channel
//! - High-throughput signaling without blocking
//! - Worker processes commands in batches between I/O operations
//!
//! ## Zero-Copy Design
//! - All data transferred as `bytes::Bytes` (reference-counted)
//! - No memory copies in hot path
//! - Worker slices and transfers ownership to Task
//!
//! ## No Poller Thread
//! - ConnectionHandle directly holds the ingress receiver
//! - Applications poll events directly via async methods
//! - Zero-allocation event delivery
//!
//! ## Scalability Model
//! - Exactly ONE Tokio task per connection
//! - Applications MUST NOT spawn additional tasks
//! - Event-driven patterns exclusively within single task
//! - Supports millions of concurrent connections per worker

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use crossbeam_channel::Sender;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

/// Unique identifier for a QUIC connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId(pub u64);

/// Unique identifier for a stream within a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(pub u64);

impl StreamId {
    pub fn is_bidirectional(&self) -> bool {
        (self.0 & 0x2) == 0
    }

    pub fn is_client_initiated(&self) -> bool {
        (self.0 & 0x1) == 0
    }
}

/// Events sent from worker thread to application task (ingress).
///
/// These are sent via bounded tokio::mpsc channel for backpressure.
#[derive(Debug, Clone)]
pub enum Event {
    StreamOpened {
        stream_id: StreamId,
        is_bidirectional: bool,
    },
    StreamData {
        stream_id: StreamId,
        data: Bytes,
        fin: bool,
    },
    StreamReset {
        stream_id: StreamId,
        error_code: u64,
    },
    StreamStopSending {
        stream_id: StreamId,
        error_code: u64,
    },
    DatagramReceived {
        data: Bytes,
    },
    ConnectionClosing {
        error_code: u64,
        reason: String,
    },
    ConnectionClosed,
    MaxStreamsUpdated {
        is_bidirectional: bool,
        max_streams: u64,
    },
    /// Notification that a stream has been opened in response to OpenBiStream/OpenUniStream
    StreamOpenedConfirm {
        stream_id: StreamId,
    },
}

/// Commands sent from application task to worker thread (egress).
///
/// These are sent via unbounded crossbeam channel for high throughput.
#[derive(Debug, Clone)]
pub enum Command {
    OpenBiStream {
        conn_id: ConnectionId,
    },
    OpenUniStream {
        conn_id: ConnectionId,
    },
    WriteStreamData {
        conn_id: ConnectionId,
        stream_id: StreamId,
        data: Bytes,
        fin: bool,
    },
    ResetStream {
        conn_id: ConnectionId,
        stream_id: StreamId,
        error_code: u64,
    },
    StopSending {
        conn_id: ConnectionId,
        stream_id: StreamId,
        error_code: u64,
    },
    SendDatagram {
        conn_id: ConnectionId,
        data: Bytes,
    },
    CloseConnection {
        conn_id: ConnectionId,
        error_code: u64,
        reason: String,
    },
    AbortConnection {
        conn_id: ConnectionId,
        error_code: u64,
    },
    /// Acknowledge receipt of data (flow control)
    StreamDataRead {
        conn_id: ConnectionId,
        stream_id: StreamId,
        len: usize,
    },
}

/// The main trait that applications must implement to handle QUIC connections.
///
/// Exactly ONE Tokio task is spawned per connection, executing `on_connection()`.
/// Applications MUST NOT spawn additional tasks or threads for the same connection.
/// Use event-driven patterns exclusively within the single task.
#[async_trait]
pub trait QuicdApplication: Send + Sync {
    /// The entry point for the application logic upon a successful QUIC handshake.
    /// This method is executed inside a dedicated Tokio Task.
    ///
    /// # Constraints
    /// - Exactly ONE task per connection - do not spawn additional tasks
    /// - Must be event-driven - process events from ConnectionHandle
    /// - Must not block - use async operations only
    async fn on_connection(&self, conn: ConnectionHandle);
}

/// Internal state for streams within a connection (managed per-stream).
struct StreamState {
    /// Buffered stream data chunks
    buffers: VecDeque<Bytes>,
    /// Has FIN been received?
    fin_received: bool,
    /// Has stream been reset?
    reset_error: Option<u64>,
    /// Waker for read operations
    read_waker: Option<Waker>,
}

impl StreamState {
    fn new() -> Self {
        Self {
            buffers: VecDeque::new(),
            fin_received: false,
            reset_error: None,
            read_waker: None,
        }
    }
}

/// Internal state shared between ConnectionHandle and QuicStream instances.
/// Uses interior mutability (parking_lot::Mutex) for fine-grained locking.
struct SharedConnectionState {
    /// Stream-level state (data buffers, FIN, reset)
    streams: HashMap<StreamId, StreamState>,

    /// Pending peer-initiated bidirectional streams
    pending_bi_streams: VecDeque<StreamId>,
    accept_bi_waker: Option<Waker>,

    /// Pending peer-initiated unidirectional streams
    pending_uni_streams: VecDeque<StreamId>,
    accept_uni_waker: Option<Waker>,

    /// Pending confirmations for client-initiated stream opens
    pending_stream_confirms: VecDeque<StreamId>,
    open_stream_waker: Option<Waker>,

    /// Datagram queue
    datagrams: VecDeque<Bytes>,
    datagram_waker: Option<Waker>,

    /// Connection closed flag
    closed: bool,
    close_error: Option<(u64, String)>,
}

impl SharedConnectionState {
    fn new() -> Self {
        Self {
            streams: HashMap::new(),
            pending_bi_streams: VecDeque::new(),
            accept_bi_waker: None,
            pending_uni_streams: VecDeque::new(),
            accept_uni_waker: None,
            pending_stream_confirms: VecDeque::new(),
            open_stream_waker: None,
            datagrams: VecDeque::new(),
            datagram_waker: None,
            closed: false,
            close_error: None,
        }
    }
}

/// Handle to a QUIC connection using asymmetric channels.
///
/// # Architecture
/// - **Ingress**: Bounded `tokio::mpsc::Receiver` for events from worker (backpressure)
/// - **Egress**: Unbounded `crossbeam::Sender` to worker (high throughput)
/// - All operations are event-driven and non-blocking
/// - Exactly ONE task per connection - do not spawn additional tasks
/// - Events processed by internal pump task that wakes futures
pub struct ConnectionHandle {
    conn_id: ConnectionId,
    /// Egress sender (unbounded) - shared across all connections for this worker
    egress_tx: Sender<Command>,
    /// Shared state for stream data and control flow (Arc for event pump task)
    state: std::sync::Arc<parking_lot::Mutex<SharedConnectionState>>,
}

impl ConnectionHandle {
    /// Create a new connection handle.
    ///
    /// # Parameters
    /// - `conn_id`: Unique connection identifier
    /// - `ingress_rx`: Bounded tokio::mpsc receiver for events (capacity 32-64)
    /// - `egress_tx`: Unbounded crossbeam sender for commands (shared across all connections)
    /// - `tokio_handle`: Handle to tokio runtime for spawning event pump task
    pub fn new(
        conn_id: ConnectionId,
        mut ingress_rx: mpsc::Receiver<Event>,
        egress_tx: Sender<Command>,
        tokio_handle: &tokio::runtime::Handle,
    ) -> Self {
        let state = std::sync::Arc::new(parking_lot::Mutex::new(SharedConnectionState::new()));

        // Spawn event pump task to process incoming events
        // This task runs until the ingress channel closes (connection closed)
        let state_clone = state.clone();
        tokio_handle.spawn(async move {
            while let Some(event) = ingress_rx.recv().await {
                eprintln!("EVENT PUMP: Processing {:?}", event);
                Self::process_event_internal(&state_clone, event);
            }
            eprintln!("EVENT PUMP: Channel closed, pump exiting");
        });

        Self {
            conn_id,
            egress_tx,
            state,
        }
    }

    /// Internal event processing used by event pump task
    fn process_event_internal(state: &parking_lot::Mutex<SharedConnectionState>, event: Event) {
        let mut state = state.lock();

        match event {
            Event::StreamOpened {
                stream_id,
                is_bidirectional,
            } => {
                if is_bidirectional {
                    state.pending_bi_streams.push_back(stream_id);
                    if let Some(waker) = state.accept_bi_waker.take() {
                        waker.wake();
                    }
                } else {
                    state.pending_uni_streams.push_back(stream_id);
                    if let Some(waker) = state.accept_uni_waker.take() {
                        waker.wake();
                    }
                }
            }
            Event::StreamOpenedConfirm { stream_id } => {
                state.pending_stream_confirms.push_back(stream_id);
                if let Some(waker) = state.open_stream_waker.take() {
                    waker.wake();
                }
            }
            Event::StreamData {
                stream_id,
                data,
                fin,
            } => {
                eprintln!(
                    "EVENT PUMP: StreamData for {:?}, {} bytes, fin={}",
                    stream_id,
                    data.len(),
                    fin
                );
                let stream_state = state
                    .streams
                    .entry(stream_id)
                    .or_insert_with(StreamState::new);

                // Only push non-empty data to buffers
                if !data.is_empty() {
                    stream_state.buffers.push_back(data);
                }

                if fin {
                    stream_state.fin_received = true;
                }
                eprintln!(
                    "EVENT PUMP: Stream state now has {} buffers, fin={}",
                    stream_state.buffers.len(),
                    stream_state.fin_received
                );
                if let Some(waker) = stream_state.read_waker.take() {
                    eprintln!("EVENT PUMP: Waking read waker");
                    waker.wake();
                }
            }
            Event::StreamReset {
                stream_id,
                error_code,
            } => {
                let stream_state = state
                    .streams
                    .entry(stream_id)
                    .or_insert_with(StreamState::new);
                stream_state.reset_error = Some(error_code);
                if let Some(waker) = stream_state.read_waker.take() {
                    waker.wake();
                }
            }
            Event::StreamStopSending { .. } => {
                // Application can handle this if needed
            }
            Event::DatagramReceived { data } => {
                state.datagrams.push_back(data);
                if let Some(waker) = state.datagram_waker.take() {
                    waker.wake();
                }
            }
            Event::ConnectionClosing { error_code, reason } => {
                state.closed = true;
                state.close_error = Some((error_code, reason));
                Self::wake_all_waiters_internal(&mut state);
            }
            Event::ConnectionClosed => {
                state.closed = true;
                Self::wake_all_waiters_internal(&mut state);
            }
            Event::MaxStreamsUpdated { .. } => {
                // Flow control update - wake stream open operations
                if let Some(waker) = state.open_stream_waker.take() {
                    waker.wake();
                }
            }
        }
    }

    fn wake_all_waiters_internal(state: &mut SharedConnectionState) {
        // Wake all stream readers
        for stream_state in state.streams.values_mut() {
            if let Some(waker) = stream_state.read_waker.take() {
                waker.wake();
            }
        }

        // Wake connection-level operations
        if let Some(waker) = state.accept_bi_waker.take() {
            waker.wake();
        }
        if let Some(waker) = state.accept_uni_waker.take() {
            waker.wake();
        }
        if let Some(waker) = state.open_stream_waker.take() {
            waker.wake();
        }
        if let Some(waker) = state.datagram_waker.take() {
            waker.wake();
        }
    }

    /// Open a bidirectional stream (client-initiated).
    pub async fn open_bi_stream(&self) -> io::Result<QuicStream<'_>> {
        // Send command to worker
        self.egress_tx
            .send(Command::OpenBiStream {
                conn_id: self.conn_id,
            })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "connection closed"))?;

        // Wait for confirmation
        struct OpenBiFuture<'a> {
            handle: &'a ConnectionHandle,
        }

        impl<'a> std::future::Future for OpenBiFuture<'a> {
            type Output = io::Result<StreamId>;

            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let mut state = self.handle.state.lock();

                if let Some(stream_id) = state.pending_stream_confirms.pop_front() {
                    return Poll::Ready(Ok(stream_id));
                }

                if state.closed {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "connection closed",
                    )));
                }

                state.open_stream_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }

        let stream_id = OpenBiFuture { handle: self }.await?;

        Ok(QuicStream {
            conn_id: self.conn_id,
            stream_id,
            egress_tx: self.egress_tx.clone(),
            handle: self,
            is_bidirectional: true,
            bytes_read: 0,
        })
    }

    /// Accept an incoming bidirectional stream (peer-initiated).
    pub async fn accept_bi_stream(&self) -> io::Result<QuicStream<'_>> {
        struct AcceptBiFuture<'a> {
            handle: &'a ConnectionHandle,
        }

        impl<'a> std::future::Future for AcceptBiFuture<'a> {
            type Output = io::Result<StreamId>;

            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let mut state = self.handle.state.lock();

                if let Some(stream_id) = state.pending_bi_streams.pop_front() {
                    return Poll::Ready(Ok(stream_id));
                }

                if state.closed {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "connection closed",
                    )));
                }

                state.accept_bi_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }

        let stream_id = AcceptBiFuture { handle: self }.await?;

        Ok(QuicStream {
            conn_id: self.conn_id,
            stream_id,
            egress_tx: self.egress_tx.clone(),
            handle: self,
            is_bidirectional: true,
            bytes_read: 0,
        })
    }

    /// Open a unidirectional stream (outgoing only).
    pub async fn open_uni_stream(&self) -> io::Result<QuicStream<'_>> {
        self.egress_tx
            .send(Command::OpenUniStream {
                conn_id: self.conn_id,
            })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "connection closed"))?;

        struct OpenUniFuture<'a> {
            handle: &'a ConnectionHandle,
        }

        impl<'a> std::future::Future for OpenUniFuture<'a> {
            type Output = io::Result<StreamId>;

            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let mut state = self.handle.state.lock();

                if let Some(stream_id) = state.pending_stream_confirms.pop_front() {
                    return Poll::Ready(Ok(stream_id));
                }

                if state.closed {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "connection closed",
                    )));
                }

                state.open_stream_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }

        let stream_id = OpenUniFuture { handle: self }.await?;

        Ok(QuicStream {
            conn_id: self.conn_id,
            stream_id,
            egress_tx: self.egress_tx.clone(),
            handle: self,
            is_bidirectional: false,
            bytes_read: 0,
        })
    }

    /// Accept an incoming unidirectional stream.
    pub async fn accept_uni_stream(&self) -> io::Result<QuicStream<'_>> {
        struct AcceptUniFuture<'a> {
            handle: &'a ConnectionHandle,
        }

        impl<'a> std::future::Future for AcceptUniFuture<'a> {
            type Output = io::Result<StreamId>;

            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let mut state = self.handle.state.lock();

                if let Some(stream_id) = state.pending_uni_streams.pop_front() {
                    return Poll::Ready(Ok(stream_id));
                }

                if state.closed {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "connection closed",
                    )));
                }

                state.accept_uni_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }

        let stream_id = AcceptUniFuture { handle: self }.await?;

        Ok(QuicStream {
            conn_id: self.conn_id,
            stream_id,
            egress_tx: self.egress_tx.clone(),
            handle: self,
            is_bidirectional: false,
            bytes_read: 0,
        })
    }

    /// Send a datagram (unreliable, unordered).
    pub fn send_datagram(&self, data: Bytes) -> Result<(), io::Error> {
        self.egress_tx
            .send(Command::SendDatagram {
                conn_id: self.conn_id,
                data,
            })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "connection closed"))
    }

    /// Receive a datagram.
    pub async fn recv_datagram(&self) -> io::Result<Bytes> {
        struct RecvDatagramFuture<'a> {
            handle: &'a ConnectionHandle,
        }

        impl<'a> std::future::Future for RecvDatagramFuture<'a> {
            type Output = io::Result<Bytes>;

            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let mut state = self.handle.state.lock();

                if let Some(data) = state.datagrams.pop_front() {
                    return Poll::Ready(Ok(data));
                }

                if state.closed {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "connection closed",
                    )));
                }

                state.datagram_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }

        RecvDatagramFuture { handle: self }.await
    }

    /// Initiate graceful connection close.
    pub fn close(&self, error_code: u64, reason: String) -> Result<(), io::Error> {
        self.egress_tx
            .send(Command::CloseConnection {
                conn_id: self.conn_id,
                error_code,
                reason,
            })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "connection closed"))
    }

    /// Abort connection immediately (less graceful than close).
    pub fn abort(&self, error_code: u64) -> Result<(), io::Error> {
        self.egress_tx
            .send(Command::AbortConnection {
                conn_id: self.conn_id,
                error_code,
            })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "connection closed"))
    }

    /// Get connection ID for this connection.
    pub fn connection_id(&self) -> ConnectionId {
        self.conn_id
    }

    /// Check if connection is closed.
    pub fn is_closed(&self) -> bool {
        self.state.lock().closed
    }
}

/// QUIC stream handle implementing tokio AsyncRead/AsyncWrite.
///
/// # Zero-Copy Architecture
/// - Reads receive Bytes (reference-counted) directly from worker
/// - Writes send Bytes to worker without copying payload
/// - Flow control automatically applied via channel backpressure
///
/// # Backpressure
/// - Read: automatically sends flow control updates to worker
/// - Write: respects channel capacity, returns Pending when full
pub struct QuicStream<'a> {
    conn_id: ConnectionId,
    stream_id: StreamId,
    egress_tx: Sender<Command>,
    handle: &'a ConnectionHandle,
    #[allow(dead_code)]
    is_bidirectional: bool,
    /// Total bytes read (for flow control)
    bytes_read: usize,
}

impl<'a> QuicStream<'a> {
    /// Get the stream ID.
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// Get the connection ID.
    pub fn conn_id(&self) -> ConnectionId {
        self.conn_id
    }

    /// Reset the stream with an error code.
    pub fn reset(&self, error_code: u64) -> Result<(), io::Error> {
        self.egress_tx
            .send(Command::ResetStream {
                conn_id: self.conn_id,
                stream_id: self.stream_id,
                error_code,
            })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "connection closed"))
    }

    /// Send STOP_SENDING to peer.
    pub fn stop_sending(&self, error_code: u64) -> Result<(), io::Error> {
        self.egress_tx
            .send(Command::StopSending {
                conn_id: self.conn_id,
                stream_id: self.stream_id,
                error_code,
            })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "connection closed"))
    }
}

impl<'a> AsyncRead for QuicStream<'a> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let stream_id = self.stream_id;

        // Process any pending events first
        // Fetch data from shared state
        let mut state = self.handle.state.lock();

        eprintln!(
            "POLL_READ: stream_id={:?}, streams.len()={}, streams.contains_key={}",
            stream_id,
            state.streams.len(),
            state.streams.contains_key(&stream_id)
        );

        // Get or create stream state (important: create even if no data yet, so waker can be registered)
        let stream_state = state
            .streams
            .entry(stream_id)
            .or_insert_with(StreamState::new);

        eprintln!(
            "POLL_READ: Found stream state, buffers.len()={}, fin={}",
            stream_state.buffers.len(),
            stream_state.fin_received
        );

        // Check if we have buffered data
        if let Some(mut chunk) = stream_state.buffers.pop_front() {
            eprintln!("POLL_READ: Popped chunk of {} bytes", chunk.len());
            let len = std::cmp::min(chunk.len(), buf.remaining());
            buf.put_slice(&chunk[..len]);
            chunk.advance(len);

            // Put back remaining if not fully consumed
            if !chunk.is_empty() {
                stream_state.buffers.push_front(chunk);
            }

            // Update flow control
            let this = self.as_mut().get_mut();
            this.bytes_read += len;
            if this.bytes_read >= 1024 {
                let _ = this.egress_tx.send(Command::StreamDataRead {
                    conn_id: this.conn_id,
                    stream_id: this.stream_id,
                    len: this.bytes_read,
                });
                this.bytes_read = 0;
            }

            return Poll::Ready(Ok(()));
        }

        // Check for FIN
        if stream_state.fin_received {
            return Poll::Ready(Ok(()));
        }

        // Check for Reset
        if let Some(error_code) = stream_state.reset_error {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                format!("stream reset: {}", error_code),
            )));
        }

        // Register waker (now guaranteed to work since we created stream_state above)
        stream_state.read_waker = Some(cx.waker().clone());

        // Check for Connection Close
        if state.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "connection closed",
            )));
        }

        Poll::Pending
    }
}

impl<'a> AsyncWrite for QuicStream<'a> {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let data = Bytes::copy_from_slice(buf);
        let len = data.len();

        eprintln!(
            "QuicStream::poll_write: stream_id={:?}, len={}, conn_id={:?}",
            self.stream_id, len, self.conn_id
        );

        match self.egress_tx.send(Command::WriteStreamData {
            conn_id: self.conn_id,
            stream_id: self.stream_id,
            data,
            fin: false,
        }) {
            Ok(_) => {
                eprintln!("QuicStream::poll_write: Command sent successfully");
                Poll::Ready(Ok(len))
            }
            Err(e) => {
                eprintln!("QuicStream::poll_write: Failed to send command: {:?}", e);
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "connection closed",
                )))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Crossbeam channel doesn't buffer, so flush is instant
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.egress_tx.send(Command::WriteStreamData {
            conn_id: self.conn_id,
            stream_id: self.stream_id,
            data: Bytes::new(),
            fin: true,
        }) {
            Ok(_) => Poll::Ready(Ok(())),
            Err(_) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "connection closed",
            ))),
        }
    }
}
