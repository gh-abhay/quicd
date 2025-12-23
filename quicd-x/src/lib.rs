//! quicd-x: Application Bridge Interface for QUIC Server
//!
//! # Architecture: Asymmetric Channel Design
//!
//! This crate provides the bridge between worker threads and application tasks with:
//!
//! ## Ingress (Worker → App): Bounded tokio::mpsc
//! - **Per-connection** bounded channel (capacity 32-64)
//! - Provides automatic backpressure to worker when app is slow
//! - Worker detects full channel and applies QUIC flow control
//!
//! ## Egress (App → Worker): Unbounded crossbeam
//! - **Shared per-worker** unbounded channel
//! - All app tasks send to same worker channel
//! - High-throughput signaling without blocking
//!
//! ## Zero-Copy Design
//! - All data transferred as `bytes::Bytes` (reference-counted)
//! - No memory copies in hot path

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use crossbeam_channel::{Sender, TrySendError};
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
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
    }
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

/// Internal state shared between async operations on a connection.
struct SharedState {
    // Stream data buffers
    stream_buffers: HashMap<StreamId, VecDeque<Bytes>>,
    stream_fin: HashMap<StreamId, bool>,
    stream_reset: HashMap<StreamId, u64>,
    stream_wakers: HashMap<StreamId, Waker>,
    
    // Pending opened streams
    pending_bi_streams: VecDeque<StreamId>,
    pending_uni_streams: VecDeque<StreamId>,
    accept_bi_waker: Option<Waker>,
    accept_uni_waker: Option<Waker>,
    
    // Pending stream confirmations for open operations
    pending_stream_confirms: VecDeque<StreamId>,
    open_stream_waker: Option<Waker>,
    
    // Datagrams
    datagrams: VecDeque<Bytes>,
    datagram_waker: Option<Waker>,
    
    // Connection state
    closed: bool,
    close_error: Option<(u64, String)>,
}


impl SharedState {
    fn new() -> Self {
        Self {
            stream_buffers: HashMap::new(),
            stream_fin: HashMap::new(),
            stream_reset: HashMap::new(),
            stream_wakers: HashMap::new(),
            pending_bi_streams: VecDeque::new(),
            pending_uni_streams: VecDeque::new(),
            accept_bi_waker: None,
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
pub struct ConnectionHandle {
    conn_id: ConnectionId,
    egress_tx: Sender<Command>,
    state: Arc<Mutex<SharedState>>,
}

impl ConnectionHandle {
    /// Create a new connection handle.
    ///
    /// # Parameters
    /// - `conn_id`: Unique connection identifier
    /// - `ingress_rx`: Bounded tokio::mpsc receiver for events (capacity 32-64)
    /// - `egress_tx`: Unbounded crossbeam sender for commands (shared across all connections)
    pub fn new(
        conn_id: ConnectionId,
        mut ingress_rx: mpsc::Receiver<Event>,
        egress_tx: Sender<Command>,
    ) -> Self {
        let state = Arc::new(Mutex::new(SharedState::new()));
        
        let handle = Self {
            conn_id,
            egress_tx,
            state: state.clone(),
        };
        
        // Spawn event processing task
        tokio::spawn(async move {
            loop {
                // Receive next event
                match ingress_rx.recv().await {
                    Some(Event::StreamOpened { stream_id, is_bidirectional }) => {
                        let mut state = state.lock();
                        if is_bidirectional {
                            state.pending_bi_streams.push_back(stream_id);
                            if let Some(waker) = state.accept_bi_waker.take() {
                                drop(state);
                                waker.wake();
                            }
                        } else {
                            state.pending_uni_streams.push_back(stream_id);
                            if let Some(waker) = state.accept_uni_waker.take() {
                                drop(state);
                                waker.wake();
                            }
                        }
                    }
                    Some(Event::StreamOpenedConfirm { stream_id }) => {
                        let mut state = state.lock();
                        state.pending_stream_confirms.push_back(stream_id);
                        if let Some(waker) = state.open_stream_waker.take() {
                            drop(state);
                            waker.wake();
                        }
                    }
                    Some(Event::StreamData { stream_id, data, fin }) => {
                        let mut state = state.lock();
                        state.stream_buffers.entry(stream_id).or_default().push_back(data);
                        if fin {
                            state.stream_fin.insert(stream_id, true);
                        }
                        if let Some(waker) = state.stream_wakers.remove(&stream_id) {
                            drop(state);
                            waker.wake();
                        }
                    }
                    Some(Event::StreamReset { stream_id, error_code }) => {
                        let mut state = state.lock();
                        state.stream_reset.insert(stream_id, error_code);
                        if let Some(waker) = state.stream_wakers.remove(&stream_id) {
                            drop(state);
                            waker.wake();
                        }
                    }
                    Some(Event::DatagramReceived { data }) => {
                        let mut state = state.lock();
                        state.datagrams.push_back(data);
                        if let Some(waker) = state.datagram_waker.take() {
                            drop(state);
                            waker.wake();
                        }
                    }
                    Some(Event::ConnectionClosing { error_code, reason }) => {
                        let mut state = state.lock();
                        state.closed = true;
                        state.close_error = Some((error_code, reason));
                        // Wake all waiting operations
                        for (_, waker) in state.stream_wakers.drain() {
                            waker.wake();
                        }
                        if let Some(waker) = state.accept_bi_waker.take() { waker.wake(); }
                        if let Some(waker) = state.accept_uni_waker.take() { waker.wake(); }
                        if let Some(waker) = state.datagram_waker.take() { waker.wake(); }
                        if let Some(waker) = state.open_stream_waker.take() { waker.wake(); }
                        return;
                    }
                    Some(Event::ConnectionClosed) => {
                        let mut state = state.lock();
                        state.closed = true;
                        // Wake all waiting operations
                        for (_, waker) in state.stream_wakers.drain() {
                            waker.wake();
                        }
                        if let Some(waker) = state.accept_bi_waker.take() { waker.wake(); }
                        if let Some(waker) = state.accept_uni_waker.take() { waker.wake(); }
                        if let Some(waker) = state.datagram_waker.take() { waker.wake(); }
                        if let Some(waker) = state.open_stream_waker.take() { waker.wake(); }
                        return;
                    }
                    Some(Event::MaxStreamsUpdated { .. }) => {
                        // Flow control update, wake stream open operations
                        let mut state = state.lock();
                        if let Some(waker) = state.open_stream_waker.take() {
                            drop(state);
                            waker.wake();
                        }
                    }
                    Some(Event::StreamStopSending { .. }) => {
                        // Handle stop sending if needed
                    }
                    None => {
                        // Channel closed
                        let mut state = state.lock();
                        state.closed = true;
                        for (_, waker) in state.stream_wakers.drain() {
                            waker.wake();
                        }
                        if let Some(waker) = state.accept_bi_waker.take() { waker.wake(); }
                        if let Some(waker) = state.accept_uni_waker.take() { waker.wake(); }
                        if let Some(waker) = state.datagram_waker.take() { waker.wake(); }
                        if let Some(waker) = state.open_stream_waker.take() { waker.wake(); }
                        return;
                    }
                }
            }
        });
        
        handle
    }
    
    /// Open a bidirectional stream (client-initiated).
    pub async fn open_bi_stream(&self) -> io::Result<QuicStream> {
        // Send command to worker
        self.egress_tx.send(Command::OpenBiStream { conn_id: self.conn_id })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "connection closed"))?;
        
        // Wait for confirmation
        struct OpenBiFuture {
            state: Arc<Mutex<SharedState>>,
        }
        
        impl std::future::Future for OpenBiFuture {
            type Output = io::Result<StreamId>;
            
            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let mut state = self.state.lock();
                
                if let Some(stream_id) = state.pending_stream_confirms.pop_front() {
                    return Poll::Ready(Ok(stream_id));
                }
                
                if state.closed {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "connection closed"
                    )));
                }
                
                state.open_stream_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
        
        let stream_id = OpenBiFuture { state: self.state.clone() }.await?;
        
        Ok(QuicStream {
            conn_id: self.conn_id,
            stream_id,
            egress_tx: self.egress_tx.clone(),
            state: self.state.clone(),
            is_bidirectional: true,
            read_buf: None,
            bytes_read: 0,
        })
    }

    /// Accept an incoming bidirectional stream (peer-initiated).
    pub async fn accept_bi_stream(&self) -> io::Result<QuicStream> {
        struct AcceptBiFuture {
            state: Arc<Mutex<SharedState>>,
        }
        
        impl std::future::Future for AcceptBiFuture {
            type Output = io::Result<StreamId>;
            
            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let mut state = self.state.lock();
                
                // Look for peer-initiated bidirectional stream
                if let Some(stream_id) = state.pending_bi_streams.pop_front() {
                    return Poll::Ready(Ok(stream_id));
                }
                
                if state.closed {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "connection closed"
                    )));
                }
                
                state.accept_bi_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
        
        let stream_id = AcceptBiFuture { state: self.state.clone() }.await?;
        
        Ok(QuicStream {
            conn_id: self.conn_id,
            stream_id,
            egress_tx: self.egress_tx.clone(),
            state: self.state.clone(),
            is_bidirectional: true,
            read_buf: None,
            bytes_read: 0,
        })
    }

    /// Open a unidirectional stream (outgoing only).
    pub async fn open_uni_stream(&self) -> io::Result<QuicStream> {
        self.egress_tx.send(Command::OpenUniStream { conn_id: self.conn_id })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "connection closed"))?;
        
        struct OpenUniFuture {
            state: Arc<Mutex<SharedState>>,
        }
        
        impl std::future::Future for OpenUniFuture {
            type Output = io::Result<StreamId>;
            
            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let mut state = self.state.lock();
                
                if let Some(stream_id) = state.pending_stream_confirms.pop_front() {
                    return Poll::Ready(Ok(stream_id));
                }
                
                if state.closed {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "connection closed"
                    )));
                }
                
                state.open_stream_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
        
        let stream_id = OpenUniFuture { state: self.state.clone() }.await?;
        
        Ok(QuicStream {
            conn_id: self.conn_id,
            stream_id,
            egress_tx: self.egress_tx.clone(),
            state: self.state.clone(),
            is_bidirectional: false,
            read_buf: None,
            bytes_read: 0,
        })
    }

    /// Accept an incoming unidirectional stream.
    pub async fn accept_uni_stream(&self) -> io::Result<QuicStream> {
        struct AcceptUniFuture {
            state: Arc<Mutex<SharedState>>,
        }
        
        impl std::future::Future for AcceptUniFuture {
            type Output = io::Result<StreamId>;
            
            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let mut state = self.state.lock();
                
                if let Some(stream_id) = state.pending_uni_streams.pop_front() {
                    return Poll::Ready(Ok(stream_id));
                }
                
                if state.closed {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "connection closed"
                    )));
                }
                
                state.accept_uni_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
        
        let stream_id = AcceptUniFuture { state: self.state.clone() }.await?;
        
        Ok(QuicStream {
            conn_id: self.conn_id,
            stream_id,
            egress_tx: self.egress_tx.clone(),
            state: self.state.clone(),
            is_bidirectional: false,
            read_buf: None,
            bytes_read: 0,
        })
    }

    /// Send a datagram (unreliable, unordered).
    pub fn send_datagram(&self, data: Bytes) -> Result<(), TrySendError<Command>> {
        self.egress_tx.try_send(Command::SendDatagram {
            conn_id: self.conn_id,
            data,
        })
    }
    
    /// Receive a datagram.
    pub async fn recv_datagram(&self) -> io::Result<Bytes> {
        struct RecvDatagramFuture {
            state: Arc<Mutex<SharedState>>,
        }
        
        impl std::future::Future for RecvDatagramFuture {
            type Output = io::Result<Bytes>;
            
            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let mut state = self.state.lock();
                
                if let Some(data) = state.datagrams.pop_front() {
                    return Poll::Ready(Ok(data));
                }
                
                if state.closed {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "connection closed"
                    )));
                }
                
                state.datagram_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
        
        RecvDatagramFuture { state: self.state.clone() }.await
    }
    
    /// Initiate graceful connection close.
    pub fn close(&self, error_code: u64, reason: String) -> Result<(), TrySendError<Command>> {
        self.egress_tx.try_send(Command::CloseConnection {
            conn_id: self.conn_id,
            error_code,
            reason,
        })
    }

    /// Abort connection immediately (less graceful than close).
    pub fn abort(&self, error_code: u64) -> Result<(), TrySendError<Command>> {
        self.egress_tx.try_send(Command::AbortConnection {
            conn_id: self.conn_id,
            error_code,
        })
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
pub struct QuicStream {
    conn_id: ConnectionId,
    stream_id: StreamId,
    egress_tx: Sender<Command>,
    state: Arc<Mutex<SharedState>>,
    #[allow(dead_code)]
    is_bidirectional: bool,
    /// Current buffer being read
    read_buf: Option<Bytes>,
    /// Total bytes read (for flow control)
    bytes_read: usize,
}

impl QuicStream {
    /// Get the stream ID.
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// Get the connection ID.
    pub fn conn_id(&self) -> ConnectionId {
        self.conn_id
    }
    
    /// Reset the stream with an error code.
    pub fn reset(&self, error_code: u64) -> Result<(), TrySendError<Command>> {
        self.egress_tx.try_send(Command::ResetStream {
            conn_id: self.conn_id,
            stream_id: self.stream_id,
            error_code,
        })
    }
    
    /// Send STOP_SENDING to peer.
    pub fn stop_sending(&self, error_code: u64) -> Result<(), TrySendError<Command>> {
        self.egress_tx.try_send(Command::StopSending {
            conn_id: self.conn_id,
            stream_id: self.stream_id,
            error_code,
        })
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let stream_id = self.stream_id;
        
        // Try to read from current buffer first
        if let Some(ref mut bytes) = self.as_mut().get_mut().read_buf {
            if !bytes.is_empty() {
                let len = std::cmp::min(bytes.len(), buf.remaining());
                buf.put_slice(&bytes[..len]);
                bytes.advance(len);
                
                // Update bytes read and send flow control
                let is_empty = bytes.is_empty();
                // Release the mutable borrow
                let _ = bytes;
                
                let this = self.as_mut().get_mut();
                this.bytes_read += len;
                if this.bytes_read >= 1024 {
                    let _ = this.egress_tx.try_send(Command::StreamDataRead {
                        conn_id: this.conn_id,
                        stream_id: this.stream_id,
                        len: this.bytes_read,
                    });
                    this.bytes_read = 0;
                }
                
                // Clear buffer if fully consumed
                if is_empty {
                    this.read_buf = None;
                }
                
                return Poll::Ready(Ok(()));
            }
        }
        
        // Fetch next buffer from shared state
        let state_arc = self.state.clone();
        let mut state = state_arc.lock();
        
        if let Some(queue) = state.stream_buffers.get_mut(&stream_id) {
            if let Some(chunk) = queue.pop_front() {
                drop(state);
                let this = self.as_mut().get_mut();
                this.read_buf = Some(chunk);
                // Re-call poll_read to consume from new buffer
                return self.poll_read(cx, buf);
            }
        }
        
        // Check for FIN
        if state.stream_fin.get(&stream_id) == Some(&true) {
            return Poll::Ready(Ok(()));
        }
        
        // Check for Reset
        if let Some(&error_code) = state.stream_reset.get(&stream_id) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                format!("stream reset: {}", error_code)
            )));
        }
        
        // Check for Connection Close
        if state.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "connection closed"
            )));
        }
        
        // Register waker
        state.stream_wakers.insert(stream_id, cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let data = Bytes::copy_from_slice(buf);
        let len = data.len();
        
        match self.egress_tx.try_send(Command::WriteStreamData {
            conn_id: self.conn_id,
            stream_id: self.stream_id,
            data,
            fin: false,
        }) {
            Ok(_) => Poll::Ready(Ok(len)),
            Err(TrySendError::Full(_)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(TrySendError::Disconnected(_)) => {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "connection closed"
                )))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Crossbeam channel doesn't buffer, so flush is instant
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.egress_tx.try_send(Command::WriteStreamData {
            conn_id: self.conn_id,
            stream_id: self.stream_id,
            data: Bytes::new(),
            fin: true,
        }) {
            Ok(_) => Poll::Ready(Ok(())),
            Err(TrySendError::Full(_)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(TrySendError::Disconnected(_)) => {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "connection closed"
                )))
            }
        }
    }
}
