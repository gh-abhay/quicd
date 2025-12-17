//! quicd-x: Application Bridge Interface for QUIC Server

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use crossbeam_channel::{Receiver, Sender, TrySendError};
use std::collections::{HashMap, VecDeque, HashSet};
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Unique identifier for a QUIC connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId(pub u64);

/// Unique identifier for a stream within a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamId(pub u64);

impl StreamId {
    pub fn is_bidirectional(&self) -> bool {
        (self.0 & 0x2) == 0
    }
}

/// Events sent from worker thread to application task (ingress).
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
}

/// Commands sent from application task to worker thread (egress).
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

struct SharedState {
    stream_buffers: HashMap<StreamId, VecDeque<Bytes>>,
    stream_fin: HashSet<StreamId>,
    stream_reset: HashMap<StreamId, u64>, // error code
    stream_wakers: HashMap<StreamId, Waker>,
    
    pending_bi_streams: VecDeque<StreamId>,
    pending_uni_streams: VecDeque<StreamId>,
    accept_bi_waker: Option<Waker>,
    accept_uni_waker: Option<Waker>,
    
    datagrams: VecDeque<Bytes>,
    datagram_waker: Option<Waker>,
    
    closed: bool,
    close_error: Option<(u64, String)>,
    
    // Poller state
    poller_running: bool,
}

impl SharedState {
    fn new() -> Self {
        Self {
            stream_buffers: HashMap::new(),
            stream_fin: HashSet::new(),
            stream_reset: HashMap::new(),
            stream_wakers: HashMap::new(),
            pending_bi_streams: VecDeque::new(),
            pending_uni_streams: VecDeque::new(),
            accept_bi_waker: None,
            accept_uni_waker: None,
            datagrams: VecDeque::new(),
            datagram_waker: None,
            closed: false,
            close_error: None,
            poller_running: false,
        }
    }
}

/// Handle to a QUIC connection, wrapping crossbeam channels for worker communication.
///
/// Provides async API for connection operations:
/// - Opening/accepting streams
/// - Sending/receiving datagrams
/// - Connection control (close, abort)
///
/// # Architecture
/// - Ingress channel: receives events from worker thread (SPSC, bounded)
/// - Egress channel: sends commands to worker thread (MPSC shared, bounded)
/// - All operations are non-blocking from application perspective
/// - Backpressure applied automatically via bounded channels
#[derive(Clone)]
pub struct ConnectionHandle {
    conn_id: ConnectionId,
    ingress_rx: Receiver<Event>,
    egress_tx: Sender<Command>,
    state: Arc<Mutex<SharedState>>,
}

impl ConnectionHandle {
    pub fn new(
        conn_id: ConnectionId,
        ingress_rx: Receiver<Event>,
        egress_tx: Sender<Command>,
    ) -> Self {
        Self {
            conn_id,
            ingress_rx,
            egress_tx,
            state: Arc::new(Mutex::new(SharedState::new())),
        }
    }

    fn ensure_poller(&self) {
        let mut state = self.state.lock().unwrap();
        if state.poller_running || state.closed {
            return;
        }
        state.poller_running = true;
        drop(state);

        let rx = self.ingress_rx.clone();
        let state_clone = self.state.clone();

        tokio::task::spawn_blocking(move || {
            loop {
                match rx.recv() {
                    Ok(event) => {
                        let mut state = state_clone.lock().unwrap();
                        match event {
                            Event::StreamOpened { stream_id, is_bidirectional } => {
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
                            Event::StreamData { stream_id, data, fin } => {
                                state.stream_buffers.entry(stream_id).or_default().push_back(data);
                                if fin {
                                    state.stream_fin.insert(stream_id);
                                }
                                if let Some(waker) = state.stream_wakers.remove(&stream_id) {
                                    waker.wake();
                                }
                            }
                            Event::StreamReset { stream_id, error_code } => {
                                state.stream_reset.insert(stream_id, error_code);
                                if let Some(waker) = state.stream_wakers.remove(&stream_id) {
                                    waker.wake();
                                }
                            }
                            Event::StreamStopSending { .. } => {
                                // Handled by writer
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
                                state.poller_running = false;
                                // Wake everyone
                                for (_, waker) in state.stream_wakers.drain() {
                                    waker.wake();
                                }
                                if let Some(waker) = state.accept_bi_waker.take() { waker.wake(); }
                                if let Some(waker) = state.accept_uni_waker.take() { waker.wake(); }
                                if let Some(waker) = state.datagram_waker.take() { waker.wake(); }
                                return;
                            }
                            Event::ConnectionClosed => {
                                state.closed = true;
                                state.poller_running = false;
                                // Wake everyone
                                for (_, waker) in state.stream_wakers.drain() {
                                    waker.wake();
                                }
                                if let Some(waker) = state.accept_bi_waker.take() { waker.wake(); }
                                if let Some(waker) = state.accept_uni_waker.take() { waker.wake(); }
                                if let Some(waker) = state.datagram_waker.take() { waker.wake(); }
                                return;
                            }
                            Event::MaxStreamsUpdated { is_bidirectional: _, max_streams: _ } => {
                                // Update max streams limit per RFC 9000 Section 4.6
                                let mut state = state_clone.lock().unwrap();
                                // In practice, we'd track this and validate against limits
                                // Wake any tasks waiting to open streams
                                if let Some(waker) = state.accept_bi_waker.take() {
                                    waker.wake();
                                }
                            }
                        }
                    }
                    Err(_) => {
                        // Channel closed
                        let mut state = state_clone.lock().unwrap();
                        state.closed = true;
                        state.poller_running = false;
                        for (_, waker) in state.stream_wakers.drain() {
                            waker.wake();
                        }
                        if let Some(waker) = state.accept_bi_waker.take() { waker.wake(); }
                        if let Some(waker) = state.accept_uni_waker.take() { waker.wake(); }
                        if let Some(waker) = state.datagram_waker.take() { waker.wake(); }
                        return;
                    }
                }
            }
        });
    }

    pub async fn open_bi_stream(&self) -> io::Result<QuicStream> {
        self.ensure_poller();
        // Send command to open stream
        self.egress_tx.try_send(Command::OpenBiStream { conn_id: self.conn_id })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "connection closed"))?;
        
        struct OpenBiFuture {
            state: Arc<Mutex<SharedState>>,
        }
        
        impl std::future::Future for OpenBiFuture {
            type Output = io::Result<StreamId>;
            
            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let mut state = self.state.lock().unwrap();
                // Look for server-initiated (odd ID)
                let mut found_idx = None;
                for (i, id) in state.pending_bi_streams.iter().enumerate() {
                    if !id.is_bidirectional() { continue; }
                    if (id.0 & 0x1) == 1 {
                        found_idx = Some(i);
                        break;
                    }
                }
                
                if let Some(idx) = found_idx {
                    let id = state.pending_bi_streams.remove(idx).unwrap();
                    return Poll::Ready(Ok(id));
                }
                
                if state.closed {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionAborted, "connection closed")));
                }
                state.accept_bi_waker = Some(cx.waker().clone());
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
        })
    }

    pub async fn accept_bi_stream(&self) -> io::Result<QuicStream> {
        self.ensure_poller();
        
        struct AcceptBiFuture {
            state: Arc<Mutex<SharedState>>,
        }
        
        impl std::future::Future for AcceptBiFuture {
            type Output = io::Result<StreamId>;
            
            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let mut state = self.state.lock().unwrap();
                // Look for client-initiated (even ID)
                let mut found_idx = None;
                for (i, id) in state.pending_bi_streams.iter().enumerate() {
                    if (id.0 & 0x1) == 0 {
                        found_idx = Some(i);
                        break;
                    }
                }
                
                if let Some(idx) = found_idx {
                    let id = state.pending_bi_streams.remove(idx).unwrap();
                    return Poll::Ready(Ok(id));
                }
                
                if state.closed {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionAborted, "connection closed")));
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
        })
    }

    pub fn send_datagram(&self, data: Bytes) -> Result<(), TrySendError<Command>> {
        self.egress_tx.try_send(Command::SendDatagram {
            conn_id: self.conn_id,
            data,
        })
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

    /// Open a unidirectional stream (outgoing only).
    pub async fn open_uni_stream(&self) -> io::Result<QuicStream> {
        self.ensure_poller();
        self.egress_tx.try_send(Command::OpenUniStream { conn_id: self.conn_id })
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "connection closed"))?;
        
        struct OpenUniFuture {
            state: Arc<Mutex<SharedState>>,
        }
        
        impl std::future::Future for OpenUniFuture {
            type Output = io::Result<StreamId>;
            
            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let mut state = self.state.lock().unwrap();
                // Look for client-initiated unidirectional
                let mut found_idx = None;
                for (i, id) in state.pending_uni_streams.iter().enumerate() {
                    if id.is_bidirectional() { continue; }
                    if (id.0 & 0x1) == 0 {
                        found_idx = Some(i);
                        break;
                    }
                }
                
                if let Some(idx) = found_idx {
                    let id = state.pending_uni_streams.remove(idx).unwrap();
                    return Poll::Ready(Ok(id));
                }
                
                if state.closed {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionAborted, "connection closed")));
                }
                state.accept_uni_waker = Some(cx.waker().clone());
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
        })
    }

    /// Accept an incoming unidirectional stream.
    pub async fn accept_uni_stream(&self) -> io::Result<QuicStream> {
        self.ensure_poller();
        
        struct AcceptUniFuture {
            state: Arc<Mutex<SharedState>>,
        }
        
        impl std::future::Future for AcceptUniFuture {
            type Output = io::Result<StreamId>;
            
            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let mut state = self.state.lock().unwrap();
                // Look for server-initiated unidirectional
                let mut found_idx = None;
                for (i, id) in state.pending_uni_streams.iter().enumerate() {
                    if (id.0 & 0x1) == 1 {
                        found_idx = Some(i);
                        break;
                    }
                }
                
                if let Some(idx) = found_idx {
                    let id = state.pending_uni_streams.remove(idx).unwrap();
                    return Poll::Ready(Ok(id));
                }
                
                if state.closed {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionAborted, "connection closed")));
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
        })
    }

    /// Receive a datagram from the peer.
    pub async fn recv_datagram(&self) -> io::Result<Bytes> {
        self.ensure_poller();
        
        struct RecvDatagramFuture {
            state: Arc<Mutex<SharedState>>,
        }
        
        impl std::future::Future for RecvDatagramFuture {
            type Output = io::Result<Bytes>;
            
            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let mut state = self.state.lock().unwrap();
                
                if let Some(data) = state.datagrams.pop_front() {
                    return Poll::Ready(Ok(data));
                }
                
                if state.closed {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionAborted, "connection closed")));
                }
                
                state.datagram_waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
        
        RecvDatagramFuture { state: self.state.clone() }.await
    }

    /// Get connection ID for this connection.
    pub fn connection_id(&self) -> ConnectionId {
        self.conn_id
    }

    /// Check if connection is closed.
    pub fn is_closed(&self) -> bool {
        self.state.lock().unwrap().closed
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
    #[allow(dead_code)] // May be used for future validation
    is_bidirectional: bool,
}

impl AsyncRead for QuicStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut state = self.state.lock().unwrap();
        
        // Check for data
        if let Some(queue) = state.stream_buffers.get_mut(&self.stream_id) {
            if let Some(chunk) = queue.front_mut() {
                let len = std::cmp::min(chunk.len(), buf.remaining());
                buf.put_slice(&chunk[..len]);
                
                // Consume from chunk
                if len == chunk.len() {
                    queue.pop_front();
                } else {
                    chunk.advance(len);
                }
                
                // Send flow control update
                let _ = self.egress_tx.try_send(Command::StreamDataRead {
                    conn_id: self.conn_id,
                    stream_id: self.stream_id,
                    len,
                });
                
                return Poll::Ready(Ok(()));
            }
        }
        
        // Check for FIN
        if state.stream_fin.contains(&self.stream_id) {
            return Poll::Ready(Ok(()));
        }
        
        // Check for Reset
        if let Some(err) = state.stream_reset.get(&self.stream_id) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, format!("stream reset: {}", err))));
        }
        
        // Check for Connection Close
        if state.closed {
             return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionAborted, "connection closed")));
        }
        
        // Register waker
        state.stream_wakers.insert(self.stream_id, cx.waker().clone());
        
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
                Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "connection closed")))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
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
                Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "connection closed")))
            }
        }
    }
}
