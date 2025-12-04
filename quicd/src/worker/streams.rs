//! Stream management for QUIC connections.
//!
//! This module manages the lifecycle of QUIC streams and their data flow
//! between the worker thread and application tasks.
//!
//! # Architecture
//!
//! For each QUIC stream, the stream manager maintains:
//! - **Ingress channel** (worker → app): For sending stream data chunks and FIN signals
//!   (using `StreamData` enum with zero-copy `Bytes`)
//! - **Egress channel** (app → worker): For receiving stream write commands from app tasks
//!   (using `StreamWriteCmd` with zero-copy `Bytes` and `oneshot` reply)
//!
//! These channels allow the worker to process all connections fairly without
//! blocking on any single app task.
//!
//! # Stream Types and Channel Configuration
//!
//! **Peer-initiated bidirectional streams**:
//! - Both ingress and egress channels active
//! - App reads with `RecvStream` and writes with `SendStream`
//! - App discovers stream via `AppEvent::NewStream`
//!
//! **Peer-initiated unidirectional streams**:
//! - Only ingress channel for reading
//! - App only sees `RecvStream`, no `SendStream`
//! - App discovers stream via `AppEvent::NewStream`
//!
//! **App-initiated unidirectional streams** (via `open_uni()`):
//! - Only egress channel for sending
//! - Only `SendStream` returned to app
//! - Identified by even stream IDs from server perspective
//!
//! # Event Flow - Incoming Streams
//!
//! 1. Worker detects readable stream from quiche via `conn.readable()`
//! 2. If new, `StreamManager::handle_new_stream()` is called
//! 3. Channels are created and `AppEvent::NewStream` is sent to app
//! 4. App receives event and creates handler task for the stream
//! 5. Worker receives data from quiche and sends via `send_stream_data()`
//! 6. App's `RecvStream::read()` receives data chunks as `StreamData::Data(bytes)`
//! 7. On FIN, worker calls `signal_stream_fin()`
//! 8. App's `RecvStream::read()` returns `Ok(None)` or receives `StreamData::Fin`
//!
//! # Event Flow - Outgoing Streams
//!
//! 1. App calls `ConnectionHandle::open_bi()` or `open_uni()` (returns request_id)
//! 2. Request is sent via egress_tx channel to worker
//! 3. Worker creates stream via quiche and `StreamManager::add_client_stream()`
//! 4. App receives `AppEvent::StreamOpened` or `AppEvent::UniStreamOpened`
//! 5. App writes data via `SendStream::write(data, fin)`
//! 6. Write command is sent to egress channel (handled by `poll_stream_writes()`)
//! 7. Worker polls egress channels and calls `quiche::stream_send()`
//! 8. Worker sends reply via oneshot with bytes written
//! 9. App's `write()` future completes with byte count
//!
//! # Zero-Copy Principles
//!
//! - Data is never copied within this module
//! - `bytes::Bytes` uses reference counting for cheap cloning
//! - Stream write replies include actual bytes written (app can retry if partial)
//! - Channels are bounded to prevent unbounded memory growth
//!
//! # Backpressure and Flow Control
//!
//! - Ingress channels are bounded (256 entries) to prevent excessive buffering
//! - If ingress channel fills, data is dropped (flow control handled by QUIC)
//! - Apps that process data too slowly will see their ingress channel fill
//! - Egress channels are also bounded, providing backpressure to apps
//! - This ensures worker thread never blocks on any single connection

use quicd_x::{new_recv_stream, new_send_stream, StreamData, StreamId};
use std::collections::HashMap;
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Per-connection stream state managed by the worker.
///
/// This tracks all active streams for a connection and provides channels
/// for bidirectional data flow between worker and app tasks.
///
/// # Channel Semantics
///
/// For each stream, we maintain:
/// - An **ingress channel** (`stream_ingress_txs`): Worker sends stream data events to app
/// - An **egress channel** (`stream_egress_rxs`): App sends stream write commands to worker
///
/// Both channels are:
/// - **Bounded** (256 entries): Prevents unbounded memory growth and provides backpressure
/// - **Non-blocking**: Worker uses `try_send` / `try_recv` to never block on apps
/// - **Per-stream**: Each stream is independent; one app task's slowness doesn't block others
///
/// # Thread Safety
///
/// This is NOT thread-safe - it's owned by the worker thread and only accessed
/// from one place in the worker event loop. The channels it manages are `Send` and
/// can be safely shared to tokio tasks via `RecvStream` and `SendStream` handles.
///
/// # Lifecycle
///
/// A stream's lifecycle:
/// 1. **Creation**: Via peer-initiated `handle_new_stream()` or app-initiated `open_bi()`/`open_uni()`
/// 2. **Active**: Data flows via channels
/// 3. **Finished**: App finishes reading (FIN received) or closes connection
/// 4. **Cleanup**: Stream entry removed from maps
pub struct StreamManager {
    /// Map of stream_id → ingress channel for sending stream data to app.
    ///
    /// Contains one entry per stream that the app is receiving data on.
    /// When we receive data from quiche, we send it through this channel.
    /// This is only present for streams with a read direction.
    stream_ingress_txs: HashMap<StreamId, mpsc::Sender<StreamData>>,

    /// Map of stream_id → egress channel for receiving stream data from app.
    ///
    /// Contains one entry per stream that the app can write to.
    /// We poll these channels to get write commands from the app.
    /// This is only present for streams with a write direction.
    stream_egress_rxs: HashMap<StreamId, mpsc::Receiver<quicd_x::StreamWriteCmd>>,

    /// Connection's main ingress channel for sending events to app.
    ///
    /// Used to send connection-level events like `NewStream`, `StreamFinished`, `StreamClosed`.
    /// This is shared across all streams for this connection.
    pub conn_ingress_tx: mpsc::Sender<quicd_x::AppEvent>,
}

impl StreamManager {
    /// Create a new stream manager for a connection.
    ///
    /// This is called once when the connection handshake completes and the app
    /// task is about to be spawned. The manager is then stored in the connection
    /// and used throughout the connection's lifetime.
    ///
    /// # Arguments
    ///
    /// * `conn_ingress_tx` - Channel for sending connection-level events to the app.
    ///   This is where `NewStream`, `StreamFinished`, `StreamClosed`, and other
    ///   connection-level events will be sent.
    pub fn new(conn_ingress_tx: mpsc::Sender<quicd_x::AppEvent>) -> Self {
        Self {
            stream_ingress_txs: HashMap::new(),
            stream_egress_rxs: HashMap::new(),
            conn_ingress_tx,
        }
    }

    /// Check if a stream is already being tracked.
    ///
    /// Returns true if this stream ID has been registered with the manager,
    /// false otherwise. Used to detect new incoming streams.
    pub fn has_stream(&self, stream_id: StreamId) -> bool {
        self.stream_ingress_txs.contains_key(&stream_id)
    }

    /// Get all active stream IDs (both ingress and egress).
    ///
    /// Returns a Vec containing all stream IDs that are currently being tracked
    /// by this manager. Used for checking stream writable state and other per-stream
    /// operations in the QUIC manager.
    pub fn active_stream_ids(&self) -> Vec<StreamId> {
        let mut ids: Vec<StreamId> = self.stream_ingress_txs.keys().copied().collect();
        // Also include streams that only have egress (uni streams from app)
        for egress_stream_id in self.stream_egress_rxs.keys() {
            if !ids.contains(egress_stream_id) {
                ids.push(*egress_stream_id);
            }
        }
        ids
    }

    /// Add a bidirectional stream opened by the app via `open_bi()`.
    ///
    /// This stream has both read and write directions.
    pub fn add_client_stream(
        &mut self,
        stream_id: StreamId,
        ingress_tx: tokio::sync::mpsc::Sender<StreamData>,
        egress_rx: tokio::sync::mpsc::Receiver<quicd_x::StreamWriteCmd>,
    ) {
        self.stream_ingress_txs.insert(stream_id, ingress_tx);
        self.stream_egress_rxs.insert(stream_id, egress_rx);
    }

    /// Add a unidirectional stream opened by the app via `open_uni()`.
    ///
    /// This stream only has the write direction (egress).
    pub fn add_client_uni_stream(
        &mut self,
        stream_id: StreamId,
        egress_rx: tokio::sync::mpsc::Receiver<quicd_x::StreamWriteCmd>,
    ) {
        // Uni streams from app only have egress (send) direction
        // No ingress (receive) channel needed
        self.stream_egress_rxs.insert(stream_id, egress_rx);
    }

    /// Handle a new incoming stream from the peer.
    ///
    /// This is called when the worker receives a packet that opens a new stream.
    /// It creates the necessary channels and sends a `NewStream` event to the app,
    /// allowing the app to discover and handle the new stream.
    ///
    /// # Stream Type Determination
    ///
    /// QUIC stream IDs have a specific format:
    /// - Even IDs (0, 4, 8...): Client-initiated bidirectional
    /// - Odd IDs (1, 5, 9...): Client-initiated unidirectional
    /// - Even IDs (2, 6, 10...): Server-initiated bidirectional (not supported on server receiving)
    /// - Odd IDs (3, 7, 11...): Server-initiated unidirectional (not supported on server receiving)
    ///
    /// Since we're implementing a server and receive from clients, we see even/odd patterns
    /// based on client ID generation. A stream is bidirectional if the app can both
    /// read and write on it.
    ///
    /// # Arguments
    ///
    /// * `worker_id` - For logging purposes
    /// * `stream_id` - QUIC stream ID
    /// * `bidirectional` - True if bidirectional, false if unidirectional (read-only)
    ///
    /// # Returns
    ///
    /// `true` if the stream was successfully registered and event sent to app.
    /// `false` if the ingress channel was full (app task too slow) or closed.
    ///
    /// # Backpressure
    ///
    /// If this returns false, the stream is NOT registered. The next time the worker
    /// processes this stream as readable, it will retry. This is backpressure:
    /// the app task is too slow to handle new streams, so we don't register it yet.
    pub fn handle_new_stream(
        &mut self,
        worker_id: usize,
        stream_id: StreamId,
        bidirectional: bool,
    ) -> bool {
        debug!(
            worker_id,
            stream_id, bidirectional, "Handling new incoming stream"
        );

        // Create ingress channel for sending stream data to app (worker → app)
        // Moderate buffer (256) to balance memory and responsiveness
        let (stream_ingress_tx, stream_ingress_rx) = mpsc::channel(256);

        // Create RecvStream handle for the app
        let recv_stream = new_recv_stream(stream_id, stream_ingress_rx);

        // Store the ingress_tx for use when data arrives
        self.stream_ingress_txs.insert(stream_id, stream_ingress_tx);

        // For bidirectional streams, create egress channel for app writes
        let send_stream_opt = if bidirectional {
            let (stream_egress_tx, stream_egress_rx) = mpsc::channel(256);
            let send_stream = new_send_stream(stream_id, stream_egress_tx);
            self.stream_egress_rxs.insert(stream_id, stream_egress_rx);
            Some(send_stream)
        } else {
            None
        };

        // Send NewStream event to app - this is how the app learns about the stream
        let event = quicd_x::AppEvent::NewStream {
            stream_id,
            bidirectional,
            recv_stream,
            send_stream: send_stream_opt,
        };

        if self.conn_ingress_tx.try_send(event).is_err() {
            warn!(
                worker_id,
                stream_id,
                "Failed to send NewStream event - app channel full, stream will be retried"
            );
            // Remove the channels we just added since the event wasn't sent
            self.stream_ingress_txs.remove(&stream_id);
            self.stream_egress_rxs.remove(&stream_id);
            return false;
        }

        true
    }

    /// Send stream data to the application.
    ///
    /// This is called when the worker receives data from quiche on a stream.
    /// It pushes the data into the stream's ingress channel for the app to read.
    ///
    /// # Zero-Copy
    ///
    /// The data is passed as `bytes::Bytes`, which uses reference counting
    /// and avoids copying the actual bytes.
    ///
    /// # Backpressure
    ///
    /// If the channel is full, this will log a warning and return false.
    /// The data will be lost (similar to UDP semantics for QUIC streams).
    /// In a production system, you might want to implement flow control here.
    ///
    /// # Returns
    ///
    /// `true` if data was successfully queued, `false` if channel is closed or full.
    pub fn send_stream_data(
        &mut self,
        worker_id: usize,
        stream_id: StreamId,
        data: bytes::Bytes,
    ) -> bool {
        if let Some(tx) = self.stream_ingress_txs.get(&stream_id) {
            let stream_data = StreamData::Data(data);
            match tx.try_send(stream_data) {
                Ok(()) => true,
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    warn!(
                        worker_id,
                        stream_id, "Stream ingress channel full - app task too slow (backpressure)"
                    );
                    // In production, consider flow control or rate limiting
                    false
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    debug!(
                        worker_id,
                        stream_id, "Stream ingress channel closed - app task terminated"
                    );
                    // Clean up the closed channel
                    self.stream_ingress_txs.remove(&stream_id);
                    false
                }
            }
        } else {
            debug!(
                worker_id,
                stream_id, "No ingress channel for stream (may be unidirectional)"
            );
            false
        }
    }

    /// Signal end-of-stream (FIN) to the application.
    ///
    /// This is called when quiche indicates the peer has sent the FIN flag.
    /// It sends a `StreamData::Fin` signal to indicate no more data will arrive,
    /// followed by a `StreamFinished` event.
    pub fn signal_stream_fin(&mut self, worker_id: usize, stream_id: StreamId) {
        if let Some(tx) = self.stream_ingress_txs.get(&stream_id) {
            // Send FIN signal - app's recv_stream.read() will get Ok(None) after this
            let fin_data = StreamData::Fin;
            match tx.try_send(fin_data) {
                Ok(()) => {
                    debug!(worker_id, stream_id, "Signaled stream FIN");
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    warn!(
                        worker_id,
                        stream_id, "Stream ingress channel full - cannot send FIN (backpressure)"
                    );
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    debug!(
                        worker_id,
                        stream_id, "Stream ingress channel closed - app already terminated"
                    );
                    // Clean up
                    self.stream_ingress_txs.remove(&stream_id);
                }
            }
        }

        // Also send StreamFinished event for completeness
        let event = quicd_x::AppEvent::StreamFinished { stream_id };
        match self.conn_ingress_tx.try_send(event) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                warn!(
                    worker_id,
                    stream_id,
                    "Connection ingress channel full - cannot send StreamFinished (backpressure)"
                );
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                debug!(
                    worker_id,
                    stream_id, "Connection ingress channel closed - app already terminated"
                );
            }
        }
    }

    /// Handle stream closure (peer reset or local close).
    ///
    /// This is called when:
    /// - Peer resets the stream with an error code
    /// - App resets the stream locally
    /// - Connection is closing (all streams close)
    ///
    /// It cleans up the stream's channels and sends a `StreamClosed` event.
    pub fn handle_stream_close(
        &mut self,
        worker_id: usize,
        stream_id: StreamId,
        app_initiated: bool,
        error_code: u64,
    ) {
        debug!(
            worker_id,
            stream_id, app_initiated, error_code, "Handling stream close"
        );

        // Clean up both channels - stream is no longer active
        self.stream_ingress_txs.remove(&stream_id);
        self.stream_egress_rxs.remove(&stream_id);

        // Send StreamClosed event to notify app
        let event = quicd_x::AppEvent::StreamClosed {
            stream_id,
            app_initiated,
            error_code,
        };
        match self.conn_ingress_tx.try_send(event) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                warn!(
                    worker_id,
                    stream_id,
                    "Connection ingress channel full - cannot send StreamClosed (backpressure)"
                );
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                debug!(
                    worker_id,
                    stream_id, "Connection ingress channel closed - app already terminated"
                );
            }
        }
    }

    /// Poll for stream data from the application to send.
    ///
    /// This is called by the worker during its event loop to collect all pending
    /// writes from app tasks. It's non-blocking: drains all available commands
    /// from each stream's egress channel and returns them.
    ///
    /// # Design
    ///
    /// This method uses `try_recv()` to drain all pending writes without blocking.
    /// If a channel has multiple pending writes, they're all drained in one call.
    /// This ensures:
    /// - **Fairness**: All connections get their writes processed in each event loop iteration
    /// - **Non-blocking**: Worker never waits on any app task
    /// - **Batching**: Multiple writes from same stream/connection are collected together
    /// - **Efficiency**: No context switches or blocking calls
    ///
    /// # Backpressure
    ///
    /// If an egress channel becomes full (256 pending writes), the app's `SendStream::write()`
    /// will not complete until the worker processes and replies to some writes. This provides
    /// natural backpressure: apps that send too fast will have their write futures pend.
    ///
    /// # Returns
    ///
    /// A vector of tuples: `(stream_id, data, fin, reply_tx)`
    /// - `stream_id`: Which stream to write to
    /// - `data`: Bytes to write (zero-copy via `Bytes` reference counting)
    /// - `fin`: Whether to set the FIN flag (end-of-stream)
    /// - `reply_tx`: Oneshot channel to send success/error back to app
    ///
    /// # Caller Responsibility
    ///
    /// The worker event loop must:
    /// 1. Call `conn.stream_send()` for each returned write
    /// 2. Send the reply via `reply_tx` with actual bytes written or an error
    /// 3. Handle errors gracefully without panicking
    /// 4. Call `collect_packets_for_conn()` to send resulting packets
    ///
    /// # Zero-Copy
    ///
    /// The `Bytes` objects are reference-counted and are not copied here.
    /// If the same data is written multiple times, it's cheap to clone.
    pub fn poll_stream_writes(
        &mut self,
        _worker_id: usize,
    ) -> Vec<(
        StreamId,
        bytes::Bytes,
        bool,
        tokio::sync::oneshot::Sender<Result<usize, quicd_x::ConnectionError>>,
    )> {
        let mut writes = Vec::new();

        // Drain all pending commands from each stream's egress channel (non-blocking)
        // We iterate through all active streams and try_recv() any pending writes
        for (stream_id, rx) in self.stream_egress_rxs.iter_mut() {
            // Try to get commands until the channel is empty
            // This drains the queue for this stream without blocking
            while let Ok(cmd) = rx.try_recv() {
                writes.push((*stream_id, cmd.data, cmd.fin, cmd.reply));
            }
        }

        writes
    }
}
