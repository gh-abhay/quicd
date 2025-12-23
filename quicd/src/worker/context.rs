//! Worker Context: Slab-based Connection Management
//!
//! # Zero-Contention Architecture
//! Each worker owns a `Slab` for O(1) connection lookup and insertion.
//! - **Pre-allocated**: Slab size determined at startup (e.g., 1M connections)
//! - **Thread-local**: No cross-worker communication for connection state
//! - **CID routing**: eBPF ensures all packets for a CID reach the same worker
//!
//! # Connection Lifecycle
//! 1. **Handshake**: Initial packet creates entry in Slab, gets unique index
//! 2. **Active**: Connection processes packets, generates app events
//! 3. **App Spawn**: On handshake completion, spawn tokio task with ConnectionHandle
//! 4. **Teardown**: On close, remove from Slab, close channels

use ahash::AHashMap;
use bytes::Bytes;
use crossbeam_channel::{Sender, unbounded};
use parking_lot::Mutex;
use quicd_quic::{ConnectionConfig, QuicConnection, Side};
use quicd_x::{Command, ConnectionId, Event, StreamId};
use slab::Slab;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

/// Maximum capacity of ingress channel (Worker → App).
/// Bounded to provide backpressure when app is slow.
const INGRESS_CHANNEL_CAPACITY: usize = 64;

/// Connection state stored in the Slab.
///
/// # Memory Layout
/// This struct is optimized for cache efficiency:
/// - Hot fields (quic_conn, channels) at the start
/// - Cold fields (metadata) at the end
pub struct ConnectionState {
    /// The quicd-quic state machine
    pub quic_conn: QuicConnection,
    
    /// Bounded sender for events to application task
    /// When full, worker applies QUIC flow control
    pub ingress_tx: Option<mpsc::Sender<Event>>,
    
    /// Remote peer address
    pub peer_addr: SocketAddr,
    
    /// Connection creation time
    pub created_at: Instant,
    
    /// ALPN negotiated protocol
    pub alpn: Option<String>,
    
    /// Whether handshake is complete
    pub handshake_complete: bool,
    
    /// Whether application task has been spawned
    pub app_spawned: bool,
}

impl ConnectionState {
    pub fn new(
        quic_conn: QuicConnection,
        peer_addr: SocketAddr,
    ) -> Self {
        Self {
            quic_conn,
            ingress_tx: None,
            peer_addr,
            created_at: Instant::now(),
            alpn: None,
            handshake_complete: false,
            app_spawned: false,
        }
    }
}

/// Worker-local context holding all connection state.
///
/// # Thread Safety
/// This is NOT Send/Sync - it lives entirely on the worker thread.
pub struct WorkerContext {
    /// Pre-allocated Slab for connection storage
    /// Index is used for O(1) lookup
    connections: Slab<ConnectionState>,
    
    /// Mapping from ConnectionId to Slab index
    /// Uses AHashMap for fast lookups
    cid_to_index: AHashMap<u64, usize>,
    
    /// Shared egress channel for all app tasks assigned to this worker
    /// Unbounded for high-throughput signaling
    egress_tx: Sender<Command>,
    
    /// Egress channel receiver (worker polls this)
    egress_rx: crossbeam_channel::Receiver<Command>,
    
    /// Tokio runtime handle for spawning application tasks
    runtime_handle: tokio::runtime::Handle,
    
    /// Application registry (ALPN → factory)
    app_registry: Arc<crate::apps::AppRegistry>,
    
    /// Worker ID for logging
    worker_id: usize,
    
    /// Connection config template
    conn_config: ConnectionConfig,
}

impl WorkerContext {
    /// Create a new worker context.
    ///
    /// # Parameters
    /// - `worker_id`: Unique worker identifier
    /// - `max_connections`: Slab capacity (e.g., 1_000_000)
    /// - `runtime_handle`: Tokio runtime for spawning app tasks
    /// - `app_registry`: Shared application registry
    /// - `conn_config`: Template for creating QUIC connections
    pub fn new(
        worker_id: usize,
        max_connections: usize,
        runtime_handle: tokio::runtime::Handle,
        app_registry: Arc<crate::apps::AppRegistry>,
        conn_config: ConnectionConfig,
    ) -> Self {
        let (egress_tx, egress_rx) = unbounded();
        
        info!(
            worker_id,
            max_connections,
            "Initializing worker context with Slab capacity"
        );
        
        Self {
            connections: Slab::with_capacity(max_connections),
            cid_to_index: AHashMap::with_capacity(max_connections),
            egress_tx,
            egress_rx,
            runtime_handle,
            app_registry,
            worker_id,
            conn_config,
        }
    }
    
    /// Get a connection by ConnectionId.
    pub fn get_connection(&self, cid: &ConnectionId) -> Option<&ConnectionState> {
        let index = self.cid_to_index.get(&cid.0)?;
        self.connections.get(*index)
    }
    
    /// Get a mutable connection by ConnectionId.
    pub fn get_connection_mut(&mut self, cid: &ConnectionId) -> Option<&mut ConnectionState> {
        let index = self.cid_to_index.get(&cid.0)?;
        self.connections.get_mut(*index)
    }
    
    /// Insert a new connection.
    ///
    /// Returns the Slab index for the connection.
    pub fn insert_connection(
        &mut self,
        cid: ConnectionId,
        state: ConnectionState,
    ) -> Result<usize, &'static str> {
        if self.connections.len() >= self.connections.capacity() {
            error!(
                worker_id = self.worker_id,
                "Slab at capacity, rejecting new connection"
            );
            return Err("slab at capacity");
        }
        
        let index = self.connections.insert(state);
        self.cid_to_index.insert(cid.0, index);
        
        debug!(
            worker_id = self.worker_id,
            conn_id = cid.0,
            slab_index = index,
            total_connections = self.connections.len(),
            "Inserted new connection into Slab"
        );
        
        Ok(index)
    }
    
    /// Remove a connection by ConnectionId.
    pub fn remove_connection(&mut self, cid: &ConnectionId) -> Option<ConnectionState> {
        let index = self.cid_to_index.remove(&cid.0)?;
        let state = self.connections.try_remove(index)?;
        
        debug!(
            worker_id = self.worker_id,
            conn_id = cid.0,
            slab_index = index,
            remaining_connections = self.connections.len(),
            "Removed connection from Slab"
        );
        
        Some(state)
    }
    
    /// Spawn application task for a connection.
    ///
    /// Called once handshake is complete and ALPN is negotiated.
    pub fn spawn_app_task(&mut self, cid: ConnectionId) -> Result<(), String> {
        let index = self.cid_to_index.get(&cid.0)
            .ok_or("connection not found")?;
        
        let conn_state = self.connections.get_mut(*index)
            .ok_or("invalid slab index")?;
        
        if conn_state.app_spawned {
            return Ok(());
        }
        
        let alpn = conn_state.alpn.as_ref()
            .ok_or("ALPN not negotiated")?;
        
        let app = self.app_registry.get(alpn)
            .ok_or_else(|| format!("no application registered for ALPN: {}", alpn))?;
        
        // Create bounded ingress channel
        let (ingress_tx, ingress_rx) = mpsc::channel(INGRESS_CHANNEL_CAPACITY);
        conn_state.ingress_tx = Some(ingress_tx);
        conn_state.app_spawned = true;
        
        // Create ConnectionHandle
        let handle = quicd_x::ConnectionHandle::new(
            cid,
            ingress_rx,
            self.egress_tx.clone(),
        );
        
        info!(
            worker_id = self.worker_id,
            conn_id = cid.0,
            alpn = %alpn,
            "Spawning application task"
        );
        
        // Spawn on Tokio runtime
        let app_instance = app();  // Call the factory to create application instance
        self.runtime_handle.spawn(async move {
            app_instance.on_connection(handle).await;
        });
        
        Ok(())
    }
    
    /// Process a command from application task.
    pub fn handle_command(&mut self, cmd: Command) {
        match cmd {
            Command::OpenBiStream { conn_id } => {
                trace!(worker_id = self.worker_id, conn_id = conn_id.0, "OpenBiStream");
                if let Some(conn_state) = self.get_connection_mut(&conn_id) {
                    // TODO: Call quic_conn.open_stream(Bidirectional)
                    // Then send Event::StreamOpenedConfirm
                }
            }
            Command::WriteStreamData { conn_id, stream_id, data, fin } => {
                trace!(
                    worker_id = self.worker_id,
                    conn_id = conn_id.0,
                    stream_id = stream_id.0,
                    len = data.len(),
                    fin,
                    "WriteStreamData"
                );
                if let Some(conn_state) = self.get_connection_mut(&conn_id) {
                    // TODO: Call quic_conn.write_stream(stream_id, data, fin)
                }
            }
            Command::CloseConnection { conn_id, error_code, reason } => {
                info!(
                    worker_id = self.worker_id,
                    conn_id = conn_id.0,
                    error_code,
                    reason = %reason,
                    "CloseConnection"
                );
                if let Some(conn_state) = self.get_connection_mut(&conn_id) {
                    // TODO: Call quic_conn.close(error_code, reason)
                }
            }
            // Handle other commands...
            _ => {
                trace!(worker_id = self.worker_id, "Unhandled command: {:?}", cmd);
            }
        }
    }
    
    /// Try to receive commands from egress channel (non-blocking).
    pub fn poll_commands(&mut self) {
        while let Ok(cmd) = self.egress_rx.try_recv() {
            self.handle_command(cmd);
        }
    }
    
    /// Get egress channel sender (for sharing with app tasks).
    pub fn egress_sender(&self) -> Sender<Command> {
        self.egress_tx.clone()
    }
    
    /// Get number of active connections.
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }
}
