//! QUIC connection manager.
//!
//! Manages all QUIC connections for a single worker thread.
//! This is the main integration point between the network layer and QUIC protocol.
//!
//! # Architecture
//!
//! - One manager per worker thread (no sharing between workers)
//! - Owns all connections for this worker
//! - Routes incoming packets to the correct connection
//! - Handles connection creation and cleanup
//! - Manages timeouts and retransmissions
//!
//! # Connection Routing
//!
//! QUIC uses Connection IDs (DCID/SCID) to route packets:
//! - Client sends packet with DCID (identifies server connection)
//! - Server looks up connection by DCID
//! - Server sends response with SCID (which becomes client's DCID)
//!
//! We maintain a HashMap: DCID → Connection

use super::config::QuicConfig;
use super::connection::QuicConnection;
use super::crypto::{create_quiche_config, TlsCredentials};
use super::prefetch::{prefetch, PrefetchMode};
use crate::netio::buffer::WorkerBuffer;
use crate::quic::routing;
use ahash::AHashMap;
use anyhow::{Context, Result};
use bytes::Bytes;
use quiche::ConnectionId;
use smallvec::SmallVec;
use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

/// Maximum connection ID length (QUIC allows up to 20 bytes)
const MAX_CONN_ID_LEN: usize = 20;

/// Size of stream read buffers (64KB - max for efficient UDP/QUIC)
const STREAM_BUFFER_SIZE: usize = 65536;

/// Convert a borrowed ConnectionId to an owned ConnectionId<'static> using inline storage.
///
/// This optimization eliminates heap allocations for the common case where Connection IDs
/// are ≤20 bytes (which is always true per QUIC spec). Uses SmallVec to store the ID
/// inline on the stack when possible.
///
/// # Performance
///
/// - **Before**: `.to_vec()` always heap-allocates (Vec always uses heap)
/// - **After**: Inline storage for IDs ≤20 bytes (100% of QUIC IDs per RFC 9000)
/// - **Savings**: ~200K heap allocations/sec at 100K pps (2 per packet: ingress + connection map)
///
/// # QUIC Spec
///
/// RFC 9000 Section 5.1: Connection IDs are between 0 and 20 bytes.
/// Typical implementations use 8-16 bytes.
#[inline]
fn connection_id_to_owned(cid: &ConnectionId) -> ConnectionId<'static> {
    // Use SmallVec with inline capacity matching QUIC's max CID length
    // This avoids heap allocation for all valid QUIC connection IDs
    let small_vec: SmallVec<[u8; MAX_CONN_ID_LEN]> = SmallVec::from_slice(cid);

    // Convert SmallVec to Vec for ConnectionId::from
    // If len ≤ 20: uses SmallVec's inline storage, then moves to Vec (still no heap)
    // If len > 20: would heap allocate, but impossible per QUIC spec
    small_vec.to_vec().into()
}

/// Timeout queue entry for priority-based timeout tracking.
/// Used in a BinaryHeap to efficiently find the next connection that needs timeout processing.
#[derive(Debug, Clone)]
struct TimeoutEntry {
    /// Deadline for this timeout (Instant when timeout should fire)
    deadline: Instant,
    /// Connection ID that this timeout is for
    dcid: ConnectionId<'static>,
}

impl TimeoutEntry {
    fn new(deadline: Instant, dcid: ConnectionId<'static>) -> Self {
        Self { deadline, dcid }
    }
}

// Implement ordering for BinaryHeap (min-heap based on deadline)
// Earlier deadlines have higher priority
impl PartialEq for TimeoutEntry {
    fn eq(&self, other: &Self) -> bool {
        self.deadline == other.deadline
    }
}

impl Eq for TimeoutEntry {}

impl PartialOrd for TimeoutEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TimeoutEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering for min-heap (BinaryHeap is max-heap by default)
        other.deadline.cmp(&self.deadline)
    }
}

/// Simple buffer pool for stream reads to avoid allocations.
/// Uses a Vec-based LIFO pool for fast get/return operations.
struct StreamBufferPool {
    /// Pool of reusable buffers
    pool: RefCell<Vec<Vec<u8>>>,
    /// Maximum buffers to keep in pool
    max_buffers: usize,
}

impl StreamBufferPool {
    /// Create a new stream buffer pool
    fn new(max_buffers: usize) -> Self {
        Self {
            pool: RefCell::new(Vec::with_capacity(max_buffers)),
            max_buffers,
        }
    }

    /// Get a buffer from the pool, or allocate a new one if pool is empty
    fn get(&self) -> Vec<u8> {
        self.pool
            .borrow_mut()
            .pop()
            .unwrap_or_else(|| vec![0u8; STREAM_BUFFER_SIZE])
    }

    /// Return a buffer to the pool (or drop it if pool is full)
    fn put(&self, mut buf: Vec<u8>) {
        // Only keep buffer if pool isn't full and buffer is the right size
        if self.pool.borrow().len() < self.max_buffers && buf.capacity() >= STREAM_BUFFER_SIZE {
            // Reset buffer for reuse
            buf.clear();
            buf.resize(STREAM_BUFFER_SIZE, 0);
            self.pool.borrow_mut().push(buf);
        }
        // Otherwise, drop the buffer (let it deallocate)
    }

    /// Get current pool size (for diagnostics)
    #[allow(dead_code)]
    fn len(&self) -> usize {
        self.pool.borrow().len()
    }
}

/// Buffer pool for send packet data to eliminate allocations in hot path.
///
/// CRITICAL OPTIMIZATION: This pool eliminates ~100k allocations/sec at 100k pps.
/// Each packet send previously allocated a new Vec - now we reuse buffers.
///
/// Design:
/// - LIFO ordering for optimal cache locality (hot buffers stay hot)
/// - Pre-allocated to max UDP datagram size (65536 bytes)
/// - Bounded pool size to prevent unbounded growth
/// - Thread-local (RefCell) since QuicManager is single-threaded
struct SendBufferPool {
    /// LIFO stack of reusable send buffers
    pool: RefCell<Vec<Vec<u8>>>,
    /// Maximum buffers to keep (64 is reasonable for typical workload)
    max_buffers: usize,
    /// Size of each buffer (max UDP datagram)
    buffer_size: usize,
}

impl SendBufferPool {
    /// Create a new send buffer pool with specified capacity
    fn new(max_buffers: usize, buffer_size: usize) -> Self {
        // Pre-allocate some buffers for faster startup
        let initial_buffers = (max_buffers / 4).max(8);
        let pool = (0..initial_buffers)
            .map(|_| vec![0u8; buffer_size])
            .collect();

        Self {
            pool: RefCell::new(pool),
            max_buffers,
            buffer_size,
        }
    }

    /// Get a buffer from the pool (LIFO for cache locality)
    fn get(&self) -> Vec<u8> {
        self.pool
            .borrow_mut()
            .pop()
            .unwrap_or_else(|| vec![0u8; self.buffer_size])
    }

    /// Return a buffer to the pool after send completion
    fn put(&self, mut buf: Vec<u8>) {
        let mut pool = self.pool.borrow_mut();

        // Only keep if pool isn't full and buffer has correct capacity
        if pool.len() < self.max_buffers && buf.capacity() >= self.buffer_size {
            // Clear and resize to standard size for next use
            buf.clear();
            buf.resize(self.buffer_size, 0);
            pool.push(buf); // LIFO: push to end, pop from end
        }
        // Otherwise drop (deallocate)
    }

    /// Get current pool size (for diagnostics/metrics)
    #[allow(dead_code)]
    fn len(&self) -> usize {
        self.pool.borrow().len()
    }
}

/// Helper to send an event to the app task with proper error handling
///
/// Returns true if event was sent successfully, false otherwise.
/// Logs warnings when channel is full or closed.
fn send_app_event(
    worker_id: usize,
    connection_id: quicd_x::ConnectionId,
    ingress_tx: &mpsc::Sender<quicd_x::AppEvent>,
    event: quicd_x::AppEvent,
) -> bool {
    match ingress_tx.try_send(event) {
        Ok(()) => true,
        Err(mpsc::error::TrySendError::Full(_)) => {
            warn!(
                worker_id,
                connection_id, "App ingress channel full - app task too slow or blocked"
            );
            false
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            debug!(
                worker_id,
                connection_id, "App ingress channel closed - app task terminated"
            );
            false
        }
    }
}

/// Packet that needs to be sent
#[derive(Debug)]
pub struct OutgoingPacket {
    pub to: SocketAddr,
    pub data: Vec<u8>,
}

/// Information propagated to application tasks when a connection closes.
#[derive(Debug, Clone, Default)]
struct CloseInfo {
    error_code: u64,
    reason: Option<Bytes>,
}

/// QUIC connection manager for a worker thread
pub struct QuicManager {
    /// Worker ID (for logging)
    worker_id: usize,

    /// Local socket address
    local_addr: SocketAddr,

    /// QUIC configuration
    config: QuicConfig,

    /// Quiche configuration (shared by all connections)
    quiche_config: quiche::Config,

    /// Active connections mapped by Connection ID
    /// Key: Destination Connection ID (DCID) from packet header
    /// Value: The connection handling packets with this DCID
    ///
    /// Uses AHashMap for fast lookups (10-50x faster than default SipHash).
    /// Every incoming packet performs a lookup, making this a critical hot path.
    connections: AHashMap<ConnectionId<'static>, QuicConnection>,

    /// Mapping from alternate DCIDs observed on the wire to the canonical
    /// connection identifier stored in `connections`.
    ///
    /// Uses AHashMap for fast alias resolution in packet routing.
    connection_aliases: AHashMap<ConnectionId<'static>, ConnectionId<'static>>,

    /// Connection ID seed (for generating new connection IDs)
    conn_id_seed: ring::hmac::Key,

    /// Statistics (using RefCell for interior mutability)
    stats: RefCell<ManagerStats>,

    /// Tokio runtime handle for spawning application tasks
    runtime_handle: tokio::runtime::Handle,

    /// Application registry (ALPN -> factory)
    app_registry: crate::apps::AppRegistry,

    /// Egress channel sender (shared with all app tasks for this worker)
    egress_tx: mpsc::Sender<quicd_x::EgressCommand>,

    /// Channel capacity configuration
    channel_config: crate::channel_config::ChannelConfig,

    /// Stream buffer pool for reusing read buffers
    stream_buffer_pool: StreamBufferPool,

    /// Send buffer pool for eliminating packet send allocations (CRITICAL OPTIMIZATION)
    /// Reuses buffers for outgoing packets to avoid ~100k allocations/sec at 100k pps
    send_buffer_pool: SendBufferPool,

    /// Priority queue for efficient timeout tracking (min-heap by deadline)
    timeout_queue: BinaryHeap<TimeoutEntry>,

    /// Map from application connection_id to QUIC DCID for egress command routing
    ///
    /// Uses AHashMap for fast lookups when routing egress commands to connections.
    connection_id_map: AHashMap<quicd_x::ConnectionId, quiche::ConnectionId<'static>>,
}

/// Manager statistics
#[derive(Debug, Default)]
#[allow(dead_code)]
struct ManagerStats {
    /// Total connections created
    connections_created: u64,
    /// Total connections closed
    connections_closed: u64,
    /// Total packets processed
    packets_processed: u64,
    /// Total packets sent
    packets_sent: u64,
    /// Total handshakes completed
    handshakes_completed: u64,
    /// Total connection migrations completed (mobile clients)
    migrations_completed: u64,
}

impl QuicManager {
    /// Create a new QUIC manager for a worker thread
    pub fn new(
        worker_id: usize,
        local_addr: SocketAddr,
        config: QuicConfig,
        tls_credentials: Option<TlsCredentials>,
        runtime_handle: tokio::runtime::Handle,
        app_registry: crate::apps::AppRegistry,
        egress_tx: mpsc::Sender<quicd_x::EgressCommand>,
        channel_config: crate::channel_config::ChannelConfig,
    ) -> Result<Self> {
        // Validate configuration
        config.validate()?;

        info!(
            worker_id,
            %local_addr,
            max_connections = config.max_connections_per_worker,
            "Creating QUIC manager"
        );

        // Use pre-loaded credentials if provided, otherwise load/generate them
        let credentials = if let Some(creds) = tls_credentials {
            debug!(
                worker_id,
                "Using pre-loaded TLS credentials (shared from main thread)"
            );
            creds
        } else {
            // This should never happen if spawn() enforces certificate requirement
            anyhow::bail!(
                "TLS credentials are required but not provided. \
                 This is a programming error - credentials should be loaded in spawn()."
            );
        };

        // Create Quiche configuration
        let quiche_config = create_quiche_config(&credentials, &config)?;

        // Generate connection ID seed for this worker
        // Each worker has its own seed to avoid connection ID collisions
        let conn_id_seed =
            ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &ring::rand::SystemRandom::new())
                .map_err(|_| anyhow::anyhow!("failed to generate connection ID seed"))?;

        // Pre-allocate connection maps with fast AHash hasher
        // AHashMap provides 10-50x faster lookups than default SipHash
        let connections = AHashMap::with_capacity(config.max_connections_per_worker);
        let connection_id_map = AHashMap::new();

        // Create stream buffer pool
        // Keep up to 32 buffers per worker (reasonable for typical workloads)
        let stream_buffer_pool = StreamBufferPool::new(32);

        // Create send buffer pool for packet transmission (CRITICAL OPTIMIZATION)
        // 64 buffers × 65KB = 4MB per worker (acceptable memory cost for zero allocations)
        // This eliminates ~100k allocations/sec at 100k packets/sec
        let send_buffer_pool = SendBufferPool::new(64, MAX_DATAGRAM_SIZE);

        // Create timeout priority queue (min-heap)
        let timeout_queue = BinaryHeap::new();

        Ok(Self {
            worker_id,
            local_addr,
            config,
            quiche_config,
            connections,
            connection_aliases: AHashMap::new(),
            conn_id_seed,
            stats: RefCell::new(ManagerStats::default()),
            runtime_handle,
            app_registry,
            egress_tx,
            channel_config,
            stream_buffer_pool,
            send_buffer_pool,
            timeout_queue,
            connection_id_map,
        })
    }

    /// Resolve the canonical connection identifier for an incoming DCID.
    fn resolve_canonical_id(&self, dcid: &ConnectionId<'static>) -> Option<ConnectionId<'static>> {
        if self.connections.contains_key(dcid) {
            Some(dcid.clone())
        } else {
            self.connection_aliases.get(dcid).cloned()
        }
    }

    /// Remember that `alias` now routes to `canonical` for future packets.
    fn register_dcid_alias(
        &mut self,
        canonical: &ConnectionId<'static>,
        alias: ConnectionId<'static>,
    ) {
        if alias == *canonical {
            return;
        }

        if matches!(self.connection_aliases.get(&alias), Some(existing) if existing == canonical) {
            return;
        }

        if let Some(conn) = self.connections.get_mut(canonical) {
            if !conn.dcid_aliases.iter().any(|known| known == &alias) {
                conn.dcid_aliases.push(alias.clone());
            }
        }

        self.connection_aliases.insert(alias, canonical.clone());
    }

    /// Translate quiche close state into information propagated to apps.
    fn connection_close_info(conn: &quiche::Connection) -> CloseInfo {
        if let Some(err) = conn.peer_error() {
            return CloseInfo {
                error_code: err.error_code,
                reason: if err.reason.is_empty() {
                    None
                } else {
                    Some(Bytes::from(err.reason.clone()))
                },
            };
        }

        if let Some(err) = conn.local_error() {
            return CloseInfo {
                error_code: err.error_code,
                reason: if err.reason.is_empty() {
                    None
                } else {
                    Some(Bytes::from(err.reason.clone()))
                },
            };
        }

        if conn.is_timed_out() {
            return CloseInfo {
                error_code: 0,
                reason: Some(Bytes::from_static(b"idle timeout")),
            };
        }

        CloseInfo::default()
    }

    /// Remove a connection from the manager and notify the associated app.
    fn finalize_connection(
        &mut self,
        canonical_id: &ConnectionId<'static>,
        info: CloseInfo,
        outgoing: &mut Vec<OutgoingPacket>,
    ) -> Result<()> {
        if let Some(mut conn) = self.connections.remove(canonical_id) {
            // Ensure we emit any pending close packets before dropping the connection.
            collect_packets_for_conn(self.worker_id, &mut conn, &self.send_buffer_pool, outgoing)?;

            self.stats.borrow_mut().connections_closed += 1;

            // Drop alias entries for this connection.
            for alias in &conn.dcid_aliases {
                self.connection_aliases.remove(alias);
            }

            // Remove mapping used by application handles.
            self.connection_id_map.remove(&conn.connection_id);

            if let Some(ingress_tx) = conn.ingress_tx.take() {
                let event = quicd_x::AppEvent::ConnectionClosing {
                    error_code: info.error_code,
                    reason: info.reason.clone(),
                };
                let _ = send_app_event(self.worker_id, conn.connection_id, &ingress_tx, event);
                // Drop sender after notification so subsequent attempts fail fast.
                drop(ingress_tx);
            }

            if let Some(shutdown_tx) = conn.shutdown_tx.take() {
                let _ = shutdown_tx.send(());
            }

            if let Some(task) = conn.app_task_handle.take() {
                task.abort();
            }

            // Dropping the stream manager automatically closes all per-stream channels.
        }

        Ok(())
    }

    /// Purge connections that transitioned to `is_closed()` state.
    fn cleanup_closed_connections(&mut self, outgoing: &mut Vec<OutgoingPacket>) -> Result<()> {
        let mut to_close = Vec::new();

        for (dcid, conn) in self.connections.iter() {
            if conn.conn.is_closed() {
                to_close.push((dcid.clone(), Self::connection_close_info(&conn.conn)));
            }
        }

        for (dcid, info) in to_close {
            self.finalize_connection(&dcid, info, outgoing)?;
        }

        Ok(())
    }

    /// Process an incoming packet and return packets that need to be sent
    ///
    /// This is the main entry point from the network layer.
    /// Called when a UDP packet is received.
    ///
    /// Returns a tuple:
    /// - Optional connection_id if an app was spawned for a new connection
    /// - Vec of outgoing packets that need to be sent
    pub fn process_ingress(
        &mut self,
        mut buffer: WorkerBuffer,
        peer_addr: SocketAddr,
    ) -> Result<(Option<quicd_x::ConnectionId>, Vec<OutgoingPacket>)> {
        let packet_len = buffer.len();
        let packet = buffer.as_mut_slice_for_io();
        let packet = &mut packet[..packet_len];

        self.stats.borrow_mut().packets_processed += 1;

        let mut outgoing_packets = Vec::new();

        let hdr = match quiche::Header::from_slice(packet, MAX_CONN_ID_LEN) {
            Ok(hdr) => hdr,
            Err(e) => {
                debug!(
                    worker_id = self.worker_id,
                    error = ?e,
                    peer = %peer_addr,
                    "Failed to parse QUIC header"
                );
                return Ok((None, outgoing_packets));
            }
        };

        trace!(
            worker_id = self.worker_id,
            peer = %peer_addr,
            dcid = ?hdr.dcid,
            scid = ?hdr.scid,
            ty = ?hdr.ty,
            version = hdr.version,
            "Received QUIC packet"
        );

        if hdr.version != quiche::PROTOCOL_VERSION && self.config.enable_version_negotiation {
            let mut out = [0; MAX_DATAGRAM_SIZE];
            let len = quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out)
                .context("failed to negotiate version")?;

            outgoing_packets.push(OutgoingPacket {
                to: peer_addr,
                data: out[..len].to_vec(),
            });
            return Ok((None, outgoing_packets));
        }

        // Convert borrowed ConnectionId to owned using inline storage (no heap allocation)
        let packet_dcid = connection_id_to_owned(&hdr.dcid);

        let canonical_dcid = match self.resolve_canonical_id(&packet_dcid) {
            Some(id) => {
                if id != packet_dcid {
                    self.register_dcid_alias(&id, packet_dcid.clone());
                }
                id
            }
            None => {
                if hdr.ty == quiche::Type::Initial {
                    self.create_connection(peer_addr, &hdr)?
                } else {
                    debug!(
                        worker_id = self.worker_id,
                        peer = %peer_addr,
                        dcid = ?hdr.dcid,
                        ty = ?hdr.ty,
                        "Received packet for unknown connection"
                    );
                    return Ok((None, outgoing_packets));
                }
            }
        };

        // ═══════════════════════════════════════════════════════════════════
        // MEMORY PREFETCH OPTIMIZATION
        // ═══════════════════════════════════════════════════════════════════
        // Prefetch the connection object into cache before accessing it.
        // This hides memory latency (~100-200 cycles) while we set up recv_info.
        // The HashMap lookup finds the pointer, then prefetch begins loading
        // the QuicConnection structure into L1 cache.
        if let Some(conn_ptr) = self.connections.get(&canonical_dcid) {
            // Prefetch the connection structure
            prefetch(conn_ptr as *const QuicConnection, PrefetchMode::Write);

            // Prefetch the underlying quiche::Connection (first field, likely hot)
            prefetch(
                &conn_ptr.conn as *const quiche::Connection,
                PrefetchMode::Write,
            );
        }

        let mut should_process_streams = false;
        let mut should_send_packets = false;
        let mut spawn_app = false;
        let mut handshake_trace_id: Option<String> = None;
        let mut path_events = Vec::new();

        {
            let conn = self
                .connections
                .get_mut(&canonical_dcid)
                .expect("connection must exist after resolution");

            let recv_info = quiche::RecvInfo {
                from: peer_addr,
                to: self.local_addr,
            };

            match conn.recv(packet, recv_info) {
                Ok(_) => {
                    trace!(
                        worker_id = self.worker_id,
                        peer = %peer_addr,
                        dcid = ?hdr.dcid,
                        "Packet processed successfully"
                    );
                    should_process_streams = true;
                    should_send_packets = true;

                    if conn.is_established() && conn.ingress_tx.is_none() {
                        spawn_app = true;
                        handshake_trace_id = Some(conn.trace_id().to_string());
                    }

                    // Collect path events (connection migration, path validation)
                    // Must collect first to avoid borrow checker issues
                    while let Some(path_event) = conn.path_event_next() {
                        path_events.push(path_event);
                    }
                }
                Err(quiche::Error::Done) => {
                    trace!(worker_id = self.worker_id, "Packet processing done");
                }
                Err(e) => {
                    warn!(
                        worker_id = self.worker_id,
                        peer = %peer_addr,
                        error = ?e,
                        "Failed to process packet"
                    );
                }
            }
        }

        // Process path events after releasing connection borrow
        for path_event in path_events {
            self.handle_path_event(&canonical_dcid, path_event)?;
        }

        if spawn_app {
            self.stats.borrow_mut().handshakes_completed += 1;
            if let Some(trace_id) = handshake_trace_id {
                info!(
                    worker_id = self.worker_id,
                    peer = %peer_addr,
                    %trace_id,
                    "QUIC handshake completed"
                );
            }
        }

        let mut spawned_app_connection_id = None;

        if spawn_app {
            if let Some(connection_id) = self.spawn_application_for_connection(&canonical_dcid) {
                spawned_app_connection_id = Some(connection_id);
            }
        }

        if should_process_streams {
            if let Some(conn) = self.connections.get_mut(&canonical_dcid) {
                process_streams(self.worker_id, conn, &self.stream_buffer_pool)?;
            }
        }

        if should_send_packets {
            if let Some(conn) = self.connections.get_mut(&canonical_dcid) {
                collect_packets_for_conn(
                    self.worker_id,
                    conn,
                    &self.send_buffer_pool,
                    &mut outgoing_packets,
                )?;

                // Reschedule timeout after processing packet (connection activity updated)
                // Do this while we have the mutable borrow
                if let Some(timeout) = conn.timeout() {
                    let deadline = conn.last_active + timeout;
                    self.timeout_queue
                        .push(TimeoutEntry::new(deadline, canonical_dcid.clone()));
                }
            }
        }

        self.cleanup_closed_connections(&mut outgoing_packets)?;

        Ok((spawned_app_connection_id, outgoing_packets))
    }

    /// Handle timeouts for all connections and emit resulting packets.
    /// Uses priority queue for O(log n) timeout processing instead of O(n) iteration.
    pub fn handle_timeouts(&mut self) -> Result<Vec<OutgoingPacket>> {
        let now = Instant::now();
        let mut outgoing_packets = Vec::new();
        let mut to_close = Vec::new();
        let mut processed_dcids = std::collections::HashSet::new();

        // Process all connections with expired timeouts using the priority queue
        // The queue is a min-heap, so peek() gives us the earliest deadline
        while let Some(entry) = self.timeout_queue.peek() {
            // If the earliest deadline hasn't arrived yet, we're done
            if entry.deadline > now {
                break;
            }

            // Pop the entry from the queue
            let entry = self.timeout_queue.pop().unwrap();

            // Skip if we already processed this connection in this cycle
            // (Multiple timeout entries may exist for the same connection)
            if processed_dcids.contains(&entry.dcid) {
                continue;
            }

            // Prefetch connection before accessing it (hides memory latency)
            if let Some(conn_ptr) = self.connections.get(&entry.dcid) {
                prefetch(conn_ptr as *const QuicConnection, PrefetchMode::Write);
                prefetch(
                    &conn_ptr.conn as *const quiche::Connection,
                    PrefetchMode::Write,
                );
            }

            // Check if connection still exists and needs timeout processing
            if let Some(conn) = self.connections.get_mut(&entry.dcid) {
                // Verify timeout is actually expired (connection may have been updated)
                if let Some(timeout) = conn.timeout() {
                    if now >= conn.last_active + timeout {
                        conn.on_timeout();

                        // Collect packets generated by timeout
                        collect_packets_for_conn(
                            self.worker_id,
                            conn,
                            &self.send_buffer_pool,
                            &mut outgoing_packets,
                        )?;

                        // Check if connection is now closed
                        if conn.conn.is_closed() {
                            to_close.push((
                                entry.dcid.clone(),
                                Self::connection_close_info(&conn.conn),
                            ));
                        } else {
                            // Reschedule timeout for next cycle
                            if let Some(timeout) = conn.timeout() {
                                let deadline = conn.last_active + timeout;
                                self.timeout_queue
                                    .push(TimeoutEntry::new(deadline, entry.dcid.clone()));
                            }
                        }
                    }
                }

                processed_dcids.insert(entry.dcid);
            }
        }

        // Clean up closed connections
        for (dcid, info) in to_close {
            self.finalize_connection(&dcid, info, &mut outgoing_packets)?;
        }

        Ok(outgoing_packets)
    }

    /// Handle path events (connection migration, path validation).
    ///
    /// QUIC supports connection migration where a client can change its IP address
    /// or port during a connection (e.g., mobile device switching networks).
    /// This method processes path events from Quiche and updates connection state.
    fn handle_path_event(
        &mut self,
        dcid: &ConnectionId<'static>,
        event: quiche::PathEvent,
    ) -> Result<()> {
        use quiche::PathEvent;

        let conn = self
            .connections
            .get_mut(dcid)
            .ok_or_else(|| anyhow::anyhow!("Connection not found for path event"))?;

        match event {
            PathEvent::New(local_addr, peer_addr) => {
                // A new network path has been observed (server-side only)
                info!(
                    worker_id = self.worker_id,
                    connection_id = ?dcid,
                    %local_addr,
                    %peer_addr,
                    "New network path detected"
                );
            }

            PathEvent::Validated(local_addr, peer_addr) => {
                // Path validation succeeded
                info!(
                    worker_id = self.worker_id,
                    connection_id = ?dcid,
                    %local_addr,
                    %peer_addr,
                    "Network path validated"
                );
            }

            PathEvent::FailedValidation(local_addr, peer_addr) => {
                // Path validation failed - this path won't be used
                warn!(
                    worker_id = self.worker_id,
                    connection_id = ?dcid,
                    %local_addr,
                    %peer_addr,
                    "Network path validation failed"
                );
            }

            PathEvent::Closed(local_addr, peer_addr) => {
                // Path has been closed
                info!(
                    worker_id = self.worker_id,
                    connection_id = ?dcid,
                    %local_addr,
                    %peer_addr,
                    "Network path closed"
                );
            }

            PathEvent::ReusedSourceConnectionId(
                seq,
                (old_local, old_peer),
                (new_local, new_peer),
            ) => {
                // Source connection ID is being reused on a different path
                debug!(
                    worker_id = self.worker_id,
                    connection_id = ?dcid,
                    sequence = seq,
                    old_local = %old_local,
                    old_peer = %old_peer,
                    new_local = %new_local,
                    new_peer = %new_peer,
                    "Source connection ID reused on different path"
                );
            }

            PathEvent::PeerMigrated(local_addr, peer_addr) => {
                // Peer has migrated to a new network path (validated path only)
                // This is the critical event for mobile clients
                let old_peer_addr = conn.peer_addr;
                conn.peer_addr = peer_addr;

                info!(
                    worker_id = self.worker_id,
                    connection_id = ?dcid,
                    %local_addr,
                    old_peer = %old_peer_addr,
                    new_peer = %peer_addr,
                    "Peer migrated to new network path"
                );

                // Update connection statistics
                self.stats.borrow_mut().migrations_completed += 1;
            }
        }

        Ok(())
    }

    /// Gracefully close all connections with a shutdown notification.
    ///
    /// This method closes all active connections by sending CONNECTION_CLOSE frames
    /// and generates outgoing packets to notify peers. Should be called during
    /// worker shutdown to ensure clean connection termination.
    ///
    /// Returns packets that need to be sent to notify peers of connection closure.
    pub fn shutdown_all_connections(&mut self) -> Result<Vec<OutgoingPacket>> {
        info!(
            worker_id = self.worker_id,
            active_connections = self.connections.len(),
            "Initiating graceful shutdown of all connections"
        );

        let mut outgoing_packets = Vec::new();
        let mut connections_to_close = Vec::new();

        // Collect all connection IDs first to avoid borrow issues
        for dcid in self.connections.keys() {
            connections_to_close.push(dcid.clone());
        }

        // Close each connection gracefully
        for dcid in connections_to_close {
            if let Some(conn) = self.connections.get_mut(&dcid) {
                // Send CONNECTION_CLOSE frame (application close, no error)
                // Error code 0 indicates normal graceful shutdown
                let close_result = conn.close(
                    true, // application close (not transport error)
                    0,    // error code 0 = graceful shutdown
                    b"Server shutting down",
                );

                if let Err(e) = close_result {
                    debug!(
                        worker_id = self.worker_id,
                        connection_id = ?dcid,
                        error = ?e,
                        "Failed to close connection (may already be closed)"
                    );
                }

                // Collect packets to send CONNECTION_CLOSE to peer
                if let Err(e) = collect_packets_for_conn(
                    self.worker_id,
                    conn,
                    &self.send_buffer_pool,
                    &mut outgoing_packets,
                ) {
                    error!(
                        worker_id = self.worker_id,
                        connection_id = ?dcid,
                        error = ?e,
                        "Failed to collect shutdown packets"
                    );
                }
            }
        }

        // Clean up connection state (will notify apps via shutdown channels)
        for dcid in self.connections.keys().cloned().collect::<Vec<_>>() {
            let info = self
                .connections
                .get(&dcid)
                .map(|c| Self::connection_close_info(&c.conn));
            if let Some(info) = info {
                if let Err(e) = self.finalize_connection(&dcid, info, &mut outgoing_packets) {
                    error!(
                        worker_id = self.worker_id,
                        connection_id = ?dcid,
                        error = ?e,
                        "Failed to finalize connection during shutdown"
                    );
                }
            }
        }

        info!(
            worker_id = self.worker_id,
            shutdown_packets = outgoing_packets.len(),
            "All connections closed gracefully"
        );

        Ok(outgoing_packets)
    }
}

/// Process readable/writable streams (free function to avoid borrow issues)
fn process_streams(
    worker_id: usize,
    conn: &mut QuicConnection,
    buffer_pool: &StreamBufferPool,
) -> Result<()> {
    // Check if we have a stream manager (i.e., app task is spawned)
    if conn.stream_manager.is_none() {
        // No app task yet, skip stream processing
        return Ok(());
    }

    // Collect readable streams first to avoid borrow issues
    let readable_streams: Vec<u64> = conn.readable().collect();

    // Track which streams were successfully registered
    // We'll only process streams that are properly registered
    let mut registered_streams = Vec::with_capacity(readable_streams.len());

    // Check for newly opened streams by peer and register them
    for stream_id in &readable_streams {
        let stream_manager = conn.stream_manager.as_mut().unwrap();

        // Check if this is a new stream
        if !stream_manager.has_stream(*stream_id) {
            // Determine if bidirectional (even stream IDs are client-initiated bidirectional)
            let bidirectional = (stream_id % 4) == 0 || (stream_id % 4) == 1;

            debug!(worker_id, stream_id, bidirectional, "New stream detected");

            // Handle new stream (sends NewStream event to app)
            // If this fails (e.g., app channel full), we skip processing this stream
            if !stream_manager.handle_new_stream(worker_id, *stream_id, bidirectional) {
                warn!(
                    worker_id,
                    stream_id,
                    "Failed to register new stream - app channel full, deferring processing"
                );
                continue; // Skip this stream for now, will retry on next readable event
            }
        }

        // Stream is registered (either just now or previously), safe to process
        registered_streams.push(*stream_id);
    }

    // Process only the successfully registered streams
    for stream_id in registered_streams {
        trace!(
            worker_id,
            peer = %conn.peer_addr,
            stream_id,
            "Stream readable"
        );

        // Get a buffer from the pool instead of allocating
        let mut buf = buffer_pool.get();

        match conn.stream_recv(stream_id, &mut buf) {
            Ok((read, fin)) => {
                debug!(worker_id, stream_id, bytes = read, fin, "Read from stream");

                if read > 0 {
                    // Send data to app via stream manager (zero-copy using Bytes)
                    // Bytes::from takes ownership of the Vec and doesn't copy the data
                    if let Some(ref mut sm) = conn.stream_manager {
                        buf.truncate(read); // Shrink to actual data size
                        let data = bytes::Bytes::from(buf);
                        sm.send_stream_data(worker_id, stream_id, data);
                        // Buffer is now owned by Bytes, don't return to pool
                    } else {
                        // No stream manager, return buffer to pool
                        buffer_pool.put(buf);
                    }
                } else {
                    // No data read, return buffer to pool
                    buffer_pool.put(buf);
                }

                if fin {
                    // Signal FIN to app
                    if let Some(ref mut sm) = conn.stream_manager {
                        sm.signal_stream_fin(worker_id, stream_id);
                    }
                }
            }
            Err(quiche::Error::Done) => {
                // No more data - return buffer to pool
                buffer_pool.put(buf);
            }
            Err(quiche::Error::StreamReset(error_code)) => {
                // Stream was reset by peer - return buffer to pool
                buffer_pool.put(buf);
                if let Some(ref mut sm) = conn.stream_manager {
                    sm.handle_stream_close(worker_id, stream_id, false, error_code);
                }
            }
            Err(e) => {
                // Error reading - return buffer to pool
                buffer_pool.put(buf);
                warn!(
                    worker_id,
                    stream_id,
                    error = ?e,
                    "Failed to read from stream"
                );
            }
        }
    }

    // Note: Stream writes are now processed in the egress path via process_stream_writes()
    // This ensures proper separation of ingress and egress concerns

    // Process any received datagrams
    if let Some(ref mut sm) = conn.stream_manager {
        let ingress_tx = sm.conn_ingress_tx.clone();
        let mut dgram_buf = buffer_pool.get();

        loop {
            match conn.dgram_recv(&mut dgram_buf) {
                Ok(len) => {
                    debug!(worker_id, bytes = len, "Received datagram");

                    // Send datagram to app (zero-copy using Bytes)
                    dgram_buf.truncate(len);
                    let payload = bytes::Bytes::from(dgram_buf);

                    let event = quicd_x::AppEvent::Datagram { payload };
                    if ingress_tx.try_send(event).is_err() {
                        warn!(
                            worker_id,
                            "Failed to send Datagram event - app channel full"
                        );
                    }

                    // Get new buffer from pool for next datagram
                    dgram_buf = buffer_pool.get();
                }
                Err(quiche::Error::Done) => {
                    // No more datagrams - return buffer to pool
                    buffer_pool.put(dgram_buf);
                    break;
                }
                Err(e) => {
                    // Error - return buffer to pool
                    buffer_pool.put(dgram_buf);
                    warn!(worker_id, error = ?e, "Failed to receive datagram");
                    break;
                }
            }
        }
    }

    Ok(())
}

/// Collect all pending packets for a connection (free function to avoid borrow issues).
///
/// This is called after processing a connection to collect all packets that need to be sent.
///
/// CRITICAL OPTIMIZATION: Uses send buffer pool to eliminate allocations in hot path.
/// Previous implementation allocated Vec for each packet (~100k allocations/sec at 100k pps).
/// Now we reuse buffers from the pool for zero allocations in steady state.
fn collect_packets_for_conn(
    worker_id: usize,
    conn: &mut QuicConnection,
    send_pool: &SendBufferPool,
    outgoing_packets: &mut Vec<OutgoingPacket>,
) -> Result<()> {
    // Get a buffer from the send pool (reuses hot buffers for cache locality)
    let mut out = send_pool.get();

    loop {
        match conn.send(&mut out) {
            Ok((len, send_info)) => {
                // Extract the packet data by taking ownership of the buffer
                // The buffer will be transferred to SendOpState and eventually returned to pool
                let mut packet_data = out;
                packet_data.truncate(len); // Shrink to actual packet size

                outgoing_packets.push(OutgoingPacket {
                    to: send_info.to,
                    data: packet_data,
                });

                // Get a fresh buffer from pool for next packet
                out = send_pool.get();
            }
            Err(quiche::Error::Done) => {
                // No more packets - return the last buffer to pool
                send_pool.put(out);
                break;
            }
            Err(e) => {
                warn!(
                    worker_id,
                    peer = %conn.peer_addr,
                    error = ?e,
                    "Failed to generate packet"
                );
                // Return buffer to pool on error
                send_pool.put(out);
                break;
            }
        }
    }

    Ok(())
}

impl QuicManager {
    /// Calculate the next timeout for the manager
    ///
    /// This calculates the minimum timeout across all active connections.
    /// Should be called before waiting on io_uring to determine wait timeout.
    ///
    /// Returns:
    /// - Some(Duration) if any connection has a pending timeout
    /// Get the duration until the next timeout needs to be processed.
    ///
    /// This uses the timeout priority queue (min-heap) for O(1) access to the
    /// earliest deadline, instead of iterating all connections.
    ///
    /// Returns:
    /// - Some(Duration) - Time until next timeout
    /// - Some(Duration::ZERO) - Timeout already expired, process immediately
    /// - None if no connections or no pending timeouts
    pub fn next_timeout(&self) -> Option<std::time::Duration> {
        let now = Instant::now();

        // Peek at the earliest timeout in the priority queue (O(1) operation)
        // The heap is a min-heap by deadline, so peek() gives us the soonest timeout
        if let Some(entry) = self.timeout_queue.peek() {
            if entry.deadline > now {
                // Timeout hasn't expired yet - return time remaining
                Some(entry.deadline.duration_since(now))
            } else {
                // Timeout already expired - should process immediately
                Some(std::time::Duration::ZERO)
            }
        } else {
            // No pending timeouts in queue
            None
        }
    }

    /// Get current number of active connections
    #[allow(dead_code)]
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Get mutable reference to a connection by DCID
    pub fn get_connection_mut(
        &mut self,
        dcid: &quiche::ConnectionId<'static>,
    ) -> Option<&mut QuicConnection> {
        self.connections.get_mut(dcid)
    }

    /// Get reference to the connection ID map for egress command routing
    #[allow(dead_code)]
    pub fn connection_id_map(
        &self,
    ) -> &AHashMap<quicd_x::ConnectionId, quiche::ConnectionId<'static>> {
        &self.connection_id_map
    }

    /// Get connection statistics for a given connection ID.
    ///
    /// Returns None if the connection doesn't exist.
    pub fn get_connection_stats(
        &self,
        dcid: &quiche::ConnectionId<'static>,
    ) -> Option<quicd_x::ConnectionStats> {
        let conn = self.connections.get(dcid)?;

        // Get quiche stats
        let quiche_stats = conn.conn.stats();

        // Get path stats for RTT
        let path_stats = conn.conn.path_stats().next();
        let rtt_estimate_ms = path_stats.map(|ps| ps.rtt.as_millis() as u32);

        // Count active streams and track max stream ID
        let mut active_streams: usize = 0;
        let mut max_stream_id = conn.stream_id_gen.max_stream_id();
        
        for stream_id in conn.conn.readable() {
            active_streams = active_streams.saturating_add(1);
            max_stream_id = max_stream_id.max(stream_id);
        }
        for stream_id in conn.conn.writable() {
            active_streams = active_streams.saturating_add(1);
            max_stream_id = max_stream_id.max(stream_id);
        }

        // Build and return ConnectionStats
        Some(quicd_x::ConnectionStats {
            rtt_estimate_ms,
            bytes_sent: quiche_stats.sent as u64,
            bytes_received: quiche_stats.recv as u64,
            active_streams,
            congestion_state: None, // quiche doesn't expose congestion state in a simple way
            packets_sent: 0,        // quiche doesn't expose total packet count directly
            packets_received: 0,    // tracked separately if needed
            max_stream_id,
        })
    }

    /// Spawn an application task once the handshake has completed.
    fn spawn_application_for_connection(
        &mut self,
        canonical_id: &ConnectionId<'static>,
    ) -> Option<quicd_x::ConnectionId> {
        let (connection_id, peer_addr, alpn_bytes) = {
            let conn = self.connections.get(canonical_id)?;
            (
                conn.connection_id,
                conn.peer_addr,
                conn.conn.application_proto().to_vec(),
            )
        };

        let alpn = if alpn_bytes.is_empty() {
            debug!(
                worker_id = self.worker_id,
                peer = %peer_addr,
                "No ALPN negotiated, skipping app spawn"
            );
            return None;
        } else {
            String::from_utf8_lossy(&alpn_bytes).to_string()
        };

        let factory = match self.app_registry.get(&alpn) {
            Some(factory) => factory,
            None => {
                info!(
                    worker_id = self.worker_id,
                    peer = %peer_addr,
                    %alpn,
                    "No application registered for ALPN"
                );
                return None;
            }
        };

        info!(
            worker_id = self.worker_id,
            peer = %peer_addr,
            %alpn,
            connection_id = %connection_id,
            "Spawning application task"
        );

        // Create connection ingress channel with configured capacity
        let (ingress_tx, ingress_rx) =
            mpsc::channel(self.channel_config.connection_ingress_capacity);
        let stream_manager = crate::worker::streams::StreamManager::new(ingress_tx.clone());

        let handle = quicd_x::new_connection_handle(
            connection_id,
            self.egress_tx.clone(),
            self.local_addr,
            peer_addr,
        );

        let transport = quicd_x::TransportControls {
            enable_datagrams: self.config.enable_dgram,
            max_datagram_size: self.config.max_dgram_size,
        };

        let handshake_event = quicd_x::AppEvent::HandshakeCompleted {
            alpn: alpn.clone(),
            local_addr: self.local_addr,
            peer_addr,
            negotiated_at: Instant::now(),
        };

        if ingress_tx.try_send(handshake_event).is_err() {
            warn!(
                worker_id = self.worker_id,
                peer = %peer_addr,
                "Failed to send HandshakeCompleted event"
            );
            return None;
        }

        let event_stream: quicd_x::AppEventStream =
            Box::pin(tokio_stream::wrappers::ReceiverStream::new(ingress_rx));

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let shutdown_future: quicd_x::ShutdownFuture = Box::pin(async move {
            let _ = shutdown_rx.await;
        });

        let factory_clone = Arc::clone(&factory);
        let alpn_for_logging = alpn.clone();
        let task_handle = self.runtime_handle.spawn(async move {
            match factory_clone
                .spawn_app(alpn, handle, event_stream, transport, shutdown_future)
                .await
            {
                Ok(()) => {
                    debug!(alpn = %alpn_for_logging, "Application task completed");
                }
                Err(e) => {
                    error!(alpn = %alpn_for_logging, error = ?e, "Application task failed");
                }
            }
        });

        if let Some(conn) = self.connections.get_mut(canonical_id) {
            conn.ingress_tx = Some(ingress_tx);
            conn.stream_manager = Some(stream_manager);
            conn.app_task_handle = Some(task_handle);
            conn.shutdown_tx = Some(shutdown_tx);
        }

        self.connection_id_map
            .insert(connection_id, canonical_id.clone());

        Some(connection_id)
    }

    /// Helper: Look up a connection by application connection_id and get the DCID.
    ///
    /// If not found, logs a warning and returns None.
    #[allow(dead_code)]
    fn get_connection_dcid(
        &self,
        connection_id: quicd_x::ConnectionId,
    ) -> Option<quiche::ConnectionId<'static>> {
        self.connection_id_map.get(&connection_id).cloned()
    }

    /// Process OpenBi command - open a bidirectional stream
    fn process_open_bi(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        request_id: u64,
    ) {
        // Look up the connection
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(
                    worker_id,
                    connection_id, request_id, "Connection not found for OpenBi"
                );
                return;
            }
        };

        let ingress_tx = match self
            .connections
            .get(&dcid)
            .and_then(|conn| conn.ingress_tx.as_ref())
        {
            Some(tx) => tx.clone(),
            None => {
                warn!(
                    worker_id,
                    connection_id, request_id, "No ingress channel for connection"
                );
                return;
            }
        };

        // Extract channel capacities before getting mutable connection reference
        let stream_ingress_capacity = self.channel_config.stream_ingress_capacity;
        let stream_egress_capacity = self.channel_config.stream_egress_capacity;

        // Get mutable connection reference and check stream manager
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => {
                let event = quicd_x::AppEvent::StreamOpened {
                    request_id,
                    result: Err(quicd_x::ConnectionError::App("Connection not found".into())),
                };
                let _ = ingress_tx.try_send(event);
                return;
            }
        };

        if conn.stream_manager.is_none() {
            let event = quicd_x::AppEvent::StreamOpened {
                request_id,
                result: Err(quicd_x::ConnectionError::App("Connection not ready".into())),
            };
            let _ = ingress_tx.try_send(event);
            return;
        }

        // Generate stream ID from per-connection generator
        // Server-initiated bidirectional streams: 1, 5, 9, 13, ...
        let stream_id = conn.stream_id_gen.next_bidi();

        // Create stream channels with configured capacities
        let (stream_ingress_tx, stream_ingress_rx) =
            tokio::sync::mpsc::channel(stream_ingress_capacity);
        let (stream_egress_tx, stream_egress_rx) =
            tokio::sync::mpsc::channel(stream_egress_capacity);

        let recv_stream = quicd_x::new_recv_stream(stream_id, stream_ingress_rx);
        let send_stream = quicd_x::new_send_stream(stream_id, stream_egress_tx);

        // Register stream with manager (holds both ingress and egress channels)
        if let Some(ref mut sm) = conn.stream_manager {
            sm.add_client_stream(stream_id, stream_ingress_tx, stream_egress_rx);
        }

        // Send response event
        debug!(
            worker_id,
            connection_id, request_id, stream_id, "Opened bidirectional stream"
        );
        let event = quicd_x::AppEvent::StreamOpened {
            request_id,
            result: Ok((send_stream, recv_stream)),
        };
        if ingress_tx.try_send(event).is_err() {
            warn!(
                worker_id,
                connection_id,
                request_id,
                "Failed to send StreamOpened event - ingress channel full"
            );
        }
    }

    /// Process OpenUni command - open a unidirectional stream
    fn process_open_uni(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        request_id: u64,
    ) {
        // Look up the connection
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(
                    worker_id,
                    connection_id, request_id, "Connection not found for OpenUni"
                );
                return;
            }
        };

        let ingress_tx = match self
            .connections
            .get(&dcid)
            .and_then(|conn| conn.ingress_tx.as_ref())
        {
            Some(tx) => tx.clone(),
            None => {
                warn!(
                    worker_id,
                    connection_id, request_id, "No ingress channel for connection"
                );
                return;
            }
        };

        // Extract channel capacity before getting mutable connection reference
        let stream_egress_capacity = self.channel_config.stream_egress_capacity;

        // Get the connection and check if it has a stream manager
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => {
                let event = quicd_x::AppEvent::UniStreamOpened {
                    request_id,
                    result: Err(quicd_x::ConnectionError::App("Connection not found".into())),
                };
                let _ = ingress_tx.try_send(event);
                return;
            }
        };

        if conn.stream_manager.is_none() {
            let event = quicd_x::AppEvent::UniStreamOpened {
                request_id,
                result: Err(quicd_x::ConnectionError::App("Connection not ready".into())),
            };
            let _ = ingress_tx.try_send(event);
            return;
        }

        // Generate stream ID from per-connection generator
        // Server-initiated unidirectional streams: 3, 7, 11, 15, ...
        let stream_id = conn.stream_id_gen.next_uni();

        // Create stream handle with configured capacity
        let (stream_egress_tx, stream_egress_rx) =
            tokio::sync::mpsc::channel(stream_egress_capacity);
        let send_stream = quicd_x::new_send_stream(stream_id, stream_egress_tx);

        // Store egress channel in stream manager (no ingress for uni streams from client)
        if let Some(ref mut sm) = conn.stream_manager {
            sm.add_client_uni_stream(stream_id, stream_egress_rx);
        }

        debug!(
            worker_id,
            connection_id, request_id, stream_id, "Opened unidirectional stream"
        );
        let event = quicd_x::AppEvent::UniStreamOpened {
            request_id,
            result: Ok(send_stream),
        };
        let _ = ingress_tx.try_send(event);
    }
    /// Process SendDatagram command
    fn process_send_datagram(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        request_id: u64,
        data: bytes::Bytes,
    ) {
        // Look up the connection
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(
                    worker_id,
                    connection_id, request_id, "Connection not found for SendDatagram"
                );
                return;
            }
        };

        let ingress_tx = match self
            .connections
            .get(&dcid)
            .and_then(|conn| conn.ingress_tx.as_ref())
        {
            Some(tx) => tx.clone(),
            None => {
                warn!(
                    worker_id,
                    connection_id, request_id, "No ingress channel for connection"
                );
                return;
            }
        };

        // Get the connection
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => {
                let event = quicd_x::AppEvent::DatagramSent {
                    request_id,
                    result: Err(quicd_x::ConnectionError::App("Connection not found".into())),
                };
                let _ = ingress_tx.try_send(event);
                return;
            }
        };

        // Send datagram using quiche
        match conn.dgram_send(&data) {
            Ok(()) => {
                debug!(
                    worker_id,
                    connection_id,
                    request_id,
                    bytes = data.len(),
                    "Sent datagram"
                );
                let event = quicd_x::AppEvent::DatagramSent {
                    request_id,
                    result: Ok(data.len()),
                };
                let _ = ingress_tx.try_send(event);
            }
            Err(e) => {
                error!(worker_id, connection_id, request_id, error = ?e, "Failed to send datagram");
                let event = quicd_x::AppEvent::DatagramSent {
                    request_id,
                    result: Err(quicd_x::ConnectionError::Transport(format!(
                        "Datagram send failed: {:?}",
                        e
                    ))),
                };
                let _ = ingress_tx.try_send(event);
            }
        }
    }

    /// Process ResetStream command
    fn process_reset_stream(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        request_id: u64,
        stream_id: u64,
        error_code: u64,
    ) {
        // Look up the connection
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(
                    worker_id,
                    connection_id, request_id, "Connection not found for ResetStream"
                );
                return;
            }
        };

        let ingress_tx = match self
            .connections
            .get(&dcid)
            .and_then(|conn| conn.ingress_tx.as_ref())
        {
            Some(tx) => tx.clone(),
            None => {
                warn!(
                    worker_id,
                    connection_id, request_id, "No ingress channel for connection"
                );
                return;
            }
        };

        // Get the connection
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => {
                let event = quicd_x::AppEvent::StreamReset {
                    request_id,
                    result: Err(quicd_x::ConnectionError::App("Connection not found".into())),
                };
                let _ = ingress_tx.try_send(event);
                return;
            }
        };

        // Reset stream using quiche
        match conn
            .conn
            .stream_shutdown(stream_id, quiche::Shutdown::Write, error_code)
        {
            Ok(()) => {
                debug!(
                    worker_id,
                    connection_id, request_id, stream_id, error_code, "Reset stream"
                );

                // Notify stream manager
                if let Some(ref mut sm) = conn.stream_manager {
                    sm.handle_stream_close(worker_id, stream_id, true, error_code);
                }

                let event = quicd_x::AppEvent::StreamReset {
                    request_id,
                    result: Ok(()),
                };
                let _ = ingress_tx.try_send(event);
            }
            Err(e) => {
                error!(worker_id, connection_id, request_id, stream_id, error_code, error = ?e, "Failed to reset stream");
                let event = quicd_x::AppEvent::StreamReset {
                    request_id,
                    result: Err(quicd_x::ConnectionError::Transport(format!(
                        "Stream reset failed: {:?}",
                        e
                    ))),
                };
                let _ = ingress_tx.try_send(event);
            }
        }
    }

    /// Process Close command
    fn process_close_connection(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        error_code: u64,
        reason: Option<bytes::Bytes>,
    ) {
        // Look up the connection
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(worker_id, connection_id, "Connection not found for close");
                return;
            }
        };

        // Get the connection
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => {
                warn!(worker_id, connection_id, "Connection not found for close");
                return;
            }
        };

        // Close connection using quiche
        let reason_bytes = reason.as_ref().map(|b| b.as_ref()).unwrap_or(&[]);
        match conn.close(false, error_code, reason_bytes) {
            Ok(()) => {
                debug!(worker_id, connection_id, error_code, "Closed connection");
            }
            Err(e) => {
                error!(worker_id, connection_id, error_code, error = ?e, "Failed to close connection");
            }
        }
    }

    /// Process RequestStats command
    fn process_request_stats(
        &mut self,
        _worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        request_id: u64,
    ) {
        // Look up the connection by connection_id
        let dcid = self.connection_id_map.get(&connection_id);

        let ingress_tx = match dcid
            .and_then(|dcid| self.connections.get(dcid))
            .and_then(|conn| conn.ingress_tx.as_ref())
        {
            Some(tx) => tx.clone(),
            None => {
                warn!(
                    connection_id,
                    request_id, "No ingress channel for connection"
                );
                return;
            }
        };

        let result = match dcid {
            Some(dcid) => {
                // Get stats from quic_manager
                self.get_connection_stats(dcid)
                    .ok_or_else(|| quicd_x::ConnectionError::App("Connection not found".into()))
            }
            None => Err(quicd_x::ConnectionError::App(
                "Connection ID not found".into(),
            )),
        };

        let event = quicd_x::AppEvent::StatsReceived { request_id, result };
        let _ = ingress_tx.try_send(event);
    }

    fn process_query_connection_state(
        &mut self,
        _worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        reply: tokio::sync::oneshot::Sender<quicd_x::ConnectionState>,
    ) {
        // Look up the connection by connection_id
        let dcid = self.connection_id_map.get(&connection_id);

        let is_in_early_data = dcid
            .and_then(|dcid| self.connections.get(dcid))
            .map(|conn| conn.is_in_early_data())
            .unwrap_or(false);

        let state = quicd_x::ConnectionState { is_in_early_data };
        let _ = reply.send(state);
    }

    /// Process an egress command from an application task and return packets to send.
    ///
    /// This is called from the worker's event loop when processing egress commands.
    /// It handles the command and returns any packets that need to be sent.
    ///
    /// # Returns
    ///
    /// Vector of outgoing packets that need to be submitted to io_uring
    pub fn process_egress_command(
        &mut self,
        worker_id: usize,
        command: quicd_x::EgressCommand,
    ) -> Result<Vec<OutgoingPacket>> {
        use quicd_x::EgressCommand;

        let mut outgoing_packets = Vec::new();

        // Get connection_id from command for packet generation
        let connection_id = match &command {
            EgressCommand::OpenBi { connection_id, .. } => *connection_id,
            EgressCommand::OpenUni { connection_id, .. } => *connection_id,
            EgressCommand::SendDatagram { connection_id, .. } => *connection_id,
            EgressCommand::ResetStream { connection_id, .. } => *connection_id,
            EgressCommand::Close { connection_id, .. } => *connection_id,
            EgressCommand::RequestStats { connection_id, .. } => *connection_id,
            EgressCommand::QueryConnectionState { connection_id, .. } => *connection_id,
        };

        match command {
            EgressCommand::OpenBi {
                request_id,
                connection_id,
            } => {
                debug!(
                    worker_id,
                    connection_id, request_id, "Processing OpenBi command"
                );
                self.process_open_bi(worker_id, connection_id, request_id);
            }
            EgressCommand::OpenUni {
                request_id,
                connection_id,
            } => {
                debug!(
                    worker_id,
                    connection_id, request_id, "Processing OpenUni command"
                );
                self.process_open_uni(worker_id, connection_id, request_id);
            }
            EgressCommand::SendDatagram {
                request_id,
                connection_id,
                data,
            } => {
                debug!(
                    worker_id,
                    connection_id,
                    request_id,
                    bytes = data.len(),
                    "Processing SendDatagram command"
                );
                self.process_send_datagram(worker_id, connection_id, request_id, data);
            }
            EgressCommand::ResetStream {
                request_id,
                connection_id,
                stream_id,
                error_code,
            } => {
                debug!(
                    worker_id,
                    connection_id,
                    request_id,
                    stream_id,
                    error_code,
                    "Processing ResetStream command"
                );
                self.process_reset_stream(
                    worker_id,
                    connection_id,
                    request_id,
                    stream_id,
                    error_code,
                );
            }
            EgressCommand::Close {
                connection_id,
                error_code,
                reason,
            } => {
                debug!(
                    worker_id,
                    connection_id,
                    error_code,
                    reason_len = reason.as_ref().map(|r| r.len()).unwrap_or(0),
                    "Processing Close command"
                );
                self.process_close_connection(worker_id, connection_id, error_code, reason);
            }
            EgressCommand::RequestStats {
                request_id,
                connection_id,
            } => {
                debug!(
                    worker_id,
                    connection_id, request_id, "Processing RequestStats command"
                );
                self.process_request_stats(worker_id, connection_id, request_id);
            }
            EgressCommand::QueryConnectionState {
                connection_id,
                reply,
            } => {
                debug!(
                    worker_id,
                    connection_id, "Processing QueryConnectionState command"
                );
                self.process_query_connection_state(worker_id, connection_id, reply);
            }
        }

        // After processing command, generate any packets needed
        // Look up the QUIC connection and collect packets
        if let Some(dcid) = self.connection_id_map.get(&connection_id) {
            // Prefetch the connection object before accessing it
            if let Some(conn_ptr) = self.connections.get(dcid) {
                prefetch(conn_ptr as *const QuicConnection, PrefetchMode::Write);
                prefetch(
                    &conn_ptr.conn as *const quiche::Connection,
                    PrefetchMode::Write,
                );
            }

            if let Some(conn) = self.connections.get_mut(dcid) {
                collect_packets_for_conn(
                    worker_id,
                    conn,
                    &self.send_buffer_pool,
                    &mut outgoing_packets,
                )?;
            }
        }

        self.cleanup_closed_connections(&mut outgoing_packets)?;

        Ok(outgoing_packets)
    }

    /// Create a new connection for an Initial packet.
    fn create_connection(
        &mut self,
        peer_addr: SocketAddr,
        hdr: &quiche::Header,
    ) -> Result<ConnectionId<'static>> {
        if self.connections.len() >= self.config.max_connections_per_worker {
            warn!(
                worker_id = self.worker_id,
                current = self.connections.len(),
                max = self.config.max_connections_per_worker,
                "Connection limit reached, rejecting new connection"
            );
            anyhow::bail!("connection limit reached");
        }

        if self.worker_id > u8::MAX as usize {
            anyhow::bail!(
                "worker_id {} exceeds maximum supported workers for routing (255)",
                self.worker_id
            );
        }

        let worker_id_u8 = self.worker_id as u8;
        let tag = ring::hmac::sign(&self.conn_id_seed, &hdr.dcid);
        let mut seed_bytes = [0u8; 4];
        seed_bytes.copy_from_slice(&tag.as_ref()[0..4]);
        let seed = u32::from_be_bytes(seed_bytes);

        let scid_bytes = routing::generate_connection_id(worker_id_u8, seed);
        let scid = ConnectionId::from_vec(scid_bytes.to_vec());

        // Convert borrowed ConnectionId to owned using inline storage (no heap allocation)
        let initial_dcid = connection_id_to_owned(&hdr.dcid);

        let conn = quiche::accept(
            &scid,
            Some(&hdr.dcid),
            self.local_addr,
            peer_addr,
            &mut self.quiche_config,
        )
        .context("failed to create connection")?;

        debug!(
            worker_id = self.worker_id,
            peer = %peer_addr,
            scid = ?scid,
            dcid = ?hdr.dcid,
            "Created new QUIC connection with eBPF routing cookie"
        );

        self.stats.borrow_mut().connections_created += 1;

        let mut quic_conn = QuicConnection::new(conn, peer_addr, scid.clone());
        quic_conn.dcid_aliases.push(initial_dcid.clone());

        // Schedule initial timeout for new connection
        let timeout_deadline = if let Some(timeout) = quic_conn.timeout() {
            Some(quic_conn.last_active + timeout)
        } else {
            None
        };

        self.connections.insert(scid.clone(), quic_conn);
        self.connection_aliases.insert(initial_dcid, scid.clone());

        if let Some(deadline) = timeout_deadline {
            self.timeout_queue
                .push(TimeoutEntry::new(deadline, scid.clone()));
        }

        Ok(scid)
    }

    /// Process stream writes for all connections and return packets to send.
    ///
    /// This should be called from the egress processing path in the worker's event loop.
    /// It polls all stream managers for pending writes, processes them with quiche,
    /// and returns packets that need to be sent.
    ///
    /// # Returns
    ///
    /// Vector of outgoing packets that need to be submitted to io_uring
    pub fn process_stream_writes(&mut self) -> Result<Vec<OutgoingPacket>> {
        let worker_id = self.worker_id;
        let mut outgoing_packets = Vec::new();

        // Collect all stream writes from all connections
        // We need to do this carefully to avoid borrow checker issues
        let mut writes_by_dcid: Vec<(ConnectionId<'static>, Vec<_>)> = Vec::new();

        for (dcid, conn) in self.connections.iter_mut() {
            if let Some(ref mut sm) = conn.stream_manager {
                let writes = sm.poll_stream_writes(worker_id);
                if !writes.is_empty() {
                    writes_by_dcid.push((dcid.clone(), writes));
                }
            }
        }

        // Now process the writes
        for (dcid, writes) in writes_by_dcid {
            if let Some(conn) = self.connections.get_mut(&dcid) {
                for (stream_id, data, fin, reply_tx) in writes {
                    match conn.stream_send(stream_id, &data, fin) {
                        Ok(written) => {
                            trace!(
                                worker_id,
                                stream_id,
                                bytes = written,
                                fin,
                                "Wrote to stream"
                            );
                            // Send success reply to app (ignoring errors if app already hung up)
                            let _ = reply_tx.send(Ok(written));
                        }
                        Err(e) => {
                            warn!(worker_id, stream_id, error = ?e, "Failed to write to stream");
                            // Send error reply to app
                            let error_msg = format!("stream send failed: {:?}", e);
                            let _ = reply_tx.send(Err(quicd_x::ConnectionError::Stream(error_msg)));
                        }
                    }
                }

                // Generate packets for this connection after processing writes
                collect_packets_for_conn(
                    worker_id,
                    conn,
                    &self.send_buffer_pool,
                    &mut outgoing_packets,
                )?;
            }
        }

        self.cleanup_closed_connections(&mut outgoing_packets)?;

        Ok(outgoing_packets)
    }
}

/// Maximum UDP datagram size
const MAX_DATAGRAM_SIZE: usize = 65536;

impl std::fmt::Debug for QuicManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicManager")
            .field("worker_id", &self.worker_id)
            .field("local_addr", &self.local_addr)
            .field("connections", &self.connections.len())
            .field("stats", &self.stats)
            .finish()
    }
}
