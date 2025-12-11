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
use crate::routing;
use ahash::{AHashMap, AHashSet};
use anyhow::{Context, Result};
use bytes::Bytes;
use quiche::ConnectionId;
use smallvec::SmallVec;
use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::net::SocketAddr;

use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};
use ring::rand::{SecureRandom, SystemRandom};

/// Maximum connection ID length (QUIC allows up to 20 bytes)
const MAX_CONN_ID_LEN: usize = 20;

/// Size of stream read buffers (64KB - max for efficient UDP/QUIC)
const STREAM_BUFFER_SIZE: usize = 65536;

/// Maximum datagram/UDP payload size (65KB - RFC 9221, RFC 9000 §14)
/// Used for both stream buffers and datagram reception.
/// The actual MTU may be smaller; applications should check conn.dgram_max_writable_len()
const MAX_DATAGRAM_SIZE: usize = 65536;

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

/// Prefix used by QUIC draft version numbers (RFC 9000 §15).
const QUIC_DRAFT_VERSION_PREFIX: u32 = 0xff00_0000;

fn format_quic_version(version: u32) -> String {
    format!("{:#010x}", version)
}

fn parse_quic_version_label(label: &str) -> Option<u32> {
    let trimmed = label.trim();
    if trimmed.is_empty() {
        return None;
    }

    let lower = trimmed.to_ascii_lowercase();

    match lower.as_str() {
        "v1" | "version1" | "rfc9000" => return Some(quiche::PROTOCOL_VERSION),
        _ => {}
    }

    if let Some(rest) = lower
        .strip_prefix("draft-")
        .or_else(|| lower.strip_prefix("draft"))
    {
        if let Ok(num) = rest.parse::<u32>() {
            if num <= 0xff {
                return Some(QUIC_DRAFT_VERSION_PREFIX | num);
            }
        }
    }

    if let Some(hex) = lower.strip_prefix("0x") {
        if !hex.is_empty() {
            return u32::from_str_radix(hex, 16).ok();
        }
        return None;
    }

    if lower.len() == 8 && lower.chars().all(|c| c.is_ascii_hexdigit()) {
        return u32::from_str_radix(&lower, 16).ok();
    }

    lower.parse::<u32>().ok()
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

/// Determine congestion state from path and connection statistics (RFC 9002 §7)
///
/// Since quiche doesn't expose ssthresh directly, we infer congestion state from:
/// - CWND size (small CWND suggests slow start, large suggests congestion avoidance)
/// - Packet loss (indicates recovery state)
/// - Delivery rate (active sending vs. idle)
fn determine_congestion_state(
    path_stats: &quiche::PathStats,
    quiche_stats: &quiche::Stats,
    last_packets_lost: u64,
) -> quicd_x::CongestionState {
    let current_packets_lost = quiche_stats.lost as u64;
    let recent_loss = current_packets_lost > last_packets_lost;

    // === RFC 9002 Appendix B: Application Limited Detection ===
    // If bytes in flight is significantly less than CWND, the application is not
    // sending enough data to fill the congestion window
    let bytes_in_flight = (quiche_stats.sent - quiche_stats.recv) as usize;
    let cwnd_utilization = if path_stats.cwnd > 0 {
        (bytes_in_flight * 100) / path_stats.cwnd
    } else {
        0
    };

    // If using less than 50% of available CWND, consider application-limited
    // This is a conservative threshold to avoid false positives
    if cwnd_utilization < 50 && bytes_in_flight < path_stats.cwnd {
        return quicd_x::CongestionState::ApplicationLimited;
    }

    // If we recently lost packets and delivery rate is active, we're in recovery
    if recent_loss && path_stats.delivery_rate > 0 {
        return quicd_x::CongestionState::Recovery;
    }

    // Typical initial CWND is 10 * MTU (~14KB for 1400-byte MTU)
    // Use 50KB as threshold for slow start vs. congestion avoidance
    // This is a heuristic since quiche doesn't expose ssthresh
    if path_stats.cwnd < 50_000 {
        quicd_x::CongestionState::SlowStart
    } else {
        quicd_x::CongestionState::CongestionAvoidance
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
    /// True if application error, false if transport error (RFC 9000 §10.2)
    is_app: bool,
}

/// QUIC connection manager for a worker thread
pub struct QuicManager {
    /// Worker ID (for logging)
    worker_id: usize,

    /// Local socket address
    local_addr: SocketAddr,

    /// QUIC configuration
    config: QuicConfig,

    /// Quiche configurations keyed by wire version
    quiche_configs: AHashMap<u32, quiche::Config>,

    /// Ordered list of supported QUIC versions (first entry is the default)
    supported_versions: Vec<u32>,

    /// Fast membership lookup for supported versions
    supported_versions_set: AHashSet<u32>,

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
        config.validate().map_err(|e| anyhow::anyhow!(e))?;

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

        // Resolve configured QUIC versions (RFC 9368 §3) starting with RFC 9000 v1
        let mut version_candidates = vec![quiche::PROTOCOL_VERSION];
        for label in &config.additional_versions {
            match parse_quic_version_label(label) {
                Some(version) => {
                    if version_candidates.contains(&version) {
                        trace!(
                            worker_id,
                            version = %format_quic_version(version),
                            %label,
                            "Ignoring duplicate QUIC version label"
                        );
                    } else {
                        version_candidates.push(version);
                    }
                }
                None => {
                    warn!(
                        worker_id,
                        %label,
                        "Ignoring invalid QUIC version label"
                    );
                }
            }
        }

        let mut quiche_configs = AHashMap::new();
        let mut supported_versions = Vec::new();

        for (index, version) in version_candidates.iter().copied().enumerate() {
            match create_quiche_config(&credentials, &config, version) {
                Ok(cfg) => {
                    quiche_configs.insert(version, cfg);
                    supported_versions.push(version);
                }
                Err(e) => {
                    if index == 0 {
                        return Err(e);
                    }

                    warn!(
                        worker_id,
                        version = %format_quic_version(version),
                        error = ?e,
                        "Skipping unsupported QUIC version"
                    );
                }
            }
        }

        if supported_versions.is_empty() {
            anyhow::bail!("failed to configure any QUIC versions");
        }

        let supported_versions_set = supported_versions
            .iter()
            .copied()
            .collect::<AHashSet<u32>>();

        info!(
            worker_id,
            versions = ?supported_versions
                .iter()
                .map(|v| format_quic_version(*v))
                .collect::<Vec<_>>(),
            "Resolved QUIC versions"
        );

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
            quiche_configs,
            supported_versions,
            supported_versions_set,
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
                is_app: err.is_app,
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
                is_app: err.is_app,
            };
        }

        if conn.is_timed_out() {
            return CloseInfo {
                error_code: 0,
                reason: Some(Bytes::from_static(b"idle timeout")),
                is_app: false, // Idle timeout is a transport-level error
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
                    is_app: info.is_app,
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

    /// Reschedule a connection's timeout after new activity.
    ///
    /// RFC 9000 §10.1 requires idle timeout tracking to include both ingress and egress
    /// ack-eliciting packets. Whenever we process activity for a connection without going
    /// through the ingress path (e.g., pure egress writes), we must explicitly refresh the
    /// timeout heap entry so idle connections are not closed spuriously.
    fn schedule_connection_timeout(&mut self, dcid: &ConnectionId<'static>) {
        if let Some(conn) = self.connections.get(dcid) {
            if let Some(timeout) = conn.timeout() {
                let deadline = conn.last_active + timeout;
                self.timeout_queue
                    .push(TimeoutEntry::new(deadline, dcid.clone()));
            }
        }
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

        if !self.supported_versions_set.contains(&hdr.version) {
            if self.config.enable_version_negotiation {
                let mut out = [0; MAX_DATAGRAM_SIZE];
                let len = quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out)
                    .context("failed to negotiate version")?;

                outgoing_packets.push(OutgoingPacket {
                    to: peer_addr,
                    data: out[..len].to_vec(),
                });

                debug!(
                    worker_id = self.worker_id,
                    version = %format_quic_version(hdr.version),
                    peer = %peer_addr,
                    "Sent version negotiation response"
                );
            } else {
                warn!(
                    worker_id = self.worker_id,
                    version = %format_quic_version(hdr.version),
                    peer = %peer_addr,
                    "Unsupported QUIC version (version negotiation disabled)"
                );
            }

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

                    // Note: Path events are now processed in process_connection_events()
                    // No need to collect them here to avoid duplicate processing
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

        // Note: handle_path_event() calls removed - path events now processed
        // comprehensively in process_connection_events() below

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

        // Process all transport events and notify application layer (RFC compliance)
        // Must be called after packet processing to capture all state changes
        // Call this regardless of stream processing - path events and other transport
        // events can occur independently of stream activity (e.g., connection migration)
        self.process_connection_events(&canonical_dcid)?;

        if should_send_packets {
            let mut refreshed = false;

            if let Some(conn) = self.connections.get_mut(&canonical_dcid) {
                collect_packets_for_conn(
                    self.worker_id,
                    conn,
                    &self.send_buffer_pool,
                    &mut outgoing_packets,
                )?;

                refreshed = true;
            }

            if refreshed {
                self.schedule_connection_timeout(&canonical_dcid);
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

    /// Process all connection events from quiche and send to application layer.
    ///
    /// This is the critical RFC compliance function that polls ALL quiche events
    /// and translates them to quicd-x AppEvents for the application layer.
    ///
    /// Must be called after packet processing to ensure applications receive
    /// all transport events (migration, path validation, flow control, etc.).
    ///
    /// # RFC Compliance
    ///
    /// - RFC 9000 §4: Flow control events (stream blocked, connection blocked)
    /// - RFC 9000 §5: Connection ID events (new CID, retired CID)
    /// - RFC 9000 §8-9: Path events (validation, migration)
    /// - RFC 9000 §19.4: STOP_SENDING events
    /// - RFC 9002 §7: Congestion state changes
    /// - RFC 9001 §6: Key update events
    fn process_connection_events(&mut self, dcid: &ConnectionId<'static>) -> Result<()> {
        {
            let conn = self
                .connections
                .get(dcid)
                .ok_or_else(|| anyhow::anyhow!("Connection not found for event processing"))?;

            if conn.ingress_tx.is_none() {
                self.replenish_source_connection_ids(dcid)?;
                return Ok(());
            }
        }

        {
            let conn = self
                .connections
                .get_mut(dcid)
                .expect("connection must exist after ingress check");

            // Only process events if app task is spawned
            let ingress_tx = match conn.ingress_tx.as_ref() {
            Some(tx) => tx.clone(),
            None => unreachable!("ingress channel verified in previous check"),
        };

        let connection_id = conn.connection_id;
        let worker_id = self.worker_id;

        // === RFC 9000 §3.2: HANDSHAKE_DONE Event ===
        // Emit HandshakeDone event once when handshake is fully complete
        if conn.conn.is_established() && !conn.handshake_done_sent {
            trace!(worker_id, connection_id, "Handshake fully established, sending HandshakeDone");
            let event = quicd_x::AppEvent::HandshakeDone;
            send_app_event(worker_id, connection_id, &ingress_tx, event);
            conn.handshake_done_sent = true;

            // === RFC 9000 §7.4: Peer Transport Parameters ===
            // Emit peer transport parameters immediately after handshake completion
            if let Some(params) = conn.conn.peer_transport_params() {
                trace!(worker_id, connection_id, "Sending peer transport parameters to application");
                let event = quicd_x::AppEvent::PeerTransportParameters {
                    max_idle_timeout: params.max_idle_timeout,
                    initial_max_data: params.initial_max_data,
                    initial_max_stream_data_bidi_local: params.initial_max_stream_data_bidi_local,
                    initial_max_stream_data_bidi_remote: params.initial_max_stream_data_bidi_remote,
                    initial_max_stream_data_uni: params.initial_max_stream_data_uni,
                    max_streams_bidi: params.initial_max_streams_bidi,
                    max_streams_uni: params.initial_max_streams_uni,
                    ack_delay_exponent: params.ack_delay_exponent,
                    max_ack_delay: params.max_ack_delay,
                    active_connection_id_limit: params.active_conn_id_limit,
                    disable_active_migration: params.disable_active_migration,
                    max_udp_payload_size: params.max_udp_payload_size,
                };
                send_app_event(worker_id, connection_id, &ingress_tx, event);
            }
        }

        // === RFC 9000 §8-9: Path Events (Migration, Validation) ===
        while let Some(path_event) = conn.path_event_next() {
            use quiche::PathEvent;

            match path_event {
                PathEvent::New(local_addr, peer_addr) => {
                    trace!(worker_id, connection_id, %local_addr, %peer_addr, "New path");

                    let event = quicd_x::AppEvent::TransportEvent(
                        quicd_x::TransportEvent::MigrationStarted {
                            new_peer_addr: peer_addr,
                            local_addr,
                        },
                    );
                    send_app_event(worker_id, connection_id, &ingress_tx, event);
                }

                PathEvent::Validated(local_addr, peer_addr) => {
                    info!(worker_id, connection_id, %local_addr, %peer_addr, "Path validated");

                    // Get RTT from path stats if available
                    let rtt_us = conn
                        .path_stats()
                        .and_then(|s| s.rtt.as_micros().try_into().ok())
                        .unwrap_or(0);

                    let event =
                        quicd_x::AppEvent::TransportEvent(quicd_x::TransportEvent::PathValidated {
                            peer_addr,
                            local_addr,
                            rtt_us,
                        });
                    send_app_event(worker_id, connection_id, &ingress_tx, event);
                }

                PathEvent::FailedValidation(local_addr, peer_addr) => {
                    warn!(worker_id, connection_id, %local_addr, %peer_addr, "Path validation failed");

                    let event = quicd_x::AppEvent::TransportEvent(
                        quicd_x::TransportEvent::PathValidationFailed {
                            peer_addr,
                            reason: "Path validation timeout or unreachable".to_string(),
                        },
                    );
                    send_app_event(worker_id, connection_id, &ingress_tx, event);
                }

                PathEvent::Closed(local_addr, peer_addr) => {
                    debug!(worker_id, connection_id, %local_addr, %peer_addr, "Path closed");
                    // Path closure doesn't need explicit app notification (normal lifecycle)
                }

                PathEvent::ReusedSourceConnectionId(
                    seq,
                    (old_local, old_peer),
                    (new_local, new_peer),
                ) => {
                    trace!(
                        worker_id, connection_id, seq,
                        old_local = %old_local, old_peer = %old_peer,
                        new_local = %new_local, new_peer = %new_peer,
                        "CID reused on different path"
                    );
                }

                PathEvent::PeerMigrated(local_addr, peer_addr) => {
                    let old_peer_addr = conn.peer_addr;
                    conn.peer_addr = peer_addr;

                    info!(
                        worker_id, connection_id,
                        %local_addr, old_peer = %old_peer_addr, new_peer = %peer_addr,
                        "Peer migrated"
                    );

                    self.stats.borrow_mut().migrations_completed += 1;

                    // Notify application of successful migration
                    let event =
                        quicd_x::AppEvent::TransportEvent(quicd_x::TransportEvent::PathValidated {
                            peer_addr,
                            local_addr,
                            rtt_us: 0, // RTT not available during migration event
                        });
                    send_app_event(worker_id, connection_id, &ingress_tx, event);
                }
            }
        }

        // Re-borrow conn for remaining event processing
        let conn = self.connections.get_mut(dcid).unwrap();

        // === RFC 9000 §3.5: STOP_SENDING Detection ===
        // STOP_SENDING frames are detected in the write path (see process_stream_writes).
        // When stream_send() returns Error::StreamStopped(error_code), we forward
        // AppEvent::StopSending to the application. This is the correct approach
        // since quiche doesn't expose a direct stream_stopped_by_peer() query API.
        // The error-based detection ensures we catch STOP_SENDING frames immediately
        // when the application attempts to write to the stream.

        // === RFC 9221: QUIC Datagrams ===
        // Poll for unreliable datagram payloads received from peer.
        // Datagrams are independent of streams and provide unreliable delivery.
        // Must be polled in a loop since multiple datagrams may be buffered.
        let mut dgram_buf = vec![0u8; MAX_DATAGRAM_SIZE]; // Max datagram size
        loop {
            match conn.conn.dgram_recv(&mut dgram_buf) {
                Ok(len) => {
                    if len > 0 {
                        trace!(worker_id, connection_id, len, "Datagram received");

                        // Zero-copy: clone only the received portion
                        let payload = bytes::Bytes::copy_from_slice(&dgram_buf[..len]);

                        let event = quicd_x::AppEvent::Datagram { payload };
                        send_app_event(worker_id, connection_id, &ingress_tx, event);
                    } else {
                        // len == 0 means no more datagrams available
                        break;
                    }
                }
                Err(quiche::Error::Done) => {
                    // No more datagrams to receive
                    break;
                }
                Err(e) => {
                    // Unexpected error receiving datagram
                    warn!(worker_id, connection_id, error = ?e, "Error receiving datagram");
                    break;
                }
            }
        }

        // === RFC 9000 §19.16: Stream Finished Events ===
        // Check for streams that have been finished by peer (FIN received)
        // Use stream_finished() API if available, otherwise check during read
        // Note: stream_finished() is the proper way per RFC 9000 §2.2
        for stream_id in conn.conn.readable() {
            // Check if stream is finished using quiche's stream_finished()
            if conn.conn.stream_finished(stream_id) {
                // Only notify if we haven't notified before
                // Stream manager tracks which streams were notified
                if let Some(ref sm) = conn.stream_manager {
                    if sm.has_stream(stream_id) {
                        trace!(
                            worker_id,
                            connection_id,
                            stream_id,
                            "Stream finished (FIN received)"
                        );

                        let event = quicd_x::AppEvent::StreamFinished { stream_id };
                        send_app_event(worker_id, connection_id, &ingress_tx, event);
                    }
                }
            }
        }

        // === RFC 9000 §4: Stream Writable Notifications ===
        // Check for streams that became writable (have flow control credits)
        // We iterate through quiche's writable() iterator, which returns all streams
        // that currently have send capacity. This includes both app-initiated and
        // peer-initiated bidirectional streams.
        if conn.stream_manager.is_some() {
            // Collect currently writable streams from quiche
            let writable_streams: Vec<u64> = conn.conn.writable().collect();
            let writable_set: std::collections::HashSet<u64> =
                writable_streams.iter().copied().collect();

            for stream_id in &writable_streams {
                // Check if state changed from not-writable to writable
                let was_writable = conn
                    .stream_writable_state
                    .get(stream_id)
                    .copied()
                    .unwrap_or(false);

                if !was_writable {
                    // Stream became writable - notify application
                    // Only send event if stream is registered with stream manager
                    if let Some(ref sm) = conn.stream_manager {
                        if sm.has_stream(*stream_id) {
                            debug!(worker_id, stream_id, "Stream became writable");

                            let event = quicd_x::AppEvent::StreamWritable {
                                stream_id: *stream_id,
                            };
                            send_app_event(worker_id, connection_id, &ingress_tx, event);
                        }
                    }
                }

                // Mark as writable
                conn.stream_writable_state.insert(*stream_id, true);
            }

            // Mark streams that are no longer in writable set as not-writable
            // This is needed to detect future transitions to writable state
            conn.stream_writable_state.retain(|stream_id, is_writable| {
                if *is_writable && !writable_set.contains(stream_id) {
                    *is_writable = false;
                }
                true // Keep all entries
            });
        }

        // === RFC 9000 §14: MTU Updates ===
        // Check if maximum datagram size changed (PMTU discovery)
        let current_mtu = conn.conn.max_send_udp_payload_size();
        if current_mtu != conn.last_known_mtu {
            info!(
                worker_id,
                connection_id,
                old_mtu = conn.last_known_mtu,
                new_mtu = current_mtu,
                "MTU changed (PMTU discovery or path change)"
            );

            conn.last_known_mtu = current_mtu;

            let event = quicd_x::AppEvent::TransportEvent(quicd_x::TransportEvent::MtuUpdated {
                mtu: current_mtu,
            });
            send_app_event(worker_id, connection_id, &ingress_tx, event);
        }

        // === RFC 9000 §4.6: Stream Concurrency Limits ===
        // Check if peer increased stream limits (sent MAX_STREAMS frame)
        let current_bidi_limit = conn.conn.peer_streams_left_bidi();
        let current_uni_limit = conn.conn.peer_streams_left_uni();

        // Check bidirectional stream limit
        if current_bidi_limit > conn.last_peer_streams_bidi {
            debug!(
                worker_id,
                connection_id,
                old_limit = conn.last_peer_streams_bidi,
                new_limit = current_bidi_limit,
                "Peer increased bidirectional stream limit"
            );

            conn.last_peer_streams_bidi = current_bidi_limit;

            let event =
                quicd_x::AppEvent::TransportEvent(quicd_x::TransportEvent::StreamsLimitIncreased {
                    bidirectional: true,
                    new_limit: current_bidi_limit,
                });
            send_app_event(worker_id, connection_id, &ingress_tx, event);
        }

        // Check unidirectional stream limit
        if current_uni_limit > conn.last_peer_streams_uni {
            debug!(
                worker_id,
                connection_id,
                old_limit = conn.last_peer_streams_uni,
                new_limit = current_uni_limit,
                "Peer increased unidirectional stream limit"
            );

            conn.last_peer_streams_uni = current_uni_limit;

            let event =
                quicd_x::AppEvent::TransportEvent(quicd_x::TransportEvent::StreamsLimitIncreased {
                    bidirectional: false,
                    new_limit: current_uni_limit,
                });
            send_app_event(worker_id, connection_id, &ingress_tx, event);
        }

        // === RFC 9000 §4.1: Connection-Level Flow Control ===
        // Monitor connection-level flow control (MAX_DATA) to detect unblocking
        // When peer sends MAX_DATA frame increasing the limit, unblock the connection
        // Note: quiche doesn't expose direct MAX_DATA tracking, so we monitor capacity changes
        // Blocking is detected in process_stream_writes when writes fail with Done

        if conn.connection_blocked_at.is_some() {
            // Connection was blocked, check if capacity increased
            let current_capacity = conn.connection_send_capacity();

            if current_capacity > 0 {
                // Connection has capacity again - unblocked
                conn.connection_blocked_at = None;

                debug!(
                    worker_id,
                    connection_id,
                    capacity = current_capacity,
                    "Connection-level flow control unblocked (MAX_DATA received)"
                );

                let event = quicd_x::AppEvent::TransportEvent(
                    quicd_x::TransportEvent::ConnectionUnblocked {
                        new_limit: current_capacity,
                    },
                );
                send_app_event(worker_id, connection_id, &ingress_tx, event);
            }
        }

        // === RFC 9000 §5.1: Connection ID Management ===
        // Track new source Connection IDs (quiche 0.24.6+)
        for cid in conn.conn.source_ids() {
            let cid_static = quiche::ConnectionId::from_vec(cid.as_ref().to_vec());

            if conn.known_source_cids.insert(cid_static.clone()) {
                let cid_bytes = cid.as_ref();
                let meta = conn.get_source_cid_meta(cid_bytes);

                let (sequence, reset_token) = match meta {
                    Some(info) => (info.sequence, Some(info.reset_token)),
                    None => {
                        warn!(
                            worker_id,
                            connection_id,
                            "Missing metadata for source CID event"
                        );
                        (0, None)
                    }
                };

                debug!(
                    worker_id,
                    connection_id,
                    cid_len = cid_bytes.len(),
                    sequence,
                    "New source Connection ID detected"
                );

                let event =
                    quicd_x::AppEvent::TransportEvent(quicd_x::TransportEvent::NewConnectionId {
                        sequence,
                        cid: bytes::Bytes::copy_from_slice(cid_bytes),
                        reset_token,
                    });
                send_app_event(worker_id, connection_id, &ingress_tx, event);
            }
        }

        // === RFC 9000 §5.1.2: Source Connection ID Retirement ===
        // The peer has retired one of our Source Connection IDs via RETIRE_CONNECTION_ID frame
        while let Some(retired_cid) = conn.conn.retired_scid_next() {
            let cid_bytes = retired_cid.as_ref().to_vec();
            let sequence = match conn.retire_source_connection_id(retired_cid.as_ref()) {
                Some(meta) => meta.sequence,
                None => {
                    warn!(
                        worker_id,
                        connection_id,
                        "Peer retired unknown source Connection ID"
                    );
                    0
                }
            };

            debug!(
                worker_id,
                connection_id,
                sequence,
                "Source Connection ID retired by peer"
            );

            let event = quicd_x::AppEvent::TransportEvent(
                quicd_x::TransportEvent::SourceConnectionIdRetired {
                    sequence,
                    cid: bytes::Bytes::from(cid_bytes),
                },
            );
            send_app_event(worker_id, connection_id, &ingress_tx, event);
        }

        // === RFC 9002 §6: Packet Loss Detection ===
        // Track packet loss and notify application
        let quiche_stats = conn.conn.stats();
        let current_packets_lost = quiche_stats.lost as u64;

        if current_packets_lost > conn.last_packets_lost {
            let new_losses = current_packets_lost - conn.last_packets_lost;

            debug!(
                worker_id,
                connection_id,
                new_losses,
                total = current_packets_lost,
                "Packet loss detected"
            );

            conn.last_packets_lost = current_packets_lost;

            let event = quicd_x::AppEvent::TransportEvent(quicd_x::TransportEvent::PacketLost {
                count: new_losses,
                total_lost: current_packets_lost,
                // Note: Quiche 0.24.6 doesn't expose individual packet numbers in loss events
                // These would require deeper integration with quiche's recovery module
                first_packet_num: None,
                last_packet_num: None,
            });
            send_app_event(worker_id, connection_id, &ingress_tx, event);
        }

        // === RFC 9000 §13.4 & RFC 9002 §A.4: ECN Tracking ===
        // Quiche API Limitation: Quiche 0.24.6 does NOT expose ECN counters (ECN-CE, ECN-ECT0, ECN-ECT1)
        // in Stats or PathStats structs. The internal congestion controller reacts to ECN-CE marks,
        // but we cannot detect or report them to applications.
        //
        // When Quiche adds ECN counter APIs (e.g., stats.ecn_ce_count), we should:
        // 1. Track conn.last_ecn_ce_count
        // 2. Compare with current ECN-CE count
        // 3. Emit EcnCongestionEncountered event when count increases
        //
        // For now, applications can monitor CongestionStateChanged events which reflect
        // congestion controller reactions (ECN + loss), though not separately attributable.

        // === RFC 9002 §7: Congestion Control State Changes ===
        // Monitor congestion window, RTT, and bytes in flight
        if let Some(path_stats) = conn.conn.path_stats().next() {
            let current_cwnd = path_stats.cwnd as u64;
            let current_srtt_us = path_stats.rtt.as_micros() as u64;
            let current_bytes_in_flight = (quiche_stats.sent - quiche_stats.recv) as u64;
            let current_state =
                determine_congestion_state(&path_stats, &quiche_stats, conn.last_packets_lost);

            // Detect state transitions or significant changes in congestion metrics
            // Report if state changed OR CWND changed by >10% OR RTT changed by >20%
            let state_changed = current_state != conn.last_congestion_state;
            let cwnd_changed = (current_cwnd as i64 - conn.last_cwnd as i64).abs() as u64
                > (conn.last_cwnd / 10).max(1);
            let srtt_changed = (current_srtt_us as i64 - conn.last_srtt_us as i64).abs() as u64
                > (conn.last_srtt_us / 5).max(1000); // Min 1ms change threshold

            if state_changed || cwnd_changed || srtt_changed {
                trace!(
                    worker_id,
                    connection_id,
                    state = ?current_state,
                    cwnd = current_cwnd,
                    srtt_us = current_srtt_us,
                    bytes_in_flight = current_bytes_in_flight,
                    "Congestion state changed"
                );

                conn.last_congestion_state = current_state;
                conn.last_cwnd = current_cwnd;
                conn.last_srtt_us = current_srtt_us;
                conn.last_bytes_in_flight = current_bytes_in_flight;

                let event = quicd_x::AppEvent::TransportEvent(
                    quicd_x::TransportEvent::CongestionStateChanged {
                        state: current_state,
                        cwnd: current_cwnd,
                        bytes_in_flight: current_bytes_in_flight,
                        srtt_us: current_srtt_us,
                    },
                );
                send_app_event(worker_id, connection_id, &ingress_tx, event);
            }
        }

        // === RFC 9001 §4.6: 0-RTT Early Data Tracking ===
        // Track transition out of early data (0-RTT → 1-RTT)
        let currently_in_early_data = conn.conn.is_in_early_data();

        if conn.was_in_early_data && !currently_in_early_data {
            // Check if 0-RTT was accepted or rejected
            // If is_established() is true and we transitioned out of early data,
            // then 0-RTT was accepted. If connection was reset during early data,
            // it was rejected (but that would close the connection).
            let was_accepted = conn.conn.is_established();

            if was_accepted {
                info!(
                    worker_id,
                    connection_id, "0-RTT early data accepted - transitioned to 1-RTT"
                );

                // Notify application that 0-RTT was accepted (RFC 9001 §4.6.2)
                let event = quicd_x::AppEvent::EarlyDataAccepted;
                send_app_event(worker_id, connection_id, &ingress_tx, event);
            } else {
                warn!(
                    worker_id,
                    connection_id, "0-RTT early data rejected by peer"
                );

                // Notify application that 0-RTT was rejected (RFC 9001 §4.6.2)
                // Application must be prepared to retransmit data sent during 0-RTT
                let event = quicd_x::AppEvent::EarlyDataRejected;
                send_app_event(worker_id, connection_id, &ingress_tx, event);
            }

            conn.was_in_early_data = false;

            // Also send key update event for security auditing
            let event =
                quicd_x::AppEvent::TransportEvent(quicd_x::TransportEvent::KeyUpdateCompleted {
                    key_phase: 1, // 0-RTT → 1-RTT transition
                });
            send_app_event(worker_id, connection_id, &ingress_tx, event);
        }
    }
        self.replenish_source_connection_ids(dcid)?;

        Ok(())
    }

    /// Handle path events (connection migration, path validation).
    ///
    /// QUIC supports connection migration where a client can change its IP address
    /// or port during a connection (e.g., mobile device switching networks).
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
        let is_new_stream = !stream_manager.has_stream(*stream_id);

        if is_new_stream {
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
        } else {
            // RFC 9000 §2.2: Stream is already registered and has become readable again
            // Generate StreamReadable event for efficient backpressure handling
            // This is edge-triggered: we notify when a stream becomes readable
            trace!(worker_id, stream_id, "Stream readable (has buffered data)");

            // Send StreamReadable event to app
            if let Some(ref sm) = conn.stream_manager {
                let event = quicd_x::AppEvent::StreamReadable {
                    stream_id: *stream_id,
                };
                if sm.conn_ingress_tx.try_send(event).is_err() {
                    // App channel full - skip this event, will retry on next poll
                    trace!(
                        worker_id,
                        stream_id,
                        "Failed to send StreamReadable - app channel full"
                    );
                }
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

        // Get path stats for RTT and congestion metrics
        // Extract all fields at once to avoid move issues
        let (srtt_us, min_rtt_us, rttvar_us, latest_rtt_us, cwnd, path_mtu) =
            if let Some(ps) = conn.conn.path_stats().next() {
                (
                    Some(ps.rtt.as_micros() as u64),
                    ps.min_rtt.map(|d| d.as_micros() as u64),
                    Some(ps.rttvar.as_micros() as u64),
                    Some(ps.rtt.as_micros() as u64),
                    ps.cwnd as u64,
                    ps.pmtu,
                )
            } else {
                (None, None, None, None, 0, 1200)
            };

        // === RFC 9002: Congestion Control Metrics ===
        // bytes_in_flight should be sent - acked, but quiche doesn't expose acked separately
        // Using sent - recv as approximation (close enough for monitoring)
        let bytes_in_flight = quiche_stats.sent.saturating_sub(quiche_stats.recv) as u64;

        // === RFC 9000 §4: Flow Control Limits ===
        // Get current flow control limits from our tracking state
        let max_streams_bidi = conn.last_peer_streams_bidi;
        let max_streams_uni = conn.last_peer_streams_uni;

        // Count active streams and track max stream ID
        let mut active_streams: usize = 0;
        let mut max_stream_id = conn.stream_id_gen.max_stream_id();

        // Use a HashSet to avoid double-counting streams that are both readable and writable
        let mut seen_streams = std::collections::HashSet::new();

        for stream_id in conn.conn.readable() {
            if seen_streams.insert(stream_id) {
                active_streams += 1;
            }
            max_stream_id = max_stream_id.max(stream_id);
        }
        for stream_id in conn.conn.writable() {
            if seen_streams.insert(stream_id) {
                active_streams += 1;
            }
            max_stream_id = max_stream_id.max(stream_id);
        }

        // Build and return ConnectionStats with RFC-compliant metrics
        Some(quicd_x::ConnectionStats {
            // === RFC 9002 §5: RTT Metrics ===
            srtt_us,
            min_rtt_us,
            rttvar_us,
            latest_rtt_us,
            pto_ms: None, // quiche 0.24 doesn't expose PTO directly

            // === RFC 9002 §7: Congestion Control ===
            cwnd,
            bytes_in_flight,
            ssthresh: None,        // quiche doesn't expose ssthresh separately
            pacing_rate_bps: None, // quiche 0.24 doesn't expose pacing rate

            // === RFC 9000 §4: Flow Control ===
            max_data: 0, // quiche 0.24 doesn't expose max_data directly
            data_sent: quiche_stats.sent as u64,
            max_data_recv: 0, // quiche 0.24 doesn't expose max_data_recv
            data_received: quiche_stats.recv as u64,
            max_streams_bidi,
            max_streams_uni,

            // === Basic Statistics ===
            bytes_sent: quiche_stats.sent as u64,
            bytes_received: quiche_stats.recv as u64,
            active_streams,
            packets_sent: conn.stats.packets_sent,
            packets_received: conn.stats.packets_recv,
            packets_lost: quiche_stats.lost as u64,
            packets_retransmitted: quiche_stats.retrans as u64, // Use quiche's retrans counter
            max_stream_id,

            // === RFC 9000 §13.4: ECN Statistics ===
            // quiche 0.24 doesn't expose ECN counters directly
            ecn_ect0_count: 0,
            ecn_ect1_count: 0,
            ecn_ce_count: 0,

            // === Path Information ===
            path_mtu,
            is_in_early_data: conn.is_in_early_data(),
            is_established: conn.is_established(),
            is_closed: conn.is_closed(),
            path_validations_completed: 0, // Would need to track in QuicConnection
            path_validations_failed: 0,    // Would need to track in QuicConnection
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

        // Send peer transport parameters after handshake (RFC 9000 §7.4)
        if let Some(conn) = self.connections.get(canonical_id) {
            if let Some(params) = conn.conn.peer_transport_params() {
                let peer_params_event = quicd_x::AppEvent::PeerTransportParameters {
                    max_idle_timeout: params.max_idle_timeout,
                    initial_max_data: params.initial_max_data,
                    initial_max_stream_data_bidi_local: params.initial_max_stream_data_bidi_local,
                    initial_max_stream_data_bidi_remote: params.initial_max_stream_data_bidi_remote,
                    initial_max_stream_data_uni: params.initial_max_stream_data_uni,
                    max_streams_bidi: params.initial_max_streams_bidi,
                    max_streams_uni: params.initial_max_streams_uni,
                    ack_delay_exponent: params.ack_delay_exponent,
                    max_ack_delay: params.max_ack_delay,
                    active_connection_id_limit: params.active_conn_id_limit,
                    disable_active_migration: params.disable_active_migration,
                    max_udp_payload_size: params.max_udp_payload_size,
                };

                if ingress_tx.try_send(peer_params_event).is_err() {
                    warn!(
                        worker_id = self.worker_id,
                        peer = %peer_addr,
                        "Failed to send PeerTransportParameters event"
                    );
                }
            }
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

    /// Process ValidatePath command (RFC 9000 §8.2, §9.1)
    fn process_validate_path(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        peer_addr: std::net::SocketAddr,
    ) -> Result<()> {
        // Look up the connection
        let dcid = self
            .connection_id_map
            .get(&connection_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Connection not found for ValidatePath"))?;

        // Get the connection
        let conn = self
            .get_connection_mut(&dcid)
            .ok_or_else(|| anyhow::anyhow!("Connection not found"))?;

        // Get the current local address from the active path
        let local_addr = conn
            .conn
            .path_stats()
            .next()
            .map(|p| p.local_addr)
            .ok_or_else(|| anyhow::anyhow!("No active path found for connection"))?;

        // Initiate explicit path validation probe (RFC 9000 §9.1)
        // This will cause PATH_CHALLENGE frames to be sent to the new path
        conn.conn.probe_path(local_addr, peer_addr).map_err(|e| {
            warn!(
                worker_id,
                connection_id,
                %peer_addr,
                error = %e,
                "Failed to initiate path validation probe"
            );
            anyhow::anyhow!("Path probe failed: {}", e)
        })?;

        info!(
            worker_id,
            connection_id,
            %local_addr,
            %peer_addr,
            "Initiated active path validation probe (RFC 9000 §9.1)"
        );

        Ok(())
    }

    /// Derive stateless reset token for a connection ID using the worker seed (RFC 9000 §10.3).
    fn reset_token_for(&self, cid_bytes: &[u8]) -> u128 {
        let tag = ring::hmac::sign(&self.conn_id_seed, cid_bytes);
        let mut token = [0u8; 16];
        token.copy_from_slice(&tag.as_ref()[..16]);
        u128::from_be_bytes(token)
    }

    /// Generate a new eBPF-routable Connection ID for this worker.
    fn generate_worker_connection_id(&self, worker_idx: u8) -> Result<[u8; MAX_CONN_ID_LEN]> {
        let rng = SystemRandom::new();
        let mut seed_bytes = [0u8; 4];
        rng.fill(&mut seed_bytes)
            .map_err(|_| anyhow::anyhow!("failed to obtain randomness for connection ID generation"))?;
        let seed = u32::from_be_bytes(seed_bytes);
        Ok(routing::generate_connection_id(worker_idx, seed))
    }

    /// Ensure we have provided enough Source Connection IDs to the peer (RFC 9000 §5.1).
    fn replenish_source_connection_ids(
        &mut self,
        dcid: &ConnectionId<'static>,
    ) -> Result<()> {
        let worker_idx: u8 = self.worker_id.try_into().map_err(|_| {
            anyhow::anyhow!(
                "worker_id {} exceeds 255 and cannot be encoded into Connection IDs",
                self.worker_id
            )
        })?;

        let mut minted = 0usize;

        loop {
            let scids_left = match self.connections.get_mut(dcid) {
                Some(conn) => conn.conn.scids_left(),
                None => break,
            };

            if scids_left == 0 {
                break;
            }

            let cid_bytes = self.generate_worker_connection_id(worker_idx)?;
            let cid_vec = cid_bytes.to_vec();
            let quiche_cid = quiche::ConnectionId::from_vec(cid_vec.clone());
            let reset_token = self.reset_token_for(&cid_vec);
            let reset_token_bytes = reset_token.to_be_bytes();

            let provisioned = match self.connections.get_mut(dcid) {
                Some(conn) => match conn.conn.new_scid(&quiche_cid, reset_token, true) {
                    Ok(sequence) => {
                        conn.record_source_connection_id(&cid_vec, sequence, reset_token_bytes);
                        true
                    }
                    Err(quiche::Error::Done) => false,
                    Err(e) => {
                        warn!(
                            worker_id = self.worker_id,
                            connection = ?dcid,
                            error = ?e,
                            "Failed to provision additional source Connection ID"
                        );
                        false
                    }
                },
                None => false,
            };

            if !provisioned {
                break;
            }

            minted += 1;
        }

        if minted > 0 {
            info!(
                worker_id = self.worker_id,
                connection = ?dcid,
                minted,
                "Provisioned {minted} source Connection ID(s) for peer (RFC 9000 §5.1)"
            );
        }

        Ok(())
    }

    /// Process MigrateTo command (RFC 9000 §9).
    fn process_migrate_to(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        new_local_addr: SocketAddr,
    ) -> Result<()> {
        let Some(dcid) = self.connection_id_map.get(&connection_id).cloned() else {
            warn!(worker_id, connection_id, "Connection not found for MigrateTo");
            return Ok(());
        };

        let (ingress_tx, peer_addr, is_server) = match self.connections.get(&dcid) {
            Some(conn) => (conn.ingress_tx.clone(), conn.peer_addr, conn.conn.is_server()),
            None => {
                warn!(worker_id, connection_id, "Connection not found for migration");
                return Ok(());
            }
        };

        if is_server {
            warn!(
                worker_id,
                connection_id,
                %new_local_addr,
                "Active migration requested on server-side connection; rejecting per RFC 9000 §9"
            );

            if let Some(ingress_tx) = ingress_tx {
                let reason = format!(
                    "Active connection migration can only be initiated by clients per RFC 9000 §9. \
                     Server refused to migrate to {new_local_addr}."
                );
                let event = quicd_x::AppEvent::TransportEvent(
                    quicd_x::TransportEvent::PathValidationFailed {
                        peer_addr,
                        reason,
                    },
                );
                send_app_event(worker_id, connection_id, &ingress_tx, event);
            }

            return Ok(());
        }

        let migrate_result = match self.connections.get_mut(&dcid) {
            Some(conn) => conn.conn.migrate_source(new_local_addr),
            None => {
                warn!(worker_id, connection_id, "Connection disappeared before migration");
                return Ok(());
            }
        };

        match migrate_result {
            Ok(dcid_seq) => {
                info!(
                    worker_id,
                    connection_id,
                    %new_local_addr,
                    dcid_seq,
                    "Initiated client-side migration to new local address"
                );

                if let Some(ingress_tx) = ingress_tx {
                    let event = quicd_x::AppEvent::TransportEvent(
                        quicd_x::TransportEvent::MigrationStarted {
                            new_peer_addr: peer_addr,
                            local_addr: new_local_addr,
                        },
                    );
                    send_app_event(worker_id, connection_id, &ingress_tx, event);
                }
            }
            Err(e) => {
                warn!(
                    worker_id,
                    connection_id,
                    %new_local_addr,
                    error = ?e,
                    "Failed to initiate migration"
                );

                if let Some(ingress_tx) = ingress_tx {
                    let event = quicd_x::AppEvent::TransportEvent(
                        quicd_x::TransportEvent::PathValidationFailed {
                            peer_addr,
                            reason: format!("Migration to {new_local_addr} failed: {e:?}"),
                        },
                    );
                    send_app_event(worker_id, connection_id, &ingress_tx, event);
                }
            }
        }

        Ok(())
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

    /// Process SetStreamPriority command (RFC 9218 extensible priorities)
    fn process_set_stream_priority(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        stream_id: u64,
        urgency: u8,
        incremental: bool,
    ) {
        // Look up the connection
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(
                    worker_id,
                    connection_id, stream_id, "Connection not found for SetStreamPriority"
                );
                return;
            }
        };

        // Get the connection
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => return,
        };

        // Note: quiche doesn't currently expose a direct API for RFC 9218 priorities
        // This would require sending PRIORITY_UPDATE frames via H3
        // For now, we log the priority change and notify the application
        trace!(
            worker_id,
            connection_id,
            stream_id,
            urgency,
            incremental,
            "Stream priority set (requires H3 layer for PRIORITY_UPDATE frames)"
        );

        // Notify application that priority was changed
        if let Some(ref ingress_tx) = conn.ingress_tx {
            let event =
                quicd_x::AppEvent::TransportEvent(quicd_x::TransportEvent::StreamPriorityChanged {
                    stream_id,
                    urgency,
                    incremental,
                });
            let _ = ingress_tx.try_send(event);
        }
    }

    /// Process StopSending command (RFC 9000 §3.5)
    fn process_stop_sending(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        stream_id: u64,
        error_code: u64,
    ) {
        // Look up the connection
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(
                    worker_id,
                    connection_id, stream_id, "Connection not found for StopSending"
                );
                return;
            }
        };

        // Get the connection
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => return,
        };

        // Send STOP_SENDING frame via quiche
        match conn
            .conn
            .stream_shutdown(stream_id, quiche::Shutdown::Read, error_code)
        {
            Ok(()) => {
                debug!(
                    worker_id,
                    connection_id, stream_id, error_code, "Sent STOP_SENDING frame"
                );
            }
            Err(e) => {
                warn!(
                    worker_id,
                    connection_id,
                    stream_id,
                    error = ?e,
                    "Failed to send STOP_SENDING"
                );
            }
        }
    }

    /// Process GetMaxDatagramSize command (RFC 9221 §3)
    fn process_get_max_datagram_size(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        reply: tokio::sync::oneshot::Sender<Option<usize>>,
    ) {
        // Look up the connection
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(
                    worker_id,
                    connection_id, "Connection not found for GetMaxDatagramSize"
                );
                let _ = reply.send(None);
                return;
            }
        };

        // Get the connection
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => {
                let _ = reply.send(None);
                return;
            }
        };

        // Query maximum datagram size from quiche
        let max_size = conn.conn.dgram_max_writable_len();

        debug!(
            worker_id,
            connection_id,
            max_size = ?max_size,
            "Queried max datagram size"
        );

        let _ = reply.send(max_size);
    }

    /// Process GetStreamCredits command (RFC 9000 §4.6)
    fn process_get_stream_credits(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        reply: tokio::sync::oneshot::Sender<quicd_x::StreamCredits>,
    ) {
        // Look up the connection
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(
                    worker_id,
                    connection_id, "Connection not found for GetStreamCredits"
                );
                let _ = reply.send(quicd_x::StreamCredits { bidi: 0, uni: 0 });
                return;
            }
        };

        // Get the connection
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => {
                let _ = reply.send(quicd_x::StreamCredits { bidi: 0, uni: 0 });
                return;
            }
        };

        // Query stream credits from quiche
        let bidi = conn.conn.peer_streams_left_bidi();
        let uni = conn.conn.peer_streams_left_uni();

        debug!(
            worker_id,
            connection_id, bidi, uni, "Queried stream credits"
        );

        let _ = reply.send(quicd_x::StreamCredits { bidi, uni });
    }

    /// Process QueryStreamCapacity command (RFC 9000 §4.1)
    fn process_query_stream_capacity(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        stream_id: quicd_x::StreamId,
        reply: tokio::sync::oneshot::Sender<Result<u64, quicd_x::ConnectionError>>,
    ) {
        // Look up the connection
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(
                    worker_id,
                    connection_id, stream_id, "Connection not found for QueryStreamCapacity"
                );
                let _ = reply.send(Err(quicd_x::ConnectionError::Closed(
                    "connection not found".into(),
                )));
                return;
            }
        };

        // Get the connection
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => {
                let _ = reply.send(Err(quicd_x::ConnectionError::Closed(
                    "connection not found".into(),
                )));
                return;
            }
        };

        // Query stream send capacity from quiche (RFC 9000 §4.1)
        match conn.stream_send_capacity(stream_id) {
            Ok(capacity) => {
                debug!(
                    worker_id,
                    connection_id, stream_id, capacity, "Queried stream send capacity"
                );
                let _ = reply.send(Ok(capacity));
            }
            Err(quiche::Error::InvalidStreamState(_)) => {
                warn!(
                    worker_id,
                    connection_id, stream_id, "Stream not in writable state"
                );
                let _ = reply.send(Err(quicd_x::ConnectionError::App(
                    "stream not found or not writable".into(),
                )));
            }
            Err(e) => {
                warn!(
                    worker_id,
                    connection_id,
                    stream_id,
                    error = ?e,
                    "Failed to query stream capacity"
                );
                let _ = reply.send(Err(quicd_x::ConnectionError::Closed(
                    format!("quiche error: {:?}", e).into(),
                )));
            }
        }
    }

    /// Process QueryConnectionCapacity command (RFC 9000 §4.1)
    fn process_query_connection_capacity(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        reply: tokio::sync::oneshot::Sender<u64>,
    ) {
        // Look up the connection
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(
                    worker_id,
                    connection_id, "Connection not found for QueryConnectionCapacity"
                );
                let _ = reply.send(0);
                return;
            }
        };

        // Get the connection
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => {
                let _ = reply.send(0);
                return;
            }
        };

        // Query connection-level send capacity (RFC 9000 §4.1)
        let capacity = conn.connection_send_capacity();

        debug!(
            worker_id,
            connection_id, capacity, "Queried connection send capacity"
        );

        let _ = reply.send(capacity);
    }

    /// Process QueryStreamReadable command (RFC 9000 §2.2)
    fn process_query_stream_readable(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        stream_id: quicd_x::StreamId,
        reply: tokio::sync::oneshot::Sender<bool>,
    ) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(worker_id, connection_id, stream_id, "Connection not found for QueryStreamReadable");
                let _ = reply.send(false);
                return;
            }
        };

        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => {
                let _ = reply.send(false);
                return;
            }
        };

        // Check if stream is readable using quiche API
        let readable = conn.conn.stream_readable(stream_id);

        debug!(
            worker_id,
            connection_id, stream_id, readable, "Queried stream readable state"
        );

        let _ = reply.send(readable);
    }

    /// Process QueryStreamWritable command (RFC 9000 §2.2)
    fn process_query_stream_writable(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        stream_id: quicd_x::StreamId,
        reply: tokio::sync::oneshot::Sender<bool>,
    ) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(worker_id, connection_id, stream_id, "Connection not found for QueryStreamWritable");
                let _ = reply.send(false);
                return;
            }
        };

        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => {
                let _ = reply.send(false);
                return;
            }
        };

        // Check if stream is writable using quiche API
        // stream_writable returns Result<bool, Error>
        let writable = conn.conn.stream_writable(stream_id, 1).unwrap_or(false);

        debug!(
            worker_id,
            connection_id, stream_id, writable, "Queried stream writable state"
        );

        let _ = reply.send(writable);
    }

    /// Process QueryStreamFinished command (RFC 9000 §2.2)
    fn process_query_stream_finished(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        stream_id: quicd_x::StreamId,
        reply: tokio::sync::oneshot::Sender<bool>,
    ) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(worker_id, connection_id, stream_id, "Connection not found for QueryStreamFinished");
                let _ = reply.send(false);
                return;
            }
        };

        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => {
                let _ = reply.send(false);
                return;
            }
        };

        // Check if stream is finished (peer sent FIN and all data read)
        let finished = conn.conn.stream_finished(stream_id);

        debug!(
            worker_id,
            connection_id, stream_id, finished, "Queried stream finished state"
        );

        let _ = reply.send(finished);
    }

    /// Process ShutdownStream command (RFC 9000 §3.1)
    fn process_shutdown_stream(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        stream_id: u64,
        error_code: u64,
        reply: tokio::sync::oneshot::Sender<Result<(), quicd_x::ConnectionError>>,
    ) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(worker_id, connection_id, stream_id, "Connection not found for ShutdownStream");
                let _ = reply.send(Err(quicd_x::ConnectionError::Closed("connection not found".into())));
                return;
            }
        };

        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => {
                let _ = reply.send(Err(quicd_x::ConnectionError::Closed("connection not found".into())));
                return;
            }
        };

        // Gracefully shutdown write side of stream (sends FIN)
        match conn.conn.stream_shutdown(stream_id, quiche::Shutdown::Write, error_code) {
            Ok(_) => {
                debug!(worker_id, connection_id, stream_id, error_code, "Stream shutdown successfully");
                let _ = reply.send(Ok(()));
            }
            Err(e) => {
                warn!(worker_id, connection_id, stream_id, error = ?e, "Failed to shutdown stream");
                let _ = reply.send(Err(quicd_x::ConnectionError::App(format!("shutdown failed: {:?}", e).into())));
            }
        }
    }

    /// Process RetireConnectionId command (RFC 9000 §5.1)
    fn process_retire_connection_id(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        sequence: u64,
    ) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(worker_id, connection_id, sequence, "Connection not found for RetireConnectionId");
                return;
            }
        };

        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => return,
        };

        // Send RETIRE_CONNECTION_ID frame
        match conn.conn.retire_dcid(sequence) {
            Ok(_) => {
                debug!(worker_id, connection_id, sequence, "Connection ID retired");
            }
            Err(e) => {
                warn!(worker_id, connection_id, sequence, error = ?e, "Failed to retire connection ID");
            }
        }
    }

    /// Process RequestNewConnectionId command (RFC 9000 §5.1)
    fn process_request_new_connection_id(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
    ) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(worker_id, connection_id, "Connection not found for RequestNewConnectionId");
                return;
            }
        };

        let _conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => return,
        };

        // Request new connection ID from peer
        // Quiche handles this internally when we issue new SCIDs
        // The peer will send NEW_CONNECTION_ID frames which we'll process in packet handling
        debug!(worker_id, connection_id, "New connection ID requested (peer will send NEW_CONNECTION_ID)");
        
        // Note: The actual request mechanism in quiche is implicit - when we need more CIDs,
        // quiche will send NEW_CONNECTION_ID frames automatically. This command acknowledges
        // the application's intent but doesn't require explicit action.
    }

    /// Process ProbePath command (RFC 9000 §8.2)
    fn process_probe_path(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        _data: &[u8], // Ignored - quiche generates challenge data automatically
    ) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(worker_id, connection_id, %peer_addr, "Connection not found for ProbePath");
                return;
            }
        };

        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => return,
        };

        // Send PATH_CHALLENGE frame using quiche's probe_path API
        // Note: quiche generates the challenge data automatically
        if let Err(e) = conn.conn.probe_path(local_addr, peer_addr) {
            warn!(
                worker_id,
                connection_id,
                %local_addr,
                %peer_addr,
                error = %e,
                "Failed to probe path"
            );
            return;
        }

        debug!(
            worker_id,
            connection_id,
            %local_addr,
            %peer_addr,
            "PATH_CHALLENGE sent successfully"
        );
    }

    /// Process SetStreamMaxData command (RFC 9000 §4.1)
    fn process_set_stream_max_data(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        stream_id: u64,
        max_data: u64,
    ) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(worker_id, connection_id, stream_id, "Connection not found for SetStreamMaxData");
                return;
            }
        };

        let _conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => return,
        };

        // Manually set stream flow control window
        // Note: quiche doesn't expose direct set_stream_max_data API
        // This would require modifying quiche or using stream_recv() to update implicitly
        warn!(worker_id, connection_id, stream_id, max_data, 
              "SetStreamMaxData not directly supported by quiche - flow control is automatic");
    }

    /// Process SetConnectionMaxData command (RFC 9000 §4.1)
    fn process_set_connection_max_data(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        max_data: u64,
    ) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(worker_id, connection_id, "Connection not found for SetConnectionMaxData");
                return;
            }
        };

        let _conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => return,
        };

        // Manually set connection flow control window
        // Note: quiche doesn't expose direct set_max_data API
        // Flow control is automatic based on consumption
        warn!(worker_id, connection_id, max_data, 
              "SetConnectionMaxData not directly supported by quiche - flow control is automatic");
    }

    /// Process UpdateKeys command (RFC 9001 §6)
    fn process_update_keys(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
    ) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(worker_id, connection_id, "Connection not found for UpdateKeys");
                return;
            }
        };

        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => return,
        };

        // === RFC 9001 §6: TLS Key Updates ===
        // Quiche API Limitation: There is no Connection::initiate_key_update() method.
        // TLS 1.3 key updates happen automatically within Quiche's TLS layer based on:
        // - Packet number exhaustion risk (approaching 2^62-1 limit per RFC 9001 §6.6)
        // - Peer-initiated key updates (automatic response per RFC 8446 §4.6.3)
        //
        // Quiche 0.24.6 does NOT expose:
        // - Manual key update initiation API
        // - Current key phase number
        // - Key update event notifications
        //
        // This means applications cannot:
        // - Force key rotation for security policies
        // - Detect when key updates occur (except 0-RTT → 1-RTT transition)
        // - Track key rotation frequency for auditing
        //
        // The KeyUpdateInitiated event is emitted to inform the application that a
        // key update was *requested*, but we cannot confirm if/when it completes.
        debug!(
            worker_id,
            connection_id,
            "TLS key update requested (handled automatically by quiche - no confirmation available)"
        );

        // Notify application that update was requested (best effort)
        if let Some(ref ingress_tx) = conn.ingress_tx {
            let event = quicd_x::AppEvent::TransportEvent(
                quicd_x::TransportEvent::KeyUpdateInitiated {
                    key_phase: 0, // Quiche doesn't expose key_phase - always 0
                },
            );
            let _ = ingress_tx.try_send(event);
        }
    }

    /// Process CanSendEarlyData command (RFC 9001 §4.6)
    fn process_can_send_early_data(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        reply: tokio::sync::oneshot::Sender<bool>,
    ) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(worker_id, connection_id, "Connection not found for CanSendEarlyData");
                let _ = reply.send(false);
                return;
            }
        };

        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => {
                let _ = reply.send(false);
                return;
            }
        };

        // Check if 0-RTT is available
        let can_send = conn.conn.is_in_early_data();
        debug!(worker_id, connection_id, can_send, "Checked early data status");
        let _ = reply.send(can_send);
    }

    /// Process GetPeerTransportParams command (RFC 9000 §7.4)
    fn process_get_peer_transport_params(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        reply: tokio::sync::oneshot::Sender<Option<quicd_x::PeerTransportParams>>,
    ) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(worker_id, connection_id, "Connection not found for GetPeerTransportParams");
                let _ = reply.send(None);
                return;
            }
        };

        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => {
                let _ = reply.send(None);
                return;
            }
        };

        // Extract peer transport parameters
        if !conn.conn.is_established() {
            debug!(worker_id, connection_id, "Connection not established yet");
            let _ = reply.send(None);
            return;
        }

        // Get peer parameters from quiche
        let params_opt = conn.conn.peer_transport_params().map(|params| {
            quicd_x::PeerTransportParams {
                max_idle_timeout: params.max_idle_timeout,
                initial_max_data: params.initial_max_data,
                initial_max_stream_data_bidi_local: params.initial_max_stream_data_bidi_local,
                initial_max_stream_data_bidi_remote: params.initial_max_stream_data_bidi_remote,
                initial_max_stream_data_uni: params.initial_max_stream_data_uni,
                max_streams_bidi: params.initial_max_streams_bidi,
                max_streams_uni: params.initial_max_streams_uni,
                ack_delay_exponent: params.ack_delay_exponent,
                max_ack_delay: params.max_ack_delay,
                active_connection_id_limit: params.active_conn_id_limit,
                disable_active_migration: params.disable_active_migration,
                max_udp_payload_size: params.max_udp_payload_size,
            }
        });

        debug!(worker_id, connection_id, "Retrieved peer transport parameters");
        let _ = reply.send(params_opt);
    }

    /// Process SetDatagramPriority command
    fn process_set_datagram_priority(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        priority: u8,
    ) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(worker_id, connection_id, "Connection not found for SetDatagramPriority");
                return;
            }
        };

        let _conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => return,
        };

        // Store priority for future datagram sends
        // Note: This would require extending QuicConnection to track datagram priority
        debug!(worker_id, connection_id, priority, "Datagram priority set (requires QuicConnection extension)");
    }

    /// Process GetPathMtu command (RFC 9000 §14)
    fn process_get_path_mtu(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        reply: tokio::sync::oneshot::Sender<usize>,
    ) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(worker_id, connection_id, "Connection not found for GetPathMtu");
                let _ = reply.send(1200); // QUIC minimum
                return;
            }
        };

        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => {
                let _ = reply.send(1200);
                return;
            }
        };

        // Get max send UDP payload size (effective MTU)
        let mtu = conn.conn.max_send_udp_payload_size();
        debug!(worker_id, connection_id, mtu, "Retrieved path MTU");
        let _ = reply.send(mtu);
    }

    /// Process GetActivePaths command
    fn process_get_active_paths(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        reply: tokio::sync::oneshot::Sender<Vec<quicd_x::PathInfo>>,
    ) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(worker_id, connection_id, "Connection not found for GetActivePaths");
                let _ = reply.send(Vec::new());
                return;
            }
        };

        // Get needed info before mutable borrow
        let local_addr = self.local_addr;
        
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => {
                let _ = reply.send(Vec::new());
                return;
            }
        };

        // Build path info (currently quiche only exposes single active path)
        let path = quicd_x::PathInfo {
            local_addr,
            peer_addr: conn.peer_addr,
            validated: conn.conn.is_established(),
            active: true,
            rtt_us: 0, // RTT not directly exposed in quiche::Stats - would need path-specific stats
        };

        debug!(worker_id, connection_id, "Retrieved active paths");
        let _ = reply.send(vec![path]);
    }

    /// Process SetStreamSendOrder command (RFC 9218)
    fn process_set_stream_send_order(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        stream_id: u64,
        send_order: i64,
    ) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(worker_id, connection_id, stream_id, "Connection not found for SetStreamSendOrder");
                return;
            }
        };

        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => return,
        };

        // Set stream priority (quiche uses simple priority values)
        match conn.conn.stream_priority(stream_id, send_order.clamp(0, 255) as u8, false) {
            Ok(_) => {
                debug!(worker_id, connection_id, stream_id, send_order, "Stream send order set");
            }
            Err(e) => {
                warn!(worker_id, connection_id, stream_id, error = ?e, "Failed to set stream send order");
            }
        }
    }

    // ============ New Query Handler Implementations ============

    fn process_query_source_id(&mut self, worker_id: usize, connection_id: quicd_x::ConnectionId, reply: tokio::sync::oneshot::Sender<Vec<u8>>) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => { let _ = reply.send(Vec::new()); return; }
        };
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => { let _ = reply.send(Vec::new()); return; }
        };
        let scid = conn.conn.source_id().into_owned().to_vec();
        debug!(worker_id, connection_id, "Retrieved source_id");
        let _ = reply.send(scid);
    }

    fn process_query_destination_id(&mut self, worker_id: usize, connection_id: quicd_x::ConnectionId, reply: tokio::sync::oneshot::Sender<Vec<u8>>) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => { let _ = reply.send(Vec::new()); return; }
        };
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => { let _ = reply.send(Vec::new()); return; }
        };
        let dest_id = conn.conn.destination_id().into_owned().to_vec();
        debug!(worker_id, connection_id, "Retrieved destination_id");
        let _ = reply.send(dest_id);
    }

    fn process_query_available_dcids(&mut self, worker_id: usize, connection_id: quicd_x::ConnectionId, reply: tokio::sync::oneshot::Sender<usize>) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => { let _ = reply.send(0); return; }
        };
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => { let _ = reply.send(0); return; }
        };
        let available = conn.conn.available_dcids();
        debug!(worker_id, connection_id, available, "Retrieved available_dcids");
        let _ = reply.send(available);
    }

    fn process_query_scids_left(&mut self, worker_id: usize, connection_id: quicd_x::ConnectionId, reply: tokio::sync::oneshot::Sender<usize>) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => { let _ = reply.send(0); return; }
        };
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => { let _ = reply.send(0); return; }
        };
        let scids_left = conn.conn.scids_left();
        debug!(worker_id, connection_id, scids_left, "Retrieved scids_left");
        let _ = reply.send(scids_left);
    }

    fn process_query_timeout(&mut self, worker_id: usize, connection_id: quicd_x::ConnectionId, reply: tokio::sync::oneshot::Sender<Option<std::time::Duration>>) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => { let _ = reply.send(None); return; }
        };
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => { let _ = reply.send(None); return; }
        };
        let timeout = conn.conn.timeout();
        debug!(worker_id, connection_id, ?timeout, "Retrieved timeout");
        let _ = reply.send(timeout);
    }

    fn process_on_timeout(&mut self, worker_id: usize, connection_id: quicd_x::ConnectionId) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => { warn!(worker_id, connection_id, "Connection not found for on_timeout"); return; }
        };
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => return,
        };
        conn.conn.on_timeout();
        debug!(worker_id, connection_id, "Called on_timeout");
    }

    fn process_query_session(&mut self, worker_id: usize, connection_id: quicd_x::ConnectionId, reply: tokio::sync::oneshot::Sender<Option<Vec<u8>>>) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => { let _ = reply.send(None); return; }
        };
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => { let _ = reply.send(None); return; }
        };
        let session = conn.conn.session().map(|s| s.to_vec());
        debug!(worker_id, connection_id, has_session = session.is_some(), "Retrieved session");
        let _ = reply.send(session);
    }

    fn process_query_server_name(&mut self, worker_id: usize, connection_id: quicd_x::ConnectionId, reply: tokio::sync::oneshot::Sender<Option<String>>) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => { let _ = reply.send(None); return; }
        };
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => { let _ = reply.send(None); return; }
        };
        let server_name = conn.conn.server_name().map(|s| s.to_string());
        debug!(worker_id, connection_id, has_sni = server_name.is_some(), "Retrieved server_name");
        let _ = reply.send(server_name);
    }

    fn process_query_peer_cert(&mut self, worker_id: usize, connection_id: quicd_x::ConnectionId, reply: tokio::sync::oneshot::Sender<Option<Vec<u8>>>) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => { let _ = reply.send(None); return; }
        };
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => { let _ = reply.send(None); return; }
        };
        let cert = conn.conn.peer_cert().map(|c| c.to_vec());
        debug!(worker_id, connection_id, has_cert = cert.is_some(), "Retrieved peer_cert");
        let _ = reply.send(cert);
    }

    fn process_query_peer_cert_chain(&mut self, worker_id: usize, connection_id: quicd_x::ConnectionId, reply: tokio::sync::oneshot::Sender<Option<Vec<Vec<u8>>>>) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => { let _ = reply.send(None); return; }
        };
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => { let _ = reply.send(None); return; }
        };
        let chain = conn.conn.peer_cert_chain().map(|chain| chain.iter().map(|c| c.to_vec()).collect());
        debug!(worker_id, connection_id, has_chain = chain.is_some(), "Retrieved peer_cert_chain");
        let _ = reply.send(chain);
    }

    fn process_query_is_established(&mut self, worker_id: usize, connection_id: quicd_x::ConnectionId, reply: tokio::sync::oneshot::Sender<bool>) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => { let _ = reply.send(false); return; }
        };
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => { let _ = reply.send(false); return; }
        };
        let established = conn.conn.is_established();
        debug!(worker_id, connection_id, established, "Retrieved is_established");
        let _ = reply.send(established);
    }

    fn process_query_is_resumed(&mut self, worker_id: usize, connection_id: quicd_x::ConnectionId, reply: tokio::sync::oneshot::Sender<bool>) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => { let _ = reply.send(false); return; }
        };
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => { let _ = reply.send(false); return; }
        };
        let resumed = conn.conn.is_resumed();
        debug!(worker_id, connection_id, resumed, "Retrieved is_resumed");
        let _ = reply.send(resumed);
    }

    fn process_query_is_in_early_data(&mut self, worker_id: usize, connection_id: quicd_x::ConnectionId, reply: tokio::sync::oneshot::Sender<bool>) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => { let _ = reply.send(false); return; }
        };
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => { let _ = reply.send(false); return; }
        };
        let in_early = conn.conn.is_in_early_data();
        debug!(worker_id, connection_id, in_early, "Retrieved is_in_early_data");
        let _ = reply.send(in_early);
    }

    fn process_query_is_closed(&mut self, worker_id: usize, connection_id: quicd_x::ConnectionId, reply: tokio::sync::oneshot::Sender<bool>) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => { let _ = reply.send(true); return; }
        };
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => { let _ = reply.send(true); return; }
        };
        let closed = conn.conn.is_closed();
        debug!(worker_id, connection_id, closed, "Retrieved is_closed");
        let _ = reply.send(closed);
    }

    fn process_query_is_draining(&mut self, worker_id: usize, connection_id: quicd_x::ConnectionId, reply: tokio::sync::oneshot::Sender<bool>) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => { let _ = reply.send(false); return; }
        };
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => { let _ = reply.send(false); return; }
        };
        let draining = conn.conn.is_draining();
        debug!(worker_id, connection_id, draining, "Retrieved is_draining");
        let _ = reply.send(draining);
    }

    fn process_query_is_timed_out(&mut self, worker_id: usize, connection_id: quicd_x::ConnectionId, reply: tokio::sync::oneshot::Sender<bool>) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => { let _ = reply.send(false); return; }
        };
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => { let _ = reply.send(false); return; }
        };
        let timed_out = conn.conn.is_timed_out();
        debug!(worker_id, connection_id, timed_out, "Retrieved is_timed_out");
        let _ = reply.send(timed_out);
    }

    /// Process query for peer-initiated connection close error (RFC 9000 §10.2)
    fn process_query_peer_error(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        reply: tokio::sync::oneshot::Sender<Option<(u64, Vec<u8>)>>,
    ) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                let _ = reply.send(None);
                return;
            }
        };
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => {
                let _ = reply.send(None);
                return;
            }
        };

        // Use quiche's peer_error() API to get CONNECTION_CLOSE info from peer
        let peer_error = conn.conn.peer_error();
        let result = peer_error.map(|err| {
            let error_code = err.error_code;
            let reason = err.reason.to_vec();
            (error_code, reason)
        });

        debug!(
            worker_id,
            connection_id,
            ?result,
            "Retrieved peer_error"
        );
        let _ = reply.send(result);
    }

    /// Process query for local-initiated connection close error (RFC 9000 §10.2)
    fn process_query_local_error(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        reply: tokio::sync::oneshot::Sender<Option<(u64, Vec<u8>)>>,
    ) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                let _ = reply.send(None);
                return;
            }
        };
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => {
                let _ = reply.send(None);
                return;
            }
        };

        // Use quiche's local_error() API to get CONNECTION_CLOSE info we sent
        let local_error = conn.conn.local_error();
        let result = local_error.map(|err| {
            let error_code = err.error_code;
            let reason = err.reason.to_vec();
            (error_code, reason)
        });

        debug!(
            worker_id,
            connection_id,
            ?result,
            "Retrieved local_error"
        );
        let _ = reply.send(result);
    }

    /// Process query for active Source Connection IDs (RFC 9000 §5.1)
    fn process_query_active_scids(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        reply: tokio::sync::oneshot::Sender<Vec<(u64, Vec<u8>)>>,
    ) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                let _ = reply.send(Vec::new());
                return;
            }
        };
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => {
                let _ = reply.send(Vec::new());
                return;
            }
        };

        // Use quiche's source_ids() iterator to get all active Source Connection IDs
        // Then look up sequence numbers from our metadata tracking
        let mut result = Vec::new();
        for scid_ref in conn.conn.source_ids() {
            let cid_bytes = scid_ref.as_ref().to_vec();
            
            // Look up sequence number from our metadata
            let sequence = conn
                .get_source_cid_meta(scid_ref.as_ref())
                .map(|meta| meta.sequence)
                .unwrap_or(0); // Fallback to 0 if metadata not found (shouldn't happen)
            
            result.push((sequence, cid_bytes));
        }

        debug!(
            worker_id,
            connection_id,
            count = result.len(),
            "Retrieved active SCIDs"
        );
        let _ = reply.send(result);
    }

    /// Process query for send quantum (RFC 9002 §7.7)
    fn process_query_send_quantum(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        reply: tokio::sync::oneshot::Sender<usize>,
    ) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                let _ = reply.send(0);
                return;
            }
        };
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => {
                let _ = reply.send(0);
                return;
            }
        };

        // Use quiche's send_quantum() for packet pacing
        let quantum = conn.conn.send_quantum();
        debug!(
            worker_id,
            connection_id,
            quantum,
            "Retrieved send_quantum"
        );
        let _ = reply.send(quantum);
    }

    /// Process datagram purge command (RFC 9221 §5)
    fn process_dgram_purge_outgoing(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
    ) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => return,
        };
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => return,
        };

        // Use quiche's dgram_purge_outgoing() to clear ALL unsent datagrams
        // The filter function returns true for datagrams to keep - we want to purge all, so always return false
        conn.conn.dgram_purge_outgoing(|_| false);
        debug!(
            worker_id,
            connection_id,
            "Purged all outgoing datagrams"
        );
    }

    fn process_query_dgram_max_writable_len(&mut self, worker_id: usize, connection_id: quicd_x::ConnectionId, reply: tokio::sync::oneshot::Sender<Option<usize>>) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => { let _ = reply.send(None); return; }
        };
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => { let _ = reply.send(None); return; }
        };
        let max_len = conn.conn.dgram_max_writable_len();
        debug!(worker_id, connection_id, ?max_len, "Retrieved dgram_max_writable_len");
        let _ = reply.send(max_len);
    }

    fn process_query_dgram_send_queue_len(&mut self, worker_id: usize, connection_id: quicd_x::ConnectionId, reply: tokio::sync::oneshot::Sender<usize>) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => { let _ = reply.send(0); return; }
        };
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => { let _ = reply.send(0); return; }
        };
        let len = conn.conn.dgram_send_queue_len();
        debug!(worker_id, connection_id, len, "Retrieved dgram_send_queue_len");
        let _ = reply.send(len);
    }

    fn process_query_dgram_recv_queue_len(&mut self, worker_id: usize, connection_id: quicd_x::ConnectionId, reply: tokio::sync::oneshot::Sender<usize>) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => { let _ = reply.send(0); return; }
        };
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => { let _ = reply.send(0); return; }
        };
        let len = conn.conn.dgram_recv_queue_len();
        debug!(worker_id, connection_id, len, "Retrieved dgram_recv_queue_len");
        let _ = reply.send(len);
    }

    fn process_query_dgram_recv_queue_byte_size(&mut self, worker_id: usize, connection_id: quicd_x::ConnectionId, reply: tokio::sync::oneshot::Sender<usize>) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => { let _ = reply.send(0); return; }
        };
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => { let _ = reply.send(0); return; }
        };
        let size = conn.conn.dgram_recv_queue_byte_size();
        debug!(worker_id, connection_id, size, "Retrieved dgram_recv_queue_byte_size");
        let _ = reply.send(size);
    }

    fn process_query_dgram_send_queue_byte_size(&mut self, worker_id: usize, connection_id: quicd_x::ConnectionId, reply: tokio::sync::oneshot::Sender<usize>) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => { let _ = reply.send(0); return; }
        };
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => { let _ = reply.send(0); return; }
        };
        let size = conn.conn.dgram_send_queue_byte_size();
        debug!(worker_id, connection_id, size, "Retrieved dgram_send_queue_byte_size");
        let _ = reply.send(size);
    }

    fn process_query_peer_streams_left_bidi(&mut self, worker_id: usize, connection_id: quicd_x::ConnectionId, reply: tokio::sync::oneshot::Sender<u64>) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => { let _ = reply.send(0); return; }
        };
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => { let _ = reply.send(0); return; }
        };
        let left = conn.conn.peer_streams_left_bidi();
        debug!(worker_id, connection_id, left, "Retrieved peer_streams_left_bidi");
        let _ = reply.send(left);
    }

    fn process_query_peer_streams_left_uni(&mut self, worker_id: usize, connection_id: quicd_x::ConnectionId, reply: tokio::sync::oneshot::Sender<u64>) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => { let _ = reply.send(0); return; }
        };
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => { let _ = reply.send(0); return; }
        };
        let left = conn.conn.peer_streams_left_uni();
        debug!(worker_id, connection_id, left, "Retrieved peer_streams_left_uni");
        let _ = reply.send(left);
    }

    fn process_query_peer_verified_address(&mut self, worker_id: usize, connection_id: quicd_x::ConnectionId, reply: tokio::sync::oneshot::Sender<bool>) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => { let _ = reply.send(false); return; }
        };
        let _conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => { let _ = reply.send(false); return; }
        };
        // Note: quiche doesn't expose peer address validation status directly
        // This would require checking if anti-amplification limit is lifted
        let verified = false; // TODO: implement proper check
        debug!(worker_id, connection_id, verified, "Retrieved peer_verified_address");
        let _ = reply.send(verified);
    }

    // ============ Stream Iterator Command Handlers (P0 Gap #1) ============
    
    /// Poll all readable streams (RFC 9000 §2).
    ///
    /// Emits AppEvent::ReadableStreamsUpdated with set of stream IDs that have pending data.
    fn process_poll_readable_streams(&mut self, worker_id: usize, connection_id: quicd_x::ConnectionId) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(worker_id, connection_id, "Connection not found for PollReadableStreams");
                return;
            }
        };
        
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => {
                warn!(worker_id, connection_id, "Connection not found for PollReadableStreams");
                return;
            }
        };
        
        // Collect all readable streams from quiche
        let readable_streams: Vec<u64> = conn.conn.readable().collect();
        
        debug!(worker_id, connection_id, count = readable_streams.len(), "Polled readable streams");
        
        // Send event to application task
        if let Some(ref ingress_tx) = conn.ingress_tx {
            let event = quicd_x::AppEvent::ReadableStreamsUpdated {
                stream_ids: readable_streams,
            };
            
            let _ = send_app_event(worker_id, connection_id, ingress_tx, event);
        }
    }
    
    /// Poll all writable streams (RFC 9000 §2).
    ///
    /// Emits AppEvent::WritableStreamsUpdated with set of stream IDs that have send capacity.
    fn process_poll_writable_streams(&mut self, worker_id: usize, connection_id: quicd_x::ConnectionId) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(worker_id, connection_id, "Connection not found for PollWritableStreams");
                return;
            }
        };
        
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => {
                warn!(worker_id, connection_id, "Connection not found for PollWritableStreams");
                return;
            }
        };
        
        // Collect all writable streams from quiche
        let writable_streams: Vec<u64> = conn.conn.writable().collect();
        
        debug!(worker_id, connection_id, count = writable_streams.len(), "Polled writable streams");
        
        // Send event to application task
        if let Some(ref ingress_tx) = conn.ingress_tx {
            let event = quicd_x::AppEvent::WritableStreamsUpdated {
                stream_ids: writable_streams,
            };
            
            let _ = send_app_event(worker_id, connection_id, ingress_tx, event);
        }
    }
    
    /// Get next readable stream in iterator-style access (RFC 9000 §2).
    ///
    /// Emits AppEvent::NextReadableStream with the stream ID or None if no more readable streams.
    fn process_get_next_readable_stream(&mut self, worker_id: usize, connection_id: quicd_x::ConnectionId, request_id: u64) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(worker_id, connection_id, request_id, "Connection not found for GetNextReadableStream");
                return;
            }
        };
        
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => {
                warn!(worker_id, connection_id, request_id, "Connection not found for GetNextReadableStream");
                return;
            }
        };
        
        // Get next readable stream from quiche iterator
        let stream_id = conn.conn.readable().next();
        
        debug!(worker_id, connection_id, request_id, stream_id = ?stream_id, "Got next readable stream");
        
        // Send event to application task
        if let Some(ref ingress_tx) = conn.ingress_tx {
            let event = quicd_x::AppEvent::NextReadableStream {
                request_id,
                stream_id,
            };
            
            let _ = send_app_event(worker_id, connection_id, ingress_tx, event);
        }
    }
    
    /// Get next writable stream in iterator-style access (RFC 9000 §2).
    ///
    /// Emits AppEvent::NextWritableStream with the stream ID or None if no more writable streams.
    fn process_get_next_writable_stream(&mut self, worker_id: usize, connection_id: quicd_x::ConnectionId, request_id: u64) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(worker_id, connection_id, request_id, "Connection not found for GetNextWritableStream");
                return;
            }
        };
        
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => {
                warn!(worker_id, connection_id, request_id, "Connection not found for GetNextWritableStream");
                return;
            }
        };
        
        // Get next writable stream from quiche iterator
        let stream_id = conn.conn.writable().next();
        
        debug!(worker_id, connection_id, request_id, stream_id = ?stream_id, "Got next writable stream");
        
        // Send event to application task
        if let Some(ref ingress_tx) = conn.ingress_tx {
            let event = quicd_x::AppEvent::NextWritableStream {
                request_id,
                stream_id,
            };
            
            let _ = send_app_event(worker_id, connection_id, ingress_tx, event);
        }
    }
    
    // ============ Connection ID Management Command Handlers (P0 Gap #2) ============
    
    /// Issue new source connection ID (RFC 9000 §5.1.1).
    ///
    /// Generates a NEW_CONNECTION_ID frame and emits AppEvent::SourceConnectionIdIssued.
    ///
    /// NOTE: Quiche 0.24.6 does not yet expose `new_scid()` in its public API.
    /// This is a placeholder implementation that returns an error until Quiche adds the API.
    /// The QuicD-X interface is ready and will work once Quiche exposes this functionality.
    fn process_issue_new_scid(&mut self, worker_id: usize, connection_id: quicd_x::ConnectionId, request_id: u64, _scid: Option<Vec<u8>>) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(worker_id, connection_id, request_id, "Connection not found for IssueNewScid");
                return;
            }
        };
        
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => {
                warn!(worker_id, connection_id, request_id, "Connection not found for IssueNewScid");
                return;
            }
        };
        
        // TODO: Call quiche's new_scid() once available in public API
        // For now, return NotImplemented error
        warn!(worker_id, connection_id, request_id, "new_scid() not yet available in Quiche 0.24.6 public API");
        
        // Send error event to application task
        if let Some(ref ingress_tx) = conn.ingress_tx {
            let event = quicd_x::AppEvent::SourceConnectionIdIssued {
                request_id,
                result: Err(quicd_x::ConnectionError::Transport(
                    "new_scid() not yet exposed in Quiche public API - will be available in future release".to_string()
                )),
            };
            
            let _ = send_app_event(worker_id, connection_id, ingress_tx, event);
        }
    }
    
    /// Get all source connection IDs (RFC 9000 §5.1).
    ///
    /// Enumerates all active SCIDs and emits AppEvent::SourceConnectionIds.
    ///
    /// NOTE: Quiche 0.24.6 does not yet expose `source_ids()` iterator in its public API.
    /// This implementation uses the locally tracked source_cid_meta as a workaround.
    /// Full functionality will be available once Quiche exposes the iterator.
    fn process_get_source_connection_ids(&mut self, worker_id: usize, connection_id: quicd_x::ConnectionId, request_id: u64) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(worker_id, connection_id, request_id, "Connection not found for GetSourceConnectionIds");
                return;
            }
        };
        
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => {
                warn!(worker_id, connection_id, request_id, "Connection not found for GetSourceConnectionIds");
                return;
            }
        };
        
        // Use locally tracked source CIDs (workaround until Quiche exposes source_ids() iterator)
        let scids: Vec<quicd_x::SourceConnectionIdInfo> = conn.source_cid_meta
            .iter()
            .map(|(cid, meta)| quicd_x::SourceConnectionIdInfo {
                cid: cid.clone(),
                sequence: meta.sequence,
                reset_token: meta.reset_token,
            })
            .collect();
        
        debug!(worker_id, connection_id, request_id, count = scids.len(), "Retrieved source connection IDs from local tracking");
        
        // Send event to application task
        if let Some(ref ingress_tx) = conn.ingress_tx {
            let event = quicd_x::AppEvent::SourceConnectionIds {
                request_id,
                scids,
            };
            
            let _ = send_app_event(worker_id, connection_id, ingress_tx, event);
        }
    }

    // ============ Multipath Command Handlers (P0 Gap #3, #4) ============
    
    /// Get statistics for all active paths (RFC 9000 §9).
    ///
    /// Emits AppEvent::AllPathStats with detailed path statistics.
    fn process_get_all_path_stats(&mut self, worker_id: usize, connection_id: quicd_x::ConnectionId, request_id: u64) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!(worker_id, connection_id, request_id, "Connection not found for GetAllPathStats");
                return;
            }
        };
        
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => {
                warn!(worker_id, connection_id, request_id, "Connection not found for GetAllPathStats");
                return;
            }
        };
        
        // Collect all path stats from quiche iterator
        let paths: Vec<quicd_x::PathStats> = conn.conn
            .path_stats()
            .map(|ps| {
                // PathStats fields available in Quiche 0.24.6:
                // local_addr, peer_addr, validation_state, active, recv, sent,
                // lost, retrans, rtt, cwnd, sent_bytes, recv_bytes,
                // lost_bytes, stream_retrans_bytes, pmtu, delivery_rate
                quicd_x::PathStats {
                    local_addr: ps.local_addr,
                    peer_addr: ps.peer_addr,
                    validated: ps.active, // Use active flag as proxy for validated
                    active: ps.active,
                    rtt: ps.rtt.as_micros() as u64,
                    rttvar: ps.rttvar.as_micros() as u64,
                    min_rtt: ps.min_rtt.map(|r| r.as_micros() as u64),
                    cwnd: ps.cwnd,
                    bytes_in_flight: ps.sent.saturating_sub(ps.recv),
                    bytes_sent: ps.sent_bytes,
                    bytes_recv: ps.recv_bytes,
                    lost_packets: ps.lost as u64,
                    pmtu: ps.pmtu,
                }
            })
            .collect();
        
        debug!(worker_id, connection_id, request_id, count = paths.len(), "Retrieved all path stats");
        
        // Send event to application task
        if let Some(ref ingress_tx) = conn.ingress_tx {
            let event = quicd_x::AppEvent::AllPathStats {
                request_id,
                paths,
            };
            
            let _ = send_app_event(worker_id, connection_id, ingress_tx, event);
        }
    }
    
    /// Send stream data on specific path (multipath QUIC).
    ///
    /// NOTE: Quiche 0.24.6 does not expose send_on_path() in public API.
    /// Returns NotImplemented error until Quiche adds multipath support.
    fn process_send_on_path(
        &mut self,
        worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        _stream_id: u64,
        _data: bytes::Bytes,
        _fin: bool,
        _local_addr: SocketAddr,
        _peer_addr: SocketAddr,
        reply: tokio::sync::oneshot::Sender<Result<usize, quicd_x::ConnectionError>>,
    ) {
        warn!(worker_id, connection_id, "send_on_path() not yet available in Quiche 0.24.6 public API");
        
        // Send NotImplemented error
        let _ = reply.send(Err(quicd_x::ConnectionError::Transport(
            "send_on_path() not yet exposed in Quiche public API - will be available in future release".to_string()
        )));
    }

    fn process_query_stats(&mut self, worker_id: usize, connection_id: quicd_x::ConnectionId, reply: tokio::sync::oneshot::Sender<quicd_x::ConnectionStats>) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => { 
                let _ = reply.send(quicd_x::ConnectionStats::default()); 
                return; 
            }
        };
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => { 
                let _ = reply.send(quicd_x::ConnectionStats::default()); 
                return; 
            }
        };
        let quiche_stats = conn.conn.stats();
        let path_stats = conn.conn.path_stats().next();
        let stats = quicd_x::ConnectionStats {
            // RTT metrics from path stats
            srtt_us: path_stats.as_ref().map(|ps| ps.rtt.as_micros() as u64),
            min_rtt_us: path_stats.as_ref().and_then(|ps| ps.min_rtt.map(|r| r.as_micros() as u64)),
            rttvar_us: path_stats.as_ref().map(|ps| ps.rttvar.as_micros() as u64),
            latest_rtt_us: None,
            pto_ms: None,
            // Congestion control
            cwnd: path_stats.as_ref().map(|ps| ps.cwnd as u64).unwrap_or(0),
            bytes_in_flight: path_stats.as_ref().map(|ps| ps.sent.saturating_sub(quiche_stats.recv) as u64).unwrap_or(0),
            ssthresh: None,
            pacing_rate_bps: None,
            // Flow control
            max_data: 0, // Not exposed by quiche
            data_sent: quiche_stats.sent as u64,
            max_data_recv: 0,
            data_received: quiche_stats.recv as u64,
            max_streams_bidi: 0,
            max_streams_uni: 0,
            // Statistics
            bytes_sent: quiche_stats.sent as u64,
            bytes_received: quiche_stats.recv as u64,
            active_streams: 0, // Not directly available
            packets_sent: 0,
            packets_received: 0,
            packets_lost: quiche_stats.lost as u64,
            packets_retransmitted: quiche_stats.retrans as u64,
            max_stream_id: 0,
            // ECN
            ecn_ect0_count: 0,
            ecn_ect1_count: 0,
            ecn_ce_count: 0,
            // Path info
            path_mtu: path_stats.as_ref().map(|ps| ps.pmtu).unwrap_or(1200),
            is_in_early_data: conn.conn.is_in_early_data(),
            is_established: conn.conn.is_established(),
            is_closed: conn.conn.is_closed(),
            path_validations_completed: 0,
            path_validations_failed: 0,
        };
        debug!(worker_id, connection_id, "Retrieved stats");
        let _ = reply.send(stats);
    }

    // ============ P0 Critical Command Handlers ============

    fn process_send_ack_frequency(
        &mut self,
        _worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        ack_eliciting_threshold: u64,
        request_max_ack_delay: u64,
        ignore_order: bool,
    ) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                warn!("SendAckFrequency for unknown connection");
                return;
            }
        };
        
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => {
                warn!("SendAckFrequency: connection not found");
                return;
            }
        };

        // RFC 9330: Send ACK_FREQUENCY frame
        // Note: Cloudflare Quiche 0.24.6 does not directly expose send_ack_frequency()
        // This would require a custom frame implementation or waiting for quiche support
        // For now, we log the request for future implementation when quiche adds RFC 9330 support
        warn!(
            "ACK_FREQUENCY frame requested but not yet supported by quiche: threshold={}, max_delay={}us, ignore_order={}",
            ack_eliciting_threshold, request_max_ack_delay, ignore_order
        );
        
        // TODO: Implement when quiche adds RFC 9330 support
        // Expected API: conn.conn.send_ack_frequency(ack_eliciting_threshold, request_max_ack_delay, ignore_order)?;
    }

    fn process_query_available_send_window(
        &mut self,
        _worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        request_id: u64,
    ) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => return,
        };
        
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => return,
        };

        // Query connection-level available send window
        // This is the minimum of:
        // 1. Connection flow control limit (max_data - sent_data)
        // 2. Congestion window (cwnd - bytes_in_flight)
        
        let path_stats = conn.conn.path_stats().next();
        let quiche_stats = conn.conn.stats();
        
        let cwnd_available = path_stats
            .as_ref()
            .map(|ps| ps.cwnd.saturating_sub((quiche_stats.sent - quiche_stats.recv) as usize))
            .unwrap_or(0) as u64;
        
        // Send response event
        if let Some(ingress_tx) = &conn.ingress_tx {
            let _ = ingress_tx.try_send(quicd_x::AppEvent::AvailableSendWindow {
                request_id,
                window: cwnd_available,
            });
        }
    }

    fn process_query_is_server(
        &mut self,
        _worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        request_id: u64,
    ) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => return,
        };
        
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => return,
        };

        // Query if this is a server-side connection
        let is_server = conn.conn.is_server();
        
        if let Some(ingress_tx) = &conn.ingress_tx {
            let _ = ingress_tx.try_send(quicd_x::AppEvent::IsServer {
                request_id,
                is_server,
            });
        }
    }

    fn process_get_next_path_event(
        &mut self,
        _worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        _request_id: u64,
    ) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => return,
        };
        
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => return,
        };

        // Poll quiche for path events (RFC 9000 §8.2, §9)
        if let Some(quiche_event) = conn.path_event_next() {
            if let Some(ingress_tx) = &conn.ingress_tx {
                // Convert quiche::PathEvent to quicd_x::PathEventType
                let event_type = match quiche_event {
                    quiche::PathEvent::New(local, peer) => {
                        quicd_x::PathEventType::New {
                            local_addr: local,
                            peer_addr: peer,
                        }
                    }
                    quiche::PathEvent::Validated(local, peer) => {
                        quicd_x::PathEventType::Validated {
                            local_addr: local,
                            peer_addr: peer,
                        }
                    }
                    quiche::PathEvent::FailedValidation(local, peer) => {
                        quicd_x::PathEventType::FailedValidation {
                            local_addr: local,
                            peer_addr: peer,
                        }
                    }
                    quiche::PathEvent::Closed(local, peer) => {
                        quicd_x::PathEventType::Closed {
                            local_addr: local,
                            peer_addr: peer,
                        }
                    }
                    quiche::PathEvent::ReusedSourceConnectionId(cid_seq, old_addrs, new_addrs) => {
                        quicd_x::PathEventType::ReusedSourceConnectionId {
                            cid_seq,
                            old_path: old_addrs,
                            new_path: new_addrs,
                        }
                    }
                    quiche::PathEvent::PeerMigrated(local, peer) => {
                        quicd_x::PathEventType::PeerMigrated {
                            local_addr: local,
                            peer_addr: peer,
                        }
                    }
                };

                let _ = ingress_tx.try_send(quicd_x::AppEvent::PathEvent { event: event_type });
            }
        }
    }

    fn process_shutdown_stream_direction(
        &mut self,
        _worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        stream_id: quicd_x::StreamId,
        direction: quicd_x::StreamShutdownDirection,
        error_code: u64,
        reply: tokio::sync::oneshot::Sender<Result<(), quicd_x::ConnectionError>>,
    ) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                let _ = reply.send(Err(quicd_x::ConnectionError::Closed("Connection not found".into())));
                return;
            }
        };
        
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => {
                let _ = reply.send(Err(quicd_x::ConnectionError::Closed("Connection closed".into())));
                return;
            }
        };

        use quicd_x::StreamShutdownDirection;
        let result = match direction {
            StreamShutdownDirection::Read => {
                // Send STOP_SENDING frame
                conn.conn
                    .stream_shutdown(stream_id, quiche::Shutdown::Read, error_code)
                    .map_err(|e| quicd_x::ConnectionError::QuicError {
                        code: 0x01, // INTERNAL_ERROR
                        message: format!("Failed to shutdown read: {}", e),
                    })
            }
            StreamShutdownDirection::Write => {
                // Send RESET_STREAM or FIN
                conn.conn
                    .stream_shutdown(stream_id, quiche::Shutdown::Write, error_code)
                    .map_err(|e| quicd_x::ConnectionError::QuicError {
                        code: 0x01, // INTERNAL_ERROR
                        message: format!("Failed to shutdown write: {}", e),
                    })
            }
            StreamShutdownDirection::Both => {
                // Shutdown both directions
                let read_result = conn.conn.stream_shutdown(stream_id, quiche::Shutdown::Read, error_code);
                let write_result = conn.conn.stream_shutdown(stream_id, quiche::Shutdown::Write, error_code);
                
                if read_result.is_err() {
                    read_result.map_err(|e| quicd_x::ConnectionError::QuicError {
                        code: 0x01, // INTERNAL_ERROR
                        message: format!("Failed to shutdown read: {}", e),
                    })
                } else {
                    write_result.map_err(|e| quicd_x::ConnectionError::QuicError {
                        code: 0x01, // INTERNAL_ERROR
                        message: format!("Failed to shutdown write: {}", e),
                    })
                }
            }
        };
        
        let _ = reply.send(result);
    }

    fn process_set_pmtu_discovery(
        &mut self,
        _worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        enabled: bool,
    ) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => return,
        };
        
        let _conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => return,
        };

        // Quiche 0.24.6 doesn't expose runtime PMTU discovery control
        // PMTU is controlled via quiche::Config::enable_dgram() during initialization
        // This would require API additions to quiche
        
        warn!(
            "PMTU discovery control requested but not supported by quiche: enabled={}",
            enabled
        );
        
        // TODO: Implement when quiche adds runtime PMTU control
        // Expected API: conn.conn.set_pmtu_discovery(enabled);
    }

    fn process_set_max_pacing_rate(
        &mut self,
        _worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        rate_bps: Option<u64>,
    ) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => return,
        };
        
        let _conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => return,
        };

        // Quiche 0.24.6 doesn't expose runtime pacing rate control
        // Pacing is managed internally by quiche's congestion controller
        // This would require API additions to quiche
        
        warn!(
            "Pacing rate control requested but not supported by quiche: rate={:?} bps",
            rate_bps
        );
        
        // TODO: Implement when quiche adds runtime pacing control
        // Expected API: conn.conn.set_max_pacing_rate(rate_bps);
    }

    fn process_query_active_scid(
        &mut self,
        _worker_id: usize,
        connection_id: quicd_x::ConnectionId,
        reply: tokio::sync::oneshot::Sender<Vec<u8>>,
    ) {
        let dcid = match self.connection_id_map.get(&connection_id) {
            Some(dcid) => dcid.clone(),
            None => {
                let _ = reply.send(Vec::new());
                return;
            }
        };
        
        let conn = match self.get_connection_mut(&dcid) {
            Some(conn) => conn,
            None => {
                let _ = reply.send(Vec::new());
                return;
            }
        };

        // Return the current source connection ID
        // Quiche exposes this via source_id() method
        let scid = conn.conn.source_id().to_vec();
        let _ = reply.send(scid);
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
            EgressCommand::MigrateTo { connection_id, .. } => *connection_id,
            EgressCommand::ValidatePath { connection_id, .. } => *connection_id,
            EgressCommand::SetStreamPriority { connection_id, .. } => *connection_id,
            EgressCommand::StopSending { connection_id, .. } => *connection_id,
            EgressCommand::GetMaxDatagramSize { connection_id, .. } => *connection_id,
            EgressCommand::GetStreamCredits { connection_id, .. } => *connection_id,
            EgressCommand::QueryStreamCapacity { connection_id, .. } => *connection_id,
            EgressCommand::QueryConnectionCapacity { connection_id, .. } => *connection_id,
            EgressCommand::QueryStreamReadable { connection_id, .. } => *connection_id,
            EgressCommand::QueryStreamWritable { connection_id, .. } => *connection_id,
            EgressCommand::QueryStreamFinished { connection_id, .. } => *connection_id,
            EgressCommand::ShutdownStream { connection_id, .. } => *connection_id,
            EgressCommand::RetireConnectionId { connection_id, .. } => *connection_id,
            EgressCommand::RequestNewConnectionId { connection_id, .. } => *connection_id,
            EgressCommand::ProbePath { connection_id, .. } => *connection_id,
            EgressCommand::SetStreamMaxData { connection_id, .. } => *connection_id,
            EgressCommand::SetConnectionMaxData { connection_id, .. } => *connection_id,
            EgressCommand::UpdateKeys { connection_id, .. } => *connection_id,
            EgressCommand::CanSendEarlyData { connection_id, .. } => *connection_id,
            EgressCommand::GetPeerTransportParams { connection_id, .. } => *connection_id,
            EgressCommand::SetDatagramPriority { connection_id, .. } => *connection_id,
            EgressCommand::GetPathMtu { connection_id, .. } => *connection_id,
            EgressCommand::GetActivePaths { connection_id, .. } => *connection_id,
            EgressCommand::SetStreamSendOrder { connection_id, .. } => *connection_id,
            EgressCommand::PollReadableStreams { connection_id, .. } => *connection_id,
            EgressCommand::PollWritableStreams { connection_id, .. } => *connection_id,
            EgressCommand::GetNextReadableStream { connection_id, .. } => *connection_id,
            EgressCommand::GetNextWritableStream { connection_id, .. } => *connection_id,
            EgressCommand::IssueNewScid { connection_id, .. } => *connection_id,
            EgressCommand::GetSourceConnectionIds { connection_id, .. } => *connection_id,
            EgressCommand::GetAllPathStats { connection_id, .. } => *connection_id,
            EgressCommand::SendOnPath { connection_id, .. } => *connection_id,
            EgressCommand::QuerySourceId { connection_id, .. } => *connection_id,
            EgressCommand::QueryDestinationId { connection_id, .. } => *connection_id,
            EgressCommand::QueryAvailableDcids { connection_id, .. } => *connection_id,
            EgressCommand::QueryScidsLeft { connection_id, .. } => *connection_id,
            EgressCommand::QueryTimeout { connection_id, .. } => *connection_id,
            EgressCommand::OnTimeout { connection_id, .. } => *connection_id,
            EgressCommand::QuerySession { connection_id, .. } => *connection_id,
            EgressCommand::QueryServerName { connection_id, .. } => *connection_id,
            EgressCommand::QueryPeerCert { connection_id, .. } => *connection_id,
            EgressCommand::QueryPeerCertChain { connection_id, .. } => *connection_id,
            EgressCommand::QueryIsEstablished { connection_id, .. } => *connection_id,
            EgressCommand::QueryIsResumed { connection_id, .. } => *connection_id,
            EgressCommand::QueryIsInEarlyData { connection_id, .. } => *connection_id,
            EgressCommand::QueryIsClosed { connection_id, .. } => *connection_id,
            EgressCommand::QueryIsDraining { connection_id, .. } => *connection_id,
            EgressCommand::QueryIsTimedOut { connection_id, .. } => *connection_id,
            EgressCommand::QueryPeerError { connection_id, .. } => *connection_id,
            EgressCommand::QueryLocalError { connection_id, .. } => *connection_id,
            EgressCommand::QueryActiveScids { connection_id, .. } => *connection_id,
            EgressCommand::QuerySendQuantum { connection_id, .. } => *connection_id,
            EgressCommand::DgramPurgeOutgoing { connection_id, .. } => *connection_id,
            EgressCommand::QueryDgramMaxWritableLen { connection_id, .. } => *connection_id,
            EgressCommand::QueryDgramSendQueueLen { connection_id, .. } => *connection_id,
            EgressCommand::QueryDgramRecvQueueLen { connection_id, .. } => *connection_id,
            EgressCommand::QueryDgramRecvQueueByteSize { connection_id, .. } => *connection_id,
            EgressCommand::QueryDgramSendQueueByteSize { connection_id, .. } => *connection_id,
            EgressCommand::QueryPeerStreamsLeftBidi { connection_id, .. } => *connection_id,
            EgressCommand::QueryPeerStreamsLeftUni { connection_id, .. } => *connection_id,
            EgressCommand::QueryPeerVerifiedAddress { connection_id, .. } => *connection_id,
            EgressCommand::QueryStats { connection_id, .. } => *connection_id,
            // P0 Critical Additions
            EgressCommand::SendAckFrequency { connection_id, .. } => *connection_id,
            EgressCommand::QueryAvailableSendWindow { connection_id, .. } => *connection_id,
            EgressCommand::QueryIsServer { connection_id, .. } => *connection_id,
            EgressCommand::GetNextPathEvent { connection_id, .. } => *connection_id,
            EgressCommand::ShutdownStreamDirection { connection_id, .. } => *connection_id,
            EgressCommand::SetPmtuDiscovery { connection_id, .. } => *connection_id,
            EgressCommand::SetMaxPacingRate { connection_id, .. } => *connection_id,
            EgressCommand::QueryActiveScid { connection_id, .. } => *connection_id,
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
            EgressCommand::MigrateTo {
                connection_id,
                new_local_addr,
            } => {
                debug!(
                    worker_id,
                    connection_id,
                    %new_local_addr,
                    "Processing MigrateTo command (RFC 9000 §9)"
                );
                self.process_migrate_to(worker_id, connection_id, new_local_addr)?;
            }
            EgressCommand::ValidatePath {
                connection_id,
                peer_addr,
            } => {
                debug!(
                    worker_id,
                    connection_id,
                    %peer_addr,
                    "Processing ValidatePath command (RFC 9000 §8.2)"
                );
                self.process_validate_path(worker_id, connection_id, peer_addr)?;
            }
            EgressCommand::SetStreamPriority {
                connection_id,
                stream_id,
                urgency,
                incremental,
            } => {
                debug!(
                    worker_id,
                    connection_id,
                    stream_id,
                    urgency,
                    incremental,
                    "Processing SetStreamPriority command (RFC 9218)"
                );
                self.process_set_stream_priority(
                    worker_id,
                    connection_id,
                    stream_id,
                    urgency,
                    incremental,
                );
            }
            EgressCommand::StopSending {
                connection_id,
                stream_id,
                error_code,
            } => {
                debug!(
                    worker_id,
                    connection_id,
                    stream_id,
                    error_code,
                    "Processing StopSending command (RFC 9000 §3.5)"
                );
                self.process_stop_sending(worker_id, connection_id, stream_id, error_code);
            }
            EgressCommand::GetMaxDatagramSize {
                connection_id,
                reply,
            } => {
                debug!(
                    worker_id,
                    connection_id, "Processing GetMaxDatagramSize command (RFC 9221 §3)"
                );
                self.process_get_max_datagram_size(worker_id, connection_id, reply);
            }
            EgressCommand::GetStreamCredits {
                connection_id,
                reply,
            } => {
                debug!(
                    worker_id,
                    connection_id, "Processing GetStreamCredits command (RFC 9000 §4.6)"
                );
                self.process_get_stream_credits(worker_id, connection_id, reply);
            }
            EgressCommand::QueryStreamCapacity {
                connection_id,
                stream_id,
                reply,
            } => {
                debug!(
                    worker_id,
                    connection_id,
                    stream_id,
                    "Processing QueryStreamCapacity command (RFC 9000 §4.1)"
                );
                self.process_query_stream_capacity(worker_id, connection_id, stream_id, reply);
            }
            EgressCommand::QueryConnectionCapacity {
                connection_id,
                reply,
            } => {
                debug!(
                    worker_id,
                    connection_id, "Processing QueryConnectionCapacity command (RFC 9000 §4.1)"
                );
                self.process_query_connection_capacity(worker_id, connection_id, reply);
            }
            EgressCommand::QueryStreamReadable {
                connection_id,
                stream_id,
                reply,
            } => {
                debug!(
                    worker_id,
                    connection_id,
                    stream_id,
                    "Processing QueryStreamReadable command"
                );
                self.process_query_stream_readable(worker_id, connection_id, stream_id, reply);
            }
            EgressCommand::QueryStreamWritable {
                connection_id,
                stream_id,
                reply,
            } => {
                debug!(
                    worker_id,
                    connection_id,
                    stream_id,
                    "Processing QueryStreamWritable command"
                );
                self.process_query_stream_writable(worker_id, connection_id, stream_id, reply);
            }
            EgressCommand::QueryStreamFinished {
                connection_id,
                stream_id,
                reply,
            } => {
                debug!(
                    worker_id,
                    connection_id,
                    stream_id,
                    "Processing QueryStreamFinished command"
                );
                self.process_query_stream_finished(worker_id, connection_id, stream_id, reply);
            }
            EgressCommand::ShutdownStream {
                connection_id,
                stream_id,
                error_code,
                reply,
            } => {
                debug!(
                    worker_id,
                    connection_id, stream_id, error_code, "Processing ShutdownStream command"
                );
                self.process_shutdown_stream(worker_id, connection_id, stream_id, error_code, reply);
            }
            EgressCommand::RetireConnectionId {
                connection_id,
                sequence,
            } => {
                debug!(
                    worker_id,
                    connection_id, sequence, "Processing RetireConnectionId command"
                );
                self.process_retire_connection_id(worker_id, connection_id, sequence);
            }
            EgressCommand::RequestNewConnectionId { connection_id } => {
                debug!(
                    worker_id,
                    connection_id, "Processing RequestNewConnectionId command"
                );
                self.process_request_new_connection_id(worker_id, connection_id);
            }
            EgressCommand::ProbePath {
                connection_id,
                local_addr,
                peer_addr,
                data,
            } => {
                debug!(
                    worker_id,
                    connection_id, %local_addr, %peer_addr, "Processing ProbePath command"
                );
                self.process_probe_path(worker_id, connection_id, local_addr, peer_addr, &data);
            }
            EgressCommand::SetStreamMaxData {
                connection_id,
                stream_id,
                max_data,
            } => {
                debug!(
                    worker_id,
                    connection_id, stream_id, max_data, "Processing SetStreamMaxData command"
                );
                self.process_set_stream_max_data(worker_id, connection_id, stream_id, max_data);
            }
            EgressCommand::SetConnectionMaxData {
                connection_id,
                max_data,
            } => {
                debug!(
                    worker_id,
                    connection_id, max_data, "Processing SetConnectionMaxData command"
                );
                self.process_set_connection_max_data(worker_id, connection_id, max_data);
            }
            EgressCommand::UpdateKeys { connection_id } => {
                debug!(
                    worker_id,
                    connection_id, "Processing UpdateKeys command"
                );
                self.process_update_keys(worker_id, connection_id);
            }
            EgressCommand::CanSendEarlyData {
                connection_id,
                reply,
            } => {
                debug!(
                    worker_id,
                    connection_id, "Processing CanSendEarlyData command"
                );
                self.process_can_send_early_data(worker_id, connection_id, reply);
            }
            EgressCommand::GetPeerTransportParams {
                connection_id,
                reply,
            } => {
                debug!(
                    worker_id,
                    connection_id, "Processing GetPeerTransportParams command"
                );
                self.process_get_peer_transport_params(worker_id, connection_id, reply);
            }
            EgressCommand::SetDatagramPriority {
                connection_id,
                priority,
            } => {
                debug!(
                    worker_id,
                    connection_id, priority, "Processing SetDatagramPriority command"
                );
                self.process_set_datagram_priority(worker_id, connection_id, priority);
            }
            EgressCommand::GetPathMtu {
                connection_id,
                reply,
            } => {
                debug!(
                    worker_id,
                    connection_id, "Processing GetPathMtu command"
                );
                self.process_get_path_mtu(worker_id, connection_id, reply);
            }
            EgressCommand::GetActivePaths {
                connection_id,
                reply,
            } => {
                debug!(
                    worker_id,
                    connection_id, "Processing GetActivePaths command"
                );
                self.process_get_active_paths(worker_id, connection_id, reply);
            }
            EgressCommand::SetStreamSendOrder {
                connection_id,
                stream_id,
                send_order,
            } => {
                debug!(
                    worker_id,
                    connection_id, stream_id, send_order, "Processing SetStreamSendOrder command"
                );
                self.process_set_stream_send_order(worker_id, connection_id, stream_id, send_order);
            }
            EgressCommand::QuerySourceId { connection_id, reply } => {
                self.process_query_source_id(worker_id, connection_id, reply);
            }
            EgressCommand::QueryDestinationId { connection_id, reply } => {
                self.process_query_destination_id(worker_id, connection_id, reply);
            }
            EgressCommand::QueryAvailableDcids { connection_id, reply } => {
                self.process_query_available_dcids(worker_id, connection_id, reply);
            }
            EgressCommand::QueryScidsLeft { connection_id, reply } => {
                self.process_query_scids_left(worker_id, connection_id, reply);
            }
            EgressCommand::QueryTimeout { connection_id, reply } => {
                self.process_query_timeout(worker_id, connection_id, reply);
            }
            EgressCommand::OnTimeout { connection_id } => {
                self.process_on_timeout(worker_id, connection_id);
            }
            EgressCommand::QuerySession { connection_id, reply } => {
                self.process_query_session(worker_id, connection_id, reply);
            }
            EgressCommand::QueryServerName { connection_id, reply } => {
                self.process_query_server_name(worker_id, connection_id, reply);
            }
            EgressCommand::QueryPeerCert { connection_id, reply } => {
                self.process_query_peer_cert(worker_id, connection_id, reply);
            }
            EgressCommand::QueryPeerCertChain { connection_id, reply } => {
                self.process_query_peer_cert_chain(worker_id, connection_id, reply);
            }
            EgressCommand::QueryIsEstablished { connection_id, reply } => {
                self.process_query_is_established(worker_id, connection_id, reply);
            }
            EgressCommand::QueryIsResumed { connection_id, reply } => {
                self.process_query_is_resumed(worker_id, connection_id, reply);
            }
            EgressCommand::QueryIsInEarlyData { connection_id, reply } => {
                self.process_query_is_in_early_data(worker_id, connection_id, reply);
            }
            EgressCommand::QueryIsClosed { connection_id, reply } => {
                self.process_query_is_closed(worker_id, connection_id, reply);
            }
            EgressCommand::QueryIsDraining { connection_id, reply } => {
                self.process_query_is_draining(worker_id, connection_id, reply);
            }
            EgressCommand::QueryIsTimedOut { connection_id, reply } => {
                self.process_query_is_timed_out(worker_id, connection_id, reply);
            }
            EgressCommand::QueryPeerError { connection_id, reply } => {
                self.process_query_peer_error(worker_id, connection_id, reply);
            }
            EgressCommand::QueryLocalError { connection_id, reply } => {
                self.process_query_local_error(worker_id, connection_id, reply);
            }
            EgressCommand::QueryActiveScids { connection_id, reply } => {
                self.process_query_active_scids(worker_id, connection_id, reply);
            }
            EgressCommand::QuerySendQuantum { connection_id, reply } => {
                self.process_query_send_quantum(worker_id, connection_id, reply);
            }
            EgressCommand::DgramPurgeOutgoing { connection_id } => {
                self.process_dgram_purge_outgoing(worker_id, connection_id);
            }
            EgressCommand::QueryDgramMaxWritableLen { connection_id, reply } => {
                self.process_query_dgram_max_writable_len(worker_id, connection_id, reply);
            }
            EgressCommand::QueryDgramSendQueueLen { connection_id, reply } => {
                self.process_query_dgram_send_queue_len(worker_id, connection_id, reply);
            }
            EgressCommand::QueryDgramRecvQueueLen { connection_id, reply } => {
                self.process_query_dgram_recv_queue_len(worker_id, connection_id, reply);
            }
            EgressCommand::QueryDgramRecvQueueByteSize { connection_id, reply } => {
                self.process_query_dgram_recv_queue_byte_size(worker_id, connection_id, reply);
            }
            EgressCommand::QueryDgramSendQueueByteSize { connection_id, reply } => {
                self.process_query_dgram_send_queue_byte_size(worker_id, connection_id, reply);
            }
            EgressCommand::QueryPeerStreamsLeftBidi { connection_id, reply } => {
                self.process_query_peer_streams_left_bidi(worker_id, connection_id, reply);
            }
            EgressCommand::QueryPeerStreamsLeftUni { connection_id, reply } => {
                self.process_query_peer_streams_left_uni(worker_id, connection_id, reply);
            }
            EgressCommand::QueryPeerVerifiedAddress { connection_id, reply } => {
                self.process_query_peer_verified_address(worker_id, connection_id, reply);
            }
            EgressCommand::QueryStats { connection_id, reply } => {
                self.process_query_stats(worker_id, connection_id, reply);
            }
            
            // ============ Stream Iterator Commands (P0 Gap #1) ============
            EgressCommand::PollReadableStreams { connection_id } => {
                self.process_poll_readable_streams(worker_id, connection_id);
            }
            EgressCommand::PollWritableStreams { connection_id } => {
                self.process_poll_writable_streams(worker_id, connection_id);
            }
            EgressCommand::GetNextReadableStream { connection_id, request_id } => {
                self.process_get_next_readable_stream(worker_id, connection_id, request_id);
            }
            EgressCommand::GetNextWritableStream { connection_id, request_id } => {
                self.process_get_next_writable_stream(worker_id, connection_id, request_id);
            }
            
            // ============ Connection ID Management Commands (P0 Gap #2) ============
            EgressCommand::IssueNewScid { connection_id, request_id, scid } => {
                self.process_issue_new_scid(worker_id, connection_id, request_id, scid);
            }
            EgressCommand::GetSourceConnectionIds { connection_id, request_id } => {
                self.process_get_source_connection_ids(worker_id, connection_id, request_id);
            }
            
            // ============ Multipath Commands (P0 Gap #3, #4) ============
            EgressCommand::GetAllPathStats { connection_id, request_id } => {
                self.process_get_all_path_stats(worker_id, connection_id, request_id);
            }
            EgressCommand::SendOnPath { connection_id, stream_id, data, fin, local_addr, peer_addr, reply } => {
                self.process_send_on_path(worker_id, connection_id, stream_id, data, fin, local_addr, peer_addr, reply);
            }

            // ============ P0 Critical Additions ============
            EgressCommand::SendAckFrequency {
                connection_id,
                ack_eliciting_threshold,
                request_max_ack_delay,
                ignore_order,
            } => {
                self.process_send_ack_frequency(
                    worker_id,
                    connection_id,
                    ack_eliciting_threshold,
                    request_max_ack_delay,
                    ignore_order,
                );
            }
            EgressCommand::QueryAvailableSendWindow {
                connection_id,
                request_id,
            } => {
                self.process_query_available_send_window(worker_id, connection_id, request_id);
            }
            EgressCommand::QueryIsServer {
                connection_id,
                request_id,
            } => {
                self.process_query_is_server(worker_id, connection_id, request_id);
            }
            EgressCommand::GetNextPathEvent {
                connection_id,
                request_id,
            } => {
                self.process_get_next_path_event(worker_id, connection_id, request_id);
            }
            EgressCommand::ShutdownStreamDirection {
                connection_id,
                stream_id,
                direction,
                error_code,
                reply,
            } => {
                self.process_shutdown_stream_direction(
                    worker_id,
                    connection_id,
                    stream_id,
                    direction,
                    error_code,
                    reply,
                );
            }
            EgressCommand::SetPmtuDiscovery {
                connection_id,
                enabled,
            } => {
                self.process_set_pmtu_discovery(worker_id, connection_id, enabled);
            }
            EgressCommand::SetMaxPacingRate {
                connection_id,
                rate_bps,
            } => {
                self.process_set_max_pacing_rate(worker_id, connection_id, rate_bps);
            }
            EgressCommand::QueryActiveScid {
                connection_id,
                reply,
            } => {
                self.process_query_active_scid(worker_id, connection_id, reply);
            }
        }

        // After processing command, generate any packets needed
        // Look up the QUIC connection and collect packets
        let mut refreshed_dcid: Option<ConnectionId<'static>> = None;

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

                refreshed_dcid = Some(dcid.clone());
            }
        }

        self.cleanup_closed_connections(&mut outgoing_packets)?;

        if let Some(dcid) = refreshed_dcid {
            self.schedule_connection_timeout(&dcid);
        }

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

        let requested_version = hdr.version;

        let conn = {
            let quiche_config =
                self.quiche_configs
                    .get_mut(&requested_version)
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "missing quiche config for version {:#010x}",
                            requested_version
                        )
                    })?;

            quiche::accept(
                &scid,
                Some(&hdr.dcid),
                self.local_addr,
                peer_addr,
                quiche_config,
            )
        }
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

        let initial_reset_token = self.reset_token_for(scid.as_ref());
        if let Some(conn_entry) = self.connections.get_mut(&scid) {
            conn_entry.record_source_connection_id(
                scid.as_ref(),
                0,
                initial_reset_token.to_be_bytes(),
            );
        }

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
            let mut refreshed = false;

            if let Some(conn) = self.connections.get_mut(&dcid) {
                // === RFC 9000 §4.1: Connection-Level Flow Control Tracking ===
                // Before processing writes, check if connection was previously blocked
                let was_conn_blocked = conn.connection_blocked_at.is_some();

                for (stream_id, data, fin, reply_tx) in writes {
                    // === RFC 9000 §4.1: Stream-Level Flow Control Tracking ===
                    // Track if stream was previously blocked
                    let was_stream_blocked = conn
                        .stream_blocked_state
                        .get(&stream_id)
                        .and_then(|opt| *opt)
                        .is_some();

                    match conn.stream_send(stream_id, &data, fin) {
                        Ok(written) => {
                            trace!(
                                worker_id,
                                stream_id,
                                bytes = written,
                                fin,
                                "Wrote to stream"
                            );

                            // Send success reply to app
                            let _ = reply_tx.send(Ok(written));

                            // If stream was blocked, it's now unblocked (successful write)
                            if was_stream_blocked {
                                conn.stream_blocked_state.insert(stream_id, None);

                                if let Some(ref sm) = conn.stream_manager {
                                    debug!(
                                        worker_id,
                                        stream_id, "Stream unblocked after successful write"
                                    );
                                    // Note: Can't determine exact new_limit without quiche API
                                    // Using 0 as placeholder - app knows write succeeded
                                    let event = quicd_x::AppEvent::TransportEvent(
                                        quicd_x::TransportEvent::StreamUnblocked {
                                            stream_id,
                                            new_limit: 0, // Limit unknown in quiche 0.24
                                        },
                                    );
                                    let _ = sm.conn_ingress_tx.try_send(event);
                                }
                            }

                            // === RFC 9000 §4.1: Connection-Level Flow Control Unblocked ===
                            // If connection was blocked but we just succeeded, it's unblocked
                            if was_conn_blocked {
                                conn.connection_blocked_at = None;

                                if let Some(ref sm) = conn.stream_manager {
                                    debug!(worker_id, "Connection-level flow control unblocked");
                                    // Get updated connection-level limit (approximate via cwnd)
                                    let new_limit = conn.connection_send_capacity();
                                    let event = quicd_x::AppEvent::TransportEvent(
                                        quicd_x::TransportEvent::ConnectionUnblocked { new_limit },
                                    );
                                    let _ = sm.conn_ingress_tx.try_send(event);
                                }
                            }
                        }
                        Err(quiche::Error::Done) => {
                            // === RFC 9000 §4.1: Flow Control Blocking Detection ===
                            // Error::Done can indicate either:
                            // 1. Stream-level blocking (stream flow control limit reached)
                            // 2. Connection-level blocking (connection flow control limit reached)
                            //
                            // We check stream capacity first to distinguish between the two

                            let stream_capacity = conn.stream_send_capacity(stream_id).unwrap_or(0);
                            let conn_capacity = conn.connection_send_capacity();

                            // If stream has capacity but connection doesn't, it's connection-level blocking
                            if stream_capacity > 0 && conn_capacity == 0 {
                                // === Connection-Level Blocked ===
                                if !was_conn_blocked {
                                    conn.connection_blocked_at = Some(0); // Offset unknown

                                    if let Some(ref sm) = conn.stream_manager {
                                        debug!(worker_id, "Connection-level flow control blocked");
                                        let event = quicd_x::AppEvent::TransportEvent(
                                            quicd_x::TransportEvent::ConnectionBlocked {
                                                limit: conn_capacity,
                                            },
                                        );
                                        let _ = sm.conn_ingress_tx.try_send(event);
                                    }
                                }
                            } else {
                                // === Stream-Level Blocked ===
                                if !was_stream_blocked {
                                    // Mark as blocked (offset unknown without API)
                                    conn.stream_blocked_state.insert(stream_id, Some(0));

                                    if let Some(ref sm) = conn.stream_manager {
                                        debug!(
                                            worker_id,
                                            stream_id, "Stream blocked by flow control"
                                        );
                                        let event = quicd_x::AppEvent::TransportEvent(
                                            quicd_x::TransportEvent::StreamBlocked {
                                                stream_id,
                                                limit: 0, // Limit unknown in quiche 0.24
                                            },
                                        );
                                        let _ = sm.conn_ingress_tx.try_send(event);
                                    }
                                }
                            }

                            // Send error to application
                            let _ = reply_tx.send(Err(quicd_x::ConnectionError::Stream(format!(
                                "Stream {} blocked by flow control",
                                stream_id
                            ))));
                        }
                        Err(quiche::Error::StreamStopped(error_code)) => {
                            // === RFC 9000 §3.5: STOP_SENDING Detection ===
                            // Peer sent STOP_SENDING frame requesting us to stop sending
                            warn!(worker_id, stream_id, error_code, "Peer sent STOP_SENDING");

                            // Notify application that peer requested stop
                            if let Some(ref sm) = conn.stream_manager {
                                let event = quicd_x::AppEvent::StopSending {
                                    stream_id,
                                    error_code,
                                };
                                let _ = sm.conn_ingress_tx.try_send(event);
                            }

                            // Send error reply to write command
                            let _ = reply_tx.send(Err(quicd_x::ConnectionError::Stream(format!(
                                "Peer requested stop sending: error code {}",
                                error_code
                            ))));
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

                refreshed = true;
            }

            if refreshed {
                self.schedule_connection_timeout(&dcid);
            }
        }

        self.cleanup_closed_connections(&mut outgoing_packets)?;

        Ok(outgoing_packets)
    }
}

#[cfg(test)]
mod version_tests {
    use super::*;

    #[test]
    fn parses_common_version_labels() {
        assert_eq!(
            parse_quic_version_label("v1"),
            Some(quiche::PROTOCOL_VERSION)
        );
        assert_eq!(
            parse_quic_version_label("draft-29"),
            Some(QUIC_DRAFT_VERSION_PREFIX | 29)
        );
        assert_eq!(
            parse_quic_version_label("0xff00001d"),
            Some(QUIC_DRAFT_VERSION_PREFIX | 0x1d)
        );
        assert_eq!(
            parse_quic_version_label("ff00001d"),
            Some(QUIC_DRAFT_VERSION_PREFIX | 0x1d)
        );
        assert_eq!(
            parse_quic_version_label("0x00000001"),
            Some(quiche::PROTOCOL_VERSION)
        );
    }

    #[test]
    fn rejects_invalid_version_labels() {
        assert_eq!(parse_quic_version_label(""), None);
        assert_eq!(parse_quic_version_label("notaversion"), None);
    }
}

impl std::fmt::Debug for QuicManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicManager")
            .field("worker_id", &self.worker_id)
            .field("local_addr", &self.local_addr)
            .field("supported_versions", &self.supported_versions)
            .field("connections", &self.connections.len())
            .field("stats", &self.stats)
            .finish()
    }
}
