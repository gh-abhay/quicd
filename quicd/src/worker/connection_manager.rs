//! Connection manager for worker threads.
//!
//! Manages QUIC connections and routes packets to the appropriate connection.
//! Each worker thread has its own connection manager with isolated state.
//!
//! # Slab-Based Architecture
//!
//! Uses `Slab<ConnectionState>` for zero-allocation connection storage:
//! - Pre-allocated capacity at worker startup
//! - O(1) insertion and removal
//! - Connection IDs map to SlabIndex for routing
//! - Predictable memory footprint

use bytes::{Bytes, BytesMut};
use crate::netio::buffer::WorkerBuffer;
use crate::routing::{RoutingConnectionIdGenerator, current_generation};
use crossbeam_channel::Sender as CrossbeamSender;
use quicd_quic::{ConnectionConfig, Packet, PacketType, VERSION_1, Side, QuicConnection, DatagramInput};
use quicd_quic::{Connection, ConnectionEvent, ConnectionState as QuicConnectionState, StreamId as QuicStreamId};
use quicd_quic::cid::{ConnectionIdGenerator, ConnectionId};
use quicd_quic::crypto::CryptoLevel;
use quicd_quic::types::{Instant as QuicInstant, StreamDirection};
use quicd_x::{ConnectionHandle, Event, Command, StreamId as XStreamId};
use quicd_x::ConnectionId as XConnectionId;
use slab::Slab;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::runtime::Handle as TokioHandle;
use tokio::sync::mpsc;
use tracing::{error, info, warn, debug, trace};

/// Default maximum concurrent connections per worker.
/// This provides predictable memory usage: ~100MB per worker for 100k connections.
const DEFAULT_MAX_CONNECTIONS_PER_WORKER: usize = 100_000;

/// Slab index for a connection (maps to Slab storage).
type SlabIndex = usize;

/// Maps incoming packets to QUIC connections using Slab allocation.
pub struct ConnectionManager {
    /// Pre-allocated Slab for connection storage.
    /// Zero allocation on hot path - connections reuse slots.
    connections: Slab<ConnectionState>,
    
    /// Mapping from DCID to Slab index for packet routing.
    /// Multiple DCIDs can map to same connection (CID rotation).
    dcid_to_slab: HashMap<ConnectionId, SlabIndex>,
    
    /// Mapping from SCID to Slab index for egress command routing.
    scid_to_slab: HashMap<ConnectionId, SlabIndex>,
    
    /// Configuration for new connections.
    config: ConnectionConfig,

    /// Tokio runtime handle for spawning application tasks.
    tokio_handle: TokioHandle,
    
    /// Worker egress channel sender (unbounded, cloned for each connection).
    egress_tx: CrossbeamSender<Command>,
    
    /// CID generator for this worker (with routing cookie).
    cid_generator: Arc<dyn ConnectionIdGenerator>,
    
    worker_id: u8,
    
    /// Application registry for ALPN-based routing.
    app_registry: Arc<crate::apps::AppRegistry>,
    
    /// DDoS protection: Rate limiting for Version Negotiation packets.
    /// Maps source address to (count, window_start_time).
    /// RFC 9000 Section 5.2.2: "A server MAY limit the number of Version Negotiation packets it sends."
    vn_rate_limiter: HashMap<SocketAddr, (u32, Instant)>,
}

/// Per-connection state managed by the worker.
struct ConnectionState {
    /// The QUIC connection state machine.
    conn: QuicConnection,
    
    /// Remote peer address.
    peer_addr: SocketAddr,
    
    /// Ingress channel sender for events to application task (bounded tokio::mpsc).
    ingress_tx: mpsc::Sender<Event>,
    
    /// Ingress channel receiver (stored until app spawned).
    ingress_rx: Option<mpsc::Receiver<Event>>,
    
    /// Has the application task been spawned?
    app_spawned: bool,
    
    /// Set of streams for which we've sent StreamOpened events.
    notified_streams: HashSet<QuicStreamId>,
    
    /// Length of the server's local Connection ID (DCID for incoming packets).
    /// Used for parsing Short header packets which don't include DCID length.
    dcid_len: usize,
    
    /// Buffer for 1-RTT packets that arrive before OneRtt keys are available.
    /// RFC 9001 Section 4.1.1: Implementations SHOULD buffer these packets.
    /// Store original bytes so we can apply header protection removal later.
    buffered_1rtt_packets: Vec<(Bytes, usize, Instant)>, // (packet_bytes, datagram_size, arrival_time)
    
    /// Backpressure flag: true when ingress channel is full.
    /// When true, QUIC flow control should stop reading data.
    /// This implements asymmetric backpressure: bounded ingress for memory safety.
    ingress_backpressure: bool,
}

impl ConnectionManager {
    pub fn new(
        config: ConnectionConfig,
        tokio_handle: TokioHandle,
        egress_tx: CrossbeamSender<Command>,
        worker_id: u8,
        app_registry: Arc<crate::apps::AppRegistry>,
    ) -> Self {
        let cid_generator = Arc::new(RoutingConnectionIdGenerator::new(
            worker_id,
            current_generation(),
        ));
        
        // Pre-allocate Slab with capacity for predictable memory usage.
        // This avoids reallocation on hot path.
        let connections = Slab::with_capacity(DEFAULT_MAX_CONNECTIONS_PER_WORKER);
        
        info!(
            worker_id,
            max_connections = DEFAULT_MAX_CONNECTIONS_PER_WORKER,
            "Initialized ConnectionManager with Slab storage"
        );
        
        Self {
            connections,
            dcid_to_slab: HashMap::new(),
            scid_to_slab: HashMap::new(),
            config,
            tokio_handle,
            egress_tx,
            cid_generator,
            worker_id,
            app_registry,
            vn_rate_limiter: HashMap::new(),
        }
    }
    
    /// Get a connection by Slab index.
    fn get_connection(&self, slab_idx: SlabIndex) -> Option<&ConnectionState> {
        self.connections.get(slab_idx)
    }
    
    /// Get a mutable connection by Slab index.
    fn get_connection_mut(&mut self, slab_idx: SlabIndex) -> Option<&mut ConnectionState> {
        self.connections.get_mut(slab_idx)
    }
    
    /// Find Slab index by DCID (for incoming packets).
    fn find_by_dcid(&self, dcid: &ConnectionId) -> Option<SlabIndex> {
        self.dcid_to_slab.get(dcid).copied()
    }
    
    /// Find Slab index by SCID (for egress commands).
    fn find_by_scid(&self, scid: &ConnectionId) -> Option<SlabIndex> {
        self.scid_to_slab.get(scid).copied()
    }
    
    /// Remove a connection from the Slab and clean up all mappings.
    fn remove_connection(&mut self, slab_idx: SlabIndex) {
        if let Some(state) = self.connections.get(slab_idx) {
            // Get the SCID before removing
            let scid = state.conn.source_cid().clone();
            
            // Remove all DCID mappings for this connection
            self.dcid_to_slab.retain(|_, &mut idx| idx != slab_idx);
            
            // Remove SCID mapping
            self.scid_to_slab.remove(&scid);
        }
        
        // Remove from Slab (slot will be reused)
        self.connections.remove(slab_idx);
        
        debug!(
            worker_id = self.worker_id,
            slab_idx,
            active_connections = self.connections.len(),
            "Removed connection from Slab"
        );
    }
    
    /// Insert a new connection into the Slab and register all CID mappings.
    fn insert_connection(
        &mut self,
        dcid: ConnectionId,
        scid: ConnectionId,
        state: ConnectionState,
    ) -> Option<SlabIndex> {
        // Check if we've reached capacity
        if self.connections.len() >= DEFAULT_MAX_CONNECTIONS_PER_WORKER {
            error!(
                worker_id = self.worker_id,
                current = self.connections.len(),
                max = DEFAULT_MAX_CONNECTIONS_PER_WORKER,
                "Connection limit reached - rejecting new connection"
            );
            return None;
        }
        
        // Insert into Slab
        let slab_idx = self.connections.insert(state);
        
        // Register DCID mapping
        self.dcid_to_slab.insert(dcid, slab_idx);
        
        // Register SCID mapping
        self.scid_to_slab.insert(scid, slab_idx);
        
        debug!(
            worker_id = self.worker_id,
            slab_idx,
            active_connections = self.connections.len(),
            "Inserted new connection into Slab"
        );
        
        Some(slab_idx)
    }
    
    /// Convert std::time::Instant to quicd_quic::types::Instant
    fn to_quic_instant(instant: Instant) -> QuicInstant {
        let nanos = instant.elapsed().as_nanos() as u64;
        QuicInstant::from_nanos(nanos)
    }
    
    /// Helper to match ConnectionId from quicd-x to QUIC ConnectionId
    fn matches_conn_id(scid: &ConnectionId, conn_id: XConnectionId) -> bool {
        // Convert first 8 bytes of ConnectionId to u64 for comparison
        let mut bytes = [0u8; 8];
        let scid_bytes = scid.as_bytes();
        let len = std::cmp::min(scid_bytes.len(), 8);
        bytes[..len].copy_from_slice(&scid_bytes[..len]);
        let scid_u64 = u64::from_le_bytes(bytes);
        scid_u64 == conn_id.0
    }
    
    pub fn handle_packet(&mut self, buffer: WorkerBuffer, peer_addr: SocketAddr, now: Instant) -> Vec<(SocketAddr, Vec<u8>)> {
        let datagram_size = buffer.len();
        
        // Parse packet from buffer
        let bytes = Bytes::copy_from_slice(&buffer);
        
        // Try to determine DCID length for Short packets
        // Short packets don't encode DCID length, so we need to extract it from the first byte
        let first_byte = bytes[0];
        let is_long_header = (first_byte & 0x80) != 0;
        
        // For Short packets, we need to find the connection first to get DCID length
        let mut parse_context = quicd_quic::packet::ParseContext::default();
        
        if !is_long_header {
            // Short packet - need to find connection by trying different DCID lengths
            // Start with common lengths: 20 bytes (our default), then 8 bytes
            let possible_lens = [20, 8, 16, 12, 4];
            for &len in &possible_lens {
                if bytes.len() > 1 + len {
                    if let Some(dcid) = ConnectionId::from_slice(&bytes[1..1+len]) {
                        if let Some(slab_idx) = self.find_by_dcid(&dcid) {
                            if let Some(state) = self.get_connection(slab_idx) {
                                parse_context = quicd_quic::packet::ParseContext::with_dcid_len(state.dcid_len);
                                break;
                            }
                        }
                    }
                }
            }
        }
        
        let packet = match quicd_quic::Packet::parse_with_context(bytes.clone(), parse_context) {
             Ok(p) => p,
             Err(e) => {
                 error!("Failed to parse packet: {}", e);
                 return vec![];
             }
        };

        let dcid = packet.header.dcid.clone();
        
        // ========================================================================
        // RFC 8999 Section 6 + RFC 9000 Section 5.2.2: Version Negotiation
        // ========================================================================
        // 
        // "If a server receives a packet that indicates an unsupported version
        // and if the packet is large enough to initiate a new connection for
        // any supported version, the server SHOULD send a Version Negotiation
        // packet as described in Section 6.1."
        //
        // Only long header packets with version field can trigger VN:
        // - Initial, 0-RTT, Handshake, Retry packets have version field
        // - Short header packets do not have version field (RFC 8999 Section 5.2)
        // - Version Negotiation packets MUST NOT trigger VN response (prevent loops)
        //
        if matches!(packet.header.ty, PacketType::Initial | PacketType::ZeroRtt | 
                    PacketType::Handshake | PacketType::Retry) {
            
            // Check if version is supported
            if packet.header.version != VERSION_1 {
                debug!("Received packet with unsupported version: 0x{:08X} from {}", 
                       packet.header.version, peer_addr);
                
                // RFC 9000 Section 14.1: "A server MUST discard an Initial packet that 
                // is carried in a UDP datagram with a payload that is smaller than the 
                // smallest allowed maximum datagram size of 1200 bytes."
                //
                // "Servers MUST drop smaller packets that specify unsupported versions."
                if datagram_size < 1200 {
                    debug!("Dropping undersized packet ({} bytes) with unsupported version from {}", 
                           datagram_size, peer_addr);
                    return vec![];
                }
                
                // DDoS protection: Rate limit Version Negotiation packets
                // RFC 9000 Section 5.2.2: "A server MAY limit the number of Version 
                // Negotiation packets it sends."
                if !self.should_send_version_negotiation(peer_addr, now) {
                    warn!("Rate limiting Version Negotiation packet to {}", peer_addr);
                    return vec![];
                }
                
                // Generate and send Version Negotiation packet
                // RFC 9000 Section 17.2.1: Echo CIDs correctly
                let vn_packet = Packet::create_version_negotiation(
                    packet.header.dcid.clone(),
                    packet.header.scid.clone().unwrap_or_else(ConnectionId::empty),
                    vec![VERSION_1], // List of supported versions
                );
                
                match vn_packet.serialize() {
                    Ok(serialized) => {
                        info!("Sent Version Negotiation packet to {} (unsupported version 0x{:08X})", 
                              peer_addr, packet.header.version);
                        return vec![(peer_addr, serialized.to_vec())];
                    }
                    Err(e) => {
                        error!("Failed to serialize Version Negotiation packet: {}", e);
                        return vec![];
                    }
                }
            }
        }
        
        // Check if existing connection
        if let Some(slab_idx) = self.find_by_dcid(&dcid) {
            if let Some(state) = self.get_connection_mut(slab_idx) {
                // RFC 9001 Section 5.4: Remove header protection BEFORE decryption
                // Determine encryption level from packet type
                let encryption_level = match packet.header.ty {
                    PacketType::Initial => quicd_quic::crypto::CryptoLevel::Initial,
                    PacketType::Handshake => quicd_quic::crypto::CryptoLevel::Handshake,
                    PacketType::OneRtt => quicd_quic::crypto::CryptoLevel::OneRTT,
                    _ => {
                        error!("Unsupported packet type for existing connection: {:?}", packet.header.ty);
                        return vec![];
                    }
                };
                
                // RFC 9001 Section 5.7: Server MUST NOT process 1-RTT packets before handshake complete
                // Even if 1-RTT keys are available, buffer until handshake completes
                if encryption_level == quicd_quic::crypto::CryptoLevel::OneRTT && state.conn.state() == QuicConnectionState::Handshaking {
                    const MAX_BUFFERED_PACKETS: usize = 10;
                    if state.buffered_1rtt_packets.len() < MAX_BUFFERED_PACKETS {
                        debug!("Buffering 1-RTT packet (handshake not complete): buffer_size={}",
                               state.buffered_1rtt_packets.len() + 1);
                        state.buffered_1rtt_packets.push((bytes.clone(), datagram_size, now));
                    } else {
                        warn!("Dropping 1-RTT packet - buffer full ({} packets)", MAX_BUFFERED_PACKETS);
                    }
                    return vec![];
                }
                
                // Get HP key from the connection's TLS session
                // Header protection removal is handled internally by QuicConnection
                // during process_datagram() - it parses, decrypts, and processes frames
                
                // Process packet using Connection trait with DatagramInput
                let datagram_input = DatagramInput {
                    data: bytes.clone(),
                    recv_time: Self::to_quic_instant(now),
                };
                if let Err(e) = state.conn.process_datagram(datagram_input) {
                    error!("Connection error: {}", e);
                }
                
                self.flush_events_to_app(slab_idx);
                
                let mut packets = self.generate_packets(slab_idx, now);
                self.check_handshake_complete(slab_idx);
                
                // Process buffered 1-RTT packets if keys are now available
                packets.extend(self.process_buffered_packets(slab_idx, now));
                
                return packets;
            }
        }
        
        // New connection with supported version
        if packet.header.ty == PacketType::Initial {
            // RFC 9000 Section 14.1: Validate minimum datagram size for Initial packets
            if datagram_size < 1200 {
                debug!("Dropping undersized Initial packet ({} bytes) from {}", 
                       datagram_size, peer_addr);
                return vec![];
            }
            
            // RFC 9000: Server chooses its own CID length (1-20 bytes).
            // Use 20 bytes for maximum entropy, routing cookie, and SipHash protection.
            let scid = self.cid_generator.generate(20);
            let dcid = packet.header.dcid.clone();
            
            // Create QUIC connection state machine
            let conn = QuicConnection::new(
                Side::Server,
                scid.clone(),
                dcid.clone(),
                self.config.clone(),
            );
            
            // Create bounded tokio::mpsc channel for ingress (Worker → App)
            // Capacity of 64 provides backpressure when app is slow
            let (ingress_tx, ingress_rx) = mpsc::channel(64);
            let dcid_len = scid.len();
            
            let state = ConnectionState {
                conn,
                peer_addr,
                ingress_tx,
                ingress_rx: Some(ingress_rx),
                app_spawned: false,
                notified_streams: HashSet::new(),
                dcid_len,
                buffered_1rtt_packets: Vec::new(),
                ingress_backpressure: false,
            };
            
            // INSERT INTO SLAB IMMEDIATELY - before processing packet
            // This allows Short packets arriving during processing to find the connection
            let slab_idx = match self.insert_connection(dcid.clone(), scid.clone(), state) {
                Some(idx) => idx,
                None => {
                    error!("Failed to insert connection - Slab at capacity");
                    return vec![];
                }
            };
            
            // Now process the Initial packet
            if let Some(state) = self.get_connection_mut(slab_idx) {
                let datagram_input = DatagramInput {
                    data: bytes,
                    recv_time: Self::to_quic_instant(now),
                };
                if let Err(e) = state.conn.process_datagram(datagram_input) {
                    error!("Failed to process initial packet: {}", e);
                    // Remove the connection on failure
                    self.remove_connection(slab_idx);
                    return vec![];
                }
            }
            
            let packets = self.generate_packets(slab_idx, now);
            self.check_handshake_complete(slab_idx);
            
            return packets;
        }
        
        // Unknown connection - log and drop
        warn!("Dropping packet for unknown connection: dcid={:?}, packet_type={:?}, from {}", 
              dcid, packet.header.ty, peer_addr);
        vec![]
    }
    
    fn check_handshake_complete(&mut self, slab_idx: SlabIndex) {
        let mut should_spawn = false;
        
        if let Some(state) = self.get_connection(slab_idx) {
            let is_handshake_complete = matches!(
                state.conn.state(),
                QuicConnectionState::Active | QuicConnectionState::Closing | QuicConnectionState::Draining
            );
            if is_handshake_complete && !state.app_spawned {
                should_spawn = true;
            }
        }
        
        if should_spawn {
            self.spawn_app(slab_idx);
        }
    }
    
    fn spawn_app(&mut self, slab_idx: SlabIndex) {
        // Flush any pending events before spawning
        self.flush_events_to_app(slab_idx);
        
        // Clone shared resources before borrowing state
        let egress_tx = self.egress_tx.clone();
        let app_registry = self.app_registry.clone();
        let tokio_handle = self.tokio_handle.clone();
        
        if let Some(state) = self.get_connection_mut(slab_idx) {
            let scid = state.conn.source_cid().clone();
            if let Some(rx) = state.ingress_rx.take() {
                state.app_spawned = true;
                
                // Convert SCID to u64 (take first 8 bytes)
                let mut bytes = [0u8; 8];
                let scid_bytes = scid.as_bytes();
                let len = std::cmp::min(scid_bytes.len(), 8);
                bytes[..len].copy_from_slice(&scid_bytes[..len]);
                let conn_id_u64 = u64::from_le_bytes(bytes);
                
                let handle = ConnectionHandle::new(
                    XConnectionId(conn_id_u64),
                    rx,
                    egress_tx,
                );
                
                // Get negotiated ALPN from connection wrapper
                let alpn = state.conn.negotiated_alpn();
                // negotiated_alpn() returns Option<&[u8]>
                
                match alpn {
                    Some(alpn_bytes) => {
                        // Convert &[u8] to &str for lookup and display
                        let alpn_str = std::str::from_utf8(&alpn_bytes).unwrap_or("<invalid-utf8>");
                        
                        // Look up application factory in registry
                        match app_registry.get(alpn_str) {
                            Some(factory) => {
                                let app = factory();
                                info!("Application task spawned for connection {} with ALPN: {}", conn_id_u64, alpn_str);
                                
                                // Spawn exactly ONE tokio task per connection
                                tokio_handle.spawn(async move {
                                    app.on_connection(handle).await;
                                    debug!("Application task completed for connection {}", conn_id_u64);
                                });
                            }
                            None => {
                                warn!("No application registered for ALPN: {} (connection {})", alpn_str, conn_id_u64);
                            }
                        }
                    }
                    None => {
                        warn!("No ALPN negotiated for connection {}", conn_id_u64);
                    }
                }
            }
        }
    }
    
    /// Bridge quicd-quic ConnectionEvent to quicd-x Event and send to application.
    ///
    /// This is the critical integration point between the QUIC protocol state machine
    /// and application tasks.
    /// 
    /// # Backpressure Handling
    /// Uses try_send on bounded tokio::mpsc channel. If channel is full:
    /// - Sets ingress_backpressure flag for this connection
    /// - Worker stops reading stream data (via flush_events_to_app_with_backpressure)
    /// - Application task must process events faster to keep up
    /// - Returns true if backpressure was applied
    fn bridge_event_to_app(&mut self, event: ConnectionEvent, slab_idx: SlabIndex) -> bool {
        let ingress_tx = if let Some(state) = self.get_connection(slab_idx) {
            state.ingress_tx.clone()
        } else {
            return false;
        };
        let x_event = match event {
            ConnectionEvent::HandshakeComplete => {
                debug!("Handshake complete event received");
                // Handshake complete is handled separately by spawning application
                return false;
            }
            
            ConnectionEvent::StreamData { stream_id, data, fin } => {
                Event::StreamData {
                    stream_id: XStreamId(stream_id.0),
                    data,
                    fin,
                }
            }
            
            ConnectionEvent::StreamOpened { stream_id } => {
                let is_bidirectional = (stream_id.0 & 0x2) == 0;
                Event::StreamOpened {
                    stream_id: XStreamId(stream_id.0),
                    is_bidirectional,
                }
            }
            
            ConnectionEvent::StreamFinished { stream_id } => {
                Event::StreamData {
                    stream_id: XStreamId(stream_id.0),
                    data: Bytes::new(),
                    fin: true,
                }
            }
            
            ConnectionEvent::StreamReset { stream_id, error_code } => {
                Event::StreamReset {
                    stream_id: XStreamId(stream_id.0),
                    error_code,
                }
            }
            
            ConnectionEvent::DatagramReceived { data } => {
                Event::DatagramReceived { data }
            }
            
            ConnectionEvent::ConnectionClosing { error_code, reason } => {
                Event::ConnectionClosing {
                    error_code,
                    reason: String::from_utf8_lossy(&reason).to_string(),
                }
            }
            
            ConnectionEvent::ConnectionClosed => {
                Event::ConnectionClosed
            }
        };
        
        // Send event to application task via bounded tokio::mpsc channel
        // try_send returns immediately, providing backpressure if channel is full
        match ingress_tx.try_send(x_event) {
            Ok(_) => {
                // Successfully sent - clear backpressure flag if set
                if let Some(state) = self.get_connection_mut(slab_idx) {
                    if state.ingress_backpressure {
                        debug!("Clearing ingress backpressure for slab_idx={}", slab_idx);
                        state.ingress_backpressure = false;
                    }
                }
                false
            },
            Err(mpsc::error::TrySendError::Full(_)) => {
                // ═══════════════════════════════════════════════════════════════════
                // BACKPRESSURE HANDLING (Asymmetric Channel Strategy)
                // ═══════════════════════════════════════════════════════════════════
                // Channel is full - application task is slow (CPU bound or blocking).
                // Apply QUIC flow control to stop reading data until task catches up.
                //
                // Strategy:
                // 1. Set ingress_backpressure flag for this connection
                // 2. Stop polling events from QUIC state machine (skip StreamData)
                // 3. Connection buffer fills up naturally
                // 4. QUIC flow control signals peer to stop sending
                // 5. When channel drains, clear flag and resume polling
                //
                // Benefits:
                // - Prevents unbounded memory growth
                // - Maintains end-to-end flow control semantics
                // - Slow receiver naturally signals to sender
                // - No packet drops - QUIC retransmits if needed
                //
                // This is the "bounded ingress for memory safety" principle.
                // ═══════════════════════════════════════════════════════════════════
                if let Some(state) = self.get_connection_mut(slab_idx) {
                    if !state.ingress_backpressure {
                        warn!(
                            "Ingress channel full for slab_idx={} - applying backpressure (will stop polling events)",
                            slab_idx
                        );
                        state.ingress_backpressure = true;
                    }
                }
                true // Backpressure applied
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // Application task has terminated - close connection
                debug!("Ingress channel closed for slab_idx={} - application task ended", slab_idx);
                if let Some(state) = self.get_connection_mut(slab_idx) {
                    state.conn.close(0x00, b"application terminated");
                }
                false
            }
        }
    }
    
    fn flush_events_to_app(&mut self, slab_idx: SlabIndex) {
        // Check backpressure flag first
        let under_backpressure = self.get_connection(slab_idx)
            .map(|s| s.ingress_backpressure)
            .unwrap_or(false);
        
        if under_backpressure {
            // Don't poll events when under backpressure
            // This allows QUIC flow control to naturally throttle the sender
            trace!("Skipping event flush for slab_idx={} (backpressure active)", slab_idx);
            return;
        }
        
        if let Some(state) = self.get_connection_mut(slab_idx) {
            // Collect events to avoid borrow checker issues
            let mut events = Vec::new();
            
            // Poll all pending events from the connection
            while let Some(event) = state.conn.poll_event() {
                events.push(event);
            }
            
            // Drop the mutable borrow before calling bridge_event_to_app
            drop(state);
            
            // Now send events (bridge_event_to_app takes &mut self)
            for event in events {
                let backpressure_applied = self.bridge_event_to_app(event, slab_idx);
                
                // If backpressure was applied, stop flushing events
                // This prevents filling the channel and wasting CPU
                if backpressure_applied {
                    debug!("Backpressure applied for slab_idx={} - stopping event flush", slab_idx);
                    break;
                }
            }
        }
    }
    
    /// DDoS protection: Rate limit Version Negotiation packets.
    /// 
    /// RFC 9000 Section 5.2.2: \"A server MAY limit the number of Version Negotiation packets it sends.\"
    /// 
    /// Implements a sliding window rate limiter to prevent amplification attacks.
    /// Allows max 10 VN packets per source address per 1-second window.
    /// 
    /// # Arguments
    /// 
    /// * `peer_addr` - Source address of the packet
    /// * `now` - Current timestamp
    /// 
    /// # Returns
    /// 
    /// `true` if VN packet should be sent, `false` if rate limit exceeded
    fn should_send_version_negotiation(&mut self, peer_addr: SocketAddr, now: Instant) -> bool {
        const MAX_VN_PER_WINDOW: u32 = 10;
        const WINDOW_DURATION: Duration = Duration::from_secs(1);
        
        let entry = self.vn_rate_limiter.entry(peer_addr).or_insert((0, now));
        
        // Check if window has expired
        if now.duration_since(entry.1) > WINDOW_DURATION {
            // Reset window
            entry.0 = 1;
            entry.1 = now;
            true
        } else if entry.0 < MAX_VN_PER_WINDOW {
            // Within limit
            entry.0 += 1;
            true
        } else {
            // Rate limit exceeded
            false
        }
    }
    
    pub fn handle_command(&mut self, cmd: Command) -> Vec<(SocketAddr, Vec<u8>)> {
        let now = Instant::now();
        
        match cmd {
            Command::WriteStreamData { conn_id, stream_id, data, fin } => {
                // Find connection by ID and write data to stream
                if let Some(slab_idx) = self.find_slab_by_app_conn_id(conn_id) {
                    if let Some(state) = self.get_connection_mut(slab_idx) {
                        let quic_stream_id = QuicStreamId(stream_id.0);
                        if let Err(e) = state.conn.write_stream(quic_stream_id, data, fin) {
                            error!("Failed to write to stream {:?}: {}", stream_id, e);
                        }
                    }
                    return self.generate_packets(slab_idx, now);
                }
            }
            Command::OpenBiStream { conn_id } => {
                // Open bidirectional stream via Connection trait
                if let Some(slab_idx) = self.find_slab_by_app_conn_id(conn_id) {
                    if let Some(state) = self.get_connection_mut(slab_idx) {
                        match state.conn.open_stream(StreamDirection::Bidirectional) {
                            Ok(quic_stream_id) => {
                                // Send StreamOpenedConfirm event to application
                                let _ = state.ingress_tx.try_send(Event::StreamOpenedConfirm {
                                    stream_id: XStreamId(quic_stream_id.0),
                                });
                            }
                            Err(e) => {
                                error!("Failed to open bidirectional stream: {}", e);
                            }
                        }
                    }
                    return self.generate_packets(slab_idx, now);
                }
            }
            Command::OpenUniStream { conn_id } => {
                // Open unidirectional stream via Connection trait
                if let Some(slab_idx) = self.find_slab_by_app_conn_id(conn_id) {
                    if let Some(state) = self.get_connection_mut(slab_idx) {
                        match state.conn.open_stream(StreamDirection::Unidirectional) {
                            Ok(quic_stream_id) => {
                                // Send StreamOpenedConfirm event to application
                                let _ = state.ingress_tx.try_send(Event::StreamOpenedConfirm {
                                    stream_id: XStreamId(quic_stream_id.0),
                                });
                            }
                            Err(e) => {
                                error!("Failed to open unidirectional stream: {}", e);
                            }
                        }
                    }
                    return self.generate_packets(slab_idx, now);
                }
            }
            Command::SendDatagram { conn_id, data } => {
                // Send datagram via Connection trait
                if let Some(slab_idx) = self.find_slab_by_app_conn_id(conn_id) {
                    if let Some(state) = self.get_connection_mut(slab_idx) {
                        if let Err(e) = state.conn.send_datagram(data) {
                            error!("Failed to send datagram: {}", e);
                        }
                    }
                    return self.generate_packets(slab_idx, now);
                }
            }
            Command::CloseConnection { conn_id, error_code, reason } => {
                // Graceful connection close via Connection trait
                if let Some(slab_idx) = self.find_slab_by_app_conn_id(conn_id) {
                    if let Some(state) = self.get_connection_mut(slab_idx) {
                        state.conn.close(error_code, reason.as_bytes());
                    }
                    return self.generate_packets(slab_idx, now);
                }
            }
            Command::ResetStream { conn_id, stream_id, error_code } => {
                // Reset stream via Connection trait
                if let Some(slab_idx) = self.find_slab_by_app_conn_id(conn_id) {
                    if let Some(state) = self.get_connection_mut(slab_idx) {
                        let quic_stream_id = QuicStreamId(stream_id.0);
                        if let Err(e) = state.conn.reset_stream(quic_stream_id, error_code) {
                            error!("Failed to reset stream {:?}: {}", stream_id, e);
                        }
                    }
                    return self.generate_packets(slab_idx, now);
                }
            }
            Command::StopSending { conn_id, stream_id, error_code } => {
                // Stop sending on stream - for now just generate packets
                // TODO: Implement proper STOP_SENDING frame handling in quicd-quic
                if let Some(slab_idx) = self.find_slab_by_app_conn_id(conn_id) {
                    debug!("STOP_SENDING requested for stream {:?} with error {}", stream_id, error_code);
                    return self.generate_packets(slab_idx, now);
                }
            }
            Command::AbortConnection { conn_id, error_code } => {
                // Immediate connection abort using close()
                if let Some(slab_idx) = self.find_slab_by_app_conn_id(conn_id) {
                    if let Some(state) = self.get_connection_mut(slab_idx) {
                        state.conn.close(error_code, b"connection aborted");
                    }
                    return self.generate_packets(slab_idx, now);
                }
            }
            Command::StreamDataRead { conn_id, stream_id, len } => {
                // Flow control update - application has consumed data
                // For now, just generate packets to send any pending MAX_STREAM_DATA frames
                // TODO: Implement explicit flow control update in quicd-quic
                if let Some(slab_idx) = self.find_slab_by_app_conn_id(conn_id) {
                    trace!("Application consumed {} bytes from stream {:?}", len, stream_id);
                    return self.generate_packets(slab_idx, now);
                }
            }
        }
        vec![]
    }
    
    /// Helper to find Slab index by quicd_x ConnectionId.
    fn find_slab_by_app_conn_id(&self, conn_id: XConnectionId) -> Option<SlabIndex> {
        // Search through all connections in the Slab
        for (slab_idx, state) in &self.connections {
            let scid = state.conn.source_cid();
            // Convert scid to u64 for comparison
            let mut bytes = [0u8; 8];
            let scid_bytes = scid.as_bytes();
            let len = std::cmp::min(scid_bytes.len(), 8);
            bytes[..len].copy_from_slice(&scid_bytes[..len]);
            let conn_id_u64 = u64::from_le_bytes(bytes);
            
            if conn_id_u64 == conn_id.0 {
                return Some(slab_idx);
            }
        }
        None
    }
    
    /// Calculate next timeout deadline across all connections.
    /// Returns the duration until the next connection needs timeout processing.
    /// Used to set io_uring wait timeout for precise timer handling.
    ///
    /// RFC 9002 Section 6: Loss Detection and Congestion Control
    /// RFC 9000 Section 10.1: Idle Timeout
    pub fn next_timeout(&self, now: Instant) -> Option<Duration> {
        let quic_now = Self::to_quic_instant(now);
        let mut earliest_deadline: Option<quicd_quic::types::Instant> = None;
        
        for (_, state) in &self.connections {
            if let Some(timeout) = state.conn.next_timeout() {
                earliest_deadline = Some(match earliest_deadline {
                    Some(current) => {
                        if timeout < current {
                            timeout
                        } else {
                            current
                        }
                    }
                    None => timeout,
                });
            }
        }
        
        // Convert quicd_quic::types::Instant to Duration from now
        if let Some(deadline) = earliest_deadline {
            if deadline > quic_now {
                // Calculate duration until deadline
                // Note: quicd_quic Instant is in nanoseconds from epoch
                let deadline_nanos = deadline.as_nanos();
                let now_nanos = quic_now.as_nanos();
                let duration_nanos = deadline_nanos.saturating_sub(now_nanos);
                return Some(Duration::from_nanos(duration_nanos));
            } else {
                // Deadline already passed, process immediately
                return Some(Duration::ZERO);
            }
        }
        
        None
    }
    
    pub fn poll_timeouts(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        let mut responses = Vec::new();
        let now = Instant::now();
        let quic_now = Self::to_quic_instant(now);
        let mut to_close = Vec::new();
        let mut need_packets = Vec::new(); // Collect Slab indices that need packet generation
        
        // RFC 9002 Section 6: Loss Detection and Congestion Control
        // Check each connection for timeouts using Connection::next_timeout()
        for (slab_idx, state) in &mut self.connections {
            // Check if connection has a timeout that needs processing
            if let Some(timeout) = state.conn.next_timeout() {
                // Compare quicd_quic Instants (implements PartialOrd)
                if quic_now >= timeout {
                    // RFC 9002 Section 6.2.1: Process timeout (loss detection or PTO)
                    if let Err(e) = state.conn.process_timeout(quic_now) {
                        error!("Error processing timeout for slab_idx={}: {}", slab_idx, e);
                        to_close.push(slab_idx);
                        continue;
                    }
                    
                    // Timeout processing may generate packets to send
                    need_packets.push(slab_idx);
                }
            }
            
            // RFC 9000 Section 10.1: Idle Timeout
            // Check connection state for idle timeout or closing state
            use quicd_quic::connection::ConnectionState as QuicState;
            match state.conn.state() {
                QuicState::Closed => {
                    to_close.push(slab_idx);
                }
                _ => {
                    // Connection still active
                }
            }
        }
        
        // Generate packets for connections that need it
        for slab_idx in need_packets {
            let pkts = self.generate_packets(slab_idx, now);
            responses.extend(pkts);
        }
        
        // Remove closed connections and clean up resources
        for slab_idx in to_close {
            if let Some(state) = self.get_connection(slab_idx) {
                // Notify application task that connection is closed
                let _ = state.ingress_tx.try_send(Event::ConnectionClosed);
            }
            
            // Remove from Slab (also cleans up CID mappings)
            self.remove_connection(slab_idx);
        }
        
        responses
    }
    
    fn generate_packets(&mut self, slab_idx: SlabIndex, now: Instant) -> Vec<(SocketAddr, Vec<u8>)> {
        if let Some(state) = self.get_connection_mut(slab_idx) {
            let mut out = Vec::new();
            
            // Poll packets from the Connection trait using poll_send()
            // Connection internally manages packet generation and serialization
            loop {
                let mut buf = BytesMut::with_capacity(1500);
                match state.conn.poll_send(&mut buf, Self::to_quic_instant(now)) {
                    Some(datagram_output) => {
                        // Got a packet to send - extract the data as Vec<u8>
                        let packet_data = datagram_output.data.to_vec();
                        out.push((state.peer_addr, packet_data));
                    }
                    None => {
                        // No more packets to send
                        break;
                    }
                }
            }
            
            return out;
        }
        vec![]
    }
    
    /// Process buffered 1-RTT packets once keys become available.
    ///
    /// RFC 9001 Section 4.1.1: Implementations SHOULD buffer packets that might be
    /// reordered on the wire, and SHOULD process them once the necessary keys are available.
    fn process_buffered_packets(&mut self, slab_idx: SlabIndex, now: Instant) -> Vec<(SocketAddr, Vec<u8>)> {
        // RFC 9001 Section 5.7: Process buffered 1-RTT packets only after handshake is COMPLETE
        // First, check if we need to process buffered packets
        let (should_process, buffered) = {
            if let Some(state) = self.get_connection_mut(slab_idx) {
                // Check if handshake is complete (not just if keys are available)
                let is_handshake_complete = matches!(
                    state.conn.state(),
                    QuicConnectionState::Active | QuicConnectionState::Closing | QuicConnectionState::Draining
                );
                if !is_handshake_complete {
                    return vec![];
                }
                
                // Take buffered packets (move out of state)
                let buffered = std::mem::take(&mut state.buffered_1rtt_packets);
                
                if buffered.is_empty() {
                    return vec![];
                }
                
                info!("Processing {} buffered 1-RTT packets for connection slab_idx={}", buffered.len(), slab_idx);
                (true, buffered)
            } else {
                return vec![];
            }
        };
        
        if !should_process {
            return vec![];
        }
        
        // Now process each buffered packet (state borrow dropped)
        let mut all_outgoing = Vec::new();
        
        for (packet_bytes, _datagram_size, arrival_time) in buffered {
            // Get state again for each packet (fresh borrow)
            let state = match self.get_connection_mut(slab_idx) {
                Some(s) => s,
                None => break,
            };
            
            // Process the buffered datagram (convert arrival_time to quicd_quic::Instant)
            let quic_arrival_time = Self::to_quic_instant(arrival_time);
            let timeout_datagram = DatagramInput {
                data: packet_bytes,
                recv_time: quic_arrival_time,
            };
            if let Err(e) = state.conn.process_datagram(timeout_datagram) {
                error!("Error processing buffered packet: {}", e);
                continue;
            }
            
            // Drop state borrow before calling other self methods
            drop(state);
            
            // Flush events and generate responses
            self.flush_events_to_app(slab_idx);
            let outgoing = self.generate_packets(slab_idx, now);
            all_outgoing.extend(outgoing);
        }
        
        all_outgoing
    }
}
