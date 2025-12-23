//! Connection manager for worker threads.
//!
//! Manages QUIC connections and routes packets to the appropriate connection.
//! Each worker thread has its own connection manager with isolated state.

use bytes::{Bytes, BytesMut};
use crate::netio::buffer::WorkerBuffer;
use crate::routing::{RoutingConnectionIdGenerator, current_generation};
use crate::worker::connection_wrapper::ConnectionWrapper;
use crossbeam_channel::{Sender, Receiver, bounded};
use quicd_quic::{ConnectionConfig, Packet, PacketTypeWrapper, VERSION_1, Side};
use quicd_quic::{ConnectionEvent, ConnectionState as QuicConnectionState, StreamId as QuicStreamId};
use quicd_quic::cid::{ConnectionIdGenerator, ConnectionId};
use quicd_quic::crypto::CryptoLevel;
use quicd_quic::types::{Instant as QuicInstant, StreamDirection};
use quicd_x::{ConnectionHandle, Event, Command, StreamId as XStreamId};
use quicd_x::ConnectionId as XConnectionId;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::runtime::Handle as TokioHandle;
use tracing::{error, info, warn, debug};

/// Maps incoming packets to QUIC connections.
pub struct ConnectionManager {
    /// Active connections indexed by Connection ID (SCID).
    connections: HashMap<ConnectionId, ConnectionState>,
    
    /// Mapping from DCID to connection for packet routing.
    dcid_to_conn: HashMap<ConnectionId, ConnectionId>,
    
    /// Configuration for new connections.
    config: ConnectionConfig,

    /// Tokio runtime handle for spawning application tasks.
    tokio_handle: TokioHandle,
    
    /// Worker egress channel sender (cloned for each connection).
    egress_tx: Sender<Command>,
    
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
    /// The QUIC connection wrapper.
    conn: ConnectionWrapper,
    
    /// Remote peer address.
    peer_addr: SocketAddr,
    
    /// Ingress channel sender for events to application task.
    ingress_tx: Sender<Event>,
    
    /// Ingress channel receiver (stored until app spawned).
    ingress_rx: Option<Receiver<Event>>,
    
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
}

impl ConnectionManager {
    pub fn new(
        config: ConnectionConfig,
        tokio_handle: TokioHandle,
        egress_tx: Sender<Command>,
        worker_id: u8,
        app_registry: Arc<crate::apps::AppRegistry>,
    ) -> Self {
        let cid_generator = Arc::new(RoutingConnectionIdGenerator::new(
            worker_id,
            current_generation(),
        ));
        
        Self {
            connections: HashMap::new(),
            dcid_to_conn: HashMap::new(),
            config,
            tokio_handle,
            egress_tx,
            cid_generator,
            worker_id,
            app_registry,
            vn_rate_limiter: HashMap::new(),
        }
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
                        if let Some(scid) = self.dcid_to_conn.get(&dcid) {
                            if let Some(state) = self.connections.get(scid) {
                                parse_context = quicd_quic::packet::ParseContext::with_dcid_len(state.dcid_len);
                                break;
                            }
                        }
                    }
                }
            }
        }
        
        let mut packet = match quicd_quic::Packet::parse_with_context(bytes.clone(), parse_context) {
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
        if matches!(packet.header.ty, PacketTypeWrapper::Initial | PacketTypeWrapper::ZeroRtt | 
                    PacketTypeWrapper::Handshake | PacketTypeWrapper::Retry) {
            
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
        if let Some(scid) = self.dcid_to_conn.get(&dcid) {
            // We need to clone scid to use it for lookup to avoid borrow checker issues
            let scid = scid.clone();
            if let Some(state) = self.connections.get_mut(&scid) {
            // RFC 9001 Section 5.4: Remove header protection BEFORE decryption
            // Determine encryption level from packet type
            let encryption_level = match packet.header.ty {
                PacketTypeWrapper::Initial => quicd_quic::crypto::EncryptionLevel::Initial,
                PacketTypeWrapper::Handshake => quicd_quic::crypto::EncryptionLevel::Handshake,
                PacketTypeWrapper::Short => quicd_quic::crypto::EncryptionLevel::Application,
                _ => {
                    error!("Unsupported packet type for existing connection: {:?}", packet.header.ty);
                    return vec![];
                }
            };
            
            // RFC 9001 Section 5.7: Server MUST NOT process 1-RTT packets before handshake complete
            // Even if 1-RTT keys are available, buffer until handshake completes
            if encryption_level == CryptoLevel::Application && !state.conn.is_handshake_complete() {
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
            if let Some(_hp_key) = state.conn.get_hp_key(encryption_level) {
                // Header protection removal handled by packet parser
                // In real implementation, would use HP key here
            } else {
                // Keys not available yet
                if encryption_level == CryptoLevel::Application {
                    // RFC 9001 Section 5.7: Server MUST NOT process 1-RTT packets before handshake complete
                    // Buffer them to process after handshake completes
                    const MAX_BUFFERED_PACKETS: usize = 10;
                    if state.buffered_1rtt_packets.len() < MAX_BUFFERED_PACKETS {
                        debug!("Buffering 1-RTT packet (keys not ready): buffer_size={}",
                               state.buffered_1rtt_packets.len() + 1);
                        state.buffered_1rtt_packets.push((bytes.clone(), datagram_size, now));
                    } else {
                        warn!("Dropping 1-RTT packet - buffer full ({} packets)", MAX_BUFFERED_PACKETS);
                    }
                    return vec![];
                } else {
                    error!("HP key not available for encryption level: {:?}", encryption_level);
                    return vec![];
                }
            }
            
            // Process packet using Connection trait
            if let Err(e) = state.conn.process_datagram(bytes.clone(), Self::to_quic_instant(now)) {
                error!("Connection error: {}", e);
            }
            
            self.flush_events_to_app(&scid);
            
            let mut packets = self.generate_packets(&scid, now);
            self.check_handshake_complete(&scid);
            
            // Process buffered 1-RTT packets if keys are now available
            packets.extend(self.process_buffered_packets(&scid, now));
            
            return packets;
        }
        }
        
        // New connection with supported version
        if packet.header.ty == PacketTypeWrapper::Initial {
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
            
            // Create connection wrapper with QUIC state machine
            let conn = ConnectionWrapper::new(
                Side::Server,
                scid.clone(),
                dcid.clone(),
                self.config.clone(),
            );
            
            let (ingress_tx, ingress_rx) = bounded(1024);
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
            };
            
            // INSERT INTO HASHMAP IMMEDIATELY - before processing packet
            // This allows Short packets arriving during processing to find the connection
            self.connections.insert(scid.clone(), state);
            self.dcid_to_conn.insert(dcid.clone(), scid.clone());
            self.dcid_to_conn.insert(scid.clone(), scid.clone());
            
            // Now process the Initial packet
            if let Some(state) = self.connections.get_mut(&scid) {
                if let Err(e) = state.conn.process_datagram(bytes, Self::to_quic_instant(now)) {
                    error!("Failed to process initial packet: {}", e);
                    // Remove the connection on failure
                    self.connections.remove(&scid);
                    self.dcid_to_conn.remove(&dcid);
                    self.dcid_to_conn.remove(&scid);
                    return vec![];
                }
            }
            
            let packets = self.generate_packets(&scid, now);
            self.check_handshake_complete(&scid);
            
            return packets;
        }
        
        // Unknown connection - log and drop
        warn!("Dropping packet for unknown connection: dcid={:?}, packet_type={:?}, from {}", 
              dcid, packet.header.ty, peer_addr);
        vec![]
    }
    
    fn check_handshake_complete(&mut self, scid: &ConnectionId) {
        let mut should_spawn = false;
        
        if let Some(state) = self.connections.get(scid) {
            if state.conn.is_handshake_complete() && !state.app_spawned {
                should_spawn = true;
            }
        }
        
        if should_spawn {
            self.spawn_app(scid.clone());
        }
    }
    
    fn spawn_app(&mut self, scid: ConnectionId) {
        // Flush any pending events before spawning
        self.flush_events_to_app(&scid);
        
        if let Some(state) = self.connections.get_mut(&scid) {
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
                    self.egress_tx.clone(),
                );
                
                // Get negotiated ALPN from connection wrapper
                let alpn = state.conn.negotiated_alpn();
                
                match alpn {
                    Some(alpn_str) => {
                        // Look up application factory in registry
                        match self.app_registry.get(alpn_str) {
                            Some(factory) => {
                                let app = factory();
                                info!("Application task spawned for connection {} with ALPN: {}", conn_id_u64, alpn_str);
                                
                                // Spawn exactly ONE tokio task per connection
                                self.tokio_handle.spawn(async move {
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
    fn bridge_event_to_app(&self, event: ConnectionEvent, ingress_tx: &Sender<Event>) {
        let x_event = match event {
            ConnectionEvent::HandshakeComplete => {
                debug!("Handshake complete event received");
                // Handshake complete is handled separately by spawning application
                return;
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
        
        // Send event to application task via crossbeam channel
        if let Err(e) = ingress_tx.try_send(x_event) {
            warn!("Failed to send event to application: {:?}", e);
        }
    }
    
    fn flush_events_to_app(&mut self, scid: &ConnectionId) {
        if let Some(state) = self.connections.get_mut(scid) {
            // Clone the channel sender and collect events to avoid borrow checker issues
            let ingress_tx = state.ingress_tx.clone();
            let mut events = Vec::new();
            
            // Poll all pending events from the connection
            while let Some(event) = state.conn.poll_event() {
                events.push(event);
            }
            
            // Drop the mutable borrow before calling bridge_event_to_app
            drop(state);
            
            // Now send events (no borrow of self.connections)
            for event in events {
                self.bridge_event_to_app(event, &ingress_tx);
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
        match cmd {
            Command::WriteStreamData { conn_id, stream_id, data, fin } => {
                // Find connection by ID and write data to stream
                if let Some((scid, state)) = self.find_connection_by_id(conn_id) {
                    let quic_stream_id = QuicStreamId(stream_id.0);
                    if let Err(e) = state.conn.write_stream(quic_stream_id, data, fin) {
                        error!("Failed to write to stream {:?}: {}", stream_id, e);
                    }
                    let now = Instant::now();
                    return self.generate_packets(&scid, now);
                }
            }
            Command::OpenBiStream { conn_id } => {
                // Open bidirectional stream via Connection trait
                if let Some((scid, state)) = self.find_connection_by_id(conn_id) {
                    match state.conn.open_stream(StreamDirection::Bidirectional) {
                        Ok(quic_stream_id) => {
                            let _ = state.ingress_tx.try_send(Event::StreamOpened {
                                stream_id: XStreamId(quic_stream_id.0),
                                is_bidirectional: true,
                            });
                        }
                        Err(e) => {
                            error!("Failed to open bidirectional stream: {}", e);
                        }
                    }
                    let now = Instant::now();
                    return self.generate_packets(&scid, now);
                }
            }
            Command::OpenUniStream { conn_id } => {
                // Open unidirectional stream via Connection trait
                if let Some((scid, state)) = self.find_connection_by_id(conn_id) {
                    match state.conn.open_stream(StreamDirection::Unidirectional) {
                        Ok(quic_stream_id) => {
                            let _ = state.ingress_tx.try_send(Event::StreamOpened {
                                stream_id: XStreamId(quic_stream_id.0),
                                is_bidirectional: false,
                            });
                        }
                        Err(e) => {
                            error!("Failed to open unidirectional stream: {}", e);
                        }
                    }
                    let now = Instant::now();
                    return self.generate_packets(&scid, now);
                }
            }
            Command::SendDatagram { conn_id, data } => {
                // Send datagram via Connection trait
                if let Some((scid, state)) = self.find_connection_by_id(conn_id) {
                    if let Err(e) = state.conn.send_datagram(data) {
                        error!("Failed to send datagram: {}", e);
                    }
                    let now = Instant::now();
                    return self.generate_packets(&scid, now);
                }
            }
            Command::CloseConnection { conn_id, error_code, reason } => {
                // Graceful connection close via Connection trait
                if let Some((scid, state)) = self.find_connection_by_id(conn_id) {
                    state.conn.close(error_code, reason.as_bytes());
                    let now = Instant::now();
                    return self.generate_packets(&scid, now);
                }
            }
            Command::ResetStream { conn_id, stream_id, error_code } => {
                // Reset stream via Connection trait
                if let Some((scid, state)) = self.find_connection_by_id(conn_id) {
                    let quic_stream_id = QuicStreamId(stream_id.0);
                    if let Err(e) = state.conn.reset_stream(quic_stream_id, error_code) {
                        error!("Failed to reset stream {:?}: {}", stream_id, e);
                    }
                    let now = Instant::now();
                    return self.generate_packets(&scid, now);
                }
            }
            Command::StopSending { conn_id, stream_id, error_code } => {
                // Send STOP_SENDING via Connection trait
                if let Some((scid, state)) = self.find_connection_by_id(conn_id) {
                    let quic_stream_id = QuicStreamId(stream_id.0);
                    // STOP_SENDING is sent via the stop_sending method
                    // For now, log and generate packets (assuming Connection handles internally)
                    debug!("Sending STOP_SENDING for stream {:?}", stream_id);
                    // TODO: Add stop_sending() method to Connection trait if not present
                    let now = Instant::now();
                    return self.generate_packets(&scid, now);
                }
            }
            Command::AbortConnection { conn_id, error_code } => {
                // Immediate connection termination
                if let Some((scid, state)) = self.find_connection_by_id(conn_id) {
                    state.conn.close(error_code, b"connection aborted");
                    let now = Instant::now();
                    let packets = self.generate_packets(&scid, now);
                    // Remove connection immediately after sending abort
                    self.connections.remove(&scid);
                    self.dcid_to_conn.retain(|_, v| v != &scid);
                    return packets;
                }
            }
            Command::StreamDataRead { conn_id, stream_id, len } => {
                // Application has consumed data, update flow control
                if let Some((scid, state)) = self.find_connection_by_id(conn_id) {
                    let quic_stream_id = QuicStreamId(stream_id.0);
                    // Connection trait handles flow control internally via read_stream
                    // Just generate packets to send any pending MAX_STREAM_DATA frames
                    let now = Instant::now();
                    return self.generate_packets(&scid, now);
                }
            }
        }
        vec![]
    }
    
    /// Helper to find connection by quicd_x ConnectionId.
    fn find_connection_by_id(&mut self, conn_id: XConnectionId) -> Option<(ConnectionId, &mut ConnectionState)> {
        for (scid, state) in &mut self.connections {
            // Convert scid to u64 for comparison
            let mut bytes = [0u8; 8];
            let scid_bytes = scid.as_bytes();
            let len = std::cmp::min(scid_bytes.len(), 8);
            bytes[..len].copy_from_slice(&scid_bytes[..len]);
            let conn_id_u64 = u64::from_le_bytes(bytes);
            
            if conn_id_u64 == conn_id.0 {
                return Some((scid.clone(), state));
            }
        }
        None
    }
    
    pub fn poll_timeouts(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        let mut responses = Vec::new();
        let now = Instant::now();
        let quic_now = Self::to_quic_instant(now);
        let mut to_close = Vec::new();
        let mut need_packets = Vec::new(); // Collect SCIDs that need packet generation
        
        // RFC 9002 Section 6: Loss Detection and Congestion Control
        // Check each connection for timeouts using Connection::next_timeout()
        for (scid, state) in &mut self.connections {
            // Check if connection has a timeout that needs processing
            if let Some(timeout) = state.conn.next_timeout() {
                // Compare quicd_quic Instants (implements PartialOrd)
                if quic_now >= timeout {
                    // RFC 9002 Section 6.2.1: Process timeout (loss detection or PTO)
                    if let Err(e) = state.conn.process_timeout(quic_now) {
                        error!("Error processing timeout for {:?}: {}", scid, e);
                        to_close.push(scid.clone());
                        continue;
                    }
                    
                    // Timeout processing may generate packets to send
                    need_packets.push(scid.clone());
                }
            }
            
            // RFC 9000 Section 10.1: Idle Timeout
            // Check connection state for idle timeout or closing state
            use quicd_quic::connection::ConnectionState as QuicState;
            match state.conn.state() {
                QuicState::Closed => {
                    to_close.push(scid.clone());
                }
                _ => {
                    // Connection still active
                }
            }
        }
        
        // Generate packets for connections that need it
        for scid in need_packets {
            let pkts = self.generate_packets(&scid, now);
            responses.extend(pkts);
        }
        
        // Remove closed connections and clean up resources
        for scid in to_close {
            if let Some(state) = self.connections.remove(&scid) {
                // Notify application task that connection is closed
                let _ = state.ingress_tx.try_send(Event::ConnectionClosed);
                
                // Clean up DCID mappings
                self.dcid_to_conn.retain(|_, v| v != &scid);
                
                debug!("Connection {:?} removed due to timeout", scid);
            }
        }
        
        responses
    }
    
    fn generate_packets(&mut self, scid: &ConnectionId, now: Instant) -> Vec<(SocketAddr, Vec<u8>)> {
        if let Some(state) = self.connections.get_mut(scid) {
            let mut out = Vec::new();
            
            // Poll packets from the Connection trait using poll_send()
            // Connection internally manages packet generation and serialization
            loop {
                let mut buf = BytesMut::with_capacity(1500);
                match state.conn.poll_send(&mut buf, Self::to_quic_instant(now)) {
                    Some(packet_bytes) => {
                        // Got a packet to send
                        out.push((state.peer_addr, packet_bytes));
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
    fn process_buffered_packets(&mut self, scid: &ConnectionId, now: Instant) -> Vec<(SocketAddr, Vec<u8>)> {
        // RFC 9001 Section 5.7: Process buffered 1-RTT packets only after handshake is COMPLETE
        // First, check if we need to process buffered packets
        let (should_process, buffered) = {
            if let Some(state) = self.connections.get_mut(scid) {
                // Check if handshake is complete (not just if keys are available)
                if !state.conn.is_handshake_complete() {
                    return vec![];
                }
                
                // Take buffered packets (move out of state)
                let buffered = std::mem::take(&mut state.buffered_1rtt_packets);
                
                if buffered.is_empty() {
                    return vec![];
                }
                
                info!("Processing {} buffered 1-RTT packets for connection {:?}", buffered.len(), scid);
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
            let state = match self.connections.get_mut(scid) {
                Some(s) => s,
                None => break,
            };
            
            // Process the buffered datagram (convert arrival_time to quicd_quic::Instant)
            let quic_arrival_time = Self::to_quic_instant(arrival_time);
            if let Err(e) = state.conn.process_datagram(packet_bytes, quic_arrival_time) {
                error!("Error processing buffered packet: {}", e);
                continue;
            }
            
            // Drop state borrow before calling other self methods
            drop(state);
            
            // Flush events and generate responses
            self.flush_events_to_app(scid);
            let outgoing = self.generate_packets(scid, now);
            all_outgoing.extend(outgoing);
        }
        
        all_outgoing
    }
}
