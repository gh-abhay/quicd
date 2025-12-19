//! Connection manager for worker threads.
//!
//! Manages QUIC connections and routes packets to the appropriate connection.
//! Each worker thread has its own connection manager with isolated state.

use bytes::Bytes;
use crate::netio::buffer::WorkerBuffer;
use crate::routing::{RoutingConnectionIdGenerator, current_generation};
use crossbeam_channel::{Sender, Receiver, bounded};
use quicd_quic::{Connection, ConnectionConfig, Packet, PacketType, VERSION_1, VERSION_NEGOTIATION};
use quicd_quic::cid::{ConnectionIdGenerator, ConnectionId};
use quicd_quic::crypto::TlsSession;
use quicd_quic::stream::{Stream, StreamId};
use quicd_quic::frame::Frame;
use quicd_quic::connection::ConnectionState as QuicConnectionState;
use quicd_x::{ConnectionHandle, Event, Command};
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
    /// The QUIC connection state machine.
    conn: Connection,
    
    /// Remote peer address.
    peer_addr: SocketAddr,
    
    /// Ingress channel sender for events to application task.
    ingress_tx: Sender<Event>,
    
    /// Ingress channel receiver (stored until app spawned).
    ingress_rx: Option<Receiver<Event>>,
    
    /// Has the application task been spawned?
    app_spawned: bool,
    
    /// Set of streams for which we've sent StreamOpened events.
    notified_streams: HashSet<StreamId>,
    
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
                    let dcid = ConnectionId::from_slice(&bytes[1..1+len]);
                    if let Some(scid) = self.dcid_to_conn.get(&dcid) {
                        if let Some(state) = self.connections.get(scid) {
                            parse_context = quicd_quic::packet::ParseContext::with_dcid_len(state.dcid_len);
                            break;
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
        if let Some(scid) = self.dcid_to_conn.get(&dcid) {
            // We need to clone scid to use it for lookup to avoid borrow checker issues
            let scid = scid.clone();
            if let Some(state) = self.connections.get_mut(&scid) {
            // RFC 9001 Section 5.4: Remove header protection BEFORE decryption
            // Determine encryption level from packet type
            let encryption_level = match packet.header.ty {
                PacketType::Initial => quicd_quic::crypto::EncryptionLevel::Initial,
                PacketType::Handshake => quicd_quic::crypto::EncryptionLevel::Handshake,
                PacketType::Short => quicd_quic::crypto::EncryptionLevel::OneRtt,
                _ => {
                    error!("Unsupported packet type for existing connection: {:?}", packet.header.ty);
                    return vec![];
                }
            };
            
            // RFC 9001 Section 5.7: Server MUST NOT process 1-RTT packets before handshake complete
            // Even if 1-RTT keys are available, buffer until handshake completes
            if encryption_level == quicd_quic::crypto::EncryptionLevel::OneRtt && !state.conn.handshake_complete {
                const MAX_BUFFERED_PACKETS: usize = 10;
                if state.buffered_1rtt_packets.len() < MAX_BUFFERED_PACKETS {
                    debug!("Buffering 1-RTT packet (handshake not complete): pn={:?}, buffer_size={}",
                           packet.header.packet_number, state.buffered_1rtt_packets.len() + 1);
                    state.buffered_1rtt_packets.push((bytes.clone(), datagram_size, now));
                } else {
                    warn!("Dropping 1-RTT packet - buffer full ({} packets)", MAX_BUFFERED_PACKETS);
                }
                return vec![];
            }
            
            // Get HP key from the connection's TLS session
            if let Some(hp_key) = state.conn.get_hp_key(encryption_level) {
                if let Err(e) = packet.remove_header_protection(hp_key, bytes.as_ref()) {
                    // RFC 9001 Section 5: If header protection removal fails for 1-RTT packets,
                    // it likely means keys aren't ready yet (race condition during handshake).
                    // Drop the packet silently - client will retransmit.
                    if encryption_level == quicd_quic::crypto::EncryptionLevel::OneRtt {
                        debug!("Dropping 1-RTT packet due to HP removal failure (keys may not be ready yet): {}", e);
                    } else {
                        error!("Failed to remove header protection: {}", e);
                    }
                    return vec![];
                }
            } else {
                // Keys not available yet
                if encryption_level == quicd_quic::crypto::EncryptionLevel::OneRtt {
                    // RFC 9001 Section 5.7: Server MUST NOT process 1-RTT packets before handshake complete
                    // Buffer them to process after handshake completes
                    const MAX_BUFFERED_PACKETS: usize = 10;
                    if state.buffered_1rtt_packets.len() < MAX_BUFFERED_PACKETS {
                        debug!("Buffering 1-RTT packet (keys not ready): pn={:?}, buffer_size={}",
                               packet.header.packet_number, state.buffered_1rtt_packets.len() + 1);
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
            
            if let Err(e) = state.conn.process_packet(packet, datagram_size, now) {
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
            
            // RFC 9001 Section 5.2: Initial keys are derived from DCID from Initial packet
            // Use the DCID from the packet header to initialize TLS session
            let dcid_bytes = packet.header.dcid.as_bytes();
            
            // Get cert and key paths from config
            let cert_path = match &self.config.cert_path {
                Some(path) => path,
                None => {
                    error!("No certificate path configured");
                    return vec![];
                }
            };
            let key_path = match &self.config.key_path {
                Some(path) => path,
                None => {
                    error!("No key path configured");
                    return vec![];
                }
            };
            
            let tls = match TlsSession::new_server_with_config(dcid_bytes, scid.as_bytes(), cert_path, key_path) {
                Ok(tls) => tls,
                Err(e) => {
                    error!("Failed to create TLS session: {:?}", e);
                    return vec![];
                }
            };
            
            // RFC 9001 Section 5.4: Remove header protection BEFORE decryption
            // Initial packets use keys derived from the DCID
            // Server uses client's HP key to unprotect client-sent packets
            use quicd_quic::crypto::{KeySchedule, EncryptionLevel};
            let key_schedule = match KeySchedule::new_initial(dcid_bytes) {
                Ok(ks) => ks,
                Err(e) => {
                    error!("Failed to derive initial keys: {:?}", e);
                    return vec![];
                }
            };
            
            // Get client's HP key (server=true means get server's keys, which have client HP as remote)
            if let Some(hp_key) = key_schedule.get_hp_key(EncryptionLevel::Initial, true) {
                // Remove header protection from the packet
                if let Err(e) = packet.remove_header_protection(hp_key, bytes.as_ref()) {
                    error!("Failed to remove header protection: {}", e);
                    return vec![];
                }
            } else {
                error!("HP key not available");
                return vec![];
            }
            
            let conn = Connection::new(self.config.clone(), scid.clone(), packet.header.scid.clone().unwrap(), tls);
            
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
                if let Err(e) = state.conn.process_packet(packet, datagram_size, now) {
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
        // We need to extract fields to avoid borrow checker issues with self.spawn_app
        let mut should_spawn = false;
        eprintln!("check_handshake_complete: Checking connection {:?}", scid);
        if let Some(state) = self.connections.get(scid) {
            eprintln!("check_handshake_complete: handshake_complete={}, app_spawned={}", 
                   state.conn.handshake_complete, state.app_spawned);
            if state.conn.handshake_complete && !state.app_spawned {
                should_spawn = true;
            }
        }
        
        if should_spawn {
            eprintln!("check_handshake_complete: Spawning app for connection {:?}", scid);
            self.spawn_app(scid.clone());
        } else {
            eprintln!("check_handshake_complete: NOT spawning (should_spawn=false)");
        }
    }
    
    fn spawn_app(&mut self, scid: ConnectionId) {
        // Flush any pending events (including StreamOpened for existing streams) before spawning
        self.flush_events_to_app(&scid);
        
        if let Some(state) = self.connections.get_mut(&scid) {
            // Debug: Log that we're attempting to spawn
            eprintln!("spawn_app: Attempting to spawn application for connection {:?}", scid);
            
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
                
                // Get negotiated ALPN from TLS session
                let alpn = state.conn.tls.negotiated_alpn();
                eprintln!("spawn_app: ALPN negotiated = {:?}", alpn);
                
                match alpn {
                    Some(alpn_str) => {
                        // Look up application factory in registry
                        eprintln!("spawn_app: Looking up application for ALPN: {}", alpn_str);
                        match self.app_registry.get(&alpn_str) {
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
                                eprintln!("spawn_app: Available ALPNs in registry: {:?}", self.app_registry.alpns());
                            }
                        }
                    }
                    None => {
                        warn!("No ALPN negotiated for connection {}", conn_id_u64);
                    }
                }
            } else {
                eprintln!("spawn_app: ingress_rx already taken for connection {:?}", scid);
            }
        } else {
            eprintln!("spawn_app: Connection {:?} not found", scid);
        }
    }
    
    fn flush_events_to_app(&mut self, scid: &ConnectionId) {
        if let Some(state) = self.connections.get_mut(scid) {
            // Check for pending datagrams
            while let Some(data) = state.conn.pending_datagrams.pop_front() {
                let _ = state.ingress_tx.try_send(Event::DatagramReceived { data });
            }
            
            // Check for new streams and send StreamOpened events
            for (stream_id, _stream) in &state.conn.streams {
                // Check if we've already notified the app about this stream
                if !state.notified_streams.contains(stream_id) {
                    eprintln!("flush_events_to_app: Sending StreamOpened for stream_id={}", stream_id.0);
                    let is_bidirectional = stream_id.is_bidirectional();
                    let _ = state.ingress_tx.try_send(Event::StreamOpened {
                        stream_id: quicd_x::StreamId(stream_id.0),
                        is_bidirectional,
                    });
                    state.notified_streams.insert(*stream_id);
                }
            }
            
            // Check for stream data
            for (stream_id, stream) in &mut state.conn.streams {
                if stream.has_data() {
                    if let Ok((data, fin)) = stream.read() {
                        let _ = state.ingress_tx.try_send(Event::StreamData {
                            stream_id: quicd_x::StreamId(stream_id.0),
                            data,
                            fin,
                        });
                    }
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
        match cmd {
            Command::WriteStreamData { conn_id, stream_id, data, fin } => {
                // Find connection by ID (convert u64 to ConnectionId)
                let mut target_scid: Option<ConnectionId> = None;
                for (scid, state) in &mut self.connections {
                    // Convert scid to u64 for comparison
                    let mut bytes = [0u8; 8];
                    let scid_bytes = scid.as_bytes();
                    let len = std::cmp::min(scid_bytes.len(), 8);
                    bytes[..len].copy_from_slice(&scid_bytes[..len]);
                    let conn_id_u64 = u64::from_le_bytes(bytes);
                    
                    if conn_id_u64 == conn_id.0 {
                        // Queue data on stream
                        // Convert quicd_x::StreamId to quicd_quic::StreamId
                        let quic_stream_id = quicd_quic::stream::StreamId(stream_id.0);
                        if let Some(stream) = state.conn.streams.get_mut(&quic_stream_id) {
                            let _ = stream.queue_send(data, fin);
                        }
                        target_scid = Some(scid.clone());
                        break;
                    }
                }
                if let Some(scid) = target_scid {
                    let now = Instant::now();
                    return self.generate_packets(&scid, now);
                }
            }
            Command::OpenBiStream { conn_id } | Command::OpenUniStream { conn_id } => {
                let bidirectional = matches!(cmd, Command::OpenBiStream { .. });
                for (scid, state) in &mut self.connections {
                    let mut bytes = [0u8; 8];
                    let scid_bytes = scid.as_bytes();
                    let len = std::cmp::min(scid_bytes.len(), 8);
                    bytes[..len].copy_from_slice(&scid_bytes[..len]);
                    let conn_id_u64 = u64::from_le_bytes(bytes);
                    
                    if conn_id_u64 == conn_id.0 {
                        // Allocate new stream ID
                        let stream_id = if bidirectional {
                            let id = state.conn.next_stream_id_bidi;
                            state.conn.next_stream_id_bidi += 4;
                            id
                        } else {
                            let id = state.conn.next_stream_id_uni;
                            state.conn.next_stream_id_uni += 4;
                            id
                        };
                        
                        // Create stream
                        let max_data = if bidirectional {
                            state.conn.config.initial_max_stream_data_bidi_local
                        } else {
                            state.conn.config.initial_max_stream_data_uni
                        };
                        let stream = Stream::new(StreamId(stream_id), max_data);
                        state.conn.streams.insert(StreamId(stream_id), stream);
                        
                        // Notify application with quicd_x::StreamId
                        let _ = state.ingress_tx.try_send(Event::StreamOpened { 
                            stream_id: quicd_x::StreamId(stream_id), 
                            is_bidirectional: bidirectional 
                        });
                        break;
                    }
                }
            }
            Command::SendDatagram { conn_id, data } => {
                let mut target_scid: Option<ConnectionId> = None;
                for (scid, state) in &mut self.connections {
                    let mut bytes = [0u8; 8];
                    let scid_bytes = scid.as_bytes();
                    let len = std::cmp::min(scid_bytes.len(), 8);
                    bytes[..len].copy_from_slice(&scid_bytes[..len]);
                    let conn_id_u64 = u64::from_le_bytes(bytes);
                    
                    if conn_id_u64 == conn_id.0 {
                        // Queue DATAGRAM frame
                        state.conn.pending_frames.push_back(Frame::Datagram { data });
                        target_scid = Some(scid.clone());
                        break;
                    }
                }
                if let Some(scid) = target_scid {
                    let now = Instant::now();
                    return self.generate_packets(&scid, now);
                }
            }
            Command::CloseConnection { conn_id, error_code, reason } => {
                let mut target_scid: Option<ConnectionId> = None;
                for (scid, state) in &mut self.connections {
                    let mut bytes = [0u8; 8];
                    let scid_bytes = scid.as_bytes();
                    let len = std::cmp::min(scid_bytes.len(), 8);
                    bytes[..len].copy_from_slice(&scid_bytes[..len]);
                    let conn_id_u64 = u64::from_le_bytes(bytes);
                    
                    if conn_id_u64 == conn_id.0 {
                        state.conn.state = QuicConnectionState::Closing;
                        state.conn.pending_frames.push_back(Frame::ConnectionClose {
                            error_code,
                            frame_type: None,
                            reason,
                            is_application: true,
                        });
                        target_scid = Some(scid.clone());
                        break;
                    }
                }
                if let Some(scid) = target_scid {
                    let now = Instant::now();
                    return self.generate_packets(&scid, now);
                }
            }
            Command::ResetStream { conn_id, stream_id, error_code } => {
                // Find connection and send RESET_STREAM frame
                let mut target_scid: Option<ConnectionId> = None;
                for (scid, state) in &mut self.connections {
                    if Self::matches_conn_id(scid, conn_id) {
                        // Reset the stream per RFC 9000 Section 3.2
                        state.conn.pending_frames.push_back(Frame::ResetStream {
                            stream_id: stream_id.0,
                            error_code,
                            final_size: 0, // Should track actual sent bytes
                        });
                        target_scid = Some(scid.clone());
                        break;
                    }
                }
                if let Some(scid) = target_scid {
                    let now = Instant::now();
                    return self.generate_packets(&scid, now);
                }
            }
            Command::StopSending { conn_id, stream_id, error_code } => {
                // Find connection and send STOP_SENDING frame
                let mut target_scid: Option<ConnectionId> = None;
                for (scid, state) in &mut self.connections {
                    if Self::matches_conn_id(scid, conn_id) {
                        // Per RFC 9000 Section 3.5: Request peer stop sending on stream
                        state.conn.pending_frames.push_back(Frame::StopSending {
                            stream_id: stream_id.0,
                            error_code,
                        });
                        target_scid = Some(scid.clone());
                        break;
                    }
                }
                if let Some(scid) = target_scid {
                    let now = Instant::now();
                    return self.generate_packets(&scid, now);
                }
            }
            Command::AbortConnection { conn_id, error_code } => {
                // Immediate connection termination (less graceful than CloseConnection)
                let mut target_scid: Option<ConnectionId> = None;
                for (scid, state) in &mut self.connections {
                    if Self::matches_conn_id(scid, conn_id) {
                        // Transition to closing state immediately
                        state.conn.state = QuicConnectionState::Closing;
                        state.conn.pending_frames.push_back(Frame::ConnectionClose {
                            error_code,
                            frame_type: None,
                            reason: String::from("connection aborted"),
                            is_application: true,
                        });
                        target_scid = Some(scid.clone());
                        break;
                    }
                }
                if let Some(scid) = target_scid {
                    let now = Instant::now();
                    let packets = self.generate_packets(&scid, now);
                    // Remove connection immediately after sending abort
                    self.connections.remove(&scid);
                    return packets;
                }
            }
            Command::StreamDataRead { conn_id, stream_id, len } => {
                // Application has consumed data, send MAX_STREAM_DATA to update flow control
                // Per RFC 9000 Section 4.1: Flow control windows must be updated
                let mut target_scid: Option<ConnectionId> = None;
                for (scid, state) in &mut self.connections {
                    if Self::matches_conn_id(scid, conn_id) {
                        // Update stream-level flow control
                        let stream_id_quic = quicd_quic::stream::StreamId(stream_id.0);
                        if let Some(stream) = state.conn.streams.get_mut(&stream_id_quic) {
                            // Increment flow control window
                            let new_max = stream.max_data + len as u64;
                            stream.max_data = new_max;
                            
                            // Send MAX_STREAM_DATA frame
                            state.conn.pending_frames.push_back(Frame::MaxStreamData {
                                stream_id: stream_id.0,
                                maximum: new_max,
                            });
                        }
                        
                        // Also update connection-level flow control per RFC 9000 Section 4.1
                        let new_max_data = state.conn.max_data_local + len as u64;
                        state.conn.max_data_local = new_max_data;
                        state.conn.pending_frames.push_back(Frame::MaxData {
                            maximum: new_max_data,
                        });
                        
                        target_scid = Some(scid.clone());
                        break;
                    }
                }
                if let Some(scid) = target_scid {
                    let now = Instant::now();
                    return self.generate_packets(&scid, now);
                }
            }
        }
        vec![]
    }
    
    pub fn poll_timeouts(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        let mut responses = Vec::new();
        let now = Instant::now();
        let mut to_close = Vec::new();
        let mut need_packets = Vec::new(); // Collect SCIDs that need packet generation
        
        // RFC 9002 Section 6: Loss Detection and Congestion Control
        // Check each connection for timeouts
        for (scid, state) in &mut self.connections {
            // RFC 9002 Section 6.2: Loss Detection Timer
            // Check if loss detection timer has fired
            if let Some(timeout) = state.conn.loss_detector.get_loss_detection_timeout() {
                if now >= timeout {
                    // RFC 9002 Section 6.2.1: On Timeout
                    // Determine if this is a loss timeout or PTO timeout
                    let pto_count = state.conn.loss_detector.on_pto_timeout(now);
                    
                    if pto_count > 0 {
                        // PTO timeout - send probe packets per RFC 9002 Section 6.2.4
                        // Generate probe packet with PING frame to elicit ACK
                        state.conn.pending_frames.push_back(Frame::Ping);
                        need_packets.push(scid.clone());
                    }
                }
            }
            
            // RFC 9000 Section 10.1: Idle Timeout
            // Check if connection has been idle too long (use max of local and peer's timeout)
            let effective_timeout = state.conn.config.max_idle_timeout.max(
                state.conn.peer_params
                    .as_ref()
                    .and_then(|p| Some(p.max_idle_timeout))
                    .unwrap_or(Duration::from_secs(30))
            );
            
            if now.duration_since(state.conn.last_packet_received_time) > effective_timeout {
                // Connection idle timeout - close connection
                info!("Connection {:?} idle timeout after {:?}", scid, effective_timeout);
                to_close.push(scid.clone());
            }
            
            // RFC 9000 Section 10.2: Immediate Close
            // Check if closing/draining timeout has expired (3x PTO per RFC)
            if matches!(state.conn.state, QuicConnectionState::Closing | QuicConnectionState::Draining) {
                if let Some(closing_start) = state.conn.closing_draining_start {
                    // Use a conservative 3 second timeout as fallback
                    // In production, this would use compute_pto with actual RTT stats
                    let closing_timeout = Duration::from_secs(3);
                    if now.duration_since(closing_start) > closing_timeout {
                        // Closing timeout expired - move to closed state
                        to_close.push(scid.clone());
                    }
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
            let packets = state.conn.generate_packets(now);
            eprintln!("connection_manager::generate_packets: Got {} packets from connection", packets.len());
            let mut out = Vec::new();
            for pkt in packets {
                // Serialize packet with header protection per RFC 9001 Section 5.4
                match state.conn.serialize_with_header_protection(&pkt) {
                    Ok(buf) => {
                        eprintln!("connection_manager::generate_packets: Serialized and protected packet, size: {}", buf.len());
                        out.push((state.peer_addr, buf));
                    }
                    Err(e) => {
                        eprintln!("connection_manager::generate_packets: Failed to serialize/protect packet: {}", e);
                    }
                }
            }
            eprintln!("connection_manager::generate_packets: Returning {} protected packets", out.len());
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
        let (should_process, dcid_len, buffered) = {
            if let Some(state) = self.connections.get_mut(scid) {
                // Check if handshake is complete (not just if keys are available)
                if !state.conn.handshake_complete {
                    return vec![];
                }
                
                // Take buffered packets (move out of state)
                let buffered = std::mem::take(&mut state.buffered_1rtt_packets);
                
                if buffered.is_empty() {
                    return vec![];
                }
                
                info!("Processing {} buffered 1-RTT packets for connection {:?}", buffered.len(), scid);
                (true, state.dcid_len, buffered)
            } else {
                return vec![];
            }
        };
        
        if !should_process {
            return vec![];
        }
        
        // Now process each buffered packet (state borrow dropped)
        use quicd_quic::packet::ParseContext;
        let mut all_outgoing = Vec::new();
        
        for (packet_bytes, datagram_size, arrival_time) in buffered {
            // Get state again for each packet (fresh borrow)
            let state = match self.connections.get_mut(scid) {
                Some(s) => s,
                None => break,
            };
            
            // Parse with known DCID length
            let ctx = ParseContext::with_dcid_len(dcid_len);
            let mut packet = match quicd_quic::packet::Packet::parse_with_context(packet_bytes.clone(), ctx) {
                Ok(pkt) => pkt,
                Err(e) => {
                    warn!("Failed to parse buffered packet: {:?}", e);
                    continue;
                }
            };
            
            // Remove header protection with now-available keys
            let hp_key = match state.conn.get_hp_key(quicd_quic::crypto::EncryptionLevel::OneRtt) {
                Some(key) => key,
                None => {
                    warn!("OneRtt HP key not available for buffered packet");
                    continue;
                }
            };
            
            if let Err(e) = packet.remove_header_protection(hp_key, packet_bytes.as_ref()) {
                warn!("Failed to remove header protection from buffered packet: {:?}", e);
                continue;
            }
            
            debug!("Processing buffered packet pn={:?}", packet.header.packet_number);
            
            // Process the packet
            if let Err(e) = state.conn.process_packet(packet, datagram_size, arrival_time) {
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
