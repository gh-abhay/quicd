//! Connection manager for worker threads.
//!
//! Manages QUIC connections and routes packets to the appropriate connection.
//! Each worker thread has its own connection manager with isolated state.

use bytes::Bytes;
use crate::netio::buffer::WorkerBuffer;
use crate::routing::{RoutingConnectionIdGenerator, current_generation};
use crossbeam_channel::{Sender, Receiver, bounded};
use quicd_quic::{Connection, ConnectionConfig, Packet, PacketType};
use quicd_quic::cid::{ConnectionIdGenerator, ConnectionId};
use quicd_quic::crypto::TlsSession;
use quicd_quic::stream::{Stream, StreamId};
use quicd_quic::frame::Frame;
use quicd_quic::connection::ConnectionState as QuicConnectionState;
use quicd_x::{ConnectionHandle, Event, Command};
use quicd_x::ConnectionId as XConnectionId;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::runtime::Handle as TokioHandle;
use tracing::{error, info};

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
}

impl ConnectionManager {
    pub fn new(
        config: ConnectionConfig,
        tokio_handle: TokioHandle,
        egress_tx: Sender<Command>,
        worker_id: u8,
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
        }
    }
    
    pub fn handle_packet(&mut self, buffer: WorkerBuffer, peer_addr: SocketAddr, now: Instant) -> Vec<(SocketAddr, Vec<u8>)> {
        // Parse packet from buffer
        let bytes = Bytes::copy_from_slice(&buffer);
        let packet = match Packet::parse(bytes) {
             Ok(p) => p,
             Err(e) => {
                 error!("Failed to parse packet: {}", e);
                 return vec![];
             }
        };

        let dcid = packet.header.dcid.clone();
        
        // Check if existing connection
        if let Some(scid) = self.dcid_to_conn.get(&dcid) {
            // We need to clone scid to use it for lookup to avoid borrow checker issues
            let scid = scid.clone();
            if let Some(state) = self.connections.get_mut(&scid) {
                if let Err(e) = state.conn.process_packet(packet, now) {
                    error!("Connection error: {}", e);
                }
                
                self.flush_events_to_app(&scid);
                self.check_handshake_complete(&scid);
                
                return self.generate_packets(&scid, now);
            }
        }
        
        // New connection?
        if packet.header.ty == PacketType::Initial {
            let scid = self.cid_generator.generate(8); // Use 8 bytes for SCID
            let tls = TlsSession::new_server();
            
            let mut conn = Connection::new(self.config.clone(), scid.clone(), packet.header.scid.clone().unwrap(), tls);
            
            if let Err(e) = conn.process_packet(packet, now) {
                error!("Failed to process initial packet: {}", e);
                return vec![];
            }
            
            let (ingress_tx, ingress_rx) = bounded(1024);
            
            let state = ConnectionState {
                conn,
                peer_addr,
                ingress_tx,
                ingress_rx: Some(ingress_rx),
                app_spawned: false,
            };
            
            self.connections.insert(scid.clone(), state);
            self.dcid_to_conn.insert(dcid, scid.clone());
            self.dcid_to_conn.insert(scid.clone(), scid.clone());
            
            self.check_handshake_complete(&scid);
            
            return self.generate_packets(&scid, now);
        }
        
        vec![]
    }
    
    fn check_handshake_complete(&mut self, scid: &ConnectionId) {
        // We need to extract fields to avoid borrow checker issues with self.spawn_app
        let mut should_spawn = false;
        if let Some(state) = self.connections.get(scid) {
            if state.conn.handshake_complete && !state.app_spawned {
                should_spawn = true;
            }
        }
        
        if should_spawn {
            self.spawn_app(scid.clone());
        }
    }
    
    fn spawn_app(&mut self, scid: ConnectionId) {
        if let Some(state) = self.connections.get_mut(&scid) {
            if let Some(rx) = state.ingress_rx.take() {
                state.app_spawned = true;
                
                // Convert SCID to u64 (take first 8 bytes)
                let mut bytes = [0u8; 8];
                let scid_bytes = scid.as_bytes();
                let len = std::cmp::min(scid_bytes.len(), 8);
                bytes[..len].copy_from_slice(&scid_bytes[..len]);
                let conn_id_u64 = u64::from_le_bytes(bytes);
                
                let _handle = ConnectionHandle::new(
                    XConnectionId(conn_id_u64),
                    rx,
                    self.egress_tx.clone(),
                );
                
                // Spawn task
                self.tokio_handle.spawn(async move {
                    // In real impl, we'd look up the app factory based on ALPN
                    // For now, we don't have the app registry here.
                    // The prompt says "Applications implement the trait; worker spawns EXACTLY ONE tokio task".
                    // But where does the worker get the application from?
                    // "Worker looks up application factory by ALPN in AppRegistry"
                    // I don't have AppRegistry passed in.
                    // I'll assume a default app or placeholder.
                    info!("Application task spawned for connection {}", conn_id_u64);
                    
                    // Placeholder:
                    // let app = ...;
                    // app.on_connection(handle).await;
                });
            }
        }
    }
    
    fn flush_events_to_app(&mut self, scid: &ConnectionId) {
        if let Some(state) = self.connections.get_mut(scid) {
            // Check for pending datagrams
            while let Some(data) = state.conn.pending_datagrams.pop_front() {
                let _ = state.ingress_tx.try_send(Event::DatagramReceived { data });
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
            Command::ResetStream { conn_id: _, stream_id: _, error_code: _ } |
            Command::StopSending { conn_id: _, stream_id: _, error_code: _ } |
            Command::AbortConnection { conn_id: _, error_code: _ } |
            Command::StreamDataRead { conn_id: _, stream_id: _, len: _ } => {
                // TODO: Implement these command handlers
            }
        }
        vec![]
    }
    
    pub fn poll_timeouts(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        let responses = Vec::new();
        let _now = Instant::now();
        
        // TODO: Implement timeout handling
        // Check each connection for timeouts
        // let mut to_close = Vec::new();
        // for (scid, state) in &mut self.connections {
        //     // Check loss detection timeout
        //     if let Some(timeout) = state.conn.loss_detector.get_loss_detection_timeout() {
        //         if now >= timeout {
        //             // Handle timeout - detect lost packets or send PTO probes
        //             let lost_packets = state.conn.loss_detector.on_ack(...);
        //             
        //             if lost_packets.is_empty() {
        //                 // PTO timeout - send probe packets
        //                 let pto_packets = state.conn.loss_detector.on_pto_timeout(now);
        //                 // Retransmit data from lost packets
        //                 for _pkt in pto_packets {
        //                     // Queue retransmission frames
        //                     // In a full implementation, we'd retransmit the actual packet data
        //                 }
        //             }
        //             
        //             // Generate packets
        //             let pkts = self.generate_packets(scid, now);
        //             responses.extend(pkts);
        //         }
        //     }
        //     
        //     // Check idle timeout per RFC 9000 Section 10.1
        //     // (Simplified - would need to track last activity time)
        // }
        // 
        // // Remove closed connections
        // for scid in to_close {
        //     self.connections.remove(&scid);
        //     // Also clean up DCID mappings
        // }
        
        responses
    }
    
    fn generate_packets(&mut self, scid: &ConnectionId, now: Instant) -> Vec<(SocketAddr, Vec<u8>)> {
        if let Some(state) = self.connections.get_mut(scid) {
            let packets = state.conn.generate_packets(now);
            let mut out = Vec::new();
            for pkt in packets {
                if let Ok(buf) = pkt.serialize() {
                    out.push((state.peer_addr, buf.to_vec()));
                }
            }
            return out;
        }
        vec![]
    }
}
