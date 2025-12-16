//! Connection manager for worker threads.
//!
//! Manages QUIC connections and routes packets to the appropriate connection.
//! Each worker thread has its own connection manager with isolated state.

use crate::netio::buffer::WorkerBuffer;
use crate::routing::{RoutingConnectionIdGenerator, current_generation};
use anyhow::Result;
use crossbeam_channel::{Sender, bounded};
use quicd_quic::{Connection, ConnectionConfig, ConnectionError, Packet};
use quicd_quic::cid::ConnectionIdGenerator;
use quicd_x::{ConnectionHandle, ConnectionId, Event, Command};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::runtime::Handle as TokioHandle;
use tracing::{debug, error, warn};

/// Maps incoming packets to QUIC connections.
pub struct ConnectionManager {
    /// Active connections indexed by Connection ID.
    connections: HashMap<quicd_quic::cid::ConnectionId, ConnectionState>,
    
    /// Mapping from DCID to connection for packet routing.
    dcid_to_conn: HashMap<quicd_quic::cid::ConnectionId, quicd_quic::cid::ConnectionId>,
    
    /// Configuration for new connections.
    config: ConnectionConfig,
    
    /// Tokio runtime handle for spawning application tasks.
    tokio_handle: TokioHandle,
    
    /// Worker egress channel sender (cloned for each connection).
    egress_tx: Sender<Command>,
    
    /// CID generator for this worker (with routing cookie).
    cid_generator: Arc<dyn ConnectionIdGenerator>,
}

/// Per-connection state managed by the worker.
struct ConnectionState {
    /// The QUIC connection state machine.
    conn: Connection,
    
    /// Remote peer address.
    peer_addr: SocketAddr,
    
    /// Ingress channel sender for events to application task.
    ingress_tx: Sender<Event>,
    
    /// Application task handle (to check if it's still alive).
    _task_handle: tokio::task::JoinHandle<()>,
}

impl ConnectionManager {
    /// Create a new connection manager.
    pub fn new(
        config: ConnectionConfig,
        tokio_handle: TokioHandle,
        egress_tx: Sender<Command>,
        worker_id: u8,
    ) -> Self {
        // Create routing-aware CID generator for this worker
        let generation = current_generation();
        let cid_generator = Arc::new(RoutingConnectionIdGenerator::new(worker_id, generation));
        
        Self {
            connections: HashMap::new(),
            dcid_to_conn: HashMap::new(),
            config,
            tokio_handle,
            egress_tx,
            cid_generator,
        }
    }
    
    /// Process an incoming packet.
    ///
    /// Routes the packet to the appropriate connection or creates a new connection.
    ///
    /// Returns packets to send in response.
    pub fn handle_packet(
        &mut self,
        buffer: WorkerBuffer,
        peer_addr: SocketAddr,
    ) -> Vec<(SocketAddr, Vec<u8>)> {
        let data = buffer.as_slice();
        
        // Parse QUIC packet
        let packet = match Packet::parse(bytes::Bytes::copy_from_slice(data)) {
            Ok(pkt) => pkt,
            Err(e) => {
                debug!("Failed to parse packet from {}: {:?}", peer_addr, e);
                return Vec::new();
            }
        };
        
        // Route packet to connection by DCID
        let dcid = packet.header.dcid.clone();
        
        // Check if this is for an existing connection
        if let Some(conn_cid) = self.dcid_to_conn.get(&dcid).cloned() {
            if let Some(conn_state) = self.connections.get_mut(&conn_cid) {
                // Process packet directly inline to avoid borrow checker issues
                match conn_state.conn.handle_packet(packet) {
                    Ok(frames) => {
                        let mut packets = Vec::new();
                        // Convert frames to events and send to application
                        for frame in frames {
                            if let Some(event) = Self::frame_to_event_static(frame) {
                                if let Err(e) = conn_state.ingress_tx.try_send(event) {
                                    warn!("Failed to send event to application: {:?}", e);
                                    // Apply backpressure - TODO: adjust QUIC flow control
                                }
                            }
                        }
                        return packets;
                    }
                    Err(e) => {
                        error!("Connection error: {:?}", e);
                        return Vec::new();
                    }
                }
            }
        }
        
        // New connection - check if this is an Initial packet
        if matches!(packet.header.ty, quicd_quic::packet::PacketType::Initial) {
            return self.handle_new_connection(packet, peer_addr);
        }
        
        // Unknown connection and not an Initial packet - ignore
        debug!("Received non-Initial packet for unknown connection from {}", peer_addr);
        Vec::new()
    }
    
    /// Handle a new connection (Initial packet).
    fn handle_new_connection(
        &mut self,
        packet: Packet,
        peer_addr: SocketAddr,
    ) -> Vec<(SocketAddr, Vec<u8>)> {
        let dcid = packet.header.dcid.clone();
        let scid = packet.header.scid.clone().unwrap_or_else(|| {
            quicd_quic::cid::ConnectionId::empty()
        });
        
        // Generate local CID using routing-aware generator
        let local_cid = self.cid_generator.generate(crate::routing::CID_LENGTH);
        
        debug!("New connection from {} (DCID: {})", peer_addr, dcid);
        
        // Create QUIC connection with routing-aware generator
        let conn = match Connection::new_server(
            local_cid.clone(),
            scid,
            self.config.clone(),
            self.cid_generator.clone(),
        ) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to create connection: {:?}", e);
                return Vec::new();
            }
        };
        
        // Create per-connection ingress channel (SPSC)
        let (ingress_tx, ingress_rx) = bounded(64);
        
        // Create ConnectionHandle for application
        let conn_handle = ConnectionHandle::new(
            ConnectionId(0), // TODO: Proper connection ID
            ingress_rx,
            self.egress_tx.clone(),
        );
        
        // Spawn application task
        let task_handle = self.tokio_handle.spawn(async move {
            // TODO: Get application from registry by ALPN
            // For now, just a placeholder
            // app.on_connection(conn_handle).await;
            debug!("Application task spawned for connection");
        });
        
        // Store connection state
        let conn_state = ConnectionState {
            conn,
            peer_addr,
            ingress_tx,
            _task_handle: task_handle,
        };
        
        self.connections.insert(local_cid.clone(), conn_state);
        self.dcid_to_conn.insert(dcid, local_cid.clone());
        
        // Process the Initial packet inline
        if let Some(conn_state) = self.connections.get_mut(&local_cid) {
            match conn_state.conn.handle_packet(packet) {
                Ok(frames) => {
                    let mut packets = Vec::new();
                    for frame in frames {
                        if let Some(event) = Self::frame_to_event_static(frame) {
                            let _ = conn_state.ingress_tx.try_send(event);
                        }
                    }
                    packets
                }
                Err(_) => Vec::new(),
            }
        } else {
            Vec::new()
        }
    }
    
    /// Convert QUIC frame to application event (static version for inline use).
    fn frame_to_event_static(frame: quicd_quic::Frame) -> Option<Event> {
        match frame {
            quicd_quic::Frame::Stream { stream_id, data, fin, .. } => {
                Some(Event::StreamData {
                    stream_id: quicd_x::StreamId(stream_id),
                    data,
                    fin,
                })
            }
            quicd_quic::Frame::ResetStream { stream_id, error_code, .. } => {
                Some(Event::StreamReset {
                    stream_id: quicd_x::StreamId(stream_id),
                    error_code,
                })
            }
            quicd_quic::Frame::ConnectionClose { error_code, reason, .. } => {
                Some(Event::ConnectionClosing {
                    error_code,
                    reason,
                })
            }
            quicd_quic::Frame::MaxStreams { maximum, is_bidirectional } => {
                Some(Event::MaxStreamsUpdated {
                    is_bidirectional,
                    max_streams: maximum,
                })
            }
            quicd_quic::Frame::Datagram { data } => {
                Some(Event::DatagramReceived { data })
            }
            _ => None, // Other frames don't generate events
        }
    }
    
    /// Process egress command from application.
    pub fn handle_command(&mut self, cmd: Command) -> Vec<(SocketAddr, Vec<u8>)> {
        match cmd {
            Command::WriteStreamData { conn_id, stream_id, data, fin } => {
                // TODO: Find connection, write to stream, generate packets
                Vec::new()
            }
            Command::CloseConnection { conn_id, error_code, reason } => {
                // TODO: Send CONNECTION_CLOSE frame
                Vec::new()
            }
            _ => Vec::new(),
        }
    }
    
    /// Check for idle timeouts and loss detection events.
    pub fn poll_timeouts(&mut self) -> Vec<(SocketAddr, Vec<u8>)> {
        let mut packets = Vec::new();
        
        // Check each connection for timeouts
        let mut to_close = Vec::new();
        
        for (cid, conn_state) in &mut self.connections {
            // Check idle timeout
            if conn_state.conn.check_idle_timeout() {
                debug!("Connection {:?} idle timeout", cid);
                to_close.push(cid.clone());
                continue;
            }
            
            // Check loss detection
            if let Some(lost_packets) = conn_state.conn.poll_loss_detection() {
                debug!("Connection {:?} lost {} packets", cid, lost_packets.len());
                // TODO: Retransmit lost packets
            }
        }
        
        // Close timed-out connections
        for cid in to_close {
            self.close_connection(&cid);
        }
        
        packets
    }
    
    /// Close a connection and clean up state.
    fn close_connection(&mut self, cid: &quicd_quic::cid::ConnectionId) {
        if let Some(conn_state) = self.connections.remove(cid) {
            // Send ConnectionClosed event
            let _ = conn_state.ingress_tx.try_send(Event::ConnectionClosed);
            
            // Remove DCID mappings
            self.dcid_to_conn.retain(|_, v| v != cid);
            
            debug!("Closed connection {:?}", cid);
        }
    }
}
