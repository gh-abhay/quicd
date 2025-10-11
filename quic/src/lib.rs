use quiche::{Config, Connection, RecvInfo};
use bytes::{Bytes, BytesMut};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum QuicError {
    #[error("QUIC protocol error: {0}")]
    Quiche(#[from] quiche::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Other error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, QuicError>;

/// Input packet from network
#[derive(Debug)]
pub struct PacketIn {
    pub data: Bytes,
    pub from: SocketAddr,
    pub to: SocketAddr,
}

/// Output packet to network
#[derive(Debug)]
pub struct PacketOut {
    pub data: Bytes,
    pub to: SocketAddr,
}

/// QUIC event
#[derive(Debug)]
pub enum QuicEvent {
    NewConnection { conn_id: u64 },
    StreamData { conn_id: u64, stream_id: u64, data: Bytes, fin: bool },
    Datagram { conn_id: u64, data: Bytes },
    ConnectionClosed { conn_id: u64 },
}

/// Connection state
struct ConnectionState {
    conn: Connection,
    // Pre-allocated buffers for performance
    read_buf: BytesMut,
    write_buf: BytesMut,
}

impl ConnectionState {
    fn new(conn: Connection) -> Self {
        Self {
            conn,
            read_buf: BytesMut::with_capacity(65536), // 64KB buffer
            write_buf: BytesMut::with_capacity(65536),
        }
    }
}

/// Sans-IO QUIC engine optimized for performance
pub struct QuicEngine {
    config: Config,
    local_addr: SocketAddr,
    connections: HashMap<u64, ConnectionState>,
    conn_id_to_scid: HashMap<u64, quiche::ConnectionId<'static>>,
    scid_to_conn_id: HashMap<quiche::ConnectionId<'static>, u64>,
    next_conn_id: u64,
    // Output queue for batched sending
    output_queue: VecDeque<PacketOut>,
}

impl QuicEngine {
    pub fn new(local_addr: SocketAddr) -> Result<Self> {
        let mut config = Config::new(quiche::PROTOCOL_VERSION)?;
        // Performance optimizations
        config.set_application_protos(&[b"h3", b"webtransport"])?;
        config.set_max_idle_timeout(30000);
        config.set_max_recv_udp_payload_size(1350); // MTU optimized
        config.set_max_send_udp_payload_size(1350);
        config.set_initial_max_data(10_000_000); // 10MB
        config.set_initial_max_stream_data_bidi_local(1_000_000); // 1MB
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.enable_dgram(true, 1000, 1000); // Enable datagrams
        // Additional performance settings
        config.set_max_connection_window(10_000_000);
        config.set_max_stream_window(1_000_000);
        config.set_active_connection_id_limit(4); // Multiple CIDs for migration
        config.enable_pacing(true); // Enable pacing for better throughput

        Ok(Self {
            config,
            local_addr,
            connections: HashMap::new(),
            conn_id_to_scid: HashMap::new(),
            scid_to_conn_id: HashMap::new(),
            next_conn_id: 0,
            output_queue: VecDeque::with_capacity(1024), // Pre-allocate output queue
        })
    }

    /// Process incoming packets, return events (zero-copy where possible)
    pub fn process_packets(&mut self, packets: Vec<PacketIn>) -> Result<Vec<QuicEvent>> {
        let mut events = Vec::with_capacity(packets.len() * 2); // Pre-allocate events

        for packet in packets {
            // Extract connection ID from packet header
            let scid = self.extract_scid(&packet.data)?;

            if let Some(&conn_id) = self.scid_to_conn_id.get(&scid) {
                // Existing connection
                if let Some(conn_state) = self.connections.get_mut(&conn_id) {
                    // Process packet directly here to avoid double borrow
                    conn_state.read_buf.clear();
                    conn_state.read_buf.extend_from_slice(&packet.data);

                    // Feed packet to quiche
                    match conn_state.conn.recv(&mut conn_state.read_buf, RecvInfo {
                        from: packet.from,
                        to: self.local_addr,
                    }) {
                        Ok(len) => {
                            // Packet processed successfully
                        }
                        Err(e) => {
                            log::warn!("Failed to process packet for connection {}: {:?}", conn_id, e);
                            continue;
                        }
                    }

                    // Extract events from connection
                    Self::extract_connection_events(&mut conn_state.conn, conn_id, &mut events)?;
                }
            } else {
                // New connection attempt
                self.process_new_connection(packet, &mut events)?;
            }
        }

        Ok(events)
    }

    fn process_new_connection(&mut self, packet: PacketIn, events: &mut Vec<QuicEvent>) -> Result<()> {
        // Try to accept the connection
        let info = quiche::RecvInfo {
            from: packet.from,
            to: packet.to,
        };

        let scid = self.extract_scid(&packet.data)?.to_owned();
        let odcid = None; // For initial packets, no original DCID

        match quiche::accept(&scid, odcid, self.local_addr, packet.from, &mut self.config) {
            Ok(conn) => {
                let conn_id = self.next_conn_id;
                self.next_conn_id += 1;

                // Get SCID bytes and create owned ConnectionId
                let scid_bytes = conn.source_id().as_ref().to_vec();
                let scid_owned = quiche::ConnectionId::from_vec(scid_bytes);

                // Store connection
                let conn_state = ConnectionState::new(conn);

                self.connections.insert(conn_id, conn_state);
                self.conn_id_to_scid.insert(conn_id, scid_owned.clone());
                self.scid_to_conn_id.insert(scid_owned, conn_id);

                events.push(QuicEvent::NewConnection { conn_id });
            }
            Err(quiche::Error::Done) => {
                // Not a valid initial packet, ignore
            }
            Err(e) => {
                // Log error but don't fail - could be malformed packet
                log::debug!("Failed to accept connection: {:?}", e);
            }
        }

        Ok(())
    }

    /// Extract events from a connection
    fn extract_connection_events(conn: &mut Connection, conn_id: u64, events: &mut Vec<QuicEvent>) -> Result<()> {
        // Process readable streams
        for stream_id in conn.readable() {
                        Self::process_stream_data(conn, conn_id, stream_id, events)?;
        }

        // Process datagrams
        Self::process_datagrams(conn, conn_id, events)?;

        // Check connection state
        if conn.is_closed() {
            events.push(QuicEvent::ConnectionClosed { conn_id });
        }

        Ok(())
    }

    /// Process data from a readable stream
    fn process_stream_data(conn: &mut Connection, conn_id: u64, stream_id: u64, events: &mut Vec<QuicEvent>) -> Result<()> {
        // Use a temporary buffer for reading
        let mut buf = [0u8; 65536]; // 64KB buffer

        match conn.stream_recv(stream_id, &mut buf) {
            Ok((len, fin)) => {
                let data = Bytes::copy_from_slice(&buf[..len]);
                events.push(QuicEvent::StreamData { conn_id, stream_id, data, fin });
            }
            Err(quiche::Error::Done) => {
                // No more data available
            }
            Err(e) => return Err(e.into()),
        }

        Ok(())
    }

    /// Process datagrams
    fn process_datagrams(conn: &mut Connection, conn_id: u64, events: &mut Vec<QuicEvent>) -> Result<()> {
        let mut buf = [0u8; 65536];

        while let Ok(len) = conn.dgram_recv(&mut buf) {
            let data = Bytes::copy_from_slice(&buf[..len]);
            events.push(QuicEvent::Datagram { conn_id, data });
        }

        Ok(())
    }

    /// Extract Source Connection ID from packet (performance critical)
    fn extract_scid<'a>(&self, data: &'a Bytes) -> Result<quiche::ConnectionId<'a>> {
        if data.len() < 8 {
            return Err(QuicError::Other("Packet too small".to_string()));
        }

        // For QUIC, SCID is typically in the first part of the header
        // This is a simplified extraction - in production, parse the full header
        let scid_bytes = &data[..8];
        let scid = quiche::ConnectionId::from_ref(scid_bytes);
        Ok(scid)
    }

    /// Get outgoing packets to send (batched for performance)
    pub fn get_outgoing_packets(&mut self) -> Result<Vec<PacketOut>> {
        // Process all connections for outgoing packets
        let conn_ids: Vec<u64> = self.connections.keys().cloned().collect();
        for conn_id in conn_ids {
            if let Some(conn_state) = self.connections.get_mut(&conn_id) {
                Self::generate_outgoing_packets_for_connection(conn_state, conn_id, &mut self.output_queue)?;
            }
        }

        // Return all queued packets
        let packets = self.output_queue.drain(..).collect();
        Ok(packets)
    }

    /// Generate outgoing packets for a specific connection
    fn generate_outgoing_packets_for_connection(conn_state: &mut ConnectionState, _conn_id: u64, output_queue: &mut VecDeque<PacketOut>) -> Result<()> {
        // Clear write buffer
        conn_state.write_buf.clear();

        // Generate packets until no more data
        while let Ok((written, send_info)) = conn_state.conn.send(&mut conn_state.write_buf) {
            if written > 0 {
                let data = Bytes::copy_from_slice(&conn_state.write_buf[..written]);
                output_queue.push_back(PacketOut {
                    data,
                    to: send_info.to,
                });
            } else {
                break;
            }
        }

        Ok(())
    }

    /// Send data on a stream (zero-copy)
    pub fn send_stream_data(&mut self, conn_id: u64, stream_id: u64, data: &[u8], fin: bool) -> Result<()> {
        if let Some(conn_state) = self.connections.get_mut(&conn_id) {
            conn_state.conn.stream_send(stream_id, data, fin)?;
            // Immediately generate outgoing packets for low latency
            Self::generate_outgoing_packets_for_connection(conn_state, conn_id, &mut self.output_queue)?;
        }
        Ok(())
    }

    /// Send datagram (zero-copy)
    pub fn send_datagram(&mut self, conn_id: u64, data: &[u8]) -> Result<()> {
        if let Some(conn_state) = self.connections.get_mut(&conn_id) {
            conn_state.conn.dgram_send(data)?;
            // Immediately generate outgoing packets for low latency
            Self::generate_outgoing_packets_for_connection(conn_state, conn_id, &mut self.output_queue)?;
        }
        Ok(())
    }

    /// Close connection
    pub fn close_connection(&mut self, conn_id: u64, error: u64, reason: &[u8]) -> Result<()> {
        if let Some(conn_state) = self.connections.get_mut(&conn_id) {
            conn_state.conn.close(false, error, reason)?;
            // Generate final packets
            Self::generate_outgoing_packets_for_connection(conn_state, conn_id, &mut self.output_queue)?;
        }
        Ok(())
    }

    /// Get connection statistics for monitoring
    pub fn get_connection_stats(&self, conn_id: u64) -> Option<quiche::Stats> {
        self.connections.get(&conn_id)
            .map(|conn_state| conn_state.conn.stats())
    }

    /// Check if connection is established
    pub fn is_connection_established(&self, conn_id: u64) -> bool {
        self.connections.get(&conn_id)
            .map(|conn_state| conn_state.conn.is_established())
            .unwrap_or(false)
    }

    /// Get number of active connections
    pub fn active_connections(&self) -> usize {
        self.connections.len()
    }

    /// Cleanup closed connections (call periodically)
    pub fn cleanup_closed_connections(&mut self) {
        let closed_ids: Vec<u64> = self.connections.iter()
            .filter_map(|(id, conn_state)| {
                if conn_state.conn.is_closed() {
                    Some(*id)
                } else {
                    None
                }
            })
            .collect();

        for id in closed_ids {
            if let Some(conn_state) = self.connections.remove(&id) {
                if let Some(scid) = self.conn_id_to_scid.remove(&id) {
                    self.scid_to_conn_id.remove(&scid);
                }
                log::debug!("Cleaned up closed connection {}", id);
            }
        }
    }

}