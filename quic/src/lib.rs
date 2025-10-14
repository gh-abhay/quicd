//! QUIC protocol implementation for Superd
//!
//! This crate provides QUIC connection management and packet processing.

use bytes::Bytes;
use quiche::{Config, Connection, ConnectionId, RecvInfo};
use std::collections::HashMap;
use std::net::SocketAddr;
use thiserror::Error;
use tokio::sync::mpsc;

pub mod protocol_handler;
pub mod stream_mux;
pub mod integration;
pub mod io;

pub use protocol_handler::{ProtocolConfig, ProtocolThread};
pub use stream_mux::{StreamMultiplexer, Protocol, ProtocolRoute};
pub use integration::StreamProcessor;
pub use io::{QuicStream, StreamCommand};

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
    pub data: Vec<u8>,
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
    NewConnection(ConnectionId<'static>),
    StreamData(ConnectionId<'static>, u64, Bytes),
    Datagram(ConnectionId<'static>, Bytes),
    ConnectionLost(ConnectionId<'static>),
    Send(Vec<PacketOut>),
}

/// Holds the state for a single QUIC connection.
pub struct ConnectionState {
    /// The underlying `quiche` connection object.
    pub conn: Connection,
    /// A map of stream IDs to their corresponding data channels (sender halves).
    /// When the `ProtocolThread` receives data for a stream, it sends it here.
    stream_data_tx: HashMap<u64, mpsc::Sender<Bytes>>,
}

impl ConnectionState {
    fn new(conn: Connection) -> Self {
        Self {
            conn,
            stream_data_tx: HashMap::new(),
        }
    }
}

/// Sans-IO QUIC engine optimized for performance
pub struct QuicEngine {
    config: Config,
    pub local_addr: SocketAddr,
    connections: HashMap<ConnectionId<'static>, ConnectionState>,
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

        // Load TLS certificate and key
        // In a real app, load from file or config
        let cert_path = "cert.pem";
        let key_path = "key.pem";
        config
            .load_cert_chain_from_pem_file(cert_path)
            .map_err(|e| QuicError::Other(format!("Failed to load cert: {}", e)))?;
        config
            .load_priv_key_from_pem_file(key_path)
            .map_err(|e| QuicError::Other(format!("Failed to load key: {}", e)))?;

        Ok(Self {
            config,
            local_addr,
            connections: HashMap::new(),
        })
    }

    /// Process a single incoming packet, return events (zero-copy where possible)
    pub fn process_packet(&mut self, mut packet: PacketIn) -> Result<Vec<QuicEvent>> {
        let mut events = Vec::with_capacity(2); // Pre-allocate for typical case

        // Parse packet header to get connection ID
        let hdr = match quiche::Header::from_slice(&mut packet.data, quiche::MAX_CONN_ID_LEN) {
            Ok(hdr) => hdr,
            Err(e) => {
                log::debug!("Failed to parse QUIC header: {}", e);
                return Ok(vec![]); // Not a valid QUIC packet, ignore
            }
        };

        // Get connection ID from header
        let conn_id = hdr.dcid.clone().into_owned();

        // Find connection or create a new one
        let conn_exists = self.connections.contains_key(&conn_id);
        if !conn_exists {
            // New connection
            if hdr.ty != quiche::Type::Initial {
                log::debug!("Packet is not Initial, but no connection found. Ignoring.");
                return Ok(vec![]);
            }

            let conn =
                quiche::accept(&hdr.dcid, None, self.local_addr, packet.from, &mut self.config)?;

            let conn_id_owned = conn.destination_id().clone().into_owned();
            let conn_state = ConnectionState::new(conn);
            self.connections.insert(conn_id_owned.clone(), conn_state);
            events.push(QuicEvent::NewConnection(conn_id_owned.clone()));
        }

        // Get the connection and process the packet
        let conn_state = self.connections.get_mut(&conn_id).unwrap();

        // Process the packet
        let recv_info = RecvInfo {
            from: packet.from,
            to: self.local_addr,
        };

        match conn_state.conn.recv(&mut packet.data, recv_info) {
            Ok(_) => {}
            Err(quiche::Error::Done) => {}
            Err(e) => {
                log::warn!("Failed to process packet for connection {:?}: {}", conn_id, e);
                if conn_state.conn.is_closed() {
                    events.push(QuicEvent::ConnectionLost(conn_id.clone()));
                    self.connections.remove(&conn_id);
                }
                return Ok(events);
            }
        }

        // Process readable streams
        for stream_id in conn_state.conn.readable() {
            let mut buf = [0u8; 65535];
            while let Ok((read, _fin)) = conn_state.conn.stream_recv(stream_id, &mut buf) {
                if read == 0 {
                    break;
                }
                let data = Bytes::copy_from_slice(&buf[..read]);

                // If we have a channel for this stream, send the data.
                // Otherwise, buffer it as a `StreamData` event for the StreamProcessor
                // to handle and create a new stream.
                if let Some(tx) = conn_state.stream_data_tx.get(&stream_id) {
                    if tx.try_send(data).is_err() {
                        log::warn!("Stream {} channel full or closed, dropping data.", stream_id);
                    }
                } else {
                    events.push(QuicEvent::StreamData(conn_id.clone(), stream_id, data));
                }
            }
        }

        // Process datagrams
        while let Ok(len) = conn_state.conn.dgram_recv(&mut [0u8; 65536]) {
            let mut buf = vec![0; len];
            conn_state.conn.dgram_recv(&mut buf).unwrap();
            events.push(QuicEvent::Datagram(conn_id.clone(), Bytes::from(buf)));
        }

        // Handle connection closure
        if conn_state.conn.is_closed() {
            events.push(QuicEvent::ConnectionLost(conn_id.clone()));
            self.connections.remove(&conn_id);
        }

        Ok(events)
    }

    /// Get a mutable reference to a connection state
    pub fn get_connection_state_mut(
        &mut self,
        conn_id: &ConnectionId<'static>,
    ) -> Option<&mut ConnectionState> {
        self.connections.get_mut(conn_id)
    }

    /// Send all pending packets for all connections
    pub fn send_pending_packets(&mut self) -> Vec<PacketOut> {
        let mut packets_to_send = Vec::new();
        let mut buf = [0u8; 65536];

        for conn_state in self.connections.values_mut() {
            while let Ok((write, send_info)) = conn_state.conn.send(&mut buf) {
                packets_to_send.push(PacketOut {
                    data: Bytes::copy_from_slice(&buf[..write]),
                    to: send_info.to,
                });
            }
        }
        packets_to_send
    }

    /// Cleanup closed connections (call periodically)
    pub fn cleanup_closed_connections(&mut self) {
        self.connections.retain(|_conn_id, conn_state| {
            if conn_state.conn.is_closed() {
                log::debug!("Cleaning up closed connection: {:?}", conn_state.conn.trace_id());
                false
            } else {
                true
            }
        });
    }
}
