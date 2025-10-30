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
use crate::netio::buffer::WorkerBuffer;
use anyhow::{Context, Result};
use quiche::ConnectionId;
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Instant;
use tracing::{debug, error, info, trace, warn};

/// Maximum connection ID length (QUIC allows up to 20 bytes)
const MAX_CONN_ID_LEN: usize = 20;

/// Callback for sending packets back to the network layer
pub type SendCallback = Box<dyn Fn(SocketAddr, &[u8]) + Send>;

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
    connections: HashMap<ConnectionId<'static>, QuicConnection>,

    /// Connection ID seed (for generating new connection IDs)
    conn_id_seed: ring::hmac::Key,

    /// Callback to send packets (provided by network layer)
    send_callback: Option<SendCallback>,

    /// Statistics (using RefCell for interior mutability)
    stats: RefCell<ManagerStats>,
}

/// Manager statistics
#[derive(Debug, Default)]
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
}

impl QuicManager {
    /// Create a new QUIC manager for a worker thread
    pub fn new(worker_id: usize, local_addr: SocketAddr, config: QuicConfig) -> Result<Self> {
        // Validate configuration
        config.validate()?;

        info!(
            worker_id,
            %local_addr,
            max_connections = config.max_connections_per_worker,
            "Creating QUIC manager"
        );

        // Load or generate TLS credentials
        let credentials =
            if let (Some(cert_path), Some(key_path)) = (&config.cert_path, &config.key_path) {
                info!(
                    worker_id,
                    cert = cert_path,
                    key = key_path,
                    "Loading TLS credentials from files"
                );
                TlsCredentials::from_files(Path::new(cert_path), Path::new(key_path))?
            } else {
                warn!(
                    worker_id,
                    "Using self-signed certificate (NOT for production!)"
                );
                TlsCredentials::self_signed()?
            };

        // Create Quiche configuration
        let quiche_config = create_quiche_config(&credentials, &config)?;

        // Generate connection ID seed for this worker
        // Each worker has its own seed to avoid connection ID collisions
        let conn_id_seed =
            ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &ring::rand::SystemRandom::new())
                .map_err(|_| anyhow::anyhow!("failed to generate connection ID seed"))?;

        // Pre-allocate connection map
        let connections = HashMap::with_capacity(config.max_connections_per_worker);

        Ok(Self {
            worker_id,
            local_addr,
            config,
            quiche_config,
            connections,
            conn_id_seed,
            send_callback: None,
            stats: RefCell::new(ManagerStats::default()),
        })
    }

    /// Set the send callback (called by network layer)
    pub fn set_send_callback(&mut self, callback: SendCallback) {
        self.send_callback = Some(callback);
    }

    /// Process an incoming packet
    ///
    /// This is the main entry point from the network layer.
    /// Called when a UDP packet is received.
    pub fn process_ingress(
        &mut self,
        mut buffer: WorkerBuffer,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        // Get mutable slice for Quiche processing
        let packet_len = buffer.len();
        let packet = buffer.as_mut_slice_for_io();
        let packet = &mut packet[..packet_len]; // Limit to actual received data

        self.stats.borrow_mut().packets_processed += 1;

        // Parse QUIC header to extract connection ID
        let hdr = match quiche::Header::from_slice(packet, MAX_CONN_ID_LEN) {
            Ok(hdr) => hdr,
            Err(e) => {
                debug!(
                    worker_id = self.worker_id,
                    error = ?e,
                    peer = %peer_addr,
                    "Failed to parse QUIC header"
                );
                return Ok(()); // Ignore invalid packets
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

        // Check if this is a version negotiation packet
        if hdr.version != quiche::PROTOCOL_VERSION && self.config.enable_version_negotiation {
            // Send version negotiation
            let mut out = [0; MAX_DATAGRAM_SIZE];
            let len = quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out)
                .context("failed to negotiate version")?;

            self.send_packet(peer_addr, &out[..len]);
            return Ok(());
        }

        // Route packet to existing connection or create new one
        // Convert DCID to owned ConnectionId for lookup
        let dcid_owned: ConnectionId<'static> = hdr.dcid.to_vec().into();

        // Check if connection exists or needs to be created
        let should_create = if self.connections.contains_key(&dcid_owned) {
            false
        } else if hdr.ty == quiche::Type::Initial {
            true
        } else {
            // Packet for unknown connection (not Initial)
            debug!(
                worker_id = self.worker_id,
                peer = %peer_addr,
                dcid = ?hdr.dcid,
                ty = ?hdr.ty,
                "Received packet for unknown connection"
            );
            return Ok(()); // Ignore
        };

        // Create connection if needed
        if should_create {
            self.create_connection(peer_addr, &hdr)?;
        }

        // Now process the packet with the connection
        let worker_id = self.worker_id;
        let local_addr = self.local_addr;

        // Scope the mutable borrow of connection
        let (should_process_streams, should_send_packets) = {
            let conn = self.connections.get_mut(&dcid_owned).unwrap();

            // Process packet with Quiche
            let recv_info = quiche::RecvInfo {
                from: peer_addr,
                to: local_addr,
            };

            match conn.recv(packet, recv_info) {
                Ok(_) => {
                    trace!(
                        worker_id,
                        peer = %peer_addr,
                        dcid = ?hdr.dcid,
                        "Packet processed successfully"
                    );

                    // Check if handshake just completed
                    if conn.is_established() {
                        self.stats.borrow_mut().handshakes_completed += 1;
                        info!(
                            worker_id,
                            peer = %peer_addr,
                            trace_id = conn.trace_id(),
                            "QUIC handshake completed"
                        );
                    }

                    (true, true) // Process streams and send packets
                }
                Err(quiche::Error::Done) => {
                    // No more data to process
                    trace!(worker_id, "Packet processing done");
                    (false, false)
                }
                Err(e) => {
                    warn!(
                        worker_id,
                        peer = %peer_addr,
                        error = ?e,
                        "Failed to process packet"
                    );
                    (false, false)
                }
            }
        }; // conn borrow ends here

        // Now we can borrow again for stream processing
        if should_process_streams {
            if let Some(conn) = self.connections.get_mut(&dcid_owned) {
                process_streams(worker_id, conn)?;
            }
        }

        if should_send_packets {
            if let Some(conn) = self.connections.get_mut(&dcid_owned) {
                send_packets_for_conn(worker_id, conn, &self.send_callback)?;
            }
        }

        Ok(())
    }

    /// Create a new connection
    fn create_connection(&mut self, peer_addr: SocketAddr, hdr: &quiche::Header) -> Result<()> {
        // Check connection limit
        if self.connections.len() >= self.config.max_connections_per_worker {
            warn!(
                worker_id = self.worker_id,
                current = self.connections.len(),
                max = self.config.max_connections_per_worker,
                "Connection limit reached, rejecting new connection"
            );
            anyhow::bail!("connection limit reached");
        }

        // Generate new connection ID for server
        let mut scid_bytes = [0u8; MAX_CONN_ID_LEN];
        let scid_len = generate_cid(&self.conn_id_seed, &hdr.dcid, &mut scid_bytes);
        let scid = ConnectionId::from_vec(scid_bytes[..scid_len].to_vec());

        // Create Quiche connection
        let conn = quiche::accept(
            &scid,
            Some(&hdr.dcid),
            self.local_addr,
            peer_addr,
            &mut self.quiche_config,
        )
        .context("failed to create connection")?;

        // Set session for 0-RTT (if enabled)
        // This would be loaded from session cache in production

        debug!(
            worker_id = self.worker_id,
            peer = %peer_addr,
            scid = ?scid,
            dcid = ?hdr.dcid,
            "Created new QUIC connection"
        );

        self.stats.borrow_mut().connections_created += 1;

        // Wrap in our connection struct
        let quic_conn = QuicConnection::new(conn, peer_addr, scid.clone());

        // Store in connection map
        // Key is the DCID that client will use (our SCID)
        self.connections.insert(scid, quic_conn);

        Ok(())
    }
}

/// Process readable/writable streams (free function to avoid borrow issues)
fn process_streams(worker_id: usize, conn: &mut QuicConnection) -> Result<()> {
    // Process readable streams
    for stream_id in conn.readable().collect::<Vec<_>>() {
        trace!(
            worker_id,
            peer = %conn.peer_addr,
            stream_id,
            "Stream readable"
        );

        // TODO: Application layer will handle stream data
        // For now, just drain the stream
        let mut buf = vec![0u8; 65536];
        match conn.stream_recv(stream_id, &mut buf) {
            Ok((read, fin)) => {
                debug!(worker_id, stream_id, bytes = read, fin, "Read from stream");

                // Echo back for testing (remove in production)
                if read > 0 {
                    let _ = conn.stream_send(stream_id, &buf[..read], fin);
                }
            }
            Err(quiche::Error::Done) => {
                // No more data
            }
            Err(e) => {
                warn!(
                    worker_id,
                    stream_id,
                    error = ?e,
                    "Failed to read from stream"
                );
            }
        }
    }

    // Process writable streams
    // Application layer will use this to send data

    Ok(())
}

/// Send all pending packets for a connection (free function to avoid borrow issues)
fn send_packets_for_conn(
    worker_id: usize,
    conn: &mut QuicConnection,
    send_callback: &Option<SendCallback>,
) -> Result<()> {
    let mut out = vec![0u8; MAX_DATAGRAM_SIZE];

    loop {
        match conn.send(&mut out) {
            Ok((len, send_info)) => {
                // Inline send_packet to avoid borrow issues
                if let Some(ref callback) = send_callback {
                    callback(send_info.to, &out[..len]);
                } else {
                    error!(worker_id, "Send callback not set, dropping packet");
                }
            }
            Err(quiche::Error::Done) => {
                break; // No more packets to send
            }
            Err(e) => {
                warn!(
                    worker_id,
                    peer = %conn.peer_addr,
                    error = ?e,
                    "Failed to generate packet"
                );
                break;
            }
        }
    }

    Ok(())
}

impl QuicManager {
    /// Send a packet via the network layer
    fn send_packet(&mut self, to: SocketAddr, packet: &[u8]) {
        if let Some(ref send_callback) = self.send_callback {
            send_callback(to, packet);
            self.stats.borrow_mut().packets_sent += 1;
        } else {
            error!(
                worker_id = self.worker_id,
                "Send callback not set, dropping packet"
            );
        }
    }

    /// Handle timeouts for all connections
    ///
    /// Should be called periodically (e.g., every 10ms)
    pub fn handle_timeouts(&mut self) -> Result<()> {
        let now = Instant::now();
        let mut to_remove = Vec::new();
        let mut packets_to_send = Vec::new();

        for (dcid, conn) in self.connections.iter_mut() {
            // Check connection timeout
            if let Some(timeout) = conn.timeout() {
                if now >= conn.last_active + timeout {
                    conn.on_timeout();

                    // Generate packets after timeout
                    let mut out = vec![0u8; MAX_DATAGRAM_SIZE];
                    loop {
                        match conn.send(&mut out) {
                            Ok((len, send_info)) => {
                                packets_to_send.push((send_info.to, out[..len].to_vec()));
                            }
                            Err(quiche::Error::Done) => break,
                            Err(_) => break,
                        }
                    }
                }
            }

            // Check if connection is closed
            if conn.is_closed() {
                debug!(
                    worker_id = self.worker_id,
                    peer = %conn.peer_addr,
                    trace_id = conn.trace_id(),
                    "Connection closed"
                );
                to_remove.push(dcid.clone());
            }
        }

        // Send collected packets
        for (to, packet) in packets_to_send {
            self.send_packet(to, &packet);
        }

        // Remove closed connections
        for dcid in to_remove {
            self.connections.remove(&dcid);
            self.stats.borrow_mut().connections_closed += 1;
        }

        Ok(())
    }

    /// Get current number of active connections
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }
}

/// Maximum UDP datagram size
const MAX_DATAGRAM_SIZE: usize = 65536;

/// Generate a connection ID using HMAC
///
/// This ensures connection IDs are:
/// - Unpredictable (cryptographically secure)
/// - Unique per worker (different seed per worker)
/// - Deterministic for the same input
fn generate_cid(key: &ring::hmac::Key, input: &[u8], out: &mut [u8]) -> usize {
    let tag = ring::hmac::sign(key, input);
    let tag_bytes = tag.as_ref();

    // Use first 16 bytes of HMAC as connection ID
    let len = std::cmp::min(16, out.len());
    out[..len].copy_from_slice(&tag_bytes[..len]);
    len
}

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
