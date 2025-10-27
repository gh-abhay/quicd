//! QUIC Protocol Handler
//!
//! Implements the protocol layer for SuperD using the `quiche` crate. Each
//! protocol task owns a subset of QUIC connections, performs TLS 1.3
//! cryptography, maintains congestion-control state, and exchanges encrypted
//! datagrams with the network layer.

use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};


use parking_lot::Mutex;
use quiche::{self, ConnectionId, Header};
use rand::RngCore;
use tokio::{
    select,
    sync::{broadcast, mpsc},
    time::{interval, MissedTickBehavior},
};
use tracing::{debug, error, info, warn};

use crate::{
    config::Config,
    error::Result,
    messages::{
        NetworkToProtocol, ProtocolToApplication, ProtocolToNetwork,
    },
    network::zerocopy_buffer::ZeroCopyBuffer,
    connection_registry::{ConnectionRegistry, SharedConnectionState, ConnectionEntry},
};

const SERVER_CONN_ID_LENGTH: usize = 16;
const TIMER_RESOLUTION: Duration = Duration::from_millis(50);

/// QUIC Protocol Handler Task
///
/// Each task owns a subset of QUIC connections and communicates with a single
/// network task over unbounded channels for ingress and egress datagrams.
pub struct QuicProtocolTask {
    id: usize,
    from_network: mpsc::UnboundedReceiver<NetworkToProtocol>,
    to_network_senders: Vec<mpsc::UnboundedSender<ProtocolToNetwork>>,
    to_application: mpsc::UnboundedSender<ProtocolToApplication>,
    shutdown_rx: broadcast::Receiver<()>,
    local_addr: SocketAddr,
    quiche_config: Arc<Mutex<quiche::Config>>,
    /// Shared connection registry for all connections
    connection_registry: Arc<ConnectionRegistry>,
    /// Track active connections for monitoring (now from shared registry)
    active_connections: usize, // This will be updated from the registry
}

impl QuicProtocolTask {
    pub fn new(
        id: usize,
        from_network: mpsc::UnboundedReceiver<NetworkToProtocol>,
        to_network_senders: Vec<mpsc::UnboundedSender<ProtocolToNetwork>>,
        to_application: mpsc::UnboundedSender<ProtocolToApplication>,
        shutdown_rx: broadcast::Receiver<()>,
        local_addr: SocketAddr,
        quiche_config: Arc<Mutex<quiche::Config>>,
        connection_registry: Arc<ConnectionRegistry>,
    ) -> Self {
        Self {
            id,
            from_network,
            to_network_senders,
            to_application,
            shutdown_rx,
            local_addr,
            quiche_config,
            connection_registry,
            active_connections: 0,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        info!("Protocol task {} starting", self.id);

        let mut timer = interval(TIMER_RESOLUTION);
        timer.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            select! {
                biased;

                _ = self.shutdown_rx.recv() => {
                    info!("Protocol task {} received shutdown signal", self.id);
                    break;
                }

                _ = timer.tick() => {
                    if let Err(err) = self.process_timers() {
                        error!("Protocol task {} timer processing error: {err:?}", self.id);
                    }
                }

                message = self.from_network.recv() => {
                    match message {
                        Some(NetworkToProtocol::Datagram { buffer, addr }) => {
                            if let Err(err) = self.handle_incoming_packet(buffer, addr) {
                                warn!("Protocol task {} failed to process packet from {addr}: {err:?}", self.id);
                            }
                        }
                        None => {
                            info!("Protocol task {} network channel closed", self.id);
                            break;
                        }
                    }
                }
            }
        }

        self.drain_all_connections();
        info!("Protocol task {} shutting down", self.id);
        Ok(())
    }

    fn handle_incoming_packet(&mut self, buffer: ZeroCopyBuffer, addr: SocketAddr) -> Result<()> {
        let mut packet = (*buffer).to_vec();
        if packet.is_empty() {
            return Ok(());
        }

        let header = Header::from_slice(&mut packet, quiche::MAX_CONN_ID_LEN)?;

        debug!(
            "Protocol task {} received packet: type={:?}, version={:x}, dcid_len={}, scid_len={}, from={}",
            self.id,
            header.ty,
            header.version,
            header.dcid.len(),
            header.scid.len(),
            addr
        );

        let has_connection = self.connection_registry.connection_exists(header.dcid.as_ref());

        if has_connection {
            // Get connection data and immediately drop the reference
            let (canonical, entry) = {
                let entry_ref = self.connection_registry.get_connection(header.dcid.as_ref()).unwrap();
                let canonical = entry_ref.key().clone();
                let entry = (*entry_ref).clone();
                (canonical, entry)
            };
            self.handle_existing_connection(header, packet, addr, canonical, entry)
        } else {
            self.accept_new_connection(header, packet, addr)
        }
    }

    fn handle_existing_connection(
        &mut self,
        header: Header,
        mut packet: Vec<u8>,
        addr: SocketAddr,
        canonical_key: Vec<u8>,
        mut entry: ConnectionEntry,
    ) -> Result<()> {
        let recv_info = quiche::RecvInfo {
            from: addr,
            to: self.local_addr,
        };

        entry.state.peer = addr;

        match entry.state.conn.recv(&mut packet, recv_info) {
            Ok(_) | Err(quiche::Error::Done) => {}
            Err(err) => {
                warn!(
                    "Protocol task {} recv error on conn {}: {err:?}",
                    self.id,
                    format_conn_id(&canonical_key)
                );
            }
        }

        entry.state.refresh_timeout();
        if entry.state.conn.is_timed_out() || entry.state.conn.is_closed() {
            debug!(
                "Protocol task {} connection {} expired",
                self.id,
                format_conn_id(&canonical_key)
            );
            self.drain_send_queue(&mut entry.state)?;
            self.connection_registry.remove_connection(&canonical_key);
            self.active_connections = self.connection_registry.active_connection_count();
            return Ok(());
        }
        self.handle_readable_streams(&mut entry.state);
        self.drain_send_queue(&mut entry.state)?;

        let new_key = entry.state.conn.destination_id().as_ref().to_vec();
        if new_key != canonical_key && !entry.state.aliases.iter().any(|alias| alias == &canonical_key) {
            entry.state.aliases.push(canonical_key.clone());
        }

        if header.ty == quiche::Type::Retry {
            debug!(
                "Protocol task {} received RETRY for connection {}",
                self.id,
                format_conn_id(&new_key)
            );
        }

        self.connection_registry.insert_connection(new_key, entry);
        Ok(())
    }

    fn accept_new_connection(
        &mut self,
        header: Header,
        mut packet: Vec<u8>,
        addr: SocketAddr,
    ) -> Result<()> {
        if header.ty != quiche::Type::Initial {
            debug!(
                "Protocol task {} dropping non-initial packet for unknown connection",
                self.id
            );
            return Ok(());
        }

        if packet.len() < quiche::MIN_CLIENT_INITIAL_LEN {
            warn!(
                "Protocol task {} dropping short initial packet ({} bytes)",
                self.id,
                packet.len()
            );
            return Ok(());
        }

        if !quiche::version_is_supported(header.version) {
            debug!("Protocol task {} sending version negotiation", self.id);
            self.send_version_negotiation(&header, addr)?;
            return Ok(());
        }

        let scid = self.generate_connection_id();
        let odcid = ConnectionId::from_ref(header.dcid.as_ref());
        let mut config = self.quiche_config.lock();
        let conn = quiche::accept(&scid, Some(&odcid), self.local_addr, addr, &mut *config)?;
        drop(config);

        let conn_id = self.connection_registry.next_connection_id();

        let mut entry = ConnectionEntry {
            state: SharedConnectionState::new(conn_id, conn, addr),
            owning_task_id: self.id,
        };

        if header.dcid.as_ref() != entry.state.conn.destination_id().as_ref() {
            entry.state.aliases.push(header.dcid.as_ref().to_vec());
        }

        let recv_info = quiche::RecvInfo {
            from: addr,
            to: self.local_addr,
        };

        match entry.state.conn.recv(&mut packet, recv_info) {
            Ok(_) | Err(quiche::Error::Done) => {}
            Err(err) => {
                warn!("Protocol task {} initial recv failed: {err:?}", self.id);
            }
        }

        entry.state.refresh_timeout();
        self.handle_readable_streams(&mut entry.state);
        self.drain_send_queue(&mut entry.state)?;

        let canonical = entry.state.conn.destination_id().as_ref().to_vec();
        self.connection_registry.insert_connection(canonical.clone(), entry);
        self.active_connections = self.connection_registry.active_connection_count();

        info!(
            "Protocol task {} accepted new connection {} from {} (active: {})",
            self.id,
            format_conn_id(&canonical),
            addr,
            self.active_connections
        );
        Ok(())
    }

    fn handle_readable_streams(&mut self, state: &mut SharedConnectionState) {
        if !state.conn.is_established() {
            return;
        }

        // Send NewConnection message if this is the first time we see this connection established
        if state.conn.is_established() && !state.sent_new_connection {
            let alpn = state.conn.application_proto();
            if !alpn.is_empty() {
                let alpn_str = String::from_utf8_lossy(alpn).to_string();
                let message = ProtocolToApplication::NewConnection {
                    conn_id: state.conn_id,
                    peer_addr: state.peer,
                    alpn: alpn_str,
                };
                if let Err(err) = self.to_application.send(message) {
                    warn!("Protocol task {} failed to send NewConnection: {err:?}", self.id);
                } else {
                    state.sent_new_connection = true;
                }
            }
        }

        let mut buffer = vec![0u8; 4096];
        for stream_id in state.conn.readable() {
            // Send NewStream message for new streams
            if !state.active_streams.contains(&stream_id) {
                let alpn = state.conn.application_proto();
                if !alpn.is_empty() {
                    let alpn_str = String::from_utf8_lossy(alpn).to_string();
                    let message = ProtocolToApplication::NewStream {
                        conn_id: state.conn_id,
                        stream_id,
                        peer_addr: state.peer,
                        alpn: alpn_str,
                    };
                    if let Err(err) = self.to_application.send(message) {
                        warn!("Protocol task {} failed to send NewStream: {err:?}", self.id);
                    } else {
                        state.active_streams.insert(stream_id);
                    }
                }
            }

            loop {
                match state.conn.stream_recv(stream_id, &mut buffer) {
                    Ok((read, fin)) => {
                        if read == 0 {
                            break;
                        }
                        debug!(
                            "Protocol task {} received {} bytes on conn {} stream {} fin={}",
                            self.id, read, state.conn_id, stream_id, fin
                        );

                        // Send stream data to application layer
                        let data = &buffer[..read];
                        let buffer_pool = crate::network::zerocopy_buffer::get_buffer_pool();
                        let mut zero_copy_buf = buffer_pool.get_empty();
                        zero_copy_buf.expand(read);
                        zero_copy_buf[..read].copy_from_slice(data);

                        let message = ProtocolToApplication::StreamData {
                            conn_id: state.conn_id,
                            stream_id,
                            data: zero_copy_buf,
                            fin,
                        };
                        if let Err(err) = self.to_application.send(message) {
                            warn!("Protocol task {} failed to send StreamData: {err:?}", self.id);
                        }

                        if fin {
                            break;
                        }
                    }
                    Err(quiche::Error::Done) => break,
                    Err(err) => {
                        warn!(
                            "Protocol task {} stream recv error on conn {} stream {}: {err:?}",
                            self.id, state.conn_id, stream_id
                        );
                        break;
                    }
                }
            }
        }
    }

    fn drain_send_queue(&mut self, state: &mut SharedConnectionState) -> Result<()> {
        loop {
            let buffer_pool = crate::network::zerocopy_buffer::get_buffer_pool();
            let mut buf = buffer_pool.get_empty();

            let (written, send_info) = match state.conn.send(&mut buf) {
                Ok(res) => res,
                Err(quiche::Error::Done) => break,
                Err(err) => {
                    return Err(crate::error::Error::Network(
                        crate::error::NetworkError::IoOperationFailed(format!("conn.send failed: {err}"))
                    ));
                }
            };

            buf.truncate(written);
            self.queue_datagram(buf, send_info.to)?;
        }
        Ok(())
    }

    /// Select a network task to send to (hash by destination address for load balancing)
    fn select_network_sender(&self, addr: &SocketAddr) -> &mpsc::UnboundedSender<ProtocolToNetwork> {
        // Hash the destination address to select a network task
        // This distributes egress load across network tasks
        let hash = match addr {
            SocketAddr::V4(v4) => {
                let octets = v4.ip().octets();
                let port = v4.port();
                octets.iter().map(|&b| b as usize).sum::<usize>() + port as usize
            }
            SocketAddr::V6(v6) => {
                let octets = v6.ip().octets();
                let port = v6.port();
                octets.iter().map(|&b| b as usize).sum::<usize>() + port as usize
            }
        };
        let idx = hash % self.to_network_senders.len();
        &self.to_network_senders[idx]
    }

    fn queue_datagram(&self, buffer: ZeroCopyBuffer, addr: SocketAddr) -> Result<()> {
        let sender = self.select_network_sender(&addr);
        sender
            .send(ProtocolToNetwork::Datagram { buffer, addr })
            .map_err(|err| crate::error::Error::Network(
                crate::error::NetworkError::IoOperationFailed(format!("failed to enqueue datagram: {err}"))
            ))
    }

    fn send_version_negotiation(&self, header: &Header, addr: SocketAddr) -> Result<()> {
        let buffer_pool = crate::network::zerocopy_buffer::get_buffer_pool();
        let mut buf = buffer_pool.get_empty();
        let scid = ConnectionId::from_ref(header.scid.as_ref());
        let dcid = ConnectionId::from_ref(header.dcid.as_ref());
        let written = quiche::negotiate_version(&scid, &dcid, &mut buf)?;
        buf.truncate(written);
        self.queue_datagram(buf, addr)
    }

    fn process_timers(&mut self) -> Result<()> {
        let now = Instant::now();
        let connections_for_task = self.connection_registry.get_connections_for_task(self.id);

        for (key, mut entry) in connections_for_task {
            if entry.state.next_timeout.map(|deadline| deadline <= now).unwrap_or(false) {
                entry.state.conn.on_timeout();
                if entry.state.conn.is_timed_out() || entry.state.conn.is_closed() {
                    debug!(
                        "Protocol task {} connection {} expired after timeout",
                        self.id,
                        format_conn_id(&key)
                    );
                    self.drain_send_queue(&mut entry.state)?;
                    self.connection_registry.remove_connection(&key);
                    self.active_connections = self.connection_registry.active_connection_count();
                    continue;
                }
                entry.state.refresh_timeout();
                self.handle_readable_streams(&mut entry.state);
                self.drain_send_queue(&mut entry.state)?;
            }

            let new_key = entry.state.conn.destination_id().as_ref().to_vec();
            if new_key != key && !entry.state.aliases.iter().any(|alias| alias == &key) {
                entry.state.aliases.push(key.clone());
            }

            self.connection_registry.insert_connection(new_key, entry);
        }

        Ok(())
    }

    fn drain_all_connections(&mut self) {
        // Get all connections owned by this task
        let connections_for_task = self.connection_registry.get_connections_for_task(self.id);

        for (key, mut entry) in connections_for_task {
            if let Err(err) = entry.state.conn.close(false, 0, b"server shutdown") {
                debug!("Protocol task {} close error: {err:?}", self.id);
            }
            if let Err(err) = self.drain_send_queue(&mut entry.state) {
                debug!(
                    "Protocol task {} send during shutdown failed: {err:?}",
                    self.id
                );
            }
            // Remove from registry
            self.connection_registry.remove_connection(&key);
        }
    }

    fn generate_connection_id(&mut self) -> ConnectionId<'static> {
        let mut cid = vec![0u8; SERVER_CONN_ID_LENGTH];
        rand::thread_rng().fill_bytes(&mut cid);
        ConnectionId::from_vec(cid)
    }
}

fn format_conn_id(id: &[u8]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn build_quiche_config(config: &Config) -> Result<quiche::Config> {
    let mut quiche_config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    let protos: Vec<Vec<u8>> = config
        .quic
        .application_protos
        .iter()
        .map(|proto| proto.as_bytes().to_vec())
        .collect();
    let proto_refs: Vec<&[u8]> = protos.iter().map(|proto| proto.as_slice()).collect();
    quiche_config
        .set_application_protos(&proto_refs)
        .map_err(|e| crate::error::Error::Network(
            crate::error::NetworkError::IoOperationFailed(format!("failed to configure QUIC application protocols: {e}"))
        ))?;

    quiche_config
        .load_cert_chain_from_pem_file(&config.quic.cert_path)
        .map_err(|e| crate::error::Error::Network(
            crate::error::NetworkError::IoOperationFailed(format!(
                "failed to load TLS certificate from {}: {e}",
                config.quic.cert_path
            ))
        ))?;
    quiche_config
        .load_priv_key_from_pem_file(&config.quic.key_path)
        .map_err(|e| crate::error::Error::Network(
            crate::error::NetworkError::IoOperationFailed(format!(
                "failed to load TLS private key from {}: {e}",
                config.quic.key_path
            ))
        ))?;
    quiche_config.verify_peer(config.quic.verify_peer);

    if config.quic.enable_early_data {
        quiche_config.enable_early_data();
    }

    quiche_config.set_max_idle_timeout(config.quic.max_idle_timeout_ms);
    quiche_config.set_initial_max_data(config.quic.initial_max_data);
    quiche_config
        .set_initial_max_stream_data_bidi_local(config.quic.initial_max_stream_data_bidi_local);
    quiche_config
        .set_initial_max_stream_data_bidi_remote(config.quic.initial_max_stream_data_bidi_remote);
    quiche_config.set_initial_max_stream_data_uni(config.quic.initial_max_stream_data_uni);
    quiche_config.set_initial_max_streams_bidi(config.quic.initial_max_streams_bidi);
    quiche_config.set_initial_max_streams_uni(config.quic.initial_max_streams_uni);
    quiche_config.set_max_send_udp_payload_size(config.quic.max_send_udp_payload_size);
    quiche_config.set_max_recv_udp_payload_size(config.quic.max_recv_udp_payload_size);

    Ok(quiche_config)
}

/// Start protocol layer with fan-out architecture.
pub fn start_protocol_layer(
    config: &Config,
    from_network_receivers: Vec<mpsc::UnboundedReceiver<NetworkToProtocol>>,
    to_network_senders: Vec<mpsc::UnboundedSender<ProtocolToNetwork>>,
    to_application: mpsc::UnboundedSender<ProtocolToApplication>,
    shutdown_tx: broadcast::Sender<()>,
) -> Result<()> {
    // Validate channel counts
    // Each protocol task gets ONE receiver (ingress from network tasks via CID hashing)
    // Each protocol task gets ALL network senders (egress to any network task)
    if from_network_receivers.len() != config.protocol_threads {
        return Err(crate::error::Error::Network(
            crate::error::NetworkError::InvalidConfiguration(format!(
                "Expected {} from_network receivers (one per protocol task), got {}",
                config.protocol_threads,
                from_network_receivers.len()
            ))
        ));
    }

    if to_network_senders.len() != config.network_threads {
        return Err(crate::error::Error::Network(
            crate::error::NetworkError::InvalidConfiguration(format!(
                "Expected {} to_network senders (one per network task), got {}",
                config.network_threads,
                to_network_senders.len()
            ))
        ));
    }

    let listen_addr: SocketAddr = config
        .listen
        .parse()
        .map_err(|e| crate::error::Error::Network(
            crate::error::NetworkError::InvalidConfiguration(format!("invalid listen socket address: {e}"))
        ))?;

    let quiche_config = Arc::new(Mutex::new(build_quiche_config(config)?));

    // Create shared connection registry
    let connection_registry = Arc::new(ConnectionRegistry::new());

    // Each protocol task gets ALL network senders (for load balancing egress)
    for (idx, receiver) in from_network_receivers.into_iter().enumerate() {
        let shutdown_rx = shutdown_tx.subscribe();
        let quiche_config_clone = Arc::clone(&quiche_config);
        let senders_clone: Vec<mpsc::UnboundedSender<ProtocolToNetwork>> = 
            to_network_senders.iter().map(|s| s.clone()).collect();
        let to_application_clone = to_application.clone();
        let registry_clone = Arc::clone(&connection_registry);

        tokio_uring::spawn(async move {
            let task = QuicProtocolTask::new(
                idx,
                receiver,
                senders_clone,
                to_application_clone,
                shutdown_rx,
                listen_addr,
                quiche_config_clone,
                registry_clone,
            );

            if let Err(err) = task.run().await {
                error!("Protocol task {idx} exited with error: {err:?}");
            }
        });
    }

    info!(
        "Started protocol layer with {} QUIC tasks",
        config.protocol_threads
    );

    Ok(())
}
