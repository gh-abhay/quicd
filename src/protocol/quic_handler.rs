//! QUIC Protocol Handler
//!
//! Implements the protocol layer for SuperD using the `quiche` crate. Each
//! protocol task owns a subset of QUIC connections, performs TLS 1.3
//! cryptography, maintains congestion-control state, and exchanges encrypted
//! datagrams with the network layer.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use parking_lot::Mutex;
use quiche::{self, ConnectionId, Header};
use rand::{rngs::ThreadRng, RngCore};
use tokio::{
    select,
    sync::{broadcast, mpsc},
    time::{interval, MissedTickBehavior},
};
use tracing::{debug, error, info, warn};

use crate::{
    config::Config,
    network::{
        zerocopy_buffer::{ZeroCopyBuffer, ZeroCopyBufferMut, MAX_UDP_PAYLOAD},
        NetworkToProtocol, ProtocolToNetwork,
    },
};

const SERVER_CONN_ID_LENGTH: usize = 16;
const TIMER_RESOLUTION: Duration = Duration::from_millis(50);

struct ConnectionState {
    conn_id: u64,
    conn: quiche::Connection,
    peer: SocketAddr,
    next_timeout: Option<Instant>,
}

impl ConnectionState {
    fn new(conn_id: u64, conn: quiche::Connection, peer: SocketAddr) -> Self {
        let mut state = Self {
            conn_id,
            conn,
            peer,
            next_timeout: None,
        };
        state.refresh_timeout();
        state
    }

    fn refresh_timeout(&mut self) {
        self.next_timeout = self
            .conn
            .timeout()
            .map(|duration| Instant::now() + duration);
    }
}

struct ConnectionEntry {
    state: ConnectionState,
    aliases: Vec<Vec<u8>>,
}

/// QUIC Protocol Handler Task
///
/// Each task owns a subset of QUIC connections and communicates with a single
/// network task over unbounded channels for ingress and egress datagrams.
pub struct QuicProtocolTask {
    id: usize,
    from_network: mpsc::UnboundedReceiver<NetworkToProtocol>,
    to_network: mpsc::UnboundedSender<ProtocolToNetwork>,
    shutdown_rx: broadcast::Receiver<()>,
    local_addr: SocketAddr,
    quiche_config: Arc<Mutex<quiche::Config>>,
    connections: HashMap<Vec<u8>, ConnectionEntry>,
    aliases: HashMap<Vec<u8>, Vec<u8>>,
    next_conn_id: u64,
    rng: ThreadRng,
}

impl QuicProtocolTask {
    pub fn new(
        id: usize,
        from_network: mpsc::UnboundedReceiver<NetworkToProtocol>,
        to_network: mpsc::UnboundedSender<ProtocolToNetwork>,
        shutdown_rx: broadcast::Receiver<()>,
        local_addr: SocketAddr,
        quiche_config: Arc<Mutex<quiche::Config>>,
    ) -> Self {
        Self {
            id,
            from_network,
            to_network,
            shutdown_rx,
            local_addr,
            quiche_config,
            connections: HashMap::new(),
            aliases: HashMap::new(),
            next_conn_id: 0,
            rng: rand::thread_rng(),
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
        let mut packet = buffer.data().to_vec();
        if packet.is_empty() {
            return Ok(());
        }

        let header = Header::from_slice(&mut packet, quiche::MAX_CONN_ID_LEN)
            .map_err(|e| anyhow!("failed to parse QUIC header: {e}"))?;

        if let Some((canonical, entry)) = self.take_connection(header.dcid.as_ref()) {
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
            return Ok(());
        }
        self.handle_readable_streams(&mut entry.state);
        self.drain_send_queue(&mut entry.state)?;

        let new_key = entry.state.conn.destination_id().as_ref().to_vec();
        if new_key != canonical_key && !entry.aliases.iter().any(|alias| alias == &canonical_key) {
            entry.aliases.push(canonical_key.clone());
        }

        if header.ty == quiche::Type::Retry {
            debug!(
                "Protocol task {} received RETRY for connection {}",
                self.id,
                format_conn_id(&new_key)
            );
        }

        self.store_connection(new_key, entry);
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

        let conn_id = self.next_conn_id;
        self.next_conn_id += 1;

        let mut entry = ConnectionEntry {
            state: ConnectionState::new(conn_id, conn, addr),
            aliases: Vec::new(),
        };

        if header.dcid.as_ref() != entry.state.conn.destination_id().as_ref() {
            entry.aliases.push(header.dcid.as_ref().to_vec());
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
        self.store_connection(canonical.clone(), entry);

        info!(
            "Protocol task {} accepted new connection {} from {}",
            self.id,
            format_conn_id(&canonical),
            addr
        );
        Ok(())
    }

    fn handle_readable_streams(&self, state: &mut ConnectionState) {
        if !state.conn.is_established() {
            return;
        }

        let mut buffer = vec![0u8; 4096];
        for stream_id in state.conn.readable() {
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

    fn drain_send_queue(&mut self, state: &mut ConnectionState) -> Result<()> {
        loop {
            let mut buf = ZeroCopyBufferMut::with_capacity(MAX_UDP_PAYLOAD);
            buf.data_mut().resize(MAX_UDP_PAYLOAD, 0);

            let (written, send_info) = match state.conn.send(buf.data_mut()) {
                Ok(res) => res,
                Err(quiche::Error::Done) => break,
                Err(err) => {
                    return Err(anyhow!("conn.send failed: {err}"));
                }
            };

            buf.data_mut().truncate(written);
            let frozen = buf.freeze();
            self.queue_datagram(frozen, send_info.to)?;
        }
        Ok(())
    }

    fn queue_datagram(&self, buffer: ZeroCopyBuffer, addr: SocketAddr) -> Result<()> {
        self.to_network
            .send(ProtocolToNetwork::Datagram { buffer, addr })
            .map_err(|err| anyhow!("failed to enqueue datagram: {err}"))
    }

    fn send_version_negotiation(&self, header: &Header, addr: SocketAddr) -> Result<()> {
        let mut buf = ZeroCopyBufferMut::with_capacity(MAX_UDP_PAYLOAD);
        buf.data_mut().resize(MAX_UDP_PAYLOAD, 0);
        let scid = ConnectionId::from_ref(header.scid.as_ref());
        let dcid = ConnectionId::from_ref(header.dcid.as_ref());
        let written = quiche::negotiate_version(&scid, &dcid, buf.data_mut())?;
        buf.data_mut().truncate(written);
        self.queue_datagram(buf.freeze(), addr)
    }

    fn process_timers(&mut self) -> Result<()> {
        let now = Instant::now();
        let keys: Vec<Vec<u8>> = self.connections.keys().cloned().collect();

        for key in keys {
            if let Some((canonical, mut entry)) = self.take_connection(&key) {
                if entry
                    .state
                    .next_timeout
                    .map(|deadline| deadline <= now)
                    .unwrap_or(false)
                {
                    entry.state.conn.on_timeout();
                    if entry.state.conn.is_timed_out() || entry.state.conn.is_closed() {
                        debug!(
                            "Protocol task {} connection {} expired after timeout",
                            self.id,
                            format_conn_id(&canonical)
                        );
                        self.drain_send_queue(&mut entry.state)?;
                        continue;
                    }
                    entry.state.refresh_timeout();
                    self.handle_readable_streams(&mut entry.state);
                    self.drain_send_queue(&mut entry.state)?;
                }

                let new_key = entry.state.conn.destination_id().as_ref().to_vec();
                if new_key != canonical && !entry.aliases.iter().any(|alias| alias == &canonical) {
                    entry.aliases.push(canonical.clone());
                }

                self.store_connection(new_key, entry);
            }
        }

        Ok(())
    }

    fn drain_all_connections(&mut self) {
        let mut drained: Vec<ConnectionEntry> =
            self.connections.drain().map(|(_, entry)| entry).collect();
        self.aliases.clear();

        for entry in drained.iter_mut() {
            if let Err(err) = entry.state.conn.close(false, 0, b"server shutdown") {
                debug!("Protocol task {} close error: {err:?}", self.id);
            }
            if let Err(err) = self.drain_send_queue(&mut entry.state) {
                debug!(
                    "Protocol task {} send during shutdown failed: {err:?}",
                    self.id
                );
            }
        }
    }

    fn take_connection(&mut self, dcid: &[u8]) -> Option<(Vec<u8>, ConnectionEntry)> {
        if let Some(entry) = self.connections.remove(dcid) {
            for alias in &entry.aliases {
                self.aliases.remove(alias);
            }
            return Some((dcid.to_vec(), entry));
        }

        if let Some(canonical) = self.aliases.remove(dcid) {
            if let Some(entry) = self.connections.remove(&canonical) {
                for alias in &entry.aliases {
                    self.aliases.remove(alias);
                }
                return Some((canonical, entry));
            }
        }

        None
    }

    fn store_connection(&mut self, canonical: Vec<u8>, entry: ConnectionEntry) {
        for alias in &entry.aliases {
            self.aliases.insert(alias.clone(), canonical.clone());
        }
        self.connections.insert(canonical, entry);
    }

    fn generate_connection_id(&mut self) -> ConnectionId<'static> {
        let mut cid = vec![0u8; SERVER_CONN_ID_LENGTH];
        self.rng.fill_bytes(&mut cid);
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
        .context("failed to configure QUIC application protocols")?;

    quiche_config
        .load_cert_chain_from_pem_file(&config.quic.cert_path)
        .with_context(|| {
            format!(
                "failed to load TLS certificate from {}",
                config.quic.cert_path
            )
        })?;
    quiche_config
        .load_priv_key_from_pem_file(&config.quic.key_path)
        .with_context(|| {
            format!(
                "failed to load TLS private key from {}",
                config.quic.key_path
            )
        })?;
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
    shutdown_tx: broadcast::Sender<()>,
) -> Result<()> {
    if from_network_receivers.len() != to_network_senders.len() {
        return Err(anyhow!(
            "mismatched protocol channel counts: {} receivers vs {} senders",
            from_network_receivers.len(),
            to_network_senders.len()
        ));
    }

    if from_network_receivers.len() != config.protocol_threads {
        return Err(anyhow!(
            "protocol channel count {} does not match configured protocol_threads {}",
            from_network_receivers.len(),
            config.protocol_threads
        ));
    }

    let listen_addr: SocketAddr = config
        .listen
        .parse()
        .context("invalid listen socket address")?;

    let quiche_config = Arc::new(Mutex::new(build_quiche_config(config)?));

    for (idx, (receiver, sender)) in from_network_receivers
        .into_iter()
        .zip(to_network_senders.into_iter())
        .enumerate()
    {
        let shutdown_rx = shutdown_tx.subscribe();
        let task_config = Arc::clone(&quiche_config);

        tokio_uring::spawn(async move {
            let task =
                QuicProtocolTask::new(idx, receiver, sender, shutdown_rx, listen_addr, task_config);

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
