/// Modern event-driven network I/O using io_uring
/// This provides the best performance on Linux by:
/// - Minimizing syscalls through batched submissions
/// - Using completion-based async I/O
/// - Zero-copy buffer management
///
/// Design principles:
/// - **Purely event-driven**: ALL events use async await, zero polling
///   * Ingress: waits for io_uring completions
///   * Egress: waits on MPSC receiver
///   * Shutdown: waits on broadcast receiver (NOT polling AtomicBool!)
/// - **Isolated Sans-IO**: only handles network I/O, no protocol logic
/// - **Dedicated channels**: one receiver per protocol thread for egress
/// - **Load balanced**: SO_REUSEPORT distributes ingress packets
/// - **Event-driven shutdown**: broadcast channel for instant propagation
use super::metrics::{NetworkMetrics, SharedMetrics};
use super::zerocopy_buffer::{get_buffer_pool, ZeroCopyBuffer, MAX_UDP_PAYLOAD};
use super::{NetworkToProtocol, ToProtocolSender};

use crate::error::{Error, NetworkError, Result};

use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::select;
use tokio::sync::{broadcast, mpsc};
use tokio_uring::net::UdpSocket;
use tracing::{debug, error, info, warn};

// Import quiche for packet header parsing
use quiche::Header;

/// Network I/O task using io_uring for event-driven operations
/// Each network task has:
/// - Access to ALL protocol task senders (for load balancing via connection ID hashing)
/// - One dedicated receiver for egress packets from ALL protocol tasks (shared via broadcast or multiple receivers)
pub struct IoUringNetworkThread {
    id: usize,
    socket: UdpSocket,
    // Send ingress packets to protocol tasks (hash by connection ID)
    to_protocol_senders: Vec<ToProtocolSender>,
    // Receive egress packets from protocol tasks
    from_protocol: mpsc::UnboundedReceiver<super::ProtocolToNetwork>,
    metrics: SharedMetrics,
    // Receive shutdown signal (broadcast)
    shutdown_rx: broadcast::Receiver<()>,
}

impl IoUringNetworkThread {
    pub async fn new(
        id: usize,
        listen_addr: SocketAddr,
        to_protocol_senders: Vec<ToProtocolSender>,
        from_protocol: mpsc::UnboundedReceiver<super::ProtocolToNetwork>,
        metrics: SharedMetrics,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> std::io::Result<Self> {
        let socket = create_udp_socket(listen_addr).await?;

        Ok(Self {
            id,
            socket,
            to_protocol_senders,
            from_protocol,
            metrics,
            shutdown_rx,
        })
    }

    /// Hash connection ID bytes to select a protocol task
    fn hash_to_protocol_task_static(dcid: &[u8], num_protocol_tasks: usize) -> usize {
        // Simple hash: sum of bytes modulo number of protocol tasks
        let hash: usize = dcid.iter().map(|&b| b as usize).sum();
        hash % num_protocol_tasks
    }

    /// Extract destination connection ID from QUIC packet and hash to select protocol task
    fn extract_and_hash_dcid(buffer: &ZeroCopyBuffer, len: usize, num_protocol_tasks: usize) -> Result<usize> {
        if len < 1 {
            return Err(NetworkError::IoOperationFailed("Packet too short for QUIC header".to_string()).into());
        }

        let data = &buffer[..];

        // Parse QUIC header using quiche
        let mut packet_data = data.to_vec(); // quiche needs mutable data
        let header = Header::from_slice(&mut packet_data, quiche::MAX_CONN_ID_LEN)
            .map_err(|e| Error::Network(NetworkError::IoOperationFailed(format!("Failed to parse QUIC header: {}", e))))?;

        // Use destination connection ID for consistent routing
        let dcid_bytes = header.dcid.as_ref();
        if dcid_bytes.is_empty() {
            return Err(NetworkError::IoOperationFailed("Empty destination connection ID".to_string()).into());
        }

        Ok(Self::hash_to_protocol_task_static(dcid_bytes, num_protocol_tasks))
    }

    /// Fallback: hash source address to select protocol task when header parsing fails
    fn hash_addr_to_protocol_task(addr: &SocketAddr, num_protocol_tasks: usize) -> usize {
        match addr {
            SocketAddr::V4(v4) => {
                let ip = v4.ip().to_bits();
                let port = v4.port() as u32;
                let hash = (ip as usize).wrapping_add(port as usize);
                hash % num_protocol_tasks
            }
            SocketAddr::V6(v6) => {
                let octets = v6.ip().octets();
                let hash: usize = octets.iter().map(|&b| b as usize).sum();
                let port = v6.port() as usize;
                (hash.wrapping_add(port)) % num_protocol_tasks
            }
        }
    }

    /// Run the network task with truly event-driven io_uring
    /// Waits for ANY of three events:
    /// 1. Ingress: Network packet from NIC (io_uring completion)
    /// 2. Egress: Packet from protocol task to send (MPSC channel)
    /// 3. Shutdown: Broadcast signal to gracefully stop
    pub async fn run(self) {
        info!(
            "Network task {} starting with event-driven io_uring",
            self.id
        );

        // Extract owned values to avoid borrowing issues in select!
        let mut socket = self.socket;
        let to_protocol_senders = self.to_protocol_senders;
        let mut from_protocol = self.from_protocol;
        let metrics = self.metrics;
        let mut shutdown_rx = self.shutdown_rx;

        // Main event loop - purely event-driven, zero polling
        loop {
            select! {
                // Event 1: Ingress - Network packet received from NIC (truly async)
                recv_result = Self::recv_from_buffer_static(&mut socket) => {
                    match recv_result {
                        Ok((buffer, addr, len)) => {
                            metrics.record_packet_received(len);
                            debug!("Network task received {} bytes from {}", len, addr);

                            // Parse QUIC header to extract destination connection ID for proper routing
                            let protocol_task_idx = match Self::extract_and_hash_dcid(&buffer, len, to_protocol_senders.len()) {
                                Ok(idx) => {
                                    debug!("Routing packet with DCID to protocol task {}", idx);
                                    idx
                                }
                                Err(e) => {
                                    debug!("Failed to parse QUIC header ({}), using fallback hash", e);
                                    // Fallback: use source address hash for routing
                                    Self::hash_addr_to_protocol_task(&addr, to_protocol_senders.len())
                                }
                            };

                            // Forward to selected protocol task
                            let msg = NetworkToProtocol::Datagram { buffer, addr };
                            if let Err(e) = to_protocol_senders[protocol_task_idx].send(msg) {
                                metrics.record_channel_send_error();
                                warn!("Failed to send to protocol layer: {}", e);
                            }
                        }
                        Err(e) => {
                            if e.kind() != std::io::ErrorKind::WouldBlock {
                                metrics.record_receive_error();
                                error!("recv_from error: {}", e);
                            }
                        }
                    }
                }

                // Event 2: Egress - Packet from protocol thread to send to NIC (truly async)
                msg_option = from_protocol.recv() => {
                    match msg_option {
                        Some(super::ProtocolToNetwork::Datagram { buffer, addr }) => {
                            if let Err(e) = Self::send_to_static(&mut socket, &buffer, addr).await {
                                metrics.record_send_error();
                                error!("send_to error: {}", e);
                            } else {
                                metrics.record_packet_sent(buffer.len());
                            }
                        }
                        None => {
                            // Channel closed - protocol layer shut down
                            info!("Protocol channel closed, shutting down network task {}", self.id);
                            break;
                        }
                    }
                }

                // Event 3: Shutdown signal - broadcast event (truly async, no polling!)
                _ = shutdown_rx.recv() => {
                    info!("Network task {} received shutdown signal", self.id);
                    break;
                }
            }
        }

        info!("Network task {} shutting down", self.id);
    }

    /// Static version of recv_from_buffer to avoid borrowing self
    async fn recv_from_buffer_static(
        socket: &mut UdpSocket,
    ) -> std::io::Result<(ZeroCopyBuffer, SocketAddr, usize)> {
        let buffer_pool = get_buffer_pool();
        let mut buf = buffer_pool.get_empty();

        // Receive data directly
        let data = vec![0u8; MAX_UDP_PAYLOAD];
        let (result, received_data) = socket.recv_from(data).await;
        let (len, addr) = result?;

        // Copy received data into our zero-copy buffer
        buf.expand(len);
        buf[..len].copy_from_slice(&received_data[..len]);

        // Return the buffer directly (no freeze needed)
        let zero_copy_buf = buf;

        Ok((zero_copy_buf, addr, len))
    }

    /// Static version of send_to to avoid borrowing self
    async fn send_to_static(
        socket: &mut UdpSocket,
        buffer: &ZeroCopyBuffer,
        addr: SocketAddr,
    ) -> std::io::Result<()> {
        let data = (*buffer).to_vec();
        let (result, _buf) = socket.send_to(data, addr).await;
        result?;
        Ok(())
    }
}

/// Create a UDP socket with SO_REUSEPORT and optimizations using tokio_uring
async fn create_udp_socket(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    // Enable SO_REUSEPORT for load balancing across threads
    // NOTE: Disabled for now due to QUIC connection state issues.
    // SO_REUSEPORT distributes packets from same connection to different
    // network tasks, breaking QUIC's requirement for ordered packet processing.
    // TODO: Implement connection-aware routing or shared state
    #[cfg(target_os = "linux")]
    // socket.set_reuse_port(true)?;

    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;

    // Increase buffer sizes for high throughput
    if let Err(e) = socket.set_recv_buffer_size(16 * 1024 * 1024) {
        warn!("Failed to set recv buffer size: {}", e);
    }

    if let Err(e) = socket.set_send_buffer_size(16 * 1024 * 1024) {
        warn!("Failed to set send buffer size: {}", e);
    }

    socket.bind(&addr.into())?;

    // Convert to tokio_uring UdpSocket
    let udp_socket = UdpSocket::from_std(socket.into());

    Ok(udp_socket)
}

/// Start network I/O layer with io_uring-based async tasks
/// Creates N network tasks, each with dedicated channels to/from protocol layer
///
/// Channel architecture:
/// - Each network task has 1 sender to 1 protocol task (ingress)
/// - Each network task has 1 receiver from 1 protocol task (egress)
/// - No shared channels, no broadcasts, complete separation of concerns
pub fn start_network_layer(
    config: &crate::config::Config,
    to_protocol_senders: Vec<ToProtocolSender>,
    from_protocol_receivers: Vec<mpsc::UnboundedReceiver<super::ProtocolToNetwork>>,
    shutdown_tx: broadcast::Sender<()>,
) -> Result<()> {
    info!(
        "Starting network layer with {} io_uring tasks on {}",
        config.network_threads, config.listen
    );

    // Validate we have correct number of channels
    // Each network task needs access to ALL protocol task senders (for hashing)
    // But each network task gets ONE receiver from protocol (for egress)
    if to_protocol_senders.len() != config.protocol_threads {
        return Err(NetworkError::InvalidConfiguration(format!(
            "Expected {} to_protocol senders (one per protocol task), got {}",
            config.protocol_threads,
            to_protocol_senders.len()
        ))
        .into());
    }

    if from_protocol_receivers.len() != config.network_threads {
        return Err(NetworkError::InvalidConfiguration(format!(
            "Expected {} from_protocol receivers (one per network task), got {}",
            config.network_threads,
            from_protocol_receivers.len()
        ))
        .into());
    }

    let listen_addr: SocketAddr = config.listen.parse().map_err(|_| {
        NetworkError::SocketBindFailed(format!("Invalid listen address: {}", config.listen))
    })?;

    // Initialize buffer pool with optimal size based on expected connections
    let pool_capacity = config.calculate_buffer_pool_size();
    super::zerocopy_buffer::init_buffer_pool(pool_capacity);

    // Create shared metrics
    let metrics = Arc::new(NetworkMetrics::new());

    // Start metrics reporting task on tokio runtime
    start_metrics_task(Arc::clone(&metrics), shutdown_tx.subscribe());

    let mut receivers_iter = from_protocol_receivers.into_iter();

    // Create each network task with access to ALL protocol senders (for hashing)
    for i in 0..config.network_threads {
        // Each network task gets a CLONE of ALL protocol senders
        let to_protocol_senders_clone: Vec<ToProtocolSender> = to_protocol_senders.iter().map(|s| s.clone()).collect();
        let from_protocol = receivers_iter.next().unwrap(); // Safe due to validation above
        let metrics = Arc::clone(&metrics);
        let shutdown_rx = shutdown_tx.subscribe(); // Each task gets its own receiver

        tokio_uring::spawn(async move {
            info!("Network task {} starting on {:?}", i, listen_addr);

            match IoUringNetworkThread::new(
                i,
                listen_addr,
                to_protocol_senders_clone,
                from_protocol,
                metrics,
                shutdown_rx,
            )
            .await
            {
                Ok(net_thread) => {
                    net_thread.run().await;
                }
                Err(e) => {
                    error!("Failed to create network task {}: {}", i, e);
                }
            }
        });
    }

    Ok(())
}

/// Start metrics reporting task on Tokio runtime
fn start_metrics_task(metrics: SharedMetrics, mut shutdown_rx: broadcast::Receiver<()>) {
    tokio_uring::spawn(async move {
        // Report initial metrics
        let stats = metrics.get_stats();
        info!("Network Layer Metrics: {}", stats);

        // Wait for shutdown
        let _ = shutdown_rx.recv().await;
        info!("Metrics task shutting down");
    });
}
