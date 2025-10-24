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

use super::affinity::{CpuAffinityManager, PinningStrategy, ThreadType};
use super::metrics::{NetworkMetrics, SharedMetrics};
use super::zerocopy_buffer::{get_buffer_pool, ZeroCopyBuffer, MAX_UDP_PAYLOAD};
use super::{NetworkToProtocol, ToProtocolSender};

use crate::error::{NetworkError, Result};

use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;
use tokio::runtime::Handle;
use tokio::select;
use tokio::sync::{broadcast, mpsc};
use tokio_uring::net::UdpSocket;
use tracing::{error, info, warn};

/// Network I/O thread using io_uring for event-driven operations
/// Each network thread has:
/// - One dedicated receiver for egress packets from its assigned protocol thread
/// - One sender to forward ingress packets to its assigned protocol thread
pub struct IoUringNetworkThread {
    id: usize,
    socket: UdpSocket,
    // Send ingress packets to assigned protocol thread
    to_protocol: ToProtocolSender,
    // Receive egress packets from assigned protocol thread (dedicated channel)
    from_protocol: mpsc::UnboundedReceiver<super::ProtocolToNetwork>,
    metrics: SharedMetrics,
    // Receive shutdown signal (broadcast)
    shutdown_rx: broadcast::Receiver<()>,
}

impl IoUringNetworkThread {
    pub async fn new(
        id: usize,
        listen_addr: SocketAddr,
        to_protocol: ToProtocolSender,
        from_protocol: mpsc::UnboundedReceiver<super::ProtocolToNetwork>,
        metrics: SharedMetrics,
        shutdown_rx: broadcast::Receiver<()>,
        _tokio_handle: Handle,
    ) -> std::io::Result<Self> {
        let socket = create_udp_socket(listen_addr).await?;

        Ok(Self {
            id,
            socket,
            to_protocol,
            from_protocol,
            metrics,
            shutdown_rx,
        })
    }

    /// Run the network thread with truly event-driven io_uring
    /// Waits for ANY of three events:
    /// 1. Ingress: Network packet from NIC (io_uring completion)
    /// 2. Egress: Packet from protocol thread to send (MPSC channel)
    /// 3. Shutdown: Broadcast signal to gracefully stop
    pub async fn run(self) {
        info!("Network thread {} starting with event-driven io_uring", self.id);

        // Extract owned values to avoid borrowing issues in select!
        let mut socket = self.socket;
        let to_protocol = self.to_protocol;
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

                            // Forward to protocol layer (our assigned protocol thread)
                            let msg = NetworkToProtocol::Datagram { buffer, addr };
                            if let Err(e) = to_protocol.send(msg) {
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
                            info!("Protocol channel closed, shutting down network thread {}", self.id);
                            break;
                        }
                    }
                }

                // Event 3: Shutdown signal - broadcast event (truly async, no polling!)
                _ = shutdown_rx.recv() => {
                    info!("Network thread {} received shutdown signal", self.id);
                    break;
                }
            }
        }

        info!("Network thread {} shutting down", self.id);
    }

    /// Static version of recv_from_buffer to avoid borrowing self
    async fn recv_from_buffer_static(socket: &mut UdpSocket) -> std::io::Result<(ZeroCopyBuffer, SocketAddr, usize)> {
        let buffer_pool = get_buffer_pool();
        let mut buf = buffer_pool.acquire();

        // Ensure buffer has capacity
        buf.data_mut().resize(MAX_UDP_PAYLOAD, 0);

        let data = vec![0u8; MAX_UDP_PAYLOAD];
        let (result, received_data) = socket.recv_from(data).await;
        let (len, addr) = result?;
        
        // Copy data into our zero-copy buffer
        buf.data_mut().extend_from_slice(&received_data[..len]);
        
        // Truncate to actual received length and freeze
        buf.data_mut().truncate(len);
        let zero_copy_buf = buf.freeze();
        
        Ok((zero_copy_buf, addr, len))
    }

    /// Static version of send_to to avoid borrowing self
    async fn send_to_static(socket: &mut UdpSocket, buffer: &ZeroCopyBuffer, addr: SocketAddr) -> std::io::Result<()> {
        let data = buffer.data().to_vec();
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
    #[cfg(target_os = "linux")]
    socket.set_reuse_port(true)?;

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

/// Start network I/O layer with io_uring-based threads
/// Creates N network threads, each with dedicated channels to/from protocol layer
/// 
/// Channel architecture:
/// - Each network thread has 1 sender to 1 protocol thread (ingress)
/// - Each network thread has 1 receiver from 1 protocol thread (egress)
/// - No shared channels, no broadcasts, complete separation of concerns
pub fn start_network_layer(
    config: &crate::config::Config,
    to_protocol_senders: Vec<ToProtocolSender>,
    from_protocol_receivers: Vec<mpsc::UnboundedReceiver<super::ProtocolToNetwork>>,
    tokio_handle: Handle,
    shutdown_tx: broadcast::Sender<()>,
) -> Result<Vec<thread::JoinHandle<()>>> {
    info!(
        "Starting network layer with {} io_uring threads on {}",
        config.network_threads, config.listen
    );

    // Validate we have correct number of channels
    if to_protocol_senders.len() != config.network_threads {
        return Err(NetworkError::InvalidConfiguration(format!(
            "Expected {} to_protocol senders, got {}",
            config.network_threads,
            to_protocol_senders.len()
        )).into());
    }

    if from_protocol_receivers.len() != config.network_threads {
        return Err(NetworkError::InvalidConfiguration(format!(
            "Expected {} from_protocol receivers, got {}",
            config.network_threads,
            from_protocol_receivers.len()
        )).into());
    }

    let listen_addr: SocketAddr = config
        .listen
        .parse()
        .map_err(|_| NetworkError::SocketBindFailed(format!("Invalid listen address: {}", config.listen)))?;

    // Initialize buffer pool
    let pool_capacity = config.network_threads * 2048;
    super::zerocopy_buffer::init_buffer_pool(pool_capacity);

    // Create shared metrics
    let metrics = Arc::new(NetworkMetrics::new());

    // Create CPU affinity manager
    let affinity_manager = if config.cpu_pinning {
        CpuAffinityManager::new(PinningStrategy::Interleaved)
    } else {
        None
    };

    // Start metrics reporting task on tokio runtime
    start_metrics_task(Arc::clone(&metrics), shutdown_tx.subscribe(), tokio_handle.clone());

    let mut handles = Vec::new();
    let mut receivers_iter = from_protocol_receivers.into_iter();

    // Create each network thread with its dedicated channels
    for i in 0..config.network_threads {
        let to_protocol = to_protocol_senders[i].clone();
        let from_protocol = receivers_iter.next().unwrap(); // Safe due to validation above
        let metrics = Arc::clone(&metrics);
        let shutdown_rx = shutdown_tx.subscribe(); // Each thread gets its own receiver
        let affinity_manager = affinity_manager.clone();
        let tokio_handle = tokio_handle.clone();

        let handle = thread::Builder::new()
            .name(format!("network-io-{}", i))
            .spawn(move || {
                // Pin thread to CPU core
                if let Some(ref manager) = affinity_manager {
                    manager.pin_thread(ThreadType::Network, i);
                }

                info!("Network thread {} starting on {:?}", i, listen_addr);

                // Create and run network thread within tokio_uring runtime
                tokio_uring::start(async move {
                    match IoUringNetworkThread::new(
                        i,
                        listen_addr,
                        to_protocol,
                        from_protocol,
                        metrics,
                        shutdown_rx,
                        tokio_handle,
                    ).await {
                        Ok(net_thread) => {
                            net_thread.run().await;
                        }
                        Err(e) => {
                            error!("Failed to create network thread {}: {}", i, e);
                        }
                    }
                });
            })
            .map_err(|e| NetworkError::ThreadSpawnFailed(e.to_string()))?;

        handles.push(handle);
    }

    Ok(handles)
}

/// Start metrics reporting task on Tokio runtime
fn start_metrics_task(
    metrics: SharedMetrics, 
    mut shutdown_rx: broadcast::Receiver<()>, 
    handle: Handle
) {
    handle.spawn(async move {
        loop {
            select! {
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(10)) => {
                    let stats = metrics.get_stats();
                    info!("Network Layer Metrics: {}", stats);
                }
                _ = shutdown_rx.recv() => {
                    info!("Metrics task shutting down");
                    break;
                }
            }
        }
    });
}
