/// Modern event-driven network I/O using io_uring
/// This provides the best performance on Linux by:
/// - Minimizing syscalls through batched submissions
/// - Using completion-based async I/O
/// - Zero-copy buffer management

use super::affinity::{CpuAffinityManager, PinningStrategy, ThreadType};
use super::metrics::{NetworkMetrics, SharedMetrics};
use super::zerocopy_buffer::{get_buffer_pool, ZeroCopyBuffer, MAX_UDP_PAYLOAD};
use super::{FromProtocolReceiver, NetworkToProtocol, ToProtocolSender};

use crate::error::{NetworkError, Result};

use parking_lot::Mutex;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use tokio::runtime::Handle;
use tokio_uring::net::UdpSocket;
use tracing::{error, info, warn};

/// Network I/O thread using io_uring for event-driven operations
pub struct IoUringNetworkThread {
    id: usize,
    socket: UdpSocket,
    to_protocol: ToProtocolSender,
    from_protocol: Arc<Mutex<FromProtocolReceiver>>,
    metrics: SharedMetrics,
    running: Arc<AtomicBool>,
}

impl IoUringNetworkThread {
    pub async fn new(
        id: usize,
        listen_addr: SocketAddr,
        to_protocol: ToProtocolSender,
        from_protocol: Arc<Mutex<FromProtocolReceiver>>,
        metrics: SharedMetrics,
        running: Arc<AtomicBool>,
        _tokio_handle: Handle,
    ) -> std::io::Result<Self> {
        let socket = create_udp_socket(listen_addr).await?;

        Ok(Self {
            id,
            socket,
            to_protocol,
            from_protocol,
            metrics,
            running,
        })
    }

    /// Run the network thread with io_uring
    pub async fn run(mut self) {
        info!("Network thread {} starting with io_uring", self.id);

        while self.running.load(Ordering::Relaxed) {
            // Use a timeout to periodically check the running flag
            let timeout_result = tokio::time::timeout(
                std::time::Duration::from_millis(100), // Check every 100ms
                self.recv_from_buffer(),
            ).await;

            match timeout_result {
                Ok(recv_result) => {
                    match recv_result {
                        Ok((buffer, addr, len)) => {
                            self.metrics.record_packet_received(len);

                            // Send to protocol layer
                            let msg = NetworkToProtocol::Datagram { buffer, addr };
                            if let Err(e) = self.to_protocol.send(msg) {
                                self.metrics.record_channel_send_error();
                                warn!("Failed to send to protocol layer: {}", e);
                            }
                        }
                        Err(e) => {
                            if e.kind() != std::io::ErrorKind::WouldBlock {
                                self.metrics.record_receive_error();
                                error!("recv_from error: {}", e);
                            }
                        }
                    }
                }
                Err(_) => {
                    // Timeout - just continue to check running flag
                }
            }

            // Send pending packets from protocol layer
            self.send_pending().await;

            // Small yield to prevent busy spinning
            tokio::task::yield_now().await;
        }

        info!("Network thread {} shutting down", self.id);
    }

    /// Receive a packet using io_uring (internal method)
    async fn recv_from_buffer(&mut self) -> std::io::Result<(ZeroCopyBuffer, SocketAddr, usize)> {
        let buffer_pool = get_buffer_pool();
        let mut buf = buffer_pool.acquire();

        // Ensure buffer has capacity
        buf.data_mut().resize(MAX_UDP_PAYLOAD, 0);

        let data = vec![0u8; MAX_UDP_PAYLOAD];
        let (result, received_data) = self.socket.recv_from(data).await;
        let (len, addr) = result?;
        
        // Copy data into our zero-copy buffer
        buf.data_mut().extend_from_slice(&received_data[..len]);
        
        // Truncate to actual received length and freeze
        buf.data_mut().truncate(len);
        let zero_copy_buf = buf.freeze();
        
        Ok((zero_copy_buf, addr, len))
    }

    /// Send pending packets from protocol layer
    async fn send_pending(&mut self) {
        // Create a temporary vector to avoid borrowing issues
        let mut pending = Vec::new();
        {
            let mut from_protocol = self.from_protocol.lock();
            while let Ok(msg) = from_protocol.try_recv() {
                pending.push(msg);
            }
        }
        
        for msg in pending {
            match msg {
                super::ProtocolToNetwork::Datagram { buffer, addr } => {
                    if let Err(e) = self.send_to(&buffer, addr).await {
                        self.metrics.record_send_error();
                        error!("send_to error: {}", e);
                    } else {
                        self.metrics.record_packet_sent(buffer.len());
                    }
                }
            }
        }
    }

    /// Send a packet using io_uring
    async fn send_to(&mut self, buffer: &ZeroCopyBuffer, addr: SocketAddr) -> std::io::Result<()> {
        let data = buffer.data().to_vec();
        let (result, _buf) = self.socket.send_to(data, addr).await;
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
pub fn start_network_layer(
    config: &crate::config::Config,
    to_protocol: ToProtocolSender,
    from_protocol: FromProtocolReceiver,
    tokio_handle: Handle,
    running: Arc<AtomicBool>,
) -> Result<Vec<thread::JoinHandle<()>>> {
    info!(
        "Starting network layer with {} io_uring threads on {}",
        config.network_threads, config.listen
    );

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
    start_metrics_task(Arc::clone(&metrics), Arc::clone(&running), tokio_handle.clone());

    // Wrap from_protocol in Arc<Mutex> for sharing across threads
    let from_protocol = Arc::new(Mutex::new(from_protocol));

    let mut handles = Vec::new();

    for i in 0..config.network_threads {
        let to_protocol = to_protocol.clone();
        let from_protocol = Arc::clone(&from_protocol);
        let metrics = Arc::clone(&metrics);
        let running = Arc::clone(&running);
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
                        running,
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
fn start_metrics_task(metrics: SharedMetrics, running: Arc<AtomicBool>, handle: Handle) {
    handle.spawn(async move {
        while running.load(Ordering::Relaxed) {
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

            let stats = metrics.get_stats();
            info!("Network Layer Metrics: {}", stats);
        }
    });
}
