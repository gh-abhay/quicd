//! Dedicated network I/O thread with pinned single-threaded runtime
//!
//! This module implements the expert-recommended pattern:
//! - Dedicated OS thread per network socket
//! - Single-threaded Tokio runtime pinned to that thread
//! - SO_REUSEPORT for multi-core scaling
//! - Lock-free buffer pool for zero-allocation receives
//! - Non-blocking sends with backpressure handling
//!
//! Based on expert advice: "Run network IO pinned to dedicated OS threads
//! for the packet ingress/egress path"

use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;
use bytes::Bytes;
use crossbeam::channel::{Sender, Receiver, TrySendError};
use socket2::{Socket, Domain, Type, Protocol};
use tokio::net::UdpSocket;
use crate::{BufferPool, Metrics, Result, SuperdError};

/// Packet received from network
#[derive(Debug, Clone)]
pub struct RxPacket {
    /// Packet data (zero-copy)
    pub data: Bytes,
    /// Source address
    pub from: SocketAddr,
    /// Destination address (our local addr)
    pub to: SocketAddr,
}

/// Packet to send to network
#[derive(Debug, Clone)]
pub struct TxPacket {
    /// Packet data (zero-copy)
    pub data: Bytes,
    /// Destination address
    pub to: SocketAddr,
}

/// Configuration for network thread
#[derive(Clone)]
pub struct NetworkThreadConfig {
    /// Local address to bind to
    pub bind_addr: SocketAddr,
    /// Thread ID (for logging and affinity)
    pub thread_id: usize,
    /// Enable SO_REUSEPORT for multi-threaded scaling
    pub reuse_port: bool,
    /// Socket receive buffer size
    pub recv_buffer_size: usize,
    /// Socket send buffer size
    pub send_buffer_size: usize,
}

/// Spawns a dedicated network I/O thread
///
/// This function creates an OS thread with a single-threaded Tokio runtime
/// pinned to it. The thread handles UDP socket operations with minimal
/// latency and no scheduler jitter.
///
/// # Expert Recommendation
///
/// "Pin network socket handling to dedicated OS threads with a single-threaded
/// Tokio runtime for low and deterministic latency."
///
/// # Arguments
///
/// * `config` - Network thread configuration
/// * `rx_tx` - Sender for received packets (to app workers)
/// * `tx_rx` - Receiver for packets to transmit
/// * `buffer_pool` - Shared buffer pool for zero-allocation receives
/// * `metrics` - Shared metrics collector
///
/// # Returns
///
/// A JoinHandle for the spawned thread
pub fn spawn_network_thread(
    config: NetworkThreadConfig,
    rx_tx: Sender<RxPacket>,
    tx_rx: Receiver<TxPacket>,
    buffer_pool: BufferPool,
    metrics: Arc<Metrics>,
) -> thread::JoinHandle<Result<()>> {
    thread::Builder::new()
        .name(format!("net-io-{}", config.thread_id))
        .spawn(move || {
            // Build single-threaded runtime pinned to this OS thread
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| SuperdError::StdIo {
                    context: "Failed to create network runtime".to_string(),
                    source: e,
                })?;

            // Run the network loop on this thread's runtime
            rt.block_on(async move {
                run_network_loop(config, rx_tx, tx_rx, buffer_pool, metrics).await
            })
        })
        .expect("Failed to spawn network thread")
}

/// Main network I/O loop
///
/// This runs on a dedicated OS thread with a single-threaded runtime.
/// It handles both packet reception and transmission using tokio::select
/// to avoid blocking on either direction.
async fn run_network_loop(
    config: NetworkThreadConfig,
    rx_tx: Sender<RxPacket>,
    tx_rx: Receiver<TxPacket>,
    buffer_pool: BufferPool,
    metrics: Arc<Metrics>,
) -> Result<()> {
    log::info!("Network thread {} starting on {}", config.thread_id, config.bind_addr);

    // Create socket with SO_REUSEPORT support
    let socket = create_socket(&config)?;
    
    // Convert to tokio UdpSocket
    let socket = UdpSocket::from_std(socket.into())?;
    let local_addr = socket.local_addr()?;
    
    log::info!("Network thread {} bound to {} (SO_REUSEPORT: {})",
        config.thread_id, local_addr, config.reuse_port);

    // Main event loop
    loop {
        tokio::select! {
            // Receive from network
            recv_result = receive_packet(&socket, &buffer_pool, local_addr) => {
                match recv_result {
                    Ok(packet) => {
                        // Record metrics
                        metrics.record_packet_received(packet.data.len() as u64);
                        
                        // Try to send to app workers (non-blocking)
                        match rx_tx.try_send(packet) {
                            Ok(_) => {
                                // Success - packet forwarded
                            }
                            Err(TrySendError::Full(_)) => {
                                // Channel full - apply backpressure by dropping packet
                                // This is appropriate for UDP/QUIC where packet loss is expected
                                metrics.record_error();
                                log::warn!("Network thread {}: RX channel full, dropping packet", 
                                    config.thread_id);
                            }
                            Err(TrySendError::Disconnected(_)) => {
                                // App workers have shut down
                                log::info!("Network thread {}: RX channel disconnected, shutting down",
                                    config.thread_id);
                                return Ok(());
                            }
                        }
                    }
                    Err(e) => {
                        // Log but don't fail on receive errors
                        log::error!("Network thread {}: receive error: {}", config.thread_id, e);
                        metrics.record_error();
                    }
                }
            }
            
            // Send to network
            tx_result = async {
                // Poll crossbeam channel in non-blocking manner
                tokio::task::yield_now().await;
                tx_rx.try_recv()
            } => {
                match tx_result {
                    Ok(packet) => {
                        // Send packet
                        match socket.send_to(&packet.data, packet.to).await {
                            Ok(_) => {
                                metrics.record_packet_sent(packet.data.len() as u64);
                            }
                            Err(e) => {
                                log::error!("Network thread {}: send error: {}", config.thread_id, e);
                                metrics.record_error();
                            }
                        }
                    }
                    Err(crossbeam::channel::TryRecvError::Empty) => {
                        // No packet to send, continue
                    }
                    Err(crossbeam::channel::TryRecvError::Disconnected) => {
                        // TX channel closed - shutdown
                        log::info!("Network thread {}: TX channel disconnected, shutting down",
                            config.thread_id);
                        return Ok(());
                    }
                }
            }
        }
    }
}

/// Receive a single packet using pooled buffer
///
/// This function demonstrates the zero-copy receive path:
/// 1. Checkout BytesMut from pool (no allocation if pool has buffers)
/// 2. Receive into BytesMut
/// 3. Freeze to Bytes (zero-copy, just refcount)
/// 4. Return Bytes (cheap to clone for multicast)
async fn receive_packet(
    socket: &UdpSocket,
    buffer_pool: &BufferPool,
    local_addr: SocketAddr,
) -> Result<RxPacket> {
    // Checkout buffer from pool (zero-allocation in common case)
    let mut buf = buffer_pool.checkout();
    
    // Resize for receive (doesn't allocate if capacity is sufficient)
    buf.resize(65536, 0);
    
    // Receive packet
    let (len, from) = socket.recv_from(&mut buf).await?;
    
    // Truncate to actual length
    buf.truncate(len);
    
    // Freeze to Bytes (zero-copy - just wraps the BytesMut with refcount)
    let data = buf.freeze();
    
    Ok(RxPacket {
        data,
        from,
        to: local_addr,
    })
}

/// Create a UDP socket with optimized settings
///
/// Enables:
/// - SO_REUSEPORT (if configured) for multi-threaded scaling
/// - Large send/receive buffers
/// - Non-blocking mode
fn create_socket(config: &NetworkThreadConfig) -> Result<Socket> {
    let domain = if config.bind_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    
    // Enable SO_REUSEPORT for multi-core scaling
    if config.reuse_port {
        #[cfg(unix)]
        socket.set_reuse_address(true)?;
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            unsafe {
                let optval: libc::c_int = 1;
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_REUSEPORT,
                    &optval as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&optval) as libc::socklen_t,
                );
            }
        }
        log::debug!("SO_REUSEPORT enabled for thread {}", config.thread_id);
    }
    
    // Set socket buffer sizes (Cloudflare-inspired large buffers)
    socket.set_recv_buffer_size(config.recv_buffer_size)?;
    socket.set_send_buffer_size(config.send_buffer_size)?;
    
    // Bind socket
    socket.bind(&config.bind_addr.into())?;
    
    // Set non-blocking for Tokio
    socket.set_nonblocking(true)?;
    
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_network_thread_basic() {
        let config = NetworkThreadConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            thread_id: 0,
            reuse_port: false,
            recv_buffer_size: 2 * 1024 * 1024,
            send_buffer_size: 2 * 1024 * 1024,
        };
        
        let (rx_tx, rx_rx) = crossbeam::channel::bounded(1024);
        let (tx_tx, tx_rx) = crossbeam::channel::bounded(1024);
        let buffer_pool = BufferPool::new();
        let metrics = Arc::new(Metrics::new());
        
        let _handle = spawn_network_thread(
            config,
            rx_tx,
            tx_rx,
            buffer_pool,
            Arc::clone(&metrics),
        );
        
        // Give thread time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        // Test would send/receive packets here
        drop(tx_tx); // Close channels to shutdown thread
        drop(rx_rx);
    }
}
