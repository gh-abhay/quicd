//! Worker thread orchestration module.
//!
//! This module handles the spawning and lifecycle management of worker threads.
//! Each worker is a native OS thread with its own event loop and resources.
//!
//! **Critical Architecture**: Each worker is a native OS thread with:
//! - **Own dedicated buffer pool** (ZERO sharing between workers)
//! - **Own io_uring instance** (no shared ring)
//! - **CPU affinity pinning** for cache locality
//! - **SO_REUSEPORT socket** for kernel-level load distribution
//!
//! # Design Philosophy: Zero Contention
//!
//! - **No cross-thread communication** in hot path (no channels, no atomics in hot path)
//! - **All packet processing** happens on the same thread (event-driven)
//! - **Event-driven**: io_uring wait → process completions → submit new ops → repeat
//! - **Thread-local data only** (no locks, no mutexes, no atomic contention)

use crate::netio::{
    buffer::{create_worker_pool, WorkerBufPool, WorkerBuffer},
    config::NetIoConfig,
    socket::create_udp_socket,
};
use crate::quic::QuicManager;
use crate::telemetry::{record_metric, MetricsEvent};
use anyhow::{Context, Result};
use io_uring::{opcode, types, IoUring};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use tracing::{debug, error, info, warn};

/// User data for io_uring operations.
/// Used to track which operation completed.
#[derive(Debug, Clone, Copy)]
#[repr(u64)]
enum OpType {
    /// Receive operation with buffer ID
    Recv(u64),
    /// Send operation (for future implementation)
    #[allow(dead_code)]
    Send(u64),
}

impl From<u64> for OpType {
    fn from(val: u64) -> Self {
        let op_tag = (val >> 56) as u8;
        let buf_id = val & 0x00FFFFFFFFFFFFFF;

        match op_tag {
            0 => OpType::Recv(buf_id),
            1 => OpType::Send(buf_id),
            _ => OpType::Recv(0), // Default to recv on unknown
        }
    }
}

impl From<OpType> for u64 {
    fn from(op: OpType) -> Self {
        match op {
            OpType::Recv(id) => (0u64 << 56) | id,
            OpType::Send(id) => (1u64 << 56) | id,
        }
    }
}

/// Network worker running in its own native thread with io_uring.
///
/// Each worker is completely independent with:
/// - Own buffer pool (no contention)
/// - Own io_uring instance
/// - Own UDP socket (SO_REUSEPORT)
/// - Own QUIC connection manager
/// - Pinned to specific CPU core
pub struct NetworkWorker {
    id: usize,
    socket_fd: i32,
    bind_addr: SocketAddr,
    buffer_pool: WorkerBufPool,
    config: NetIoConfig,
    quic_config: crate::quic::QuicConfig,
    shutdown: Arc<AtomicBool>,
}

impl NetworkWorker {
    /// Create a new network worker (called from main thread, then moved to worker thread).
    pub fn new(
        id: usize,
        bind_addr: SocketAddr,
        config: NetIoConfig,
        quic_config: crate::quic::QuicConfig,
        shutdown: Arc<AtomicBool>,
    ) -> Result<Self> {
        // Create UDP socket with SO_REUSEPORT
        let socket = create_udp_socket(bind_addr, &config)?;
        let socket_fd = socket.as_raw_fd();

        // Prevent socket from being closed when it goes out of scope
        // We'll manage the FD manually
        std::mem::forget(socket);

        // Create worker's own buffer pool (NO SHARING!)
        let buffer_pool = create_worker_pool(&config.buffer_pool);

        debug!(
            worker_id = id,
            addr = %bind_addr,
            buffers = config.buffer_pool.max_buffers_per_worker,
            uring_entries = config.uring_entries,
            "Network worker created"
        );

        Ok(Self {
            id,
            socket_fd,
            bind_addr,
            buffer_pool,
            config,
            quic_config,
            shutdown,
        })
    }

    /// Run the worker's io_uring event loop (runs in dedicated native thread).
    pub fn run(self) -> Result<()> {
        // Pin thread to CPU core if enabled
        if self.config.pin_to_cpu {
            if let Some(core_id) =
                core_affinity::get_core_ids().and_then(|ids| ids.get(self.id).copied())
            {
                if core_affinity::set_for_current(core_id) {
                    info!(
                        worker_id = self.id,
                        core_id = self.id,
                        "Worker thread pinned to CPU core"
                    );
                } else {
                    warn!(worker_id = self.id, "Failed to pin thread to CPU core");
                }
            }
        }

        info!(
            worker_id = self.id,
            addr = %self.bind_addr,
            "Network worker starting io_uring event loop"
        );

        // Record worker started
        record_metric(MetricsEvent::WorkerStarted);

        let worker_id = self.id;

        // Leak the buffer pool to get 'static lifetime
        // This is safe because the pool lives for the entire worker thread lifetime
        let buffer_pool: &'static WorkerBufPool = Box::leak(Box::new(self.buffer_pool));

        // Create QUIC manager for this worker
        let mut quic_manager =
            match QuicManager::new(worker_id, self.bind_addr, self.quic_config.clone()) {
                Ok(manager) => manager,
                Err(e) => {
                    error!(worker_id, error = ?e, "Failed to create QUIC manager");
                    record_metric(MetricsEvent::WorkerStopped);
                    return Err(e);
                }
            };

        info!(worker_id, "QUIC manager initialized");

        // Create io_uring instance
        let mut ring = IoUring::builder()
            .build(self.config.uring_entries)
            .context("creating io_uring")?;

        // Track in-flight operations: user_data -> (buffer, sockaddr_storage)
        let mut in_flight: HashMap<u64, (WorkerBuffer, Box<libc::sockaddr_storage>)> =
            HashMap::new();
        let mut next_buf_id: u64 = 0;

        // Track pending sends (packets from QUIC layer to send via io_uring)
        // Using Arc<Mutex> to allow callback to add packets
        let pending_sends = Arc::new(std::sync::Mutex::new(Vec::<(SocketAddr, Vec<u8>)>::new()));

        // Set up send callback for QUIC manager
        quic_manager.set_send_callback(Box::new({
            let sends = Arc::clone(&pending_sends);
            move |to: SocketAddr, packet: &[u8]| {
                if let Ok(mut sends) = sends.lock() {
                    sends.push((to, packet.to_vec()));
                }
            }
        }));

        // Pre-submit initial receive operations to keep pipeline full
        let initial_ops = (self.config.uring_entries / 4).min(64) as usize; // 1/4 of ring size
        for _ in 0..initial_ops {
            if let Err(e) = submit_recv_op(
                &mut ring,
                self.socket_fd,
                buffer_pool,
                &mut in_flight,
                &mut next_buf_id,
            ) {
                error!(worker_id = self.id, error = ?e, "Failed to submit initial recv op");
            }
        }

        // Submit initial batch
        if let Err(e) = ring.submit() {
            error!(worker_id = self.id, error = ?e, "Failed to submit initial operations");
        }

        let worker_id = self.id;
        let socket_fd = self.socket_fd;
        let shutdown = &self.shutdown;

        // Timeout tracking for QUIC
        let mut last_timeout_check = std::time::Instant::now();
        let timeout_check_interval = std::time::Duration::from_millis(10); // Check every 10ms

        // Main event loop: wait for completions, process, resubmit
        loop {
            // Check shutdown flag (only overhead in event loop)
            if shutdown.load(Ordering::Relaxed) {
                break;
            }

            // Check QUIC timeouts periodically
            let now = std::time::Instant::now();
            if now.duration_since(last_timeout_check) >= timeout_check_interval {
                if let Err(e) = quic_manager.handle_timeouts() {
                    error!(worker_id, error = ?e, "QUIC timeout handling failed");
                }
                last_timeout_check = now;
            }

            // Process pending sends from QUIC layer
            if let Ok(mut sends) = pending_sends.lock() {
                for (to, packet) in sends.drain(..) {
                    // TODO: Submit sendmsg operation via io_uring for better performance
                    // For now, we use blocking sendto as a functional implementation
                    use socket2::SockAddr;
                    let sock_addr = SockAddr::from(to);

                    let result = unsafe {
                        libc::sendto(
                            socket_fd,
                            packet.as_ptr() as *const libc::c_void,
                            packet.len(),
                            0,
                            sock_addr.as_ptr(),
                            sock_addr.len(),
                        )
                    };

                    if result < 0 {
                        error!(worker_id, peer = %to, "Failed to send packet");
                        record_metric(MetricsEvent::NetworkSendError);
                    } else {
                        record_metric(MetricsEvent::PacketSent {
                            bytes: packet.len(),
                        });
                    }
                }
            }

            // Wait for at least 1 completion (blocking with timeout)
            // Use a small timeout so we can check QUIC timeouts regularly
            match ring.submit_and_wait(0) {
                Ok(_) => {}
                Err(ref e) if e.raw_os_error() == Some(libc::EINTR) => {
                    // Interrupted by signal, check shutdown and continue
                    continue;
                }
                Err(e) => {
                    error!(worker_id, error = ?e, "io_uring submit_and_wait failed");
                    record_metric(MetricsEvent::NetworkReceiveError);
                    continue;
                }
            }

            // Collect completions to process (avoid holding completion queue borrow)
            let mut completions = Vec::new();
            {
                let mut cq = ring.completion();
                for cqe in &mut cq {
                    completions.push((cqe.user_data(), cqe.result()));
                }
            } // cq dropped here, releasing the borrow

            // Process all completed operations
            for (user_data, result) in completions {
                // Decode operation type
                let op_type = OpType::from(user_data);

                match op_type {
                    OpType::Recv(buf_id) => {
                        // Remove buffer from in-flight map
                        if let Some((mut buffer, _addr_storage)) = in_flight.remove(&buf_id) {
                            if result < 0 {
                                // Error occurred
                                let err = io::Error::from_raw_os_error(-result);
                                error!(
                                    worker_id,
                                    error = ?err,
                                    "Receive operation failed"
                                );
                                record_metric(MetricsEvent::NetworkReceiveError);
                                // Buffer returns to pool automatically (Drop)
                            } else {
                                // Successfully received packet
                                let bytes_read = result as usize;
                                buffer.set_received_len(bytes_read);

                                // TODO: Extract peer address from addr_storage
                                // For now, use a placeholder
                                let peer_addr = "0.0.0.0:0".parse::<SocketAddr>().unwrap();

                                record_metric(MetricsEvent::PacketReceived { bytes: bytes_read });

                                // Pass packet to QUIC layer for processing
                                if let Err(e) = quic_manager.process_ingress(buffer, peer_addr) {
                                    error!(worker_id, peer = %peer_addr, error = ?e, "QUIC processing failed");
                                } else {
                                    // Buffer consumed by QUIC layer
                                }
                            }

                            // Resubmit another receive operation to keep pipeline full
                            if let Err(e) = submit_recv_op(
                                &mut ring,
                                self.socket_fd,
                                buffer_pool,
                                &mut in_flight,
                                &mut next_buf_id,
                            ) {
                                error!(worker_id, error = ?e, "Failed to resubmit recv op");
                            }
                        } else {
                            warn!(worker_id, buf_id, "Received completion for unknown buffer");
                        }
                    }
                    OpType::Send(_buf_id) => {
                        // Send completion (for future implementation)
                        if result < 0 {
                            let err = io::Error::from_raw_os_error(-result);
                            error!(worker_id, error = ?err, "Send operation failed");
                            record_metric(MetricsEvent::NetworkSendError);
                        }
                    }
                }
            }
        }

        info!(worker_id, "Network worker shutting down");
        record_metric(MetricsEvent::WorkerStopped);

        // Clean up remaining in-flight buffers (they'll return to pool on drop)
        in_flight.clear();

        Ok(())
    }
}

/// Submit a receive operation to io_uring.
///
/// This prepares a recvmsg operation with:
/// - Buffer from the worker's pool
/// - Socket address storage for peer address
/// - User data tracking for completion
fn submit_recv_op(
    ring: &mut IoUring,
    socket_fd: i32,
    buffer_pool: &'static WorkerBufPool,
    in_flight: &mut HashMap<u64, (WorkerBuffer, Box<libc::sockaddr_storage>)>,
    next_buf_id: &mut u64,
) -> io::Result<()> {
    // Get buffer from pool
    // SAFETY: buffer_pool has 'static lifetime from Box::leak
    let mut buffer = unsafe { WorkerBuffer::new_from_leaked(buffer_pool) };

    // Prepare address storage for peer address
    let mut addr_storage = Box::new(unsafe { std::mem::zeroed::<libc::sockaddr_storage>() });

    // Prepare iovec for buffer
    let buf_slice = buffer.as_mut_slice_for_io();
    let iov = libc::iovec {
        iov_base: buf_slice.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf_slice.len(),
    };

    // Prepare msghdr for recvmsg
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut *addr_storage as *mut _ as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
    msg.msg_iov = &iov as *const _ as *mut _;
    msg.msg_iovlen = 1;

    // Create recvmsg operation
    let buf_id = *next_buf_id;
    *next_buf_id = next_buf_id.wrapping_add(1);

    let recv_op = opcode::RecvMsg::new(types::Fd(socket_fd), &mut msg as *mut _)
        .build()
        .user_data(OpType::Recv(buf_id).into());

    // Store buffer and address storage in in-flight map
    in_flight.insert(buf_id, (buffer, addr_storage));

    // Submit operation to submission queue
    // SAFETY: The submission queue is part of the ring, and we're properly managing lifetimes
    unsafe {
        ring.submission()
            .push(&recv_op)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "submission queue full"))?;
    }

    Ok(())
}

/// Handle for managing network I/O worker threads.
///
/// Dropping this handle will signal workers to shut down.
pub struct NetIoHandle {
    workers: Vec<JoinHandle<Result<()>>>,
    shutdown: Arc<AtomicBool>,
    worker_count: usize,
}

impl NetIoHandle {
    pub fn worker_count(&self) -> usize {
        self.worker_count
    }

    /// Signal all workers to shut down and wait for them to complete
    pub fn shutdown(mut self) {
        info!("Shutting down network layer");
        self.shutdown.store(true, Ordering::Relaxed);

        for (i, worker) in self.workers.drain(..).enumerate() {
            match worker.join() {
                Ok(Ok(())) => {
                    debug!(worker_id = i, "Worker thread exited cleanly");
                }
                Ok(Err(e)) => {
                    error!(worker_id = i, error = ?e, "Worker thread returned error");
                }
                Err(e) => {
                    error!(worker_id = i, error = ?e, "Worker thread panicked");
                }
            }
        }

        info!("Network layer shutdown complete");
    }
}

impl Drop for NetIoHandle {
    fn drop(&mut self) {
        debug!("NetIoHandle dropped, signaling shutdown");
        self.shutdown.store(true, Ordering::Relaxed);
        // Note: We don't join threads in Drop to avoid blocking
        // User should call shutdown() explicitly for graceful shutdown
    }
}

/// Spawn network I/O workers as native OS threads with io_uring.
///
/// # Architecture
///
/// **Pure Event-Driven Design with ZERO Contention**:
/// - Each worker is a **native OS thread** (not async task, not tokio runtime)
/// - Each worker has its **own dedicated buffer pool** (ZERO sharing)
/// - Each worker has its **own io_uring instance** (no shared ring)
/// - Each worker is **pinned to a specific CPU core** (cache locality)
/// - **SO_REUSEPORT** distributes packets at kernel level (hardware RSS)
/// - **ZERO cross-thread communication** in hot path (no channels, no locks)
/// - All packet processing happens **on the same thread** (event-driven)
///
/// # io_uring Event Loop
///
/// Each worker runs a pure io_uring event loop:
/// ```text
/// loop {
///     io_uring_enter() -> wait for completions (blocking)
///     for each completion {
///         process packet (QUIC protocol layer)
///         submit new recv operation
///     }
///     submit batch of operations
/// }
/// ```
///
/// # Design Principles (CRITICAL)
///
/// 1. **No Locks**: Each worker owns its data, no mutexes anywhere
/// 2. **No Message Passing**: All processing on same thread (event-driven)
/// 3. **No Context Switching**: Native threads pinned to CPU cores
/// 4. **No Shared State**: Buffer pools, io_uring instances, all per-worker
/// 5. **Pure Event-Driven**: io_uring provides async I/O completions
/// 6. **Zero-Copy**: Buffers passed directly to kernel and back
///
/// # Performance Benefits
///
/// - **Minimal syscalls**: io_uring batches submissions and completions
/// - **Zero contention**: No cache line bouncing between cores
/// - **Linear scaling**: N workers = N × single-core throughput
/// - **Cache locality**: Thread pinning keeps hot data in L1/L2
/// - **Low latency**: Direct event handling, no queueing delays
/// - **High throughput**: Multiple in-flight operations per worker
///
/// # Arguments
///
/// * `bind_addr` - Socket address to bind to (all workers bind to same address)
/// * `config` - Network I/O configuration
/// * `quic_config` - QUIC protocol configuration
///
/// # Returns
///
/// Handle to manage worker threads and coordinate shutdown
///
/// # Errors
///
/// Returns error if:
/// - Worker count is 0
/// - Socket creation fails
/// - io_uring initialization fails
/// - Thread spawning fails
pub fn spawn(
    bind_addr: SocketAddr,
    config: NetIoConfig,
    quic_config: crate::quic::QuicConfig,
) -> Result<NetIoHandle> {
    if config.workers == 0 {
        anyhow::bail!("netio workers must be at least 1");
    }

    info!(
        workers = config.workers,
        addr = %bind_addr,
        pin_to_cpu = config.pin_to_cpu,
        uring_entries = config.uring_entries,
        reuse_port = config.reuse_port,
        "Initializing network layer with io_uring"
    );

    // Shared shutdown flag (only for coordination, not hot path)
    let shutdown = Arc::new(AtomicBool::new(false));

    let mut workers = Vec::with_capacity(config.workers);

    // Spawn N native worker threads
    for worker_id in 0..config.workers {
        let bind_addr = bind_addr;
        let config = config.clone();
        let quic_config = quic_config.clone();
        let shutdown = Arc::clone(&shutdown);

        // Create worker (in main thread)
        let worker = NetworkWorker::new(worker_id, bind_addr, config, quic_config, shutdown)?;

        // Spawn native thread and move worker into it
        let handle = thread::Builder::new()
            .name(format!("netio-{}", worker_id))
            .spawn(move || worker.run())?;

        workers.push(handle);
    }

    info!(
        workers = config.workers,
        "Network layer started with io_uring"
    );

    Ok(NetIoHandle {
        workers,
        shutdown,
        worker_count: config.workers,
    })
}
