//! Network worker threads using pure io_uring event-driven I/O.
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
//!
//! # io_uring Event Loop
//!
//! The worker runs a pure io_uring event loop:
//! 1. Submit recvmsg operations (multiple in-flight for throughput)
//! 2. Wait for completions (io_uring_enter syscall)
//! 3. Process completed operations (packet received)
//! 4. Submit new operations to keep pipeline full
//! 5. Repeat
//!
//! This provides:
//! - **Minimal syscalls**: Batch submissions and completions
//! - **Zero-copy**: Buffers passed directly to kernel
//! - **High throughput**: Multiple in-flight operations
//! - **Low latency**: Event-driven, no polling overhead

use super::buffer::{create_worker_pool, WorkerBufPool, WorkerBuffer};
use super::config::NetIoConfig;
use super::socket::create_udp_socket;
use crate::telemetry::{record_metric, MetricsEvent};
use anyhow::{Context, Result};
use io_uring::{opcode, types, IoUring};
use quiche::RecvInfo;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{debug, error, info, trace, warn};

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
/// - Pinned to specific CPU core
pub struct NetworkWorker {
    id: usize,
    socket_fd: i32,
    bind_addr: SocketAddr,
    buffer_pool: WorkerBufPool,
    config: NetIoConfig,
    shutdown: Arc<AtomicBool>,
}

impl NetworkWorker {
    /// Create a new network worker (called from main thread, then moved to worker thread).
    pub fn new(
        id: usize,
        bind_addr: SocketAddr,
        config: NetIoConfig,
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

        // Leak the buffer pool to get 'static lifetime
        // This is safe because the pool lives for the entire worker thread lifetime
        let buffer_pool: &'static WorkerBufPool = Box::leak(Box::new(self.buffer_pool));

        // Create io_uring instance
        let mut ring = IoUring::builder()
            .build(self.config.uring_entries)
            .context("creating io_uring")?;

        // Track in-flight operations: user_data -> (buffer, sockaddr_storage)
        let mut in_flight: HashMap<u64, (WorkerBuffer, Box<libc::sockaddr_storage>)> =
            HashMap::new();
        let mut next_buf_id: u64 = 0;

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
        let bind_addr = self.bind_addr;
        let shutdown = &self.shutdown;

        // Main event loop: wait for completions, process, resubmit
        loop {
            // Check shutdown flag (only overhead in event loop)
            if shutdown.load(Ordering::Relaxed) {
                break;
            }

            // Wait for at least 1 completion (blocking)
            // This is the only blocking point - we wake on packet arrival
            match ring.submit_and_wait(1) {
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
                                handle_ingress(worker_id, bind_addr, buffer, peer_addr, bytes_read);
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

/// Handle an ingress packet (all processing happens on this thread).
///
/// This function is called when a packet is received and ready for processing.
/// All QUIC protocol processing will happen here on the same thread - no message passing!
fn handle_ingress(
    worker_id: usize,
    bind_addr: SocketAddr,
    buffer: WorkerBuffer,
    from: SocketAddr,
    bytes_read: usize,
) {
    let recv_info = RecvInfo {
        from,
        to: bind_addr,
    };

    trace!(
        worker_id,
        bytes = bytes_read,
        from = %recv_info.from,
        to = %recv_info.to,
        "Datagram received"
    );

    // TODO: Pass buffer and recv_info to QUIC protocol layer
    // All processing will happen on this same thread - no message passing!
    // This is where we'll integrate with Quiche for QUIC packet processing
    drop(buffer);
}
