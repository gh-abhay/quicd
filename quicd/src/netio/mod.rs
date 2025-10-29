mod buffer;
pub mod config;
mod socket;
mod worker;

pub use config::NetIoConfig;

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use tracing::{debug, error, info};
use worker::NetworkWorker;

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
pub fn spawn(bind_addr: SocketAddr, config: NetIoConfig) -> Result<NetIoHandle> {
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
        let shutdown = Arc::clone(&shutdown);

        // Create worker (in main thread)
        let worker = NetworkWorker::new(worker_id, bind_addr, config, shutdown)?;

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
