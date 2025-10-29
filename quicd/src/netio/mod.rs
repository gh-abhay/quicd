pub mod config;
mod buffer;
mod socket;
mod worker;

pub use config::NetIoConfig;

use anyhow::Result;
use buffer::init_buffer_pool;
use std::net::SocketAddr;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tracing::{debug, error, info};
use worker::NetworkWorker;

/// Handle for managing network I/O workers.
///
/// Dropping this handle will signal workers to shut down.
pub struct NetIoHandle {
    workers: Vec<JoinHandle<()>>,
    shutdown_tx: broadcast::Sender<()>,
    worker_count: usize,
}

impl NetIoHandle {
    pub fn worker_count(&self) -> usize {
        self.worker_count
    }

    /// Signal all workers to shut down
    pub async fn shutdown(mut self) {
        info!("Shutting down network layer");
        let _ = self.shutdown_tx.send(());

        for (i, worker) in self.workers.drain(..).enumerate() {
            if let Err(e) = worker.await {
                error!(worker_id = i, error = ?e, "Worker task panicked");
            }
        }
    }
}

impl Drop for NetIoHandle {
    fn drop(&mut self) {
        debug!("NetIoHandle dropped, signaling shutdown");
        let _ = self.shutdown_tx.send(());
    }
}

/// Spawn network I/O workers as async tasks in the tokio-uring runtime.
///
/// # Architecture
///
/// - Global shared buffer pool for zero-copy operations
/// - N async worker tasks (not blocking threads)
/// - Each worker uses tokio::select! for event-driven I/O:
///   * Ingress: io_uring recv completions
///   * Egress: TODO - packets from protocol layer
///   * Shutdown: broadcast signal
/// - SO_REUSEPORT distributes ingress packets across workers
///
/// # Requirements
///
/// This function MUST be called from within a tokio-uring runtime context.
pub fn spawn(bind_addr: SocketAddr, config: NetIoConfig) -> Result<NetIoHandle> {
    if config.workers == 0 {
        anyhow::bail!("netio workers must be at least 1");
    }

    info!(
        workers = config.workers,
        addr = %bind_addr,
        "Initializing network layer"
    );

    // Initialize global shared buffer pool once
    init_buffer_pool(&config.buffer_pool);
    debug!(
        max_buffers = config.buffer_pool.max_buffers,
        buffer_size = config.buffer_pool.datagram_size,
        "Global buffer pool initialized"
    );

    // Create shutdown broadcast channel
    let (shutdown_tx, _) = broadcast::channel(1);

    let mut workers = Vec::with_capacity(config.workers);

    // Spawn N async worker tasks using tokio-uring spawn
    // since tokio-uring UdpSocket is !Send and must stay on the same runtime
    for worker_id in 0..config.workers {
        let shutdown_rx = shutdown_tx.subscribe();

        let worker = NetworkWorker::new(worker_id, bind_addr, &config, shutdown_rx)?;

        // Use tokio_uring::spawn for tasks that use io_uring
        let handle = tokio_uring::spawn(worker.run());
        workers.push(handle);
    }

    info!(workers = config.workers, "Network layer started");

    Ok(NetIoHandle {
        workers,
        shutdown_tx,
        worker_count: config.workers,
    })
}
