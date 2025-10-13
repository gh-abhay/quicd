//! # superd - High-Performance QUIC Multi-Service Daemon
//!
//! superd is a production-ready QUIC daemon optimized for **ultra-low latency**
//! and **maximum throughput** based on expert recommendations from high-performance
//! networking systems.
//!
//! ## Architecture (Expert-Recommended)
//!
//! ### Network Layer (Dedicated OS Threads)
//! - **Dedicated OS threads** with single-threaded Tokio runtimes
//! - **SO_REUSEPORT** for kernel-level load balancing across cores
//! - **Lock-free buffer pools** for zero-allocation receives
//! - **Non-blocking sends** with backpressure via try_send
//!
//! ### Application Layer (Multi-threaded Tokio)
//! - **Worker thread pool** for QUIC processing
//! - **Zero-copy** message passing via flume channels
//! - **Bytes cloning** for multi-recipient forwarding
//!
//! ### Key Optimizations
//! 1. **Zero-copy buffers**: `BytesMut` → `.freeze()` → `Bytes`
//! 2. **Lock-free channels**: `flume` for sync/async bridging
//! 3. **Pinned network threads**: Dedicated OS threads reduce jitter
//! 4. **Buffer pooling**: Reuse `BytesMut` to avoid allocations
//!
//! ## Expert Recommendations Applied
//!
//! > "Run network IO pinned to dedicated OS threads with a single-threaded
//! > Tokio runtime for low and deterministic latency."
//!
//! > "Use BytesMut → .freeze() → Bytes and pass Bytes through bounded
//! > flume channels so transfers are zero-copy."
//!
//! > "Use SO_REUSEPORT + one socket per network thread so kernel spreads
//! > UDP load across threads."
//!
//! ## Example
//!
//! ```no_run
//! use superd::{Superd, Config};
//! use std::net::SocketAddr;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     env_logger::init();
//!     
//!     let addr: SocketAddr = "0.0.0.0:4433".parse()?;
//!     let config = Config::new(addr);
//!     
//!     let server = Superd::new(config).await?;
//!     server.run().await?;
//!     
//!     Ok(())
//! }
//! ```

use std::sync::Arc;
use std::thread;

// Internal modules
mod config;
mod error;
mod metrics;
mod tasks;
mod buffer_pool;
mod network_thread;

// Public exports
pub use config::Config;
pub use error::{SuperdError, Result, ErrorContext};
pub use metrics::{Metrics, MetricsSnapshot};
pub use buffer_pool::BufferPool;
pub use network_thread::{RxPacket, TxPacket, NetworkThreadConfig, spawn_network_thread};

use quic::QuicEngine;
use services::{ServiceRegistry, echo::EchoService, http3::Http3Service};
use tasks::{RequestProcessingTask, ServiceHandlingTask};

/// Main server struct
///
/// Orchestrates network threads (OS-level) and application workers (Tokio tasks).
pub struct Superd {
    config: Config,
    quic_engine: QuicEngine,
    service_registry: ServiceRegistry,
    metrics: Arc<Metrics>,
}

impl Superd {
    /// Create a new superd instance
    ///
    /// Initializes QUIC engine and service registry.
    /// Actual network threads are spawned in `run()`.
    pub async fn new(config: Config) -> Result<Self> {
        // Validate configuration
        config.validate()
            .map_err(SuperdError::Config)?;
        
        log::info!("Initializing superd on {}", config.listen_addr);
        log::info!("Network threads: {} (SO_REUSEPORT: {})", 
            config.network_threads, config.reuse_port);
        
        // Create QUIC engine
        let quic_engine = QuicEngine::new(config.listen_addr)
            .map_err(|e| SuperdError::Quic {
                context: "Failed to initialize QUIC engine".to_string(),
                source: e,
            })?;
        
        // Create service registry and register services
        let mut service_registry = ServiceRegistry::new();
        service_registry.register("echo".to_string(), Box::new(EchoService::new()));
        service_registry.register("http3".to_string(), Box::new(Http3Service::new()));
        
        log::info!("Registered services: echo, http3");
        
        // Create metrics collector
        let metrics = Metrics::new();
        
        Ok(Self {
            config,
            quic_engine,
            service_registry,
            metrics,
        })
    }

    /// Run the superd daemon
    ///
    /// # Architecture
    ///
    /// Spawns two types of execution contexts:
    ///
    /// ## Network Threads (OS-level)
    /// - Dedicated OS threads with single-threaded Tokio runtimes
    /// - Each thread binds its own socket with SO_REUSEPORT
    /// - Kernel load-balances UDP packets across threads
    /// - Minimal latency and deterministic behavior
    ///
    /// ## Application Workers (Tokio tasks)
    /// - Multi-threaded Tokio runtime for QUIC processing
    /// - Service handling and routing
    /// - Monitoring and cleanup tasks
    ///
    /// ## Data Flow
    /// ```text
    /// Network Threads (OS)          App Workers (Tokio)
    ///   ┌─────────┐
    ///   │ Thread 0├──┐
    ///   └─────────┘  │
    ///   ┌─────────┐  │   flume      ┌──────────────┐
    ///   │ Thread 1├──┼──────────────►│ QUIC Engine  │
    ///   └─────────┘  │   (bounded)  └──────┬───────┘
    ///   ┌─────────┐  │                     │
    ///   │ Thread N├──┘                     ▼
    ///   └─────────┘                  ┌────────────┐
    ///                                │  Services  │
    ///                                └────────────┘
    /// ```
    pub async fn run(self) -> Result<()> {
        let config = self.config.clone();
        
        log::info!("Starting superd with {} network threads", config.network_threads);
        log::info!("Max connections: {}", config.max_connections);
        log::info!("Channel buffer: {} packets", config.channel_buffer_size);
        
        // Create shared buffer pool for all network threads
        // Pool size = channel_buffer_size * network_threads
        let pool_size = config.channel_buffer_size * config.network_threads;
        let buffer_pool = BufferPool::with_capacity(pool_size, 65536);
        
        // Create channels for network <-> app communication
        // Using flume for efficient sync/async bridging
        let (rx_tx, rx_rx) = flume::bounded::<RxPacket>(config.channel_buffer_size);
        let (tx_tx, tx_rx) = flume::bounded::<TxPacket>(config.channel_buffer_size);
        
        log::info!("Using flume channels for zero-copy message passing");
        
        // Spawn dedicated network I/O threads
        let mut network_handles = Vec::new();
        for thread_id in 0..config.network_threads {
            let thread_config = NetworkThreadConfig {
                bind_addr: config.listen_addr,
                thread_id,
                reuse_port: config.reuse_port,
                recv_buffer_size: config.socket_recv_buffer_size,
                send_buffer_size: config.socket_send_buffer_size,
            };
            
            let handle = spawn_network_thread(
                thread_config,
                rx_tx.clone(),
                tx_rx.clone(),
                buffer_pool.clone(),
                self.metrics.clone(),
            );
            
            network_handles.push(handle);
        }
        
        log::info!("Spawned {} network I/O threads (pinned to OS threads)", 
            config.network_threads);
        
        // Drop our copies of the senders so threads can detect shutdown
        drop(rx_tx);
        drop(tx_rx);
        
        // Create channels for app workers (using tokio for async)
        let (events_tx, events_rx) = 
            tokio::sync::mpsc::channel(config.channel_buffer_size);
        let (responses_tx, responses_rx) = 
            tokio::sync::mpsc::channel(config.channel_buffer_size);
        
        // Wrap components for shared access
        let quic_engine = Arc::new(parking_lot::Mutex::new(self.quic_engine));
        let service_registry = Arc::new(parking_lot::Mutex::new(self.service_registry));
        
        // Spawn QUIC processing worker task
        let quic_task = {
            let engine = quic_engine.clone();
            let metrics = self.metrics.clone();
            tokio::spawn(async move {
                RequestProcessingTask::new(
                    engine,
                    metrics,
                    rx_rx,
                    tx_tx,
                    events_tx,
                    responses_rx,
                ).run_with_flume().await
            })
        };
        
        // Spawn service handling task
        let service_task = {
            let registry = service_registry.clone();
            let metrics = self.metrics.clone();
            tokio::spawn(async move {
                ServiceHandlingTask::new(
                    registry,
                    metrics,
                    events_rx,
                    responses_tx,
                ).run().await
            })
        };
        
        // Spawn monitoring tasks
        let metrics_task = {
            let metrics = self.metrics.clone();
            let interval = config.metrics_interval;
            tokio::spawn(async move {
                tasks::monitoring::run_metrics_logging(metrics, interval).await
            })
        };
        
        let cleanup_task = {
            let engine = quic_engine.clone();
            let metrics = self.metrics.clone();
            let interval = config.cleanup_interval;
            tokio::spawn(async move {
                tasks::monitoring::run_connection_cleanup(engine, metrics, interval).await
            })
        };
        
        log::info!("Application worker tasks spawned");
        log::info!("superd is ready - network threads receiving on {}", config.listen_addr);
        
        // Wait for tasks to complete
        tokio::select! {
            res = quic_task => {
                log::error!("QUIC processing task exited: {:?}", res);
            }
            res = service_task => {
                log::error!("Service handling task exited: {:?}", res);
            }
            res = metrics_task => {
                log::error!("Metrics task exited: {:?}", res);
            }
            res = cleanup_task => {
                log::error!("Cleanup task exited: {:?}", res);
            }
        }
        
        // Wait for network threads to finish
        log::info!("Waiting for network threads to shut down...");
        for (i, handle) in network_handles.into_iter().enumerate() {
            match handle.join() {
                Ok(Ok(_)) => log::info!("Network thread {} shut down cleanly", i),
                Ok(Err(e)) => log::error!("Network thread {} error: {}", i, e),
                Err(_) => log::error!("Network thread {} panicked", i),
            }
        }
        
        Ok(())
    }
}
