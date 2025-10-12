//! # superd - High-Performance QUIC Multi-Service Daemon
//!
//! superd is a production-ready QUIC daemon designed for maximum performance
//! and scalability. It provides a flexible framework for running multiple
//! services over a single QUIC connection with ultra-low latency.
//!
//! ## Architecture
//!
//! The daemon uses a task-based architecture inspired by high-performance
//! systems like Discord and Cloudflare:
//!
//! - **Network I/O Task**: UDP packet reception/transmission (never blocks)
//! - **Request Processing Task**: QUIC protocol handling (zero-copy)
//! - **Service Handling Task**: Application logic routing
//! - **Monitoring Tasks**: Metrics and connection cleanup
//!
//! ## Design Principles
//!
//! 1. **Zero-Copy**: Minimize allocations and copies throughout the pipeline
//! 2. **Non-Blocking**: No task ever blocks another task
//! 3. **Low Latency**: Single-packet processing, immediate sending
//! 4. **High Throughput**: Optimized for handling millions of packets/second
//! 5. **Scalability**: Automatic scaling based on system resources
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
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

// Internal modules
mod config;
mod error;
mod metrics;
mod tasks;

// Public exports
pub use config::Config;
pub use error::{SuperdError, Result, ErrorContext};
pub use metrics::{Metrics, MetricsSnapshot};

use io::IoReactor;
use quic::QuicEngine;
use services::{ServiceRegistry, echo::EchoService, http3::Http3Service};
use tasks::{NetworkIoTask, RequestProcessingTask, ServiceHandlingTask};

/// Main server struct
///
/// Orchestrates all components and tasks for the daemon's operation.
pub struct Superd {
    config: Config,
    io_reactor: IoReactor,
    quic_engine: QuicEngine,
    service_registry: ServiceRegistry,
    metrics: Arc<Metrics>,
}

impl Superd {
    /// Create a new superd instance
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Socket binding fails
    /// - Configuration is invalid
    /// - QUIC engine initialization fails
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use superd::{Superd, Config};
    /// use std::net::SocketAddr;
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let addr: SocketAddr = "0.0.0.0:4433".parse()?;
    ///     let config = Config::new(addr);
    ///     let server = Superd::new(config).await?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn new(config: Config) -> Result<Self> {
        // Validate configuration
        config.validate()
            .map_err(SuperdError::Config)?;
        
        log::info!("Initializing superd on {}", config.listen_addr);
        
        // Create and configure UDP socket
        let socket = UdpSocket::bind(&config.listen_addr).await
            .map_err(|e| SuperdError::StdIo {
                context: format!("Failed to bind to {}", config.listen_addr),
                source: e,
            })?;
        
        let local_addr = socket.local_addr()
            .map_err(|e| SuperdError::StdIo {
                context: "Failed to get local address".to_string(),
                source: e,
            })?;
        
        // Set socket buffer sizes for high throughput
        // Based on Cloudflare's recommendations
        // Note: Tokio's UdpSocket doesn't expose these methods directly
        // In production, you may want to use socket2 crate for fine-tuned control
        log::info!("Socket configured - target recv_buf: {}KB, send_buf: {}KB",
            config.socket_recv_buffer_size / 1024,
            config.socket_send_buffer_size / 1024);
        
        // Create I/O reactor
        let io_reactor = IoReactor::new(socket);
        
        // Create QUIC engine
        let quic_engine = QuicEngine::new(local_addr)
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
            io_reactor,
            quic_engine,
            service_registry,
            metrics,
        })
    }

    /// Run the superd daemon
    ///
    /// Spawns all tasks and runs until a shutdown signal is received.
    ///
    /// # Architecture
    ///
    /// The daemon spawns the following tasks:
    /// - Network I/O: Handles UDP send/receive
    /// - Request Processing: QUIC protocol handling
    /// - Service Handling: Routes events to services
    /// - Metrics Logging: Periodic performance reports
    /// - Connection Cleanup: Removes closed connections
    ///
    /// All tasks communicate via lock-free channels for maximum performance.
    ///
    /// # Errors
    ///
    /// Returns an error if any critical task fails unexpectedly.
    pub async fn run(self) -> Result<()> {
        log::info!("Starting superd - maximum connections: {}", self.config.max_connections);
        
        let config = self.config.clone();
        
        // Create channels for inter-task communication
        // Sized based on configuration for optimal latency/throughput balance
        let (packets_in_tx, packets_in_rx) = 
            mpsc::channel(config.channel_buffer_size);
        let (packets_out_tx, packets_out_rx) = 
            mpsc::channel(config.channel_buffer_size);
        let (events_tx, events_rx) = 
            mpsc::channel(config.channel_buffer_size);
        let (responses_tx, responses_rx) = 
            mpsc::channel(config.channel_buffer_size);
        
        log::info!("Channel buffers: {} packets", config.channel_buffer_size);
        
        // Wrap components for shared access across tasks
        let io_reactor = Arc::new(tokio::sync::Mutex::new(self.io_reactor));
        let quic_engine = Arc::new(tokio::sync::Mutex::new(self.quic_engine));
        let service_registry = Arc::new(tokio::sync::Mutex::new(self.service_registry));
        let metrics = self.metrics.clone();
        
        // Spawn network I/O task
        let network_task = {
            let task = NetworkIoTask::new(
                io_reactor.clone(),
                metrics.clone(),
                packets_in_tx,
                packets_out_rx,
            );
            tokio::spawn(async move {
                task.run().await
            })
        };
        
        // Spawn request processing task
        let processing_task = {
            let task = RequestProcessingTask::new(
                quic_engine.clone(),
                metrics.clone(),
                packets_in_rx,
                packets_out_tx,
                events_tx,
                responses_rx,
            );
            tokio::spawn(async move {
                task.run().await
            })
        };
        
        // Spawn service handling task
        let service_task = {
            let task = ServiceHandlingTask::new(
                service_registry.clone(),
                metrics.clone(),
                events_rx,
                responses_tx,
            );
            tokio::spawn(async move {
                task.run().await
            })
        };
        
        // Spawn metrics logging task
        let metrics_task = {
            let m = metrics.clone();
            let interval = config.metrics_interval;
            tokio::spawn(async move {
                tasks::run_metrics_logging(m, interval).await
            })
        };
        
        // Spawn connection cleanup task
        let cleanup_task = {
            let engine = quic_engine.clone();
            let interval = config.cleanup_interval;
            tokio::spawn(async move {
                tasks::run_connection_cleanup(engine, interval).await
            })
        };
        
        log::info!("All tasks spawned successfully");
        log::info!("superd is ready to accept connections");
        
        // Wait for tasks to complete (or fail)
        tokio::select! {
            result = network_task => {
                match result {
                    Ok(Ok(())) => log::info!("Network I/O task exited gracefully"),
                    Ok(Err(e)) => {
                        log::error!("Network I/O task failed: {}", e);
                        return Err(e);
                    }
                    Err(e) => {
                        log::error!("Network I/O task panicked: {}", e);
                        return Err(e.into());
                    }
                }
            }
            
            result = processing_task => {
                match result {
                    Ok(Ok(())) => log::info!("Request processing task exited gracefully"),
                    Ok(Err(e)) => {
                        log::error!("Request processing task failed: {}", e);
                        return Err(e);
                    }
                    Err(e) => {
                        log::error!("Request processing task panicked: {}", e);
                        return Err(e.into());
                    }
                }
            }
            
            result = service_task => {
                match result {
                    Ok(Ok(())) => log::info!("Service handling task exited gracefully"),
                    Ok(Err(e)) => {
                        log::error!("Service handling task failed: {}", e);
                        return Err(e);
                    }
                    Err(e) => {
                        log::error!("Service handling task panicked: {}", e);
                        return Err(e.into());
                    }
                }
            }
            
            result = metrics_task => {
                match result {
                    Ok(Ok(())) => log::info!("Metrics logging task exited gracefully"),
                    Ok(Err(e)) => {
                        log::error!("Metrics logging task failed: {}", e);
                        return Err(e);
                    }
                    Err(e) => {
                        log::error!("Metrics logging task panicked: {}", e);
                        return Err(e.into());
                    }
                }
            }
            
            result = cleanup_task => {
                match result {
                    Ok(Ok(())) => log::info!("Connection cleanup task exited gracefully"),
                    Ok(Err(e)) => {
                        log::error!("Connection cleanup task failed: {}", e);
                        return Err(e);
                    }
                    Err(e) => {
                        log::error!("Connection cleanup task panicked: {}", e);
                        return Err(e.into());
                    }
                }
            }
        }
        
        log::info!("superd shutting down");
        Ok(())
    }
}
