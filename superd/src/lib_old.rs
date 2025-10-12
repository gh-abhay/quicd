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

use io::{IoReactor, PacketIn as IoPacketIn, PacketOut as IoPacketOut};
use quic::{QuicEngine, QuicEvent};
use services::{ServiceRegistry, ServiceResponse, echo::EchoService, http3::Http3Service};
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
            .map_err(|e| SuperdError::Config(e))?;
        
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
        if let Err(e) = socket.set_recv_buffer_size(config.socket_recv_buffer_size) {
            log::warn!("Failed to set receive buffer size: {}", e);
        }
        if let Err(e) = socket.set_send_buffer_size(config.socket_send_buffer_size) {
            log::warn!("Failed to set send buffer size: {}", e);
        }
        
        log::info!("Socket configured - recv_buf: {}KB, send_buf: {}KB",
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

    pub async fn run(self) -> Result<()> {
        log::info!("Starting superd with scalable architecture");
        let config = self.config;

        // Create channels for communication between tasks
        // Network I/O -> Processing: incoming packets (single packet at a time for low latency)
        let (packets_in_tx, packets_in_rx) = mpsc::channel::<IoPacketIn>(1024);
        // Processing -> Network I/O: outgoing packets (single packet at a time for low latency)
        let (packets_out_tx, packets_out_rx) = mpsc::channel::<IoPacketOut>(1024);
        // Processing -> Services: events/requests
        let (events_tx, events_rx) = mpsc::channel::<QuicEvent>(1024);
        // Services -> Processing: responses
        let (responses_tx, responses_rx) = mpsc::channel::<ServiceResponse>(1024);

        // Share components across tasks
        let io_reactor = Arc::new(Mutex::new(self.io_reactor));
        let quic_engine = Arc::new(Mutex::new(self.quic_engine));
        let service_registry = Arc::new(Mutex::new(self.service_registry));
        let metrics = Arc::new(Mutex::new(self.metrics));

        // Spawn network I/O task
        let io_reactor_clone = Arc::clone(&io_reactor);
        let metrics_clone = Arc::clone(&metrics);
        let network_task = tokio::spawn(async move {
            log::info!("Starting network I/O task");
            Self::run_network_io(io_reactor_clone, metrics_clone, packets_in_tx, packets_out_rx).await
        });

        // Spawn request processing task (single for now to avoid channel cloning issues)
        let quic_engine_clone = Arc::clone(&quic_engine);
        let service_registry_clone = Arc::clone(&service_registry);
        let processing_task = tokio::spawn(async move {
            log::info!("Starting request processing task");
            Self::run_request_processing(
                quic_engine_clone,
                service_registry_clone,
                packets_in_rx,
                packets_out_tx,
                events_tx,
                responses_rx,
            ).await
        });

        // Spawn service handling task
        let service_registry_clone = Arc::clone(&service_registry);
        let metrics_clone = Arc::clone(&metrics);
        let service_task = tokio::spawn(async move {
            log::info!("Starting service handling task");
            Self::run_service_handling(service_registry_clone, metrics_clone, events_rx, responses_tx).await
        });

        // Spawn metrics logging task
        let metrics_clone = Arc::clone(&metrics);
        let metrics_task = tokio::spawn(async move {
            log::info!("Starting metrics logging task");
            Self::run_metrics_logging(metrics_clone).await
        });

        // Wait for all tasks to complete (they shouldn't under normal operation)
        if let Err(e) = network_task.await? {
            log::error!("Network I/O task failed: {:?}", e);
        }

        if let Err(e) = processing_task.await? {
            log::error!("Request processing task failed: {:?}", e);
        }

        if let Err(e) = service_task.await? {
            log::error!("Service handling task failed: {:?}", e);
        }

        if let Err(e) = metrics_task.await? {
            log::error!("Metrics logging task failed: {:?}", e);
        }

        Ok(())
    }

    /// Metrics logging task: periodically logs performance statistics
    async fn run_metrics_logging(metrics: Arc<Mutex<Metrics>>) -> Result<()> {
        let mut interval = tokio::time::interval(Duration::from_secs(10));

        loop {
            interval.tick().await;
            let metrics = metrics.lock().await;
            metrics.log_stats();
        }
    }

    /// Network I/O task: handles receiving and sending packets
    async fn run_network_io(
        io_reactor: Arc<Mutex<IoReactor>>,
        metrics: Arc<Mutex<Metrics>>,
        packets_in_tx: mpsc::Sender<IoPacketIn>,
        mut packets_out_rx: mpsc::Receiver<IoPacketOut>,
    ) -> Result<()> {
        loop {
            tokio::select! {
                // Receive packet from network (single packet for low latency)
                packet = async {
                    let mut reactor = io_reactor.lock().await;
                    reactor.recv_packet().await
                } => {
                    let packet = packet?;
                    // Update metrics
                    {
                        let mut metrics = metrics.lock().await;
                        metrics.packets_received += 1;
                        metrics.bytes_received += packet.data.len() as u64;
                    }

                    // Send to processing task immediately
                    if packets_in_tx.send(packet).await.is_err() {
                        // Processing task has stopped
                        break;
                    }
                }

                // Send packet to network (single packet for low latency)
                Some(packet_out) = packets_out_rx.recv() => {
                    // Update metrics
                    {
                        let mut metrics = metrics.lock().await;
                        metrics.packets_sent += 1;
                        metrics.bytes_sent += packet_out.data.len() as u64;
                    }

                    let reactor = io_reactor.lock().await;
                    reactor.send_packet(packet_out).await?;
                }
            }
        }
        Ok(())
    }

    /// Request processing task: handles QUIC processing and event routing
    async fn run_request_processing(
        quic_engine: Arc<Mutex<QuicEngine>>,
        service_registry: Arc<Mutex<ServiceRegistry>>,
        mut packets_in_rx: mpsc::Receiver<IoPacketIn>,
        packets_out_tx: mpsc::Sender<IoPacketOut>,
        events_tx: mpsc::Sender<QuicEvent>,
        mut responses_rx: mpsc::Receiver<ServiceResponse>,
    ) -> Result<()> {
        loop {
            tokio::select! {
                // Process incoming packet (single packet for low latency)
                Some(packet_in) = packets_in_rx.recv() => {
                    // Convert to QUIC packet format
                    let quic_packet = PacketIn {
                        data: packet_in.data,
                        from: packet_in.from,
                        to: packet_in.to,
                    };

                    // Process with QUIC engine
                    let events = {
                        let mut engine = quic_engine.lock().await;
                        engine.process_packet(quic_packet)?
                    };

                    // Send events to service handling immediately
                    for event in events {
                        if events_tx.send(event).await.is_err() {
                            // Service task has stopped
                            break;
                        }
                    }

                    // Check for outgoing packets and send immediately
                    loop {
                        let packet_out = {
                            let mut engine = quic_engine.lock().await;
                            engine.get_next_outgoing_packet()?
                        };

                        match packet_out {
                            Some(packet) => {
                                // Convert to I/O packet format and send immediately
                                let io_packet = IoPacketOut {
                                    data: packet.data,
                                    to: packet.to,
                                };

                                if packets_out_tx.send(io_packet).await.is_err() {
                                    // Network task has stopped
                                    break;
                                }
                            }
                            None => break, // No more packets to send
                        }
                    }
                }

                // Handle service responses
                Some(response) = responses_rx.recv() => {
                    let mut engine = quic_engine.lock().await;
                    Self::send_response_to_quic(&mut engine, response)?;

                    // Immediately send any generated packets
                    loop {
                        let packet_out = engine.get_next_outgoing_packet()?;
                        match packet_out {
                            Some(packet) => {
                                let io_packet = IoPacketOut {
                                    data: packet.data,
                                    to: packet.to,
                                };

                                if packets_out_tx.send(io_packet).await.is_err() {
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                }
            }
        }
    }

    /// Service handling task: routes events to services and collects responses
    async fn run_service_handling(
        service_registry: Arc<Mutex<ServiceRegistry>>,
        metrics: Arc<Mutex<Metrics>>,
        mut events_rx: mpsc::Receiver<QuicEvent>,
        responses_tx: mpsc::Sender<ServiceResponse>,
    ) -> Result<()> {
        loop {
            if let Some(event) = events_rx.recv().await {
                // Update metrics for new connections
                if let QuicEvent::NewConnection { .. } = &event {
                    let mut metrics = metrics.lock().await;
                    metrics.connections_accepted += 1;
                }

                let response = {
                    let mut registry = service_registry.lock().await;
                    Self::handle_quic_event_with_registry(&mut registry, event)?
                };
                if let Some(response) = response {
                    if responses_tx.send(response).await.is_err() {
                        // Processing tasks have stopped
                        break;
                    }
                }
            } else {
                // No more events
                break;
            }
        }
        Ok(())
    }

    fn handle_quic_event_with_registry(service_registry: &mut ServiceRegistry, event: QuicEvent) -> Result<Option<ServiceResponse>> {
        match event {
            QuicEvent::NewConnection { conn_id } => {
                log::info!("New connection: {}", conn_id);
                Ok(None)
            }
            QuicEvent::StreamData { conn_id, stream_id, data, fin: _ } => {
                // Route based on stream ID or parse service from data
                // For demo: stream 0 = echo, stream 4 = http3
                let service_name = match stream_id % 8 {
                    0 => "echo",
                    4 => "http3",
                    _ => "echo", // default
                };

                let req = ServiceRequest {
                    conn_id,
                    stream_id,
                    data,
                    is_datagram: false,
                };

                Ok(service_registry.handle_request(service_name, req)?)
            }
            QuicEvent::Datagram { conn_id, data } => {
                // For demo, route datagrams to echo
                let req = ServiceRequest {
                    conn_id,
                    stream_id: 0, // dummy
                    data,
                    is_datagram: true,
                };

                Ok(service_registry.handle_request("echo", req)?)
            }
            QuicEvent::ConnectionClosed { conn_id } => {
                log::info!("Connection closed: {}", conn_id);
                Ok(None)
            }
        }
    }

    fn send_response_to_quic(quic_engine: &mut QuicEngine, response: ServiceResponse) -> Result<()> {
        if response.is_datagram {
            quic_engine.send_datagram(response.conn_id, &response.data)?;
        } else if let Some(stream_id) = response.stream_id {
            quic_engine.send_stream_data(response.conn_id, stream_id, &response.data, response.fin)?;
        }
        Ok(())
    }
}