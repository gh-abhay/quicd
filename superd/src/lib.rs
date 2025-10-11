use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};
use tokio::time::{Duration, Instant};
use quic::{QuicEngine, QuicEvent, PacketIn, QuicError};
use io::{IoReactor, PacketOut as IoPacketOut, PacketIn as IoPacketIn, IoError};
use services::{ServiceRegistry, ServiceRequest, ServiceResponse, echo::EchoService, http3::Http3Service, ServiceError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SuperdError {
    #[error("QUIC error: {0}")]
    Quic(#[from] QuicError),
    #[error("I/O error: {0}")]
    Io(#[from] IoError),
    #[error("Service error: {0}")]
    Service(#[from] ServiceError),
    #[error("Std I/O error: {0}")]
    StdIo(#[from] std::io::Error),
    #[error("Channel error: {0}")]
    Channel(String),
    #[error("Task join error: {0}")]
    TaskJoin(#[from] tokio::task::JoinError),
    #[error("Other error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, SuperdError>;

/// Basic performance metrics
#[derive(Debug, Default)]
pub struct Metrics {
    pub packets_received: u64,
    pub packets_sent: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub connections_accepted: u64,
    pub start_time: Option<Instant>,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            start_time: Some(Instant::now()),
            ..Default::default()
        }
    }

    pub fn throughput_mbps(&self) -> f64 {
        if let Some(start_time) = self.start_time {
            let elapsed = start_time.elapsed().as_secs_f64();
            if elapsed > 0.0 {
                (self.bytes_received as f64 + self.bytes_sent as f64) * 8.0 / 1_000_000.0 / elapsed
            } else {
                0.0
            }
        } else {
            0.0
        }
    }

    pub fn log_stats(&self) {
        log::info!(
            "Performance stats - Packets: {}/{} (rx/tx), Bytes: {}/{} (rx/tx), Connections: {}, Throughput: {:.2} Mbps",
            self.packets_received,
            self.packets_sent,
            self.bytes_received,
            self.bytes_sent,
            self.connections_accepted,
            self.throughput_mbps()
        );
    }
}

/// Server configuration
#[derive(Debug)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub num_network_threads: usize,
    pub num_processing_threads: usize,
    pub max_batch_size: usize,
}

/// Main server struct
pub struct Superd {
    config: Config,
    io_reactor: IoReactor,
    quic_engine: QuicEngine,
    service_registry: ServiceRegistry,
    metrics: Metrics,
}

impl Superd {
    pub async fn new(config: Config) -> Result<Self> {
        let socket = UdpSocket::bind(&config.listen_addr).await?;
        let local_addr = socket.local_addr()?;
        let io_reactor = IoReactor::new(socket);
        let quic_engine = QuicEngine::new(local_addr)?;

        let mut service_registry = ServiceRegistry::new();
        service_registry.register("echo".to_string(), Box::new(EchoService::new()));
        service_registry.register("http3".to_string(), Box::new(Http3Service::new()));

        Ok(Self {
            config,
            io_reactor,
            quic_engine,
            service_registry,
            metrics: Metrics::new(),
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