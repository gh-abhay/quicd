use std::net::SocketAddr;
use tokio::net::UdpSocket;
use quic::{QuicEngine, QuicEvent, PacketIn};
use io::IoReactor;
use services::{ServiceRegistry, ServiceRequest, ServiceResponse, echo::EchoService, http3::Http3Service};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SuperdError {
    #[error("QUIC error: {0}")]
    Quic(#[from] quic::QuicError),
    #[error("I/O error: {0}")]
    Io(#[from] io::IoError),
    #[error("Service error: {0}")]
    Service(#[from] services::ServiceError),
    #[error("Std I/O error: {0}")]
    StdIo(#[from] std::io::Error),
    #[error("Other error: {0}")]
    Other(#[from] Box<dyn std::error::Error>),
}

pub type Result<T> = std::result::Result<T, SuperdError>;

/// Server configuration
#[derive(Debug)]
pub struct Config {
    pub listen_addr: SocketAddr,
}

/// Main server struct
pub struct Superd {
    io_reactor: IoReactor,
    quic_engine: QuicEngine,
    service_registry: ServiceRegistry,
}

impl Superd {
    pub async fn new(config: Config) -> Result<Self> {
        let socket = UdpSocket::bind(&config.listen_addr).await?;
        let local_addr = socket.local_addr()?;
        let io_reactor = IoReactor::new(socket, 64); // Max batch size
        let quic_engine = QuicEngine::new(local_addr)?;

        let mut service_registry = ServiceRegistry::new();
        service_registry.register("echo".to_string(), Box::new(EchoService::new()));
        service_registry.register("http3".to_string(), Box::new(Http3Service::new()));

        Ok(Self {
            io_reactor,
            quic_engine,
            service_registry,
        })
    }

    pub async fn run(mut self) -> Result<()> {
        loop {
            // Receive packets (batched)
            let packets_in = self.io_reactor.recv_packets().await?;
            if packets_in.is_empty() {
                // No packets, yield control
                tokio::task::yield_now().await;
                continue;
            }

            // Convert to QUIC packet format
            let quic_packets: Vec<PacketIn> = packets_in.into_iter().map(|p| PacketIn {
                data: p.data,
                from: p.from,
                to: p.to,
            }).collect();

            // Process with QUIC engine
            let events = self.quic_engine.process_packets(quic_packets)?;

            // Handle QUIC events and route to services
            for event in events {
                if let Some(response) = self.handle_quic_event(event)? {
                    self.send_response(response)?;
                }
            }

            // Get outgoing packets from QUIC engine
            let packets_out = self.quic_engine.get_outgoing_packets()?;

            // Convert to I/O packet format
            let io_packets: Vec<io::PacketOut> = packets_out.into_iter().map(|p| io::PacketOut {
                data: p.data,
                to: p.to,
            }).collect();

            // Send packets (batched)
            self.io_reactor.send_packets(io_packets).await?;
        }
    }

    fn handle_quic_event(&mut self, event: QuicEvent) -> Result<Option<ServiceResponse>> {
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

                Ok(self.service_registry.handle_request(service_name, req)?)
            }
            QuicEvent::Datagram { conn_id, data } => {
                // For demo, route datagrams to echo
                let req = ServiceRequest {
                    conn_id,
                    stream_id: 0, // dummy
                    data,
                    is_datagram: true,
                };

                Ok(self.service_registry.handle_request("echo", req)?)
            }
            QuicEvent::ConnectionClosed { conn_id } => {
                log::info!("Connection closed: {}", conn_id);
                Ok(None)
            }
        }
    }

    fn send_response(&mut self, response: ServiceResponse) -> Result<()> {
        if response.is_datagram {
            self.quic_engine.send_datagram(response.conn_id, &response.data)?;
        } else if let Some(stream_id) = response.stream_id {
            self.quic_engine.send_stream_data(response.conn_id, stream_id, &response.data, response.fin)?;
        }
        Ok(())
    }
}