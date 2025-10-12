//! Request processing task
//!
//! Handles QUIC protocol processing and event routing.
//! Core of the daemon's packet processing pipeline.

use std::sync::Arc;
use tokio::sync::mpsc;
use quic::{QuicEngine, QuicEvent, PacketIn as QuicPacketIn};
use io::{PacketIn as IoPacketIn, PacketOut as IoPacketOut};
use services::ServiceResponse;
use crate::{Metrics, Result, SuperdError};

/// Request processing task configuration
pub struct RequestProcessingTask {
    quic_engine: Arc<tokio::sync::Mutex<QuicEngine>>,
    metrics: Arc<Metrics>,
    packets_in_rx: mpsc::Receiver<IoPacketIn>,
    packets_out_tx: mpsc::Sender<IoPacketOut>,
    events_tx: mpsc::Sender<QuicEvent>,
    responses_rx: mpsc::Receiver<ServiceResponse>,
}

impl RequestProcessingTask {
    /// Create a new request processing task
    pub fn new(
        quic_engine: Arc<tokio::sync::Mutex<QuicEngine>>,
        metrics: Arc<Metrics>,
        packets_in_rx: mpsc::Receiver<IoPacketIn>,
        packets_out_tx: mpsc::Sender<IoPacketOut>,
        events_tx: mpsc::Sender<QuicEvent>,
        responses_rx: mpsc::Receiver<ServiceResponse>,
    ) -> Self {
        Self {
            quic_engine,
            metrics,
            packets_in_rx,
            packets_out_tx,
            events_tx,
            responses_rx,
        }
    }
    
    /// Run the request processing task
    ///
    /// This task continuously:
    /// 1. Receives packets from the network task
    /// 2. Processes them through the QUIC engine
    /// 3. Emits events to the service task
    /// 4. Receives responses from services
    /// 5. Sends QUIC responses back to the network
    ///
    /// All operations are non-blocking for minimum latency.
    pub async fn run(mut self) -> Result<()> {
        log::info!("Request processing task started");
        
        loop {
            tokio::select! {
                // Process incoming packet (single packet for low latency)
                Some(packet_in) = self.packets_in_rx.recv() => {
                    if let Err(e) = self.process_incoming_packet(packet_in).await {
                        log::error!("Failed to process incoming packet: {}", e);
                        self.metrics.record_error();
                        // Continue processing other packets
                    }
                }
                
                // Handle service responses
                Some(response) = self.responses_rx.recv() => {
                    if let Err(e) = self.process_service_response(response).await {
                        log::error!("Failed to process service response: {}", e);
                        self.metrics.record_error();
                        // Continue processing other responses
                    }
                }
                
                // If both channels are closed, exit gracefully
                else => {
                    log::info!("Request processing task shutting down gracefully");
                    return Ok(());
                }
            }
        }
    }
    
    /// Process an incoming packet from the network
    async fn process_incoming_packet(&mut self, packet_in: IoPacketIn) -> Result<()> {
        // Convert to QUIC packet format
        let quic_packet = QuicPacketIn {
            data: packet_in.data,
            from: packet_in.from,
            to: packet_in.to,
        };
        
        // Process with QUIC engine
        let events = {
            let mut engine = self.quic_engine.lock().await;
            engine.process_packet(quic_packet)
                .map_err(|e| SuperdError::Quic {
                    context: "Failed to process QUIC packet".to_string(),
                    source: e,
                })?
        };
        
        // Send events to service handling task immediately
        for event in events {
            self.events_tx.send(event).await
                .map_err(|e| SuperdError::Channel(
                    format!("Failed to send event to service task: {}", e)
                ))?;
        }
        
        // Check for outgoing packets and send immediately
        self.send_outgoing_packets().await?;
        
        Ok(())
    }
    
    /// Process a response from a service
    async fn process_service_response(&mut self, response: ServiceResponse) -> Result<()> {
        // Send response to QUIC engine
        {
            let mut engine = self.quic_engine.lock().await;
            if response.is_datagram {
                engine.send_datagram(response.conn_id, &response.data)
                    .map_err(|e| SuperdError::Quic {
                        context: format!("Failed to send datagram for connection {}", response.conn_id),
                        source: e,
                    })?;
            } else if let Some(stream_id) = response.stream_id {
                engine.send_stream_data(response.conn_id, stream_id, &response.data, response.fin)
                    .map_err(|e| SuperdError::Quic {
                        context: format!("Failed to send stream data for connection {}", response.conn_id),
                        source: e,
                    })?;
            }
        }
        
        // Immediately send any generated packets
        self.send_outgoing_packets().await?;
        
        Ok(())
    }
    
    /// Send all available outgoing packets
    async fn send_outgoing_packets(&mut self) -> Result<()> {
        loop {
            let packet_out = {
                let mut engine = self.quic_engine.lock().await;
                engine.get_next_outgoing_packet()
                    .map_err(|e| SuperdError::Quic {
                        context: "Failed to get outgoing packet".to_string(),
                        source: e,
                    })?
            };
            
            match packet_out {
                Some(packet) => {
                    // Convert to I/O packet format and send immediately
                    let io_packet = IoPacketOut {
                        data: packet.data,
                        to: packet.to,
                    };
                    
                    self.packets_out_tx.send(io_packet).await
                        .map_err(|e| SuperdError::Channel(
                            format!("Failed to send packet to network task: {}", e)
                        ))?;
                }
                None => break, // No more packets to send
            }
        }
        
        Ok(())
    }
}
