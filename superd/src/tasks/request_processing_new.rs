//! Request processing task (Application worker)
//!
//! Runs on multi-threaded Tokio runtime to handle QUIC protocol processing.
//! Bridges network threads (flume) with service tasks (tokio channels).
//!
//! Expert recommendation: "Use multi-threaded Tokio runtime for app logic
//! (encoding, forwarding, routing decisions)"

use std::sync::Arc;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use quic::{QuicEngine, QuicEvent, PacketIn as QuicPacketIn, PacketOut as QuicPacketOut};
use services::ServiceResponse;
use crate::{RxPacket, TxPacket, Metrics, Result, SuperdError};

/// Request processing task configuration
pub struct RequestProcessingTask {
    quic_engine: Arc<Mutex<QuicEngine>>,
    metrics: Arc<Metrics>,
    rx_rx: flume::Receiver<RxPacket>,
    tx_tx: flume::Sender<TxPacket>,
    events_tx: mpsc::Sender<QuicEvent>,
    responses_rx: mpsc::Receiver<ServiceResponse>,
}

impl RequestProcessingTask {
    /// Create a new request processing task
    pub fn new(
        quic_engine: Arc<Mutex<QuicEngine>>,
        metrics: Arc<Metrics>,
        rx_rx: flume::Receiver<RxPacket>,
        tx_tx: flume::Sender<TxPacket>,
        events_tx: mpsc::Sender<QuicEvent>,
        responses_rx: mpsc::Receiver<ServiceResponse>,
    ) -> Self {
        Self {
            quic_engine,
            metrics,
            rx_rx,
            tx_tx,
            events_tx,
            responses_rx,
        }
    }
    
    /// Run the request processing task with flume channels
    ///
    /// This task continuously:
    /// 1. Receives packets from network threads (via flume)
    /// 2. Processes them through the QUIC engine
    /// 3. Emits events to service tasks (via tokio mpsc)
    /// 4. Receives responses from services
    /// 5. Sends QUIC responses back to network threads (via flume)
    ///
    /// # Zero-Copy Flow
    ///
    /// ```text
    /// Network Thread → flume::Receiver<RxPacket> (Bytes clone)
    ///   → QUIC Engine processing
    ///   → flume::Sender<TxPacket> → Network Thread (Bytes clone)
    /// ```
    ///
    /// Each `Bytes::clone()` is cheap (just refcount bump).
    pub async fn run_with_flume(mut self) -> Result<()> {
        log::info!("Request processing task started (using flume channels)");
        
        loop {
            tokio::select! {
                // Process incoming packet from network threads
                rx_packet = self.rx_rx.recv_async() => {
                    match rx_packet {
                        Ok(packet) => {
                            if let Err(e) = self.process_incoming_packet(packet).await {
                                log::error!("Failed to process incoming packet: {}", e);
                                self.metrics.record_error();
                            }
                        }
                        Err(_) => {
                            // Network threads shut down
                            log::info!("Network threads disconnected, shutting down");
                            return Ok(());
                        }
                    }
                }
                
                // Handle service responses
                Some(response) = self.responses_rx.recv() => {
                    if let Err(e) = self.process_service_response(response).await {
                        log::error!("Failed to process service response: {}", e);
                        self.metrics.record_error();
                    }
                }
                
                // If service channel closed, exit
                else => {
                    log::info!("Request processing task shutting down gracefully");
                    return Ok(());
                }
            }
        }
    }
    
    /// Process an incoming packet from network threads
    ///
    /// # Zero-Copy
    ///
    /// The `packet.data` is a `Bytes` which is cheap to clone.
    /// We pass it to QUIC engine which may clone it again for
    /// retransmission buffers - all zero-copy.
    async fn process_incoming_packet(&mut self, packet: RxPacket) -> Result<()> {
        // Convert to QUIC packet format
        // Note: Bytes::clone() is cheap (refcount bump)
        let quic_packet = QuicPacketIn {
            data: packet.data,
            from: packet.from,
            to: packet.to,
        };
        
        // Process with QUIC engine
        let events = {
            // Using parking_lot for faster mutex
            let mut engine = self.quic_engine.lock();
            engine.process_packet(quic_packet)
                .map_err(|e| SuperdError::Quic {
                    context: "Failed to process QUIC packet".to_string(),
                    source: e,
                })?
        };
        
        // Forward events to service handler
        for event in events {
            if let Err(e) = self.events_tx.send(event).await {
                log::error!("Failed to send event to service handler: {}", e);
                self.metrics.record_error();
                return Err(SuperdError::Channel(
                    "Service handler disconnected".to_string()
                ));
            }
        }
        
        // Check for outgoing packets to send
        self.send_pending_packets().await?;
        
        Ok(())
    }
    
    /// Process a response from a service
    async fn process_service_response(&mut self, response: ServiceResponse) -> Result<()> {
        // Process response through QUIC engine
        {
            let mut engine = self.quic_engine.lock();
            engine.handle_service_response(response)
                .map_err(|e| SuperdError::Quic {
                    context: "Failed to handle service response".to_string(),
                    source: e,
                })?;
        }
        
        // Send any outgoing packets
        self.send_pending_packets().await?;
        
        Ok(())
    }
    
    /// Send any pending packets from QUIC engine to network threads
    ///
    /// # Zero-Copy
    ///
    /// Each packet's `data` field is a `Bytes` which is cheap to clone.
    /// Even if we send to multiple destinations (multicast), we just
    /// call `bytes.clone()` which bumps a refcount.
    async fn send_pending_packets(&mut self) -> Result<()> {
        let packets = {
            let mut engine = self.quic_engine.lock();
            engine.take_outgoing_packets()
                .map_err(|e| SuperdError::Quic {
                    context: "Failed to get outgoing packets".to_string(),
                    source: e,
                })?
        };
        
        for quic_packet in packets {
            // Convert to TX packet format
            let tx_packet = TxPacket {
                data: quic_packet.data,
                to: quic_packet.to,
            };
            
            // Try to send to network threads (non-blocking)
            // If channel is full, drop packet (UDP semantics)
            match self.tx_tx.try_send(tx_packet) {
                Ok(_) => {
                    // Packet sent successfully
                }
                Err(flume::TrySendError::Full(_)) => {
                    // Channel full - drop packet (backpressure)
                    log::warn!("TX channel full, dropping outgoing packet");
                    self.metrics.record_error();
                }
                Err(flume::TrySendError::Disconnected(_)) => {
                    // Network threads shut down
                    return Err(SuperdError::Channel(
                        "Network threads disconnected".to_string()
                    ));
                }
            }
        }
        
        Ok(())
    }
}
