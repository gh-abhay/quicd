//! Network I/O task
//!
//! Handles UDP packet reception and transmission with minimal latency.
//! Runs independently to never block request processing.

use std::sync::Arc;
use tokio::sync::mpsc;
use io::{IoReactor, PacketIn, PacketOut};
use crate::{Metrics, Result, SuperdError};

/// Network I/O task configuration
pub struct NetworkIoTask {
    io_reactor: Arc<tokio::sync::Mutex<IoReactor>>,
    metrics: Arc<Metrics>,
    packets_in_tx: mpsc::Sender<PacketIn>,
    packets_out_rx: mpsc::Receiver<PacketOut>,
}

impl NetworkIoTask {
    /// Create a new network I/O task
    pub fn new(
        io_reactor: Arc<tokio::sync::Mutex<IoReactor>>,
        metrics: Arc<Metrics>,
        packets_in_tx: mpsc::Sender<PacketIn>,
        packets_out_rx: mpsc::Receiver<PacketOut>,
    ) -> Self {
        Self {
            io_reactor,
            metrics,
            packets_in_tx,
            packets_out_rx,
        }
    }
    
    /// Run the network I/O task
    ///
    /// This task continuously:
    /// 1. Receives packets from the network
    /// 2. Sends packets to the processing task
    /// 3. Receives packets from the processing task
    /// 4. Sends packets to the network
    ///
    /// Never blocks on either receive or send operations.
    pub async fn run(mut self) -> Result<()> {
        log::info!("Network I/O task started");
        
        loop {
            tokio::select! {
                // Receive packet from network (single packet for low latency)
                packet_result = async {
                    let mut reactor = self.io_reactor.lock().await;
                    reactor.recv_packet().await
                } => {
                    match packet_result {
                        Ok(packet) => {
                            // Record metrics
                            self.metrics.record_packet_received(packet.data.len() as u64);
                            
                            // Forward to processing task
                            if let Err(e) = self.packets_in_tx.send(packet).await {
                                log::error!("Failed to forward packet to processing task: {}", e);
                                self.metrics.record_error();
                                // Processing task has stopped, we should stop too
                                return Err(SuperdError::Channel(
                                    "Processing task disconnected".to_string()
                                ));
                            }
                        }
                        Err(e) => {
                            log::error!("Failed to receive packet: {}", e);
                            self.metrics.record_error();
                            // Don't fail the task on receive errors, just continue
                        }
                    }
                }
                
                // Send packet to network (single packet for low latency)
                Some(packet) = self.packets_out_rx.recv() => {
                    // Record metrics
                    self.metrics.record_packet_sent(packet.data.len() as u64);
                    
                    // Send to network
                    let reactor = self.io_reactor.lock().await;
                    if let Err(e) = reactor.send_packet(packet).await {
                        log::error!("Failed to send packet: {}", e);
                        self.metrics.record_error();
                        // Don't fail the task on send errors, just continue
                    }
                }
                
                // If both channels are closed, exit gracefully
                else => {
                    log::info!("Network I/O task shutting down gracefully");
                    return Ok(());
                }
            }
        }
    }
}
