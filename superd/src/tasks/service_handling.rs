//! Service handling task
//!
//! Routes QUIC events to application services and collects responses.
//! Services run independently without blocking each other.

use std::sync::Arc;
use tokio::sync::mpsc;
use quic::QuicEvent;
use services::{ServiceRegistry, ServiceRequest, ServiceResponse};
use bytes::Bytes;
use crate::{Metrics, Result, SuperdError};

/// Service handling task configuration
pub struct ServiceHandlingTask {
    service_registry: Arc<tokio::sync::Mutex<ServiceRegistry>>,
    metrics: Arc<Metrics>,
    events_rx: mpsc::Receiver<QuicEvent>,
    responses_tx: mpsc::Sender<ServiceResponse>,
}

impl ServiceHandlingTask {
    /// Create a new service handling task
    pub fn new(
        service_registry: Arc<tokio::sync::Mutex<ServiceRegistry>>,
        metrics: Arc<Metrics>,
        events_rx: mpsc::Receiver<QuicEvent>,
        responses_tx: mpsc::Sender<ServiceResponse>,
    ) -> Self {
        Self {
            service_registry,
            metrics,
            events_rx,
            responses_tx,
        }
    }
    
    /// Run the service handling task
    ///
    /// This task continuously:
    /// 1. Receives QUIC events from the processing task
    /// 2. Routes them to the appropriate service
    /// 3. Collects service responses
    /// 4. Sends responses back to the processing task
    ///
    /// Services are executed independently to prevent blocking.
    pub async fn run(mut self) -> Result<()> {
        log::info!("Service handling task started");
        
        loop {
            if let Some(event) = self.events_rx.recv().await {
                if let Err(e) = self.handle_event(event).await {
                    log::error!("Failed to handle event: {}", e);
                    self.metrics.record_error();
                    // Continue processing other events
                }
            } else {
                // No more events, exit gracefully
                log::info!("Service handling task shutting down gracefully");
                return Ok(());
            }
        }
    }
    
    /// Handle a single QUIC event
    async fn handle_event(&mut self, event: QuicEvent) -> Result<()> {
        match event {
            QuicEvent::NewConnection { conn_id } => {
                log::info!("New connection established: {}", conn_id);
                self.metrics.record_connection_accepted();
                Ok(())
            }
            
            QuicEvent::StreamData { conn_id, stream_id, data, fin } => {
                self.handle_stream_data(conn_id, stream_id, data, fin).await
            }
            
            QuicEvent::Datagram { conn_id, data } => {
                self.handle_datagram(conn_id, data).await
            }
            
            QuicEvent::ConnectionClosed { conn_id } => {
                log::info!("Connection closed: {}", conn_id);
                self.metrics.record_connection_closed();
                Ok(())
            }
        }
    }
    
    /// Handle stream data from a connection
    async fn handle_stream_data(
        &mut self,
        conn_id: u64,
        stream_id: u64,
        data: Bytes,
        _fin: bool,
    ) -> Result<()> {
        // Route based on stream ID
        // Stream 0 = echo service
        // Stream 4 = http3 service
        // This is a simple demo; production would use proper protocol parsing
        let service_name = match stream_id % 8 {
            0 => "echo",
            4 => "http3",
            _ => "echo", // default
        };
        
        let request = ServiceRequest {
            conn_id,
            stream_id,
            data,
            is_datagram: false,
        };
        
        let response = {
            let mut registry = self.service_registry.lock().await;
            registry.handle_request(service_name, request)
                .map_err(|e| SuperdError::Service {
                    context: format!("Service '{}' failed", service_name),
                    source: e,
                })?
        };
        
        if let Some(response) = response {
            self.responses_tx.send(response).await
                .map_err(|e| SuperdError::Channel(
                    format!("Failed to send response to processing task: {}", e)
                ))?;
        }
        
        Ok(())
    }
    
    /// Handle datagram from a connection
    async fn handle_datagram(&mut self, conn_id: u64, data: Bytes) -> Result<()> {
        // Route datagrams to echo service (for demo)
        let request = ServiceRequest {
            conn_id,
            stream_id: 0, // Datagrams don't have stream IDs
            data,
            is_datagram: true,
        };
        
        let response = {
            let mut registry = self.service_registry.lock().await;
            registry.handle_request("echo", request)
                .map_err(|e| SuperdError::Service {
                    context: "Echo service failed for datagram".to_string(),
                    source: e,
                })?
        };
        
        if let Some(response) = response {
            self.responses_tx.send(response).await
                .map_err(|e| SuperdError::Channel(
                    format!("Failed to send datagram response to processing task: {}", e)
                ))?;
        }
        
        Ok(())
    }
}
