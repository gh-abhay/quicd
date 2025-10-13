//! QUIC to Service Integration
//!
//! This module bridges the QUIC protocol layer with the service layer,
//! handling:
//! - Stream data → Service request conversion
//! - Protocol detection and routing
//! - Service response → Stream data conversion
//! - Bidirectional data flow

use bytes::Bytes;
use quiche::Connection;
use service::{ServiceRegistry, ServiceRequest};
use std::sync::Arc;
use tracing::{debug, warn};

use crate::stream_mux::StreamMultiplexer;

/// QUIC stream processor
///
/// Handles the end-to-end flow:
/// 1. Read stream data from QUIC connection
/// 2. Detect protocol (ALPN or stream-type)
/// 3. Route to appropriate service
/// 4. Write service response back to QUIC stream
pub struct StreamProcessor {
    /// Stream multiplexer for protocol detection
    mux: Arc<StreamMultiplexer>,
    
    /// Service registry for request processing
    services: Arc<ServiceRegistry>,
}

impl StreamProcessor {
    /// Create a new stream processor
    pub fn new(mux: Arc<StreamMultiplexer>, services: Arc<ServiceRegistry>) -> Self {
        Self { mux, services }
    }
    
    /// Process a stream that has data ready to read
    ///
    /// This is called when quiche reports a stream is readable.
    /// 
    /// # Flow
    /// 1. Read stream data from connection
    /// 2. Detect protocol via ALPN/stream-type
    /// 3. Create ServiceRequest
    /// 4. Process via ServiceRegistry
    /// 5. Write ServiceResponse back to stream
    pub fn process_stream(
        &self,
        conn: &mut Connection,
        conn_id: u64,
        stream_id: u64,
    ) -> Result<(), String> {
        // Read stream data
        let mut buf = vec![0u8; 65536]; // 64KB buffer
        let (read, fin) = conn
            .stream_recv(stream_id, &mut buf)
            .map_err(|e| format!("Failed to read stream {}: {}", stream_id, e))?;
        
        if read == 0 {
            return Ok(());
        }
        
        let stream_data = Bytes::copy_from_slice(&buf[..read]);
        
        debug!(
            conn_id = conn_id,
            stream_id = stream_id,
            bytes = read,
            fin = fin,
            "Stream data received"
        );
        
        // Get ALPN for protocol detection
        let alpn = conn.application_proto();
        
        // Detect protocol and get routing info
        let route = self.mux.detect_protocol(alpn, &stream_data);
        
        debug!(
            conn_id = conn_id,
            stream_id = stream_id,
            service = route.service_name,
            data_offset = route.data_offset,
            "Protocol detected, routing to service"
        );
        
        // Extract actual payload (after protocol-type header if present)
        let payload = if route.data_offset > 0 {
            stream_data.slice(route.data_offset..)
        } else {
            stream_data
        };
        
        // Create service request
        let request = ServiceRequest {
            connection_id: conn_id,
            stream_id: Some(stream_id),
            data: payload,
            is_datagram: false,
            alpn: Some(Bytes::copy_from_slice(alpn)),
            protocol: Some(route.service_name.to_string()),
        };
        
        // Get service handler
        let service = self.services.get(route.service_name)
            .ok_or_else(|| format!("Service not found: {}", route.service_name))?;
        
        // Process request
        let response = service
            .process(request)
            .map_err(|e| format!("Service processing error: {}", e))?;
        
        debug!(
            conn_id = conn_id,
            stream_id = stream_id,
            response_bytes = response.data.len(),
            "Service processed request, sending response"
        );
        
        // Write response to stream
        conn.stream_send(stream_id, &response.data, response.close_stream)
            .map_err(|e| format!("Failed to send response: {}", e))?;
        
        // Close stream if requested
        if response.close_stream {
            conn.stream_shutdown(stream_id, quiche::Shutdown::Write, 0)
                .map_err(|e| format!("Failed to shutdown stream: {}", e))?;
        }
        
        Ok(())
    }
    
    /// Process a datagram
    ///
    /// Datagrams are unreliable messages that don't use streams.
    pub fn process_datagram(
        &self,
        conn: &mut Connection,
        conn_id: u64,
        data: Bytes,
    ) -> Result<(), String> {
        debug!(
            conn_id = conn_id,
            bytes = data.len(),
            "Datagram received"
        );
        
        // Get ALPN for protocol detection
        let alpn = conn.application_proto();
        
        // Detect protocol
        let route = self.mux.detect_protocol(alpn, &data);
        
        // Extract payload
        let payload = if route.data_offset > 0 {
            data.slice(route.data_offset..)
        } else {
            data
        };
        
        // Create service request
        let request = ServiceRequest {
            connection_id: conn_id,
            stream_id: None,
            data: payload,
            is_datagram: true,
            alpn: Some(Bytes::copy_from_slice(alpn)),
            protocol: Some(route.service_name.to_string()),
        };
        
        // Get service handler
        let service = self.services.get(route.service_name)
            .ok_or_else(|| format!("Service not found: {}", route.service_name))?;
        
        // Process request
        let response = service
            .process(request)
            .map_err(|e| format!("Service processing error: {}", e))?;
        
        // Send datagram response
        conn.dgram_send(&response.data)
            .map_err(|e| format!("Failed to send datagram: {}", e))?;
        
        Ok(())
    }
    
    /// Poll connection for readable streams and process them
    ///
    /// This should be called in the main event loop when the connection
    /// has data available.
    pub fn poll_connection(
        &self,
        conn: &mut Connection,
        conn_id: u64,
    ) -> Result<(), String> {
        // Process all readable streams
        for stream_id in conn.readable() {
            if let Err(e) = self.process_stream(conn, conn_id, stream_id) {
                warn!(
                    conn_id = conn_id,
                    stream_id = stream_id,
                    error = %e,
                    "Error processing stream"
                );
            }
        }
        
        // Process datagrams if available
        while let Some(len) = conn.dgram_recv_front_len() {
            if len > 0 {
                let mut buf = vec![0u8; len];
                match conn.dgram_recv(&mut buf) {
                    Ok(read) => {
                        let data = Bytes::copy_from_slice(&buf[..read]);
                        if let Err(e) = self.process_datagram(conn, conn_id, data) {
                            warn!(
                                conn_id = conn_id,
                                error = %e,
                                "Error processing datagram"
                            );
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to receive datagram");
                        break;
                    }
                }
            } else {
                break;
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use service::ServiceFactory;
    
    #[test]
    fn test_stream_processor_creation() {
        let mux = Arc::new(StreamMultiplexer::new());
        let services = Arc::new(ServiceRegistry::from_services(&[]));
        
        let _processor = StreamProcessor::new(mux, services);
    }
}
