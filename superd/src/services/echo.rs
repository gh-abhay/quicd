//! Echo Service
//!
//! A simple echo service that returns whatever data it receives.
//! This is useful for testing and debugging the QUIC connection.

use super::{Service, ServiceRequest, ServiceResponse, ServiceResult};
use async_trait::async_trait;
use tracing::debug;

/// Echo service implementation
pub struct EchoService;

impl EchoService {
    /// Create a new echo service
    pub fn new() -> Self {
        Self
    }
}

impl Default for EchoService {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Service for EchoService {
    fn name(&self) -> &str {
        "echo"
    }

    fn description(&self) -> &str {
        "Simple echo service that returns received data unchanged"
    }

    async fn handle_request(&self, request: ServiceRequest) -> ServiceResult<ServiceResponse> {
        debug!(
            connection_id = request.connection_id,
            stream_id = ?request.stream_id,
            data_len = request.data.len(),
            is_datagram = request.is_datagram,
            "Echo service: received request"
        );

        // Simply echo back the data
        Ok(ServiceResponse {
            data: request.data,
            close_stream: true, // Close stream after echoing
        })
    }

    async fn on_connection_established(&self, connection_id: u64) -> ServiceResult<()> {
        debug!(connection_id, "Echo service: new connection");
        Ok(())
    }

    async fn on_connection_closed(&self, connection_id: u64) -> ServiceResult<()> {
        debug!(connection_id, "Echo service: connection closed");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[tokio::test]
    async fn test_echo_service() {
        let service = EchoService::new();

        let request = ServiceRequest {
            connection_id: 1,
            stream_id: Some(0),
            data: Bytes::from("Hello, World!"),
            is_datagram: false,
        };

        let response = service.handle_request(request.clone()).await.unwrap();

        assert_eq!(response.data, request.data);
        assert_eq!(response.close_stream, true);
    }
}
