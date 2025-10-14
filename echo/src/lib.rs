//! Echo Service
//!
//! A zero-copy echo service that returns whatever data it receives.
//! Perfect for testing, debugging, and benchmarking.

use service::{ServiceHandler, ServiceRequest, ServiceResponse, ServiceResult, ServiceFactory};
use std::sync::Arc;
use tracing::debug;

/// Echo service implementation
pub struct EchoService;

impl ServiceHandler for EchoService {
    fn name(&self) -> &'static str {
        "echo"
    }

    fn description(&self) -> &'static str {
        "A simple echo service for testing"
    }

    fn process(&self, request: ServiceRequest) -> ServiceResult<ServiceResponse> {
        debug!(
            connection_id = ?request.connection_id,
            stream_id = ?request.stream_id,
            data_len = request.data.len(),
            is_datagram = request.is_datagram,
            "EchoService: processing request"
        );

        // Echo the data back
        Ok(ServiceResponse {
            data: request.data,
            close_stream: true,
        })
    }
}

/// Compile-time factory for the echo service
pub const ECHO_SERVICE: ServiceFactory = ServiceFactory {
    name: "echo",
    description: "A simple echo service for testing",
    factory: || Arc::new(EchoService),
};

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn test_echo_service_process() {
        let service = EchoService;
        let request = ServiceRequest {
            connection_id: vec![1],
            stream_id: Some(4),
            data: Bytes::from("hello"),
            is_datagram: false,
            alpn: None,
            protocol: Some("echo".to_string()),
        };

        let response = service.process(request).unwrap();
        assert_eq!(response.data, Bytes::from("hello"));
        assert_eq!(response.close_stream, true);
    }

    #[test]
    fn test_echo_service_datagram() {
        let service = EchoService;
        let request = ServiceRequest {
            connection_id: vec![2],
            stream_id: None,
            data: Bytes::from("datagram"),
            is_datagram: true,
            alpn: None,
            protocol: Some("echo".to_string()),
        };

        let response = service.process(request).unwrap();
        assert_eq!(response.data, Bytes::from("datagram"));
    }
}