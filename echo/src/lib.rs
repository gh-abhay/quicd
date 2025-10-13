//! Echo Service
//!
//! A zero-copy echo service that returns whatever data it receives.
//! Perfect for testing, debugging, and benchmarking.

use service::{ServiceHandler, ServiceRequest, ServiceResponse, ServiceResult};
use tracing::debug;

/// Echo service handler (zero-allocation)
pub struct EchoHandler;

impl Default for EchoHandler {
    fn default() -> Self {
        Self
    }
}

impl ServiceHandler for EchoHandler {
    fn name(&self) -> &'static str {
        "echo"
    }

    fn description(&self) -> &'static str {
        "Zero-copy echo service for testing and debugging"
    }

    fn process(&self, request: ServiceRequest) -> ServiceResult<ServiceResponse> {
        debug!(
            connection_id = request.connection_id,
            stream_id = ?request.stream_id,
            data_len = request.data.len(),
            is_datagram = request.is_datagram,
            "Echo: processing request"
        );

        // Zero-copy: just return the same Bytes reference
        Ok(ServiceResponse {
            data: request.data,
            close_stream: true,
        })
    }
}

/// Compile-time service factory for Echo service
pub const ECHO_SERVICE: service::ServiceFactory = service::ServiceFactory {
    name: "echo",
    description: "Zero-copy echo service for testing and debugging",
    factory: || std::sync::Arc::new(EchoHandler),
};

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn test_echo_handler() {
        let handler = EchoHandler;

        let request = ServiceRequest {
            connection_id: 1,
            stream_id: Some(0),
            data: Bytes::from("Hello, World!"),
            is_datagram: false,
            alpn: None,
            protocol: None,
        };

        let response = handler.process(request.clone()).unwrap();

        // Should be the exact same Bytes (zero-copy)
        assert_eq!(response.data, request.data);
        assert!(response.close_stream);
    }

    #[test]
    fn test_echo_zero_copy() {
        let handler = EchoHandler;

        let data = Bytes::from_static(b"test data");
        let ptr_before = data.as_ptr();

        let request = ServiceRequest {
            connection_id: 1,
            stream_id: Some(0),
            data: data.clone(),
            is_datagram: false,
            alpn: None,
            protocol: None,
        };

        let response = handler.process(request).unwrap();

        // Verify it's the same pointer (true zero-copy)
        assert_eq!(response.data.as_ptr(), ptr_before);
    }
}