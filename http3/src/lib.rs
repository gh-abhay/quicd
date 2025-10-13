//! HTTP/3 Service
//!
//! Sans-IO HTTP/3 service that returns "Hello, World!" JSON for all paths.
//! Uses zero-copy parsing and response building where possible.

mod parser;
mod response;

use service::{ServiceError, ServiceHandler, ServiceRequest, ServiceResponse, ServiceResult};
use tracing::{debug, warn};

pub use parser::HttpRequest;
pub use response::HttpResponse;

/// HTTP/3 service handler
pub struct Http3Handler {
    // Could add state here if needed (Arc-wrapped for sharing)
}

impl Http3Handler {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for Http3Handler {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceHandler for Http3Handler {
    fn name(&self) -> &'static str {
        "http3"
    }

    fn description(&self) -> &'static str {
        "HTTP/3 service with JSON responses"
    }

    fn process(&self, request: ServiceRequest) -> ServiceResult<ServiceResponse> {
        debug!(
            connection_id = request.connection_id,
            stream_id = ?request.stream_id,
            data_len = request.data.len(),
            "HTTP/3: processing request"
        );

        // HTTP/3 requires streams, not datagrams
        if request.is_datagram {
            warn!("HTTP/3 received datagram, expected stream");
            return Err(ServiceError::InvalidRequest(
                "HTTP/3 requires stream-based transport".to_string(),
            ));
        }

        // Parse HTTP request (Sans-IO)
        let http_req = HttpRequest::parse(&request.data).map_err(|e| {
            ServiceError::InvalidRequest(format!("Failed to parse HTTP request: {}", e))
        })?;

        debug!(
            method = http_req.method,
            path = http_req.path,
            "HTTP/3 request parsed"
        );

        // Build response
        let response_data = HttpResponse::ok_json(http_req.path);

        Ok(ServiceResponse {
            data: response_data,
            close_stream: true,
        })
    }
}

/// Compile-time service factory for HTTP/3 service
pub const HTTP3_SERVICE: service::ServiceFactory = service::ServiceFactory {
    name: "http3",
    description: "HTTP/3 service with JSON responses",
    factory: || std::sync::Arc::new(Http3Handler::default()),
};

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn test_http3_handler() {
        let handler = Http3Handler::new();

        let http_request = "GET /api/test HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let request = ServiceRequest {
            connection_id: 1,
            stream_id: Some(0),
            data: Bytes::from(http_request),
            is_datagram: false,
        };

        let response = handler.process(request).unwrap();

        let response_str = String::from_utf8_lossy(&response.data);
        assert!(response_str.contains("HTTP/3 200 OK"));
        assert!(response_str.contains("Hello, World!"));
        assert!(response_str.contains("/api/test"));
        assert!(response.close_stream);
    }

    #[test]
    fn test_http3_rejects_datagram() {
        let handler = Http3Handler::new();

        let request = ServiceRequest {
            connection_id: 1,
            stream_id: None,
            data: Bytes::from("GET / HTTP/1.1\r\n\r\n"),
            is_datagram: true,
        };

        let result = handler.process(request);
        assert!(result.is_err());
    }
}