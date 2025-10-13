//! HTTP/3 Service
//!
//! A simple HTTP/3 service that always returns a "Hello, World!" JSON response
//! for all paths. This demonstrates HTTP/3 over QUIC streams.

use super::{Service, ServiceError, ServiceRequest, ServiceResponse, ServiceResult};
use async_trait::async_trait;
use bytes::Bytes;
use tracing::{debug, warn};

/// HTTP/3 service implementation
pub struct Http3Service;

impl Http3Service {
    /// Create a new HTTP/3 service
    pub fn new() -> Self {
        Self
    }

    /// Parse HTTP request line (simple parser for demo)
    fn parse_request(data: &[u8]) -> Option<(String, String)> {
        let request = String::from_utf8_lossy(data);
        let lines: Vec<&str> = request.lines().collect();

        if lines.is_empty() {
            return None;
        }

        let parts: Vec<&str> = lines[0].split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }

        Some((parts[0].to_string(), parts[1].to_string()))
    }

    /// Build HTTP/3 response
    fn build_response(status: u16, path: &str) -> Bytes {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let json_body = format!(
            r#"{{"message":"Hello, World!","service":"superd-http3","path":"{}","timestamp":{}}}"#,
            path, timestamp
        );

        let response = format!(
            "HTTP/3 {} {}\r\n\
             content-type: application/json\r\n\
             content-length: {}\r\n\
             server: superd/0.1.0\r\n\
             \r\n\
             {}",
            status,
            Self::status_text(status),
            json_body.len(),
            json_body
        );

        Bytes::from(response)
    }

    /// Get status text for HTTP status code
    fn status_text(status: u16) -> &'static str {
        match status {
            200 => "OK",
            400 => "Bad Request",
            404 => "Not Found",
            500 => "Internal Server Error",
            _ => "Unknown",
        }
    }
}

impl Default for Http3Service {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Service for Http3Service {
    fn name(&self) -> &str {
        "http3"
    }

    fn description(&self) -> &str {
        "HTTP/3 service that returns Hello World JSON for all paths"
    }

    async fn handle_request(&self, request: ServiceRequest) -> ServiceResult<ServiceResponse> {
        debug!(
            connection_id = request.connection_id,
            stream_id = ?request.stream_id,
            data_len = request.data.len(),
            is_datagram = request.is_datagram,
            "HTTP/3 service: received request"
        );

        // HTTP/3 should use streams, not datagrams
        if request.is_datagram {
            warn!("HTTP/3 received datagram, expected stream");
            return Err(ServiceError::InvalidRequest(
                "HTTP/3 requires stream, not datagram".to_string(),
            ));
        }

        // Parse the HTTP request
        let (method, path) = Self::parse_request(&request.data)
            .ok_or_else(|| ServiceError::InvalidRequest("Invalid HTTP request".to_string()))?;

        debug!(
            method = %method,
            path = %path,
            "HTTP/3 request parsed"
        );

        // For this demo, we always return 200 OK with Hello World JSON
        // regardless of the path
        let response_data = Self::build_response(200, &path);

        Ok(ServiceResponse {
            data: response_data,
            close_stream: true, // Close stream after response (HTTP/3 behavior)
        })
    }

    async fn on_connection_established(&self, connection_id: u64) -> ServiceResult<()> {
        debug!(connection_id, "HTTP/3 service: new connection");
        Ok(())
    }

    async fn on_connection_closed(&self, connection_id: u64) -> ServiceResult<()> {
        debug!(connection_id, "HTTP/3 service: connection closed");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_http3_service() {
        let service = Http3Service::new();

        let http_request = "GET /api/test HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let request = ServiceRequest {
            connection_id: 1,
            stream_id: Some(0),
            data: Bytes::from(http_request),
            is_datagram: false,
        };

        let response = service.handle_request(request).await.unwrap();

        // Verify response contains expected elements
        let response_str = String::from_utf8_lossy(&response.data);
        assert!(response_str.contains("HTTP/3 200 OK"));
        assert!(response_str.contains("Hello, World!"));
        assert!(response_str.contains("/api/test"));
        assert!(response_str.contains("application/json"));
        assert_eq!(response.close_stream, true);
    }

    #[tokio::test]
    async fn test_http3_invalid_datagram() {
        let service = Http3Service::new();

        let request = ServiceRequest {
            connection_id: 1,
            stream_id: None,
            data: Bytes::from("GET / HTTP/1.1\r\n\r\n"),
            is_datagram: true, // Wrong: HTTP/3 should use streams
        };

        let result = service.handle_request(request).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_request() {
        let request = b"GET /api/test HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let (method, path) = Http3Service::parse_request(request).unwrap();

        assert_eq!(method, "GET");
        assert_eq!(path, "/api/test");
    }

    #[test]
    fn test_build_response() {
        let response = Http3Service::build_response(200, "/test");
        let response_str = String::from_utf8_lossy(&response);

        assert!(response_str.contains("HTTP/3 200 OK"));
        assert!(response_str.contains("content-type: application/json"));
        assert!(response_str.contains("Hello, World!"));
        assert!(response_str.contains("\"/test\""));
    }
}
