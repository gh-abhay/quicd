//! HTTP Response Builder (Sans-IO)
//!
//! Efficient response building with minimal allocations.

use bytes::{BufMut, Bytes, BytesMut};

/// HTTP response builder
pub struct HttpResponse;

impl HttpResponse {
    /// Build a 200 OK JSON response
    ///
    /// This allocates once for the entire response.
    pub fn ok_json(path: &str) -> Bytes {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let json_body = format!(
            r#"{{"message":"Hello, World!","service":"superd-http3","path":"{}","timestamp":{}}}"#,
            path, timestamp
        );

        let mut buffer = BytesMut::with_capacity(256);

        // Write status line
        buffer.put_slice(b"HTTP/3 200 OK\r\n");

        // Write headers
        buffer.put_slice(b"content-type: application/json\r\n");
        buffer.put_slice(b"server: superd/1.0.0\r\n");

        // Content-Length header
        let content_length = format!("content-length: {}\r\n", json_body.len());
        buffer.put_slice(content_length.as_bytes());

        // End of headers
        buffer.put_slice(b"\r\n");

        // Body
        buffer.put_slice(json_body.as_bytes());

        buffer.freeze()
    }

    /// Build an error response
    pub fn error(status: u16, message: &str) -> Bytes {
        let json_body = format!(r#"{{"error":"{}"}}"#, message);

        let mut buffer = BytesMut::with_capacity(128);

        let status_text = Self::status_text(status);
        let status_line = format!("HTTP/3 {} {}\r\n", status, status_text);
        buffer.put_slice(status_line.as_bytes());

        buffer.put_slice(b"content-type: application/json\r\n");
        buffer.put_slice(b"server: superd/1.0.0\r\n");

        let content_length = format!("content-length: {}\r\n", json_body.len());
        buffer.put_slice(content_length.as_bytes());

        buffer.put_slice(b"\r\n");
        buffer.put_slice(json_body.as_bytes());

        buffer.freeze()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ok_json_response() {
        let response = HttpResponse::ok_json("/test");
        let response_str = String::from_utf8_lossy(&response);

        assert!(response_str.contains("HTTP/3 200 OK"));
        assert!(response_str.contains("content-type: application/json"));
        assert!(response_str.contains("Hello, World!"));
        assert!(response_str.contains("\"/test\""));
        assert!(response_str.contains("timestamp"));
    }

    #[test]
    fn test_error_response() {
        let response = HttpResponse::error(404, "Not Found");
        let response_str = String::from_utf8_lossy(&response);

        assert!(response_str.contains("HTTP/3 404 Not Found"));
        assert!(response_str.contains("error"));
    }

    #[test]
    fn test_response_format() {
        let response = HttpResponse::ok_json("/api");
        let response_str = String::from_utf8_lossy(&response);

        // Verify proper HTTP format
        let parts: Vec<&str> = response_str.split("\r\n\r\n").collect();
        assert_eq!(parts.len(), 2); // Headers and body separated
        assert!(parts[0].contains("HTTP/3"));
        assert!(parts[1].contains("{"));
    }
}
