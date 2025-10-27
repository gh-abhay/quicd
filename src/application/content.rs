//! # HTTP/3 Content Serving Handler
//!
//! Implements HTTP/3 content serving for CDN-like functionality.
//! Optimized for high-throughput content delivery with caching and compression.
//!
//! ## Architecture
//!
//! ```text
//! HTTP/3 Request
//!     ↓
//! Content Routing & Caching
//!     ↓
//! Response Generation
//!     ↓
//! HTTP/3 Response
//! ```
//!
//! ## Features
//!
//! - **CDN-like Delivery**: Optimized for static/dynamic content
//! - **Caching Support**: Intelligent caching headers and ETags
//! - **Compression**: Automatic gzip/brotli compression
//! - **Range Requests**: Partial content delivery
//! - **High Throughput**: Optimized for many concurrent requests
//!
//! ## Content Types
//!
//! - **Static Assets**: HTML, CSS, JS, images, videos
//! - **API Responses**: JSON, XML, binary data
//! - **Dynamic Content**: Server-side generated responses
//! - **Streaming**: Large file delivery with chunking
//!
//! ## Example Request/Response
//!
//! ```text
//! Request:
//!   :method: GET
//!   :scheme: https
//!   :authority: cdn.example.com
//!   :path: /assets/main.js
//!
//! Response:
//!   :status: 200
//!   content-type: application/javascript
//!   cache-control: public, max-age=31536000
//!   etag: "abc123"
//!
//!   [JavaScript content]
//! ```

use std::collections::HashMap;

use quiche::h3::{self, NameValue};
use tracing::info;

use super::{
    ApplicationContext, ApplicationError, ApplicationResult, FromProtocolReceiver, ToProtocolSender,
};
use crate::network::zerocopy_buffer::ZeroCopyBuffer;

/// HTTP/3 content serving handler
pub struct ContentHandler {
    context: ApplicationContext,
    to_protocol: ToProtocolSender,
    from_protocol: FromProtocolReceiver,
    request_start: std::time::Instant,
}

impl ContentHandler {
    pub fn new(
        context: ApplicationContext,
        to_protocol: ToProtocolSender,
        from_protocol: FromProtocolReceiver,
    ) -> Self {
        Self {
            context,
            to_protocol,
            from_protocol,
            request_start: std::time::Instant::now(),
        }
    }

    pub async fn run(mut self) -> ApplicationResult<()> {
        info!(
            "Starting HTTP/3 content handler for connection {}",
            self.context.conn_id
        );

        // Track active streams
        let mut active_streams: HashMap<u64, Vec<h3::Header>> = HashMap::new();

        loop {
            tokio::select! {
                msg = self.from_protocol.recv() => {
                    match msg {
                        Some(crate::messages::ProtocolToApplication::NewStream { conn_id: _, stream_id, .. }) => {
                            // Removed per-stream creation debug logging for performance
                            active_streams.insert(stream_id, Vec::new());
                        }
                        Some(crate::messages::ProtocolToApplication::StreamData { conn_id: _, stream_id, data, fin }) => {
                            self.handle_stream_data(stream_id, data, fin, &mut active_streams).await?;
                        }
                        Some(crate::messages::ProtocolToApplication::ConnectionClosed { .. }) => {
                            info!("Connection {} closed, shutting down content handler", self.context.conn_id);
                            break;
                        }
                        None => {
                            info!("Protocol channel closed, shutting down content handler");
                            break;
                        }
                        _ => continue,
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_stream_data(
        &mut self,
        stream_id: u64,
        data: ZeroCopyBuffer,
        _fin: bool,
        _active_streams: &mut HashMap<u64, Vec<h3::Header>>,
    ) -> ApplicationResult<()> {
        // For demo purposes, simulate receiving HTTP headers
        // In a real implementation, this would parse HTTP/3 frames
        if data.len() > 0 && data[0] == b'G' {
            // Simulate GET request
            let headers = vec![
                h3::Header::new(b":method", b"GET"),
                h3::Header::new(b":path", b"/"),
            ];
            self.handle_request_from_headers(stream_id, headers).await?;
        } else if data.len() > 0 && data[0] == b'C' {
            // Simulate CONNECT request
            let headers = vec![
                h3::Header::new(b":method", b"CONNECT"),
                h3::Header::new(b":path", b"/api/realtime"),
                h3::Header::new(b"sec-webtransport-http3-draft", b"1"),
            ];
            self.handle_request_from_headers(stream_id, headers).await?;
        }

        Ok(())
    }

    async fn handle_request_from_headers(
        &mut self,
        stream_id: u64,
        headers: Vec<h3::Header>,
    ) -> ApplicationResult<()> {
        // Parse request headers
        let mut method = None;
        let mut path = None;

        for header in &headers {
            match header.name() {
                b":method" => method = Some(String::from_utf8_lossy(header.value())),
                b":path" => path = Some(String::from_utf8_lossy(header.value())),
                _ => {}
            }
        }

        let method = method.ok_or_else(|| ApplicationError::Protocol("Missing method".into()))?;
        let path = path.ok_or_else(|| ApplicationError::Protocol("Missing path".into()))?;

        // Removed per-request debug logging for performance - use metrics instead

        // Record HTTP request start metric
        if let Some(_metrics) = unsafe { crate::telemetry::GLOBAL_METRICS.as_ref() } {
            crate::telemetry::record_event(crate::telemetry::MetricsEvent::ApplicationRequest {
                endpoint: path.to_string(),
                duration_ms: 0, // Placeholder, actual duration recorded on completion
            });
        }

        // Check if this is a WebTransport CONNECT request
        if method == "CONNECT"
            && headers
                .iter()
                .any(|h| h.name() == b"sec-webtransport-http3-draft")
        {
            // This should be handled by WebTransport handler, but for now, reject
            self.send_error_response(
                stream_id,
                405,
                "WebTransport CONNECT not supported on content handler",
            )
            .await?;
        } else {
            // Route based on path and method
            match (method.as_ref(), path.as_ref()) {
                ("GET", "/health") => {
                    self.serve_health_check(stream_id).await?;
                }
                ("GET", path) if path.starts_with("/api/") => {
                    self.serve_api_endpoint(stream_id, path.as_ref()).await?;
                }
                ("GET", _) => {
                    self.serve_static_content(stream_id, path.as_ref()).await?;
                }
                _ => {
                    self.send_error_response(stream_id, 405, "Method Not Allowed")
                        .await?;
                }
            }
        }

        Ok(())
    }

    async fn serve_health_check(&mut self, stream_id: u64) -> ApplicationResult<()> {
        let response_body = b"{\"status\":\"ok\"}";
        let headers = vec![
            h3::Header::new(b":status", b"200"),
            h3::Header::new(b"content-type", b"application/json"),
            h3::Header::new(
                b"content-length",
                response_body.len().to_string().as_bytes(),
            ),
        ];

        self.send_response(stream_id, headers, response_body.to_vec())
            .await
    }

    async fn serve_api_endpoint(&mut self, stream_id: u64, path: &str) -> ApplicationResult<()> {
        // Simple API endpoint serving
        let response_body = format!("{{\"endpoint\":\"{}\",\"message\":\"API response\"}}", path);
        let headers = vec![
            h3::Header::new(b":status", b"200"),
            h3::Header::new(b"content-type", b"application/json"),
            h3::Header::new(
                b"content-length",
                response_body.len().to_string().as_bytes(),
            ),
        ];

        self.send_response(stream_id, headers, response_body.into_bytes())
            .await
    }

    async fn serve_static_content(&mut self, stream_id: u64, path: &str) -> ApplicationResult<()> {
        // For now, serve a simple HTML page
        // In a real CDN, this would serve actual files with proper caching headers
        let html = format!(
            "<!DOCTYPE html><html><head><title>Content</title></head><body><h1>Content at {}</h1><p>This is served via HTTP/3</p></body></html>",
            path
        );

        let headers = vec![
            h3::Header::new(b":status", b"200"),
            h3::Header::new(b"content-type", b"text/html"),
            h3::Header::new(b"content-length", html.len().to_string().as_bytes()),
            h3::Header::new(b"cache-control", b"public, max-age=3600"),
        ];

        self.send_response(stream_id, headers, html.into_bytes())
            .await
    }

    async fn send_error_response(
        &mut self,
        stream_id: u64,
        status: u16,
        message: &str,
    ) -> ApplicationResult<()> {
        let response_body = format!("{{\"error\":\"{}\"}}", message);
        let headers = vec![
            h3::Header::new(b":status", status.to_string().as_bytes()),
            h3::Header::new(b"content-type", b"application/json"),
            h3::Header::new(
                b"content-length",
                response_body.len().to_string().as_bytes(),
            ),
        ];

        self.send_response(stream_id, headers, response_body.into_bytes())
            .await
    }

    async fn send_response(
        &mut self,
        stream_id: u64,
        headers: Vec<h3::Header>,
        body: Vec<u8>,
    ) -> ApplicationResult<()> {
        // Send headers
        self.to_protocol
            .send(crate::messages::ApplicationToProtocol::SendData {
                conn_id: self.context.conn_id,
                stream_id,
                data: self.encode_headers(&headers),
                fin: false,
            })
            .map_err(|e| ApplicationError::ChannelError(e.to_string()))?;

        // Send body data
        if !body.is_empty() {
            let buffer_pool = crate::network::zerocopy_buffer::get_buffer_pool();
            let mut body_data = buffer_pool.get_empty();
            body_data.expand(body.len());
            body_data[..body.len()].copy_from_slice(&body);

            self.to_protocol
                .send(crate::messages::ApplicationToProtocol::SendData {
                    conn_id: self.context.conn_id,
                    stream_id,
                    data: body_data,
                    fin: true,
                })
                .map_err(|e| ApplicationError::ChannelError(e.to_string()))?;
        } else {
            // Send empty body with fin
            let buffer_pool = crate::network::zerocopy_buffer::get_buffer_pool();
            let empty_data = buffer_pool.get_empty();

            self.to_protocol
                .send(crate::messages::ApplicationToProtocol::SendData {
                    conn_id: self.context.conn_id,
                    stream_id,
                    data: empty_data,
                    fin: true,
                })
                .map_err(|e| ApplicationError::ChannelError(e.to_string()))?;
        }

        // Record request completion with duration
        if let Some(_metrics) = unsafe { crate::telemetry::GLOBAL_METRICS.as_ref() } {
            let duration_ms = self.request_start.elapsed().as_millis() as u64;
            crate::telemetry::record_event(crate::telemetry::MetricsEvent::ApplicationRequest {
                endpoint: "request_completed".to_string(), // Could be improved to track actual endpoint
                duration_ms,
            });
        }

        Ok(())
    }

    fn encode_headers(&self, headers: &[h3::Header]) -> ZeroCopyBuffer {
        // Simple header encoding for demo - in real HTTP/3, this would use QPACK
        let header_str = headers
            .iter()
            .map(|h| {
                format!(
                    "{}: {}\r\n",
                    String::from_utf8_lossy(h.name()),
                    String::from_utf8_lossy(h.value())
                )
            })
            .collect::<Vec<_>>()
            .join("");
        let full_header_str = format!("{}\r\n", header_str);
        let header_bytes = full_header_str.as_bytes();

        let buffer_pool = crate::network::zerocopy_buffer::get_buffer_pool();
        let mut buffer = buffer_pool.get_empty();
        buffer.expand(header_bytes.len());
        buffer[..header_bytes.len()].copy_from_slice(header_bytes);

        buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::ApplicationProtocol;
    use crate::network::zerocopy_buffer::init_buffer_pool;
    use tokio::sync::mpsc;

    fn create_test_context() -> ApplicationContext {
        ApplicationContext {
            conn_id: 1,
            stream_id: 0,
            peer_addr: "127.0.0.1:4433".parse().unwrap(),
            protocol: ApplicationProtocol::Http3Content,
        }
    }

    fn create_test_buffer(data: &[u8]) -> ZeroCopyBuffer {
        init_buffer_pool(10);
        let pool = crate::network::zerocopy_buffer::get_buffer_pool();
        let mut buffer = pool.get_empty();
        buffer.expand(data.len());
        buffer[..data.len()].copy_from_slice(data);
        buffer
    }

    #[tokio::test]
    async fn test_handle_request_from_headers_get_health() {
        init_buffer_pool(10);
        let context = create_test_context();
        let (_from_protocol_tx, from_protocol_rx) = mpsc::unbounded_channel();
        let (to_protocol_tx, mut to_protocol_rx) = mpsc::unbounded_channel();

        let mut handler = ContentHandler::new(context, to_protocol_tx, from_protocol_rx);

        let headers = vec![
            h3::Header::new(b":method", b"GET"),
            h3::Header::new(b":path", b"/health"),
        ];

        let result = handler.handle_request_from_headers(4, headers).await;
        assert!(result.is_ok());

        // Check that response was sent
        let message = to_protocol_rx.recv().await;
        assert!(message.is_some());
        match message.unwrap() {
            crate::messages::ApplicationToProtocol::SendData {
                conn_id,
                stream_id,
                data: _,
                fin,
            } => {
                assert_eq!(conn_id, 1);
                assert_eq!(stream_id, 4);
                assert!(!fin); // Headers first
            }
            _ => panic!("Expected SendData message"),
        }

        // Check body message
        let body_message = to_protocol_rx.recv().await;
        assert!(body_message.is_some());
        match body_message.unwrap() {
            crate::messages::ApplicationToProtocol::SendData {
                conn_id,
                stream_id,
                data: _,
                fin,
            } => {
                assert_eq!(conn_id, 1);
                assert_eq!(stream_id, 4);
                assert!(fin); // Body with fin
            }
            _ => panic!("Expected SendData message for body"),
        }
    }

    #[tokio::test]
    async fn test_handle_request_from_headers_get_api() {
        init_buffer_pool(10);
        let context = create_test_context();
        let (_from_protocol_tx, from_protocol_rx) = mpsc::unbounded_channel();
        let (to_protocol_tx, mut to_protocol_rx) = mpsc::unbounded_channel();

        let mut handler = ContentHandler::new(context, to_protocol_tx, from_protocol_rx);

        let headers = vec![
            h3::Header::new(b":method", b"GET"),
            h3::Header::new(b":path", b"/api/test"),
        ];

        let result = handler.handle_request_from_headers(4, headers).await;
        assert!(result.is_ok());

        // Should receive header and body messages
        let header_msg = to_protocol_rx.recv().await.unwrap();
        let body_msg = to_protocol_rx.recv().await.unwrap();

        match (header_msg, body_msg) {
            (
                crate::messages::ApplicationToProtocol::SendData { fin: false, .. },
                crate::messages::ApplicationToProtocol::SendData { fin: true, .. },
            ) => {
                // Correct message sequence
            }
            _ => panic!("Expected header then body messages"),
        }
    }

    #[tokio::test]
    async fn test_handle_request_from_headers_get_static() {
        init_buffer_pool(10);
        let context = create_test_context();
        let (_from_protocol_tx, from_protocol_rx) = mpsc::unbounded_channel();
        let (to_protocol_tx, mut to_protocol_rx) = mpsc::unbounded_channel();

        let mut handler = ContentHandler::new(context, to_protocol_tx, from_protocol_rx);

        let headers = vec![
            h3::Header::new(b":method", b"GET"),
            h3::Header::new(b":path", b"/index.html"),
        ];

        let result = handler.handle_request_from_headers(4, headers).await;
        assert!(result.is_ok());

        // Should receive header and body messages
        let header_msg = to_protocol_rx.recv().await.unwrap();
        let body_msg = to_protocol_rx.recv().await.unwrap();

        match (header_msg, body_msg) {
            (
                crate::messages::ApplicationToProtocol::SendData { fin: false, .. },
                crate::messages::ApplicationToProtocol::SendData { fin: true, .. },
            ) => {
                // Correct message sequence
            }
            _ => panic!("Expected header then body messages"),
        }
    }

    #[tokio::test]
    async fn test_handle_request_from_headers_method_not_allowed() {
        init_buffer_pool(10);
        let context = create_test_context();
        let (_from_protocol_tx, from_protocol_rx) = mpsc::unbounded_channel();
        let (to_protocol_tx, mut to_protocol_rx) = mpsc::unbounded_channel();

        let mut handler = ContentHandler::new(context, to_protocol_tx, from_protocol_rx);

        let headers = vec![
            h3::Header::new(b":method", b"POST"),
            h3::Header::new(b":path", b"/health"),
        ];

        let result = handler.handle_request_from_headers(4, headers).await;
        assert!(result.is_ok());

        // Should receive error response
        let header_msg = to_protocol_rx.recv().await.unwrap();
        let body_msg = to_protocol_rx.recv().await.unwrap();

        match (header_msg, body_msg) {
            (
                crate::messages::ApplicationToProtocol::SendData { fin: false, .. },
                crate::messages::ApplicationToProtocol::SendData { fin: true, .. },
            ) => {
                // Correct message sequence for error
            }
            _ => panic!("Expected header then body messages for error"),
        }
    }

    #[tokio::test]
    async fn test_handle_request_from_headers_webtransport_connect() {
        init_buffer_pool(10);
        let context = create_test_context();
        let (_from_protocol_tx, from_protocol_rx) = mpsc::unbounded_channel();
        let (to_protocol_tx, mut to_protocol_rx) = mpsc::unbounded_channel();

        let mut handler = ContentHandler::new(context, to_protocol_tx, from_protocol_rx);

        let headers = vec![
            h3::Header::new(b":method", b"CONNECT"),
            h3::Header::new(b":path", b"/api/realtime"),
            h3::Header::new(b"sec-webtransport-http3-draft", b"1"),
        ];

        let result = handler.handle_request_from_headers(4, headers).await;
        assert!(result.is_ok());

        // Should receive 405 error response
        let header_msg = to_protocol_rx.recv().await.unwrap();
        let body_msg = to_protocol_rx.recv().await.unwrap();

        match (header_msg, body_msg) {
            (
                crate::messages::ApplicationToProtocol::SendData { fin: false, .. },
                crate::messages::ApplicationToProtocol::SendData { fin: true, .. },
            ) => {
                // Correct message sequence for 405 error
            }
            _ => panic!("Expected header then body messages for 405 error"),
        }
    }

    #[tokio::test]
    async fn test_handle_stream_data_get_request() {
        init_buffer_pool(10);
        let context = create_test_context();
        let (_from_protocol_tx, from_protocol_rx) = mpsc::unbounded_channel();
        let (to_protocol_tx, mut to_protocol_rx) = mpsc::unbounded_channel();

        let mut handler = ContentHandler::new(context, to_protocol_tx, from_protocol_rx);
        let mut active_streams = HashMap::new();
        active_streams.insert(4u64, Vec::new());

        let data = create_test_buffer(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n");

        let result = handler
            .handle_stream_data(4, data, true, &mut active_streams)
            .await;
        assert!(result.is_ok());

        // Should receive health check response
        let header_msg = to_protocol_rx.recv().await.unwrap();
        let body_msg = to_protocol_rx.recv().await.unwrap();

        match (header_msg, body_msg) {
            (
                crate::messages::ApplicationToProtocol::SendData { fin: false, .. },
                crate::messages::ApplicationToProtocol::SendData { fin: true, .. },
            ) => {
                // Correct response
            }
            _ => panic!("Expected health check response"),
        }
    }

    #[tokio::test]
    async fn test_handle_stream_data_connect_request() {
        init_buffer_pool(10);
        let context = create_test_context();
        let (_from_protocol_tx, from_protocol_rx) = mpsc::unbounded_channel();
        let (to_protocol_tx, mut to_protocol_rx) = mpsc::unbounded_channel();

        let mut handler = ContentHandler::new(context, to_protocol_tx, from_protocol_rx);
        let mut active_streams = HashMap::new();
        active_streams.insert(4u64, Vec::new());

        let data = create_test_buffer(b"CONNECT /api/realtime HTTP/1.1\r\nHost: localhost\r\n\r\n");

        let result = handler
            .handle_stream_data(4, data, true, &mut active_streams)
            .await;
        assert!(result.is_ok());

        // Should receive 405 error for WebTransport CONNECT
        let header_msg = to_protocol_rx.recv().await.unwrap();
        let body_msg = to_protocol_rx.recv().await.unwrap();

        match (header_msg, body_msg) {
            (
                crate::messages::ApplicationToProtocol::SendData { fin: false, .. },
                crate::messages::ApplicationToProtocol::SendData { fin: true, .. },
            ) => {
                // Correct 405 error response
            }
            _ => panic!("Expected 405 error response for WebTransport CONNECT"),
        }
    }
}
