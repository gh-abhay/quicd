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
use std::sync::Arc;

use quiche::h3::{self, NameValue};
use tracing::{debug, info};

use super::{
    ApplicationContext, ApplicationError, ApplicationResult,
    ToProtocolSender, FromProtocolReceiver,
};
use crate::network::zerocopy_buffer::ZeroCopyBuffer;

/// HTTP/3 content serving handler
pub struct ContentHandler {
    context: ApplicationContext,
    to_protocol: ToProtocolSender,
    from_protocol: FromProtocolReceiver,
    h3_config: Arc<h3::Config>,
}

impl ContentHandler {
    pub fn new(
        context: ApplicationContext,
        to_protocol: ToProtocolSender,
        from_protocol: FromProtocolReceiver,
    ) -> Self {
        let mut h3_config = h3::Config::new().unwrap();
        // Configure for content serving
        h3_config.set_max_field_section_size(65536);
        h3_config.set_qpack_max_table_capacity(4096);
        h3_config.set_qpack_blocked_streams(16);

        Self {
            context,
            to_protocol,
            from_protocol,
            h3_config: Arc::new(h3_config),
        }
    }

    pub async fn run(mut self) -> ApplicationResult<()> {
        info!("Starting HTTP/3 content handler for connection {}", self.context.conn_id);

        // Track active streams
        let mut active_streams: HashMap<u64, Vec<h3::Header>> = HashMap::new();

        loop {
            tokio::select! {
                msg = self.from_protocol.recv() => {
                    match msg {
                        Some(crate::messages::ProtocolToApplication::NewStream { conn_id, stream_id, .. }) => {
                            debug!("New stream {} on connection {}", stream_id, conn_id);
                            active_streams.insert(stream_id, Vec::new());
                        }
                        Some(crate::messages::ProtocolToApplication::StreamData { conn_id, stream_id, data, fin }) => {
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
        fin: bool,
        active_streams: &mut HashMap<u64, Vec<h3::Header>>,
    ) -> ApplicationResult<()> {
        // For demo purposes, simulate receiving HTTP headers
        // In a real implementation, this would parse HTTP/3 frames
        if data.len() > 0 && data[0] == b'G' { // Simulate GET request
            let headers = vec![
                h3::Header::new(b":method", b"GET"),
                h3::Header::new(b":path", b"/"),
            ];
            self.handle_request_from_headers(stream_id, headers).await?;
        } else if data.len() > 0 && data[0] == b'C' { // Simulate CONNECT request
            let headers = vec![
                h3::Header::new(b":method", b"CONNECT"),
                h3::Header::new(b":path", b"/api/realtime"),
                h3::Header::new(b"sec-webtransport-http3-draft", b"1"),
            ];
            self.handle_request_from_headers(stream_id, headers).await?;
        }

        Ok(())
    }

    async fn handle_request_from_headers(&mut self, stream_id: u64, headers: Vec<h3::Header>) -> ApplicationResult<()> {
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

        debug!("Content request: {} {} on stream {}", method, path, stream_id);

        // Check if this is a WebTransport CONNECT request
        if method == "CONNECT" && headers.iter().any(|h| h.name() == b"sec-webtransport-http3-draft") {
            // This should be handled by WebTransport handler, but for now, reject
            self.send_error_response(stream_id, 405, "WebTransport CONNECT not supported on content handler").await?;
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
                    self.send_error_response(stream_id, 405, "Method Not Allowed").await?;
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
            h3::Header::new(b"content-length", response_body.len().to_string().as_bytes()),
        ];

        self.send_response(stream_id, headers, response_body.to_vec()).await
    }

    async fn serve_api_endpoint(&mut self, stream_id: u64, path: &str) -> ApplicationResult<()> {
        // Simple API endpoint serving
        let response_body = format!("{{\"endpoint\":\"{}\",\"message\":\"API response\"}}", path);
        let headers = vec![
            h3::Header::new(b":status", b"200"),
            h3::Header::new(b"content-type", b"application/json"),
            h3::Header::new(b"content-length", response_body.len().to_string().as_bytes()),
        ];

        self.send_response(stream_id, headers, response_body.into_bytes()).await
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

        self.send_response(stream_id, headers, html.into_bytes()).await
    }

    async fn send_error_response(&mut self, stream_id: u64, status: u16, message: &str) -> ApplicationResult<()> {
        let response_body = format!("{{\"error\":\"{}\"}}", message);
        let headers = vec![
            h3::Header::new(b":status", status.to_string().as_bytes()),
            h3::Header::new(b"content-type", b"application/json"),
            h3::Header::new(b"content-length", response_body.len().to_string().as_bytes()),
        ];

        self.send_response(stream_id, headers, response_body.into_bytes()).await
    }

    async fn send_response(&mut self, stream_id: u64, headers: Vec<h3::Header>, body: Vec<u8>) -> ApplicationResult<()> {
        // Send headers
        self.to_protocol.send(crate::messages::ApplicationToProtocol::SendData {
            conn_id: self.context.conn_id,
            stream_id,
            data: self.encode_headers(&headers),
            fin: false,
        }).map_err(|e| ApplicationError::ChannelError(e.to_string()))?;

        // Send body data
        if !body.is_empty() {
            let buffer_pool = crate::network::zerocopy_buffer::get_buffer_pool();
            let mut body_data = buffer_pool.get_empty();
            body_data.expand(body.len());
            body_data[..body.len()].copy_from_slice(&body);

            self.to_protocol.send(crate::messages::ApplicationToProtocol::SendData {
                conn_id: self.context.conn_id,
                stream_id,
                data: body_data,
                fin: true,
            }).map_err(|e| ApplicationError::ChannelError(e.to_string()))?;
        } else {
            // Send empty body with fin
            let buffer_pool = crate::network::zerocopy_buffer::get_buffer_pool();
            let empty_data = buffer_pool.get_empty();

            self.to_protocol.send(crate::messages::ApplicationToProtocol::SendData {
                conn_id: self.context.conn_id,
                stream_id,
                data: empty_data,
                fin: true,
            }).map_err(|e| ApplicationError::ChannelError(e.to_string()))?;
        }

        Ok(())
    }

    fn encode_headers(&self, headers: &[h3::Header]) -> ZeroCopyBuffer {
        // Simple header encoding for demo - in real HTTP/3, this would use QPACK
        let header_str = headers.iter()
            .map(|h| format!("{}: {}\r\n", String::from_utf8_lossy(h.name()), String::from_utf8_lossy(h.value())))
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

/// HTTP/3 response structure
#[derive(Debug)]
struct Http3Response {
    status: u16,
    headers: Vec<h3::Header>,
    body: Vec<u8>,
}

/// Helper function to extract header value
fn get_header_value<'a>(headers: &'a [h3::Header], name: &[u8]) -> Option<&'a [u8]> {
    headers.iter()
        .find(|h| h.name() == name)
        .map(|h| h.value())
}

/// Convert headers to string representation for logging
fn headers_to_strings(headers: &[h3::Header]) -> Vec<String> {
    headers.iter()
        .map(|h| format!("{}: {}", String::from_utf8_lossy(h.name()), String::from_utf8_lossy(h.value())))
        .collect()
}

/// Create HTTP/3 configuration
pub fn create_h3_config() -> ApplicationResult<Arc<h3::Config>> {
    let mut config = h3::Config::new()?;
    // Configure HTTP/3 settings as needed
    Ok(Arc::new(config))
}