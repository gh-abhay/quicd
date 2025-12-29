//! hq-interop connection handling.
//!
//! Implements the HTTP/0.9 over QUIC protocol (hq-interop) as specified
//! in the QUIC interop test suite.

use async_trait::async_trait;
use bytes::Bytes;
use quicd_x::{ConnectionHandle, QuicdApplication};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn};

use crate::config::HqInteropConfig;
use crate::error::Result;
use crate::handler::{FileHandler, StaticFileHandler};

/// hq-interop application implementing QuicdApplication trait.
///
/// This handles HTTP/0.9-style requests over QUIC:
/// - Client sends: `GET /path\r\n`
/// - Server responds with raw file content (no headers, no frames)
#[derive(Clone)]
pub struct HqInteropApplication {
    config: Arc<HqInteropConfig>,
}

impl HqInteropApplication {
    /// Create a new hq-interop application with the given configuration.
    pub fn new(config: HqInteropConfig) -> Self {
        // Validate configuration
        let errors = config.validate();
        if !errors.is_empty() {
            panic!("Invalid hq-interop configuration: {}", errors.join(", "));
        }

        Self {
            config: Arc::new(config),
        }
    }

    /// Get the configuration.
    pub fn config(&self) -> &HqInteropConfig {
        &self.config
    }
}

#[async_trait]
impl QuicdApplication for HqInteropApplication {
    /// Handle a new hq-interop connection.
    ///
    /// This method runs as a single Tokio task for the entire connection lifetime.
    /// It MUST NOT spawn additional tasks or threads.
    async fn on_connection(&self, conn: ConnectionHandle) {
        info!("hq-interop connection established");

        // Create file handler
        let handler = StaticFileHandler::new(self.config.handler.clone());

        // Accept bidirectional streams (each stream is one request/response)
        loop {
            match conn.accept_bi_stream().await {
                Ok(mut stream) => {
                    let stream_id = stream.stream_id();
                    info!("hq-interop: Accepted request stream: {:?}", stream_id);

                    // Read request (plain text GET request)
                    let mut buf = vec![0u8; 4096];
                    match stream.read(&mut buf).await {
                        Ok(0) => {
                            info!("hq-interop: Stream closed immediately");
                            continue;
                        }
                        Ok(n) => {
                            info!("hq-interop: Read {} bytes from stream", n);

                            // Parse request path
                            let request_data = &buf[..n];
                            match parse_hq_request(request_data) {
                                Ok(path) => {
                                    info!("hq-interop: Request path: {}", path);

                                    // Handle request using file handler
                                    match handler.handle_request(&path).await {
                                        Ok(content) => {
                                            info!(
                                                "hq-interop: Sending {} bytes response",
                                                content.len()
                                            );

                                            // Send response (raw file content, no headers)
                                            if let Err(e) = stream.write_all(&content).await {
                                                warn!(
                                                    "hq-interop: Failed to write response: {}",
                                                    e
                                                );
                                            }

                                            // Close stream
                                            if let Err(e) = stream.shutdown().await {
                                                warn!(
                                                    "hq-interop: Failed to shutdown stream: {}",
                                                    e
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            warn!("hq-interop: Handler error: {}", e);
                                            // For hq-interop, just close the stream on error
                                            let _ = stream.shutdown().await;
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!("hq-interop: Failed to parse request: {}", e);
                                    // Close stream on parse error
                                    let _ = stream.shutdown().await;
                                }
                            }
                        }
                        Err(e) => {
                            warn!("hq-interop: Failed to read from stream: {}", e);
                        }
                    }
                }
                Err(e) => {
                    info!("hq-interop: accept_bi_stream ended: {:?}", e);
                    break;
                }
            }
        }

        info!("hq-interop connection closed");
    }
}

/// Parse hq-interop request format: `GET /path\r\n` or `GET /path\n`
///
/// Returns the requested path.
fn parse_hq_request(data: &[u8]) -> Result<String> {
    // Convert to UTF-8
    let request_str = std::str::from_utf8(data)
        .map_err(|e| crate::error::Error::InvalidRequest(format!("Invalid UTF-8: {}", e)))?;

    // Parse GET request
    let parts: Vec<&str> = request_str.split_whitespace().collect();

    if parts.len() < 2 {
        return Err(crate::error::Error::InvalidRequest(
            "Request must be: GET /path".to_string(),
        ));
    }

    if parts[0].to_uppercase() != "GET" {
        return Err(crate::error::Error::InvalidRequest(format!(
            "Only GET method supported, got: {}",
            parts[0]
        )));
    }

    let path = parts[1].trim();

    // Ensure path starts with /
    if !path.starts_with('/') {
        return Err(crate::error::Error::InvalidRequest(
            "Path must start with /".to_string(),
        ));
    }

    Ok(path.to_string())
}

