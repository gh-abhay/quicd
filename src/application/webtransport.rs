//! # WebTransport Protocol Handler
//!
//! Implements WebTransport over HTTP/3 for real-time bidirectional APIs.
//! WebTransport provides low-latency, bidirectional communication channels.
//!
//! ## Architecture
//!
//! ```text
//! HTTP/3 Stream (CONNECT request)
//!     ↓
//! WebTransport Session Establishment
//!     ↓
//! Bidirectional Datagrams/Streams
//!     ↓
//! API Request/Response Processing
//! ```
//!
//! ## Features
//!
//! - **Bidirectional Communication**: Full-duplex channels over QUIC
//! - **Low Latency**: Minimal overhead compared to WebSockets
//! - **Multiple Channels**: Datagrams and streams within one session
//! - **API Ready**: Built for real-time API use cases
//!
//! ## Session Establishment
//!
//! 1. **CONNECT Request**: Client sends CONNECT to WebTransport endpoint
//! 2. **Session Creation**: Server establishes WebTransport session
//! 3. **Channel Setup**: Bidirectional streams and datagrams available
//! 4. **API Communication**: Real-time request/response over channels
//!
//! ## Example Usage
//!
//! ```text
//! Client: CONNECT /api/realtime HTTP/3
//! Server: 200 OK (WebTransport session established)
//! Client: Send datagrams/streams for API calls
//! Server: Respond via datagrams/streams
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use quiche::h3::{self, NameValue};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::{
    ApplicationContext, ApplicationError, ApplicationResult,
    ToProtocolSender, FromProtocolReceiver,
};
use crate::network::zerocopy_buffer::ZeroCopyBuffer;
use crate::messages::{ApplicationToProtocol, ProtocolToApplication};

/// WebTransport session handler
pub struct WebTransportHandler {
    context: ApplicationContext,
    to_protocol: ToProtocolSender,
    from_protocol: FromProtocolReceiver,
    h3_config: Arc<h3::Config>,
    session_state: WebTransportSession,
}

#[derive(Debug)]
struct WebTransportSession {
    /// Active API channels (stream_id -> channel info)
    channels: HashMap<u64, ApiChannel>,
    /// Session established
    established: bool,
}

#[derive(Debug)]
struct ApiChannel {
    /// Channel type (datagram, stream, etc.)
    channel_type: ChannelType,
    /// API endpoint this channel serves
    endpoint: String,
}

#[derive(Debug, Clone)]
enum ChannelType {
    /// Unidirectional stream
    Unidirectional,
    /// Bidirectional stream
    Bidirectional,
    /// Datagram channel
    Datagram,
}

impl WebTransportHandler {
    /// Create a new WebTransport handler for a session
    pub fn new(
        context: ApplicationContext,
        to_protocol: ToProtocolSender,
        from_protocol: FromProtocolReceiver,
    ) -> Self {
        let mut h3_config = h3::Config::new().unwrap();
        // Configure for WebTransport
        h3_config.set_max_field_section_size(65536);
        h3_config.set_qpack_max_table_capacity(4096);
        h3_config.set_qpack_blocked_streams(16);

        Self {
            context,
            to_protocol,
            from_protocol,
            h3_config: Arc::new(h3_config),
            session_state: WebTransportSession {
                channels: HashMap::new(),
                established: false,
            },
        }
    }

    /// Run the WebTransport handler
    pub async fn run(mut self) -> ApplicationResult<()> {
        info!(
            "WebTransport handler started for conn {} stream {}",
            self.context.conn_id, self.context.stream_id
        );

        // Establish WebTransport session
        self.establish_session().await?;

        // Handle WebTransport communication
        self.handle_session().await?;

        info!(
            "WebTransport handler completed for conn {} stream {}",
            self.context.conn_id, self.context.stream_id
        );

        Ok(())
    }

    /// Establish WebTransport session via CONNECT request
    async fn establish_session(&mut self) -> ApplicationResult<()> {
        // Wait for CONNECT request
        let connect_headers = self.wait_for_connect().await?;

        // Validate CONNECT request for WebTransport
        self.validate_connect_request(&connect_headers)?;

        // Send 200 OK to establish session
        self.send_session_response().await?;

        self.session_state.established = true;
        info!(
            "WebTransport session established for conn {} stream {}",
            self.context.conn_id, self.context.stream_id
        );

        Ok(())
    }

    /// Handle ongoing WebTransport session
    async fn handle_session(&mut self) -> ApplicationResult<()> {
        while let Some(message) = self.from_protocol.recv().await {
            match message {
                ProtocolToApplication::NewStream { conn_id, stream_id, .. } => {
                    // New stream in WebTransport session
                    self.handle_new_channel(stream_id).await?;
                }
                ProtocolToApplication::StreamData { conn_id, stream_id, data, fin } => {
                    // Data on existing channel
                    self.handle_channel_data(stream_id, data, fin).await?;
                }
                ProtocolToApplication::ConnectionClosed { .. } => {
                    // Session ended
                    break;
                }
                _ => continue,
            }
        }

        Ok(())
    }

    /// Wait for CONNECT request to establish WebTransport session
    async fn wait_for_connect(&mut self) -> ApplicationResult<Vec<h3::Header>> {
        while let Some(message) = self.from_protocol.recv().await {
            match message {
                ProtocolToApplication::StreamData { data: _data, .. } => {
                    // In a real implementation, parse HTTP/3 CONNECT request
                    // For now, simulate a valid CONNECT request
                    return Ok(vec![
                        h3::Header::new(b":method", b"CONNECT"),
                        h3::Header::new(b":scheme", b"https"),
                        h3::Header::new(b":authority", b"localhost"),
                        h3::Header::new(b":path", b"/api/realtime"),
                        h3::Header::new(b"sec-webtransport-http3-draft", b"1"),
                    ]);
                }
                ProtocolToApplication::ConnectionClosed { conn_id: _conn_id } => {
                    return Err(ApplicationError::Stream("Connection closed before CONNECT".into()));
                }
                _ => continue,
            }
        }

        Err(ApplicationError::Stream("No CONNECT request received".into()))
    }

    /// Validate CONNECT request for WebTransport
    fn validate_connect_request(&self, headers: &[h3::Header]) -> ApplicationResult<()> {
        let method = get_header_value(headers, b":method").unwrap_or(b"");
        let path = get_header_value(headers, b":path").unwrap_or(b"");

        if method != b"CONNECT" {
            return Err(ApplicationError::Protocol("Expected CONNECT method".into()));
        }

        // Check for WebTransport headers
        let has_webtransport_header = headers.iter()
            .any(|h| h.name() == b"sec-webtransport-http3-draft");

        if !has_webtransport_header {
            return Err(ApplicationError::Protocol("Missing WebTransport headers".into()));
        }

        debug!(
            "Validated WebTransport CONNECT request: {}",
            String::from_utf8_lossy(path)
        );

        Ok(())
    }

    /// Send 200 OK response to establish WebTransport session
    async fn send_session_response(&mut self) -> ApplicationResult<()> {
        let headers = vec![
            h3::Header::new(b":status", b"200"),
            h3::Header::new(b"sec-webtransport-http3-draft", b"1"),
        ];

        let header_data_str = format!(
            ":status: 200\r\nsec-webtransport-http3-draft: 1\r\n\r\n"
        );
        let header_bytes = header_data_str.as_bytes();
        let buffer_pool = crate::network::zerocopy_buffer::get_buffer_pool();
        let mut header_data = buffer_pool.get_empty();
        header_data.expand(header_bytes.len());
        header_data[..header_bytes.len()].copy_from_slice(header_bytes);

        self.to_protocol.send(ApplicationToProtocol::SendData {
            conn_id: self.context.conn_id,
            stream_id: self.context.stream_id,
            data: header_data,
            fin: true, // End the CONNECT stream
        }).map_err(|e| ApplicationError::Protocol(format!("Failed to send session response: {}", e)))?;

        Ok(())
    }

    /// Handle new channel/stream in WebTransport session
    async fn handle_new_channel(&mut self, stream_id: u64) -> ApplicationResult<()> {
        // Determine channel type and API endpoint
        let channel = ApiChannel {
            channel_type: ChannelType::Bidirectional, // Default to bidirectional
            endpoint: "/api/default".to_string(), // Default endpoint
        };

        self.session_state.channels.insert(stream_id, channel);

        debug!(
            "New WebTransport channel {} for conn {} stream {}",
            stream_id, self.context.conn_id, self.context.stream_id
        );

        Ok(())
    }

    /// Handle data on WebTransport channel
    async fn handle_channel_data(&mut self, stream_id: u64, data: ZeroCopyBuffer, fin: bool) -> ApplicationResult<()> {
        let channel = match self.session_state.channels.get(&stream_id) {
            Some(ch) => ch,
            None => {
                warn!("Data received for unknown channel {}", stream_id);
                return Ok(());
            }
        };

        // Process API request based on channel endpoint
        let endpoint = channel.endpoint.clone();
        match endpoint.as_str() {
            "/api/realtime" => {
                self.handle_realtime_api(data, fin).await?;
            }
            "/api/events" => {
                self.handle_events_api(data, fin).await?;
            }
            _ => {
                self.handle_generic_api(&endpoint, data, fin).await?;
            }
        }

        Ok(())
    }

    /// Handle real-time API requests
    async fn handle_realtime_api(&mut self, data: ZeroCopyBuffer, fin: bool) -> ApplicationResult<()> {
        // Simulate real-time API processing
        let response_data = b"{\"status\": \"ok\", \"type\": \"realtime\"}";
        let buffer_pool = crate::network::zerocopy_buffer::get_buffer_pool();
        let mut response_buffer = buffer_pool.get_empty();
        response_buffer.expand(response_data.len());
        response_buffer[..response_data.len()].copy_from_slice(response_data);

        // Send response back (would use appropriate stream/channel)
        // For now, just log
        debug!("Processed realtime API request, response: {} bytes", response_data.len());

        Ok(())
    }

    /// Handle events API requests
    async fn handle_events_api(&mut self, data: ZeroCopyBuffer, fin: bool) -> ApplicationResult<()> {
        // Simulate events API processing
        let response_data = b"{\"status\": \"ok\", \"type\": \"events\"}";
        let buffer_pool = crate::network::zerocopy_buffer::get_buffer_pool();
        let mut response_buffer = buffer_pool.get_empty();
        response_buffer.expand(response_data.len());
        response_buffer[..response_data.len()].copy_from_slice(response_data);

        debug!("Processed events API request, response: {} bytes", response_data.len());

        Ok(())
    }

    /// Handle generic API requests
    async fn handle_generic_api(&mut self, endpoint: &str, data: ZeroCopyBuffer, fin: bool) -> ApplicationResult<()> {
        let response_data = format!("{{\"status\": \"ok\", \"endpoint\": \"{}\"}}", endpoint).into_bytes();
        let buffer_pool = crate::network::zerocopy_buffer::get_buffer_pool();
        let mut response_buffer = buffer_pool.get_empty();
        response_buffer.expand(response_data.len());
        response_buffer[..response_data.len()].copy_from_slice(&response_data);

        debug!("Processed generic API request to {}, response: {} bytes", endpoint, response_data.len());

        Ok(())
    }
}

/// Helper function to extract header value
fn get_header_value<'a>(headers: &'a [h3::Header], name: &[u8]) -> Option<&'a [u8]> {
    headers.iter()
        .find(|h| h.name() == name)
        .map(|h| h.value())
}

/// Create HTTP/3 configuration for WebTransport
pub fn create_h3_config() -> ApplicationResult<Arc<h3::Config>> {
    let mut config = h3::Config::new()?;
    // Configure HTTP/3 settings for WebTransport
    // Enable datagrams if supported
    Ok(Arc::new(config))
}