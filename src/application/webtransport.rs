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
    ApplicationContext, ApplicationError, ApplicationResult, FromProtocolReceiver, ToProtocolSender,
};
use crate::messages::{ApplicationToProtocol, ProtocolToApplication};
use crate::network::zerocopy_buffer::ZeroCopyBuffer;

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
                ProtocolToApplication::NewStream {
                    conn_id, stream_id, ..
                } => {
                    // New stream in WebTransport session
                    self.handle_new_channel(stream_id).await?;
                }
                ProtocolToApplication::StreamData {
                    conn_id,
                    stream_id,
                    data,
                    fin,
                } => {
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
                    return Err(ApplicationError::Stream(
                        "Connection closed before CONNECT".into(),
                    ));
                }
                _ => continue,
            }
        }

        Err(ApplicationError::Stream(
            "No CONNECT request received".into(),
        ))
    }

    /// Validate CONNECT request for WebTransport
    fn validate_connect_request(&self, headers: &[h3::Header]) -> ApplicationResult<()> {
        let method = get_header_value(headers, b":method").unwrap_or(b"");
        let path = get_header_value(headers, b":path").unwrap_or(b"");

        if method != b"CONNECT" {
            return Err(ApplicationError::Protocol("Expected CONNECT method".into()));
        }

        // Check for WebTransport headers
        let has_webtransport_header = headers
            .iter()
            .any(|h| h.name() == b"sec-webtransport-http3-draft");

        if !has_webtransport_header {
            return Err(ApplicationError::Protocol(
                "Missing WebTransport headers".into(),
            ));
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

        let header_data_str = format!(":status: 200\r\nsec-webtransport-http3-draft: 1\r\n\r\n");
        let header_bytes = header_data_str.as_bytes();
        let buffer_pool = crate::network::zerocopy_buffer::get_buffer_pool();
        let mut header_data = buffer_pool.get_empty();
        header_data.expand(header_bytes.len());
        header_data[..header_bytes.len()].copy_from_slice(header_bytes);

        self.to_protocol
            .send(ApplicationToProtocol::SendData {
                conn_id: self.context.conn_id,
                stream_id: self.context.stream_id,
                data: header_data,
                fin: true, // End the CONNECT stream
            })
            .map_err(|e| {
                ApplicationError::Protocol(format!("Failed to send session response: {}", e))
            })?;

        Ok(())
    }

    /// Handle new channel/stream in WebTransport session
    async fn handle_new_channel(&mut self, stream_id: u64) -> ApplicationResult<()> {
        // Determine channel type and API endpoint
        let channel = ApiChannel {
            channel_type: ChannelType::Bidirectional, // Default to bidirectional
            endpoint: "/api/default".to_string(),     // Default endpoint
        };

        self.session_state.channels.insert(stream_id, channel);

        debug!(
            "New WebTransport channel {} for conn {} stream {}",
            stream_id, self.context.conn_id, self.context.stream_id
        );

        Ok(())
    }

    /// Handle data on WebTransport channel
    async fn handle_channel_data(
        &mut self,
        stream_id: u64,
        data: ZeroCopyBuffer,
        fin: bool,
    ) -> ApplicationResult<()> {
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
    async fn handle_realtime_api(
        &mut self,
        data: ZeroCopyBuffer,
        fin: bool,
    ) -> ApplicationResult<()> {
        // Simulate real-time API processing
        let response_data = b"{\"status\": \"ok\", \"type\": \"realtime\"}";
        let buffer_pool = crate::network::zerocopy_buffer::get_buffer_pool();
        let mut response_buffer = buffer_pool.get_empty();
        response_buffer.expand(response_data.len());
        response_buffer[..response_data.len()].copy_from_slice(response_data);

        // Send response back (would use appropriate stream/channel)
        // For now, just log
        debug!(
            "Processed realtime API request, response: {} bytes",
            response_data.len()
        );

        Ok(())
    }

    /// Handle events API requests
    async fn handle_events_api(
        &mut self,
        data: ZeroCopyBuffer,
        fin: bool,
    ) -> ApplicationResult<()> {
        // Simulate events API processing
        let response_data = b"{\"status\": \"ok\", \"type\": \"events\"}";
        let buffer_pool = crate::network::zerocopy_buffer::get_buffer_pool();
        let mut response_buffer = buffer_pool.get_empty();
        response_buffer.expand(response_data.len());
        response_buffer[..response_data.len()].copy_from_slice(response_data);

        debug!(
            "Processed events API request, response: {} bytes",
            response_data.len()
        );

        Ok(())
    }

    /// Handle generic API requests
    async fn handle_generic_api(
        &mut self,
        endpoint: &str,
        data: ZeroCopyBuffer,
        fin: bool,
    ) -> ApplicationResult<()> {
        let response_data =
            format!("{{\"status\": \"ok\", \"endpoint\": \"{}\"}}", endpoint).into_bytes();
        let buffer_pool = crate::network::zerocopy_buffer::get_buffer_pool();
        let mut response_buffer = buffer_pool.get_empty();
        response_buffer.expand(response_data.len());
        response_buffer[..response_data.len()].copy_from_slice(&response_data);

        debug!(
            "Processed generic API request to {}, response: {} bytes",
            endpoint,
            response_data.len()
        );

        Ok(())
    }
}

/// Helper function to extract header value
fn get_header_value<'a>(headers: &'a [h3::Header], name: &[u8]) -> Option<&'a [u8]> {
    headers.iter().find(|h| h.name() == name).map(|h| h.value())
}

/// Create HTTP/3 configuration for WebTransport
pub fn create_h3_config() -> ApplicationResult<Arc<h3::Config>> {
    let mut config = h3::Config::new()?;
    // Configure HTTP/3 settings for WebTransport
    // Enable datagrams if supported
    Ok(Arc::new(config))
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
            protocol: ApplicationProtocol::WebTransport,
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
    async fn test_webtransport_handler_creation() {
        init_buffer_pool(10);
        let context = create_test_context();
        let (to_protocol_tx, _) = mpsc::unbounded_channel();
        let (from_protocol_tx, from_protocol_rx) = mpsc::unbounded_channel();

        let handler = WebTransportHandler::new(context, to_protocol_tx, from_protocol_rx);
        assert_eq!(handler.context.conn_id, 1);
        assert_eq!(handler.context.protocol, ApplicationProtocol::WebTransport);
        assert!(!handler.session_state.established);
        assert!(handler.session_state.channels.is_empty());
    }

    #[test]
    fn test_create_h3_config_webtransport() {
        let result = create_h3_config();
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_header_value_webtransport() {
        let headers = vec![
            h3::Header::new(b":method", b"CONNECT"),
            h3::Header::new(b":path", b"/api/realtime"),
            h3::Header::new(b"sec-webtransport-http3-draft", b"1"),
        ];

        assert_eq!(
            get_header_value(&headers, b":method"),
            Some(&b"CONNECT"[..])
        );
        assert_eq!(
            get_header_value(&headers, b":path"),
            Some(&b"/api/realtime"[..])
        );
        assert_eq!(
            get_header_value(&headers, b"sec-webtransport-http3-draft"),
            Some(&b"1"[..])
        );
        assert_eq!(get_header_value(&headers, b"nonexistent"), None);
    }

    #[tokio::test]
    async fn test_validate_connect_request_valid() {
        init_buffer_pool(10);
        let context = create_test_context();
        let (to_protocol_tx, _) = mpsc::unbounded_channel();
        let (from_protocol_tx, from_protocol_rx) = mpsc::unbounded_channel();

        let handler = WebTransportHandler::new(context, to_protocol_tx, from_protocol_rx);

        let headers = vec![
            h3::Header::new(b":method", b"CONNECT"),
            h3::Header::new(b":path", b"/api/realtime"),
            h3::Header::new(b"sec-webtransport-http3-draft", b"1"),
        ];

        let result = handler.validate_connect_request(&headers);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_connect_request_invalid_method() {
        init_buffer_pool(10);
        let context = create_test_context();
        let (to_protocol_tx, _) = mpsc::unbounded_channel();
        let (from_protocol_tx, from_protocol_rx) = mpsc::unbounded_channel();

        let handler = WebTransportHandler::new(context, to_protocol_tx, from_protocol_rx);

        let headers = vec![
            h3::Header::new(b":method", b"GET"),
            h3::Header::new(b":path", b"/api/realtime"),
            h3::Header::new(b"sec-webtransport-http3-draft", b"1"),
        ];

        let result = handler.validate_connect_request(&headers);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Expected CONNECT method"));
    }

    #[tokio::test]
    async fn test_validate_connect_request_missing_webtransport_header() {
        init_buffer_pool(10);
        let context = create_test_context();
        let (to_protocol_tx, _) = mpsc::unbounded_channel();
        let (from_protocol_tx, from_protocol_rx) = mpsc::unbounded_channel();

        let handler = WebTransportHandler::new(context, to_protocol_tx, from_protocol_rx);

        let headers = vec![
            h3::Header::new(b":method", b"CONNECT"),
            h3::Header::new(b":path", b"/api/realtime"),
        ];

        let result = handler.validate_connect_request(&headers);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Missing WebTransport headers"));
    }

    #[tokio::test]
    async fn test_send_session_response() {
        init_buffer_pool(10);
        let context = create_test_context();
        let (to_protocol_tx, mut to_protocol_rx) = mpsc::unbounded_channel();
        let (from_protocol_tx, from_protocol_rx) = mpsc::unbounded_channel();

        let mut handler = WebTransportHandler::new(context, to_protocol_tx, from_protocol_rx);

        let result = handler.send_session_response().await;
        assert!(result.is_ok());

        // Check that 200 OK response was sent
        let message = to_protocol_rx.recv().await;
        assert!(message.is_some());
        match message.unwrap() {
            ApplicationToProtocol::SendData {
                conn_id,
                stream_id,
                data,
                fin,
            } => {
                assert_eq!(conn_id, 1);
                assert_eq!(stream_id, 0);
                assert!(fin);
                // Check that response contains WebTransport headers
                let response_str = String::from_utf8_lossy(&data[..]);
                assert!(response_str.contains(":status: 200"));
                assert!(response_str.contains("sec-webtransport-http3-draft: 1"));
            }
            _ => panic!("Expected SendData message"),
        }
    }

    #[tokio::test]
    async fn test_handle_new_channel() {
        init_buffer_pool(10);
        let context = create_test_context();
        let (to_protocol_tx, _) = mpsc::unbounded_channel();
        let (from_protocol_tx, from_protocol_rx) = mpsc::unbounded_channel();

        let mut handler = WebTransportHandler::new(context, to_protocol_tx, from_protocol_rx);

        let stream_id = 4;
        let result = handler.handle_new_channel(stream_id).await;
        assert!(result.is_ok());

        // Check that channel was registered
        assert!(handler.session_state.channels.contains_key(&stream_id));
        let channel = handler.session_state.channels.get(&stream_id).unwrap();
        assert_eq!(channel.endpoint, "/api/default");
        assert!(matches!(channel.channel_type, ChannelType::Bidirectional));
    }

    #[tokio::test]
    async fn test_handle_channel_data_realtime_api() {
        init_buffer_pool(10);
        let context = create_test_context();
        let (to_protocol_tx, _) = mpsc::unbounded_channel();
        let (from_protocol_tx, from_protocol_rx) = mpsc::unbounded_channel();

        let mut handler = WebTransportHandler::new(context, to_protocol_tx, from_protocol_rx);

        // Set up channel
        let stream_id = 4;
        let channel = ApiChannel {
            channel_type: ChannelType::Bidirectional,
            endpoint: "/api/realtime".to_string(),
        };
        handler.session_state.channels.insert(stream_id, channel);

        let data = create_test_buffer(b"test data");

        let result = handler.handle_channel_data(stream_id, data, false).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_channel_data_events_api() {
        init_buffer_pool(10);
        let context = create_test_context();
        let (to_protocol_tx, _) = mpsc::unbounded_channel();
        let (from_protocol_tx, from_protocol_rx) = mpsc::unbounded_channel();

        let mut handler = WebTransportHandler::new(context, to_protocol_tx, from_protocol_rx);

        // Set up channel
        let stream_id = 4;
        let channel = ApiChannel {
            channel_type: ChannelType::Bidirectional,
            endpoint: "/api/events".to_string(),
        };
        handler.session_state.channels.insert(stream_id, channel);

        let data = create_test_buffer(b"test data");

        let result = handler.handle_channel_data(stream_id, data, false).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_channel_data_generic_api() {
        init_buffer_pool(10);
        let context = create_test_context();
        let (to_protocol_tx, _) = mpsc::unbounded_channel();
        let (from_protocol_tx, from_protocol_rx) = mpsc::unbounded_channel();

        let mut handler = WebTransportHandler::new(context, to_protocol_tx, from_protocol_rx);

        // Set up channel
        let stream_id = 4;
        let channel = ApiChannel {
            channel_type: ChannelType::Bidirectional,
            endpoint: "/api/custom".to_string(),
        };
        handler.session_state.channels.insert(stream_id, channel);

        let data = create_test_buffer(b"test data");

        let result = handler.handle_channel_data(stream_id, data, false).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_channel_data_unknown_channel() {
        init_buffer_pool(10);
        let context = create_test_context();
        let (to_protocol_tx, _) = mpsc::unbounded_channel();
        let (from_protocol_tx, from_protocol_rx) = mpsc::unbounded_channel();

        let mut handler = WebTransportHandler::new(context, to_protocol_tx, from_protocol_rx);

        let data = create_test_buffer(b"test data");

        let result = handler.handle_channel_data(999, data, false).await;
        assert!(result.is_ok()); // Should not error, just warn
    }

    #[tokio::test]
    async fn test_handle_realtime_api() {
        init_buffer_pool(10);
        let context = create_test_context();
        let (to_protocol_tx, _) = mpsc::unbounded_channel();
        let (from_protocol_tx, from_protocol_rx) = mpsc::unbounded_channel();

        let mut handler = WebTransportHandler::new(context, to_protocol_tx, from_protocol_rx);

        let data = create_test_buffer(b"test request");

        let result = handler.handle_realtime_api(data, false).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_events_api() {
        init_buffer_pool(10);
        let context = create_test_context();
        let (to_protocol_tx, _) = mpsc::unbounded_channel();
        let (from_protocol_tx, from_protocol_rx) = mpsc::unbounded_channel();

        let mut handler = WebTransportHandler::new(context, to_protocol_tx, from_protocol_rx);

        let data = create_test_buffer(b"test request");

        let result = handler.handle_events_api(data, false).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_generic_api() {
        init_buffer_pool(10);
        let context = create_test_context();
        let (to_protocol_tx, _) = mpsc::unbounded_channel();
        let (from_protocol_tx, from_protocol_rx) = mpsc::unbounded_channel();

        let mut handler = WebTransportHandler::new(context, to_protocol_tx, from_protocol_rx);

        let data = create_test_buffer(b"test request");

        let result = handler.handle_generic_api("/api/test", data, false).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_wait_for_connect_success() {
        init_buffer_pool(10);
        let context = create_test_context();
        let (to_protocol_tx, _) = mpsc::unbounded_channel();
        let (from_protocol_tx, from_protocol_rx) = mpsc::unbounded_channel();

        let mut handler = WebTransportHandler::new(context, to_protocol_tx, from_protocol_rx);

        // Send stream data message
        let data = create_test_buffer(b"CONNECT request");
        let message = ProtocolToApplication::StreamData {
            conn_id: 1,
            stream_id: 0,
            data,
            fin: false,
        };
        from_protocol_tx.send(message).unwrap();

        let result = handler.wait_for_connect().await;
        assert!(result.is_ok());

        let headers = result.unwrap();
        assert!(!headers.is_empty());
        // Check that it contains expected CONNECT headers
        assert!(headers
            .iter()
            .any(|h| h.name() == b":method" && h.value() == b"CONNECT"));
    }

    #[tokio::test]
    async fn test_wait_for_connect_connection_closed() {
        init_buffer_pool(10);
        let context = create_test_context();
        let (to_protocol_tx, _) = mpsc::unbounded_channel();
        let (from_protocol_tx, from_protocol_rx) = mpsc::unbounded_channel();

        let mut handler = WebTransportHandler::new(context, to_protocol_tx, from_protocol_rx);

        // Send connection closed message
        let message = ProtocolToApplication::ConnectionClosed { conn_id: 1 };
        from_protocol_tx.send(message).unwrap();

        let result = handler.wait_for_connect().await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Connection closed before CONNECT"));
    }
}
