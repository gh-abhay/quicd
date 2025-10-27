//! # Application Dispatcher
//!
//! Routes incoming QUIC streams to appropriate application protocol handlers
//! based on ALPN (Application-Layer Protocol Negotiation).
//!
//! ## Architecture
//!
//! ```text
//! Protocol Layer
//!     ↓ (ALPN + Stream Data)
//! Application Dispatcher
//!     ↓ (Route by Protocol)
//! HTTP/3 Handler / WebSocket Handler / Custom Handler
//! ```
//!
//! ## ALPN Protocol Mapping
//!
//! - `"h3"` → HTTP/3 Handler
//! - `"h3-29"`, `"h3-30"`, etc. → HTTP/3 Handler (draft versions)
//! - Future: `"ws"` → WebSocket Handler
//! - Future: Custom protocols
//!
//! ## Task Lifecycle
//!
//! 1. **Stream Opens**: Dispatcher receives `NewStream` message
//! 2. **ALPN Detection**: Parse protocol from ALPN string
//! 3. **Handler Spawn**: Create appropriate protocol handler task
//! 4. **Data Forwarding**: Forward stream data to handler
//! 5. **Cleanup**: Handler terminates when stream closes

use std::collections::HashMap;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::{
    content::ContentHandler,
    webtransport::WebTransportHandler,
    ApplicationContext, ApplicationError, ApplicationProtocol, ApplicationResult,
    FromProtocolReceiver, ToProtocolSender,
};
use crate::messages::ProtocolToApplication;

/// Application dispatcher - routes streams to protocol handlers
pub struct ApplicationDispatcher {
    from_protocol: FromProtocolReceiver,
    to_protocol: ToProtocolSender,
    /// Map of connection ID to handler message sender
    handlers: HashMap<u64, mpsc::UnboundedSender<ProtocolToApplication>>,
}

impl ApplicationDispatcher {
    /// Create a new application dispatcher
    pub fn new(
        from_protocol: FromProtocolReceiver,
        to_protocol: ToProtocolSender,
    ) -> ApplicationResult<Self> {
        Ok(Self {
            from_protocol,
            to_protocol,
            handlers: HashMap::new(),
        })
    }

    /// Run the application dispatcher
    pub async fn run(mut self) -> ApplicationResult<()> {
        info!("Application dispatcher started");

        while let Some(message) = self.from_protocol.recv().await {
            match message {
                ProtocolToApplication::NewConnection {
                    conn_id,
                    peer_addr,
                    alpn,
                } => {
                    debug!(
                        "New connection established: conn {} from {} with ALPN {}",
                        conn_id, peer_addr, alpn
                    );
                    self.handle_new_connection(conn_id, peer_addr, alpn).await?;
                }
                ProtocolToApplication::NewStream {
                    conn_id,
                    stream_id,
                    peer_addr,
                    alpn,
                } => {
                    // Forward to connection handler
                    if let Some(handler_tx) = self.handlers.get(&conn_id) {
                        let msg = ProtocolToApplication::NewStream {
                            conn_id,
                            stream_id,
                            peer_addr,
                            alpn,
                        };
                        if let Err(_) = handler_tx.send(msg) {
                            warn!(
                                "Failed to forward NewStream to handler for conn {}",
                                conn_id
                            );
                            self.handlers.remove(&conn_id);
                        }
                    }
                }
                ProtocolToApplication::StreamData {
                    conn_id,
                    stream_id,
                    data,
                    fin,
                } => {
                    // Forward to connection handler
                    if let Some(handler_tx) = self.handlers.get(&conn_id) {
                        let msg = ProtocolToApplication::StreamData {
                            conn_id,
                            stream_id,
                            data,
                            fin,
                        };
                        if let Err(_) = handler_tx.send(msg) {
                            warn!(
                                "Failed to forward StreamData to handler for conn {}",
                                conn_id
                            );
                            self.handlers.remove(&conn_id);
                        }
                    }
                }
                ProtocolToApplication::ConnectionClosed { conn_id } => {
                    info!("Connection closed: conn {}", conn_id);
                    self.handlers.remove(&conn_id);
                }
            }
        }

        info!("Application dispatcher shutting down");
        Ok(())
    }

    /// Handle a new connection by spawning appropriate protocol handler
    async fn handle_new_connection(
        &mut self,
        conn_id: u64,
        peer_addr: std::net::SocketAddr,
        alpn: String,
    ) -> ApplicationResult<()> {
        // Parse ALPN to determine protocol
        let protocol = match ApplicationProtocol::from_alpn(&alpn) {
            Some(proto) => proto,
            None => {
                warn!("Unsupported ALPN protocol: {} for conn {}", alpn, conn_id);
                // Close the connection with an error
                self.to_protocol
                    .send(crate::messages::ApplicationToProtocol::CloseConnection { conn_id })
                    .map_err(|e| {
                        ApplicationError::ChannelError(format!("Failed to close connection: {}", e))
                    })?;
                return Ok(());
            }
        };

        info!(
            "Starting {} handler for conn {} from {}",
            protocol.to_alpn(),
            conn_id,
            peer_addr
        );

        // Create context for the handler
        let context = ApplicationContext {
            conn_id,
            stream_id: 0, // Not used for per-connection handlers
            peer_addr,
            protocol: protocol.clone(),
        };

        // Create channels for the handler
        let (to_protocol_tx, _) =
            mpsc::unbounded_channel::<crate::messages::ApplicationToProtocol>();
        let (from_protocol_tx, from_protocol_rx) =
            mpsc::unbounded_channel::<crate::messages::ProtocolToApplication>();

        // Store the sender to forward messages to this handler
        self.handlers.insert(conn_id, from_protocol_tx);

        // Spawn the appropriate handler based on protocol
        match protocol {
            ApplicationProtocol::Http3Content => {
                let handler = ContentHandler::new(context, to_protocol_tx, from_protocol_rx);

                tokio::spawn(async move {
                    if let Err(e) = handler.run().await {
                        error!("HTTP/3 content handler error for conn {}: {}", conn_id, e);
                    }
                });
            }
            ApplicationProtocol::WebTransport => {
                let handler = WebTransportHandler::new(context, to_protocol_tx, from_protocol_rx);

                tokio::spawn(async move {
                    if let Err(e) = handler.run().await {
                        error!("WebTransport handler error for conn {}: {}", conn_id, e);
                    }
                });
            }
        }

        Ok(())
    }
}

/// Start the application layer with dispatcher
pub fn start_application_layer(
    from_protocol: FromProtocolReceiver,
    to_protocol: ToProtocolSender,
) -> ApplicationResult<()> {
    let dispatcher = ApplicationDispatcher::new(from_protocol, to_protocol)?;

    tokio::spawn(async move {
        if let Err(e) = dispatcher.run().await {
            error!("Application dispatcher error: {}", e);
        }
    });

    info!("Application layer started with HTTP/3 support");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_application_protocol_from_alpn() {
        // Test valid ALPN strings
        assert_eq!(
            ApplicationProtocol::from_alpn("h3"),
            Some(ApplicationProtocol::Http3Content)
        );
        assert_eq!(
            ApplicationProtocol::from_alpn("h3-29"),
            Some(ApplicationProtocol::Http3Content)
        );
        assert_eq!(
            ApplicationProtocol::from_alpn("h3-30"),
            Some(ApplicationProtocol::Http3Content)
        );
        assert_eq!(
            ApplicationProtocol::from_alpn("h3-31"),
            Some(ApplicationProtocol::Http3Content)
        );
        assert_eq!(
            ApplicationProtocol::from_alpn("h3-32"),
            Some(ApplicationProtocol::Http3Content)
        );

        // Test invalid ALPN strings
        assert_eq!(ApplicationProtocol::from_alpn("http/1.1"), None);
        assert_eq!(ApplicationProtocol::from_alpn("h2"), None);
        assert_eq!(ApplicationProtocol::from_alpn(""), None);
        assert_eq!(ApplicationProtocol::from_alpn("unknown"), None);
    }

    #[tokio::test]
    async fn test_application_protocol_to_alpn() {
        assert_eq!(ApplicationProtocol::Http3Content.to_alpn(), "h3");
        assert_eq!(ApplicationProtocol::WebTransport.to_alpn(), "h3");
    }

    #[tokio::test]
    async fn test_application_dispatcher_creation() {
        let (_from_protocol_tx, from_protocol_rx) = mpsc::unbounded_channel();
        let (to_protocol_tx, _) = mpsc::unbounded_channel();

        let dispatcher = ApplicationDispatcher::new(from_protocol_rx, to_protocol_tx);
        assert!(dispatcher.is_ok());

        let dispatcher = dispatcher.unwrap();
        assert!(dispatcher.handlers.is_empty());
    }

    #[tokio::test]
    async fn test_handle_new_connection_http3_content() {
        let (_from_protocol_tx, from_protocol_rx) = mpsc::unbounded_channel();
        let (to_protocol_tx, mut to_protocol_rx) = mpsc::unbounded_channel();

        let mut dispatcher = ApplicationDispatcher::new(from_protocol_rx, to_protocol_tx).unwrap();

        let conn_id = 1;
        let peer_addr = "127.0.0.1:4433".parse().unwrap();
        let alpn = "h3".to_string();

        // Handle new connection
        let result = dispatcher
            .handle_new_connection(conn_id, peer_addr, alpn)
            .await;
        assert!(result.is_ok());

        // Check that handler was registered
        assert!(dispatcher.handlers.contains_key(&conn_id));

        // Check that no close connection message was sent (since ALPN was valid)
        let timeout_result =
            tokio::time::timeout(std::time::Duration::from_millis(10), to_protocol_rx.recv()).await;
        assert!(timeout_result.is_err()); // Should timeout, no message sent
    }

    #[tokio::test]
    async fn test_handle_new_connection_unsupported_alpn() {
        let (_from_protocol_tx, from_protocol_rx) = mpsc::unbounded_channel();
        let (to_protocol_tx, mut to_protocol_rx) = mpsc::unbounded_channel();

        let mut dispatcher = ApplicationDispatcher::new(from_protocol_rx, to_protocol_tx).unwrap();

        let conn_id = 1;
        let peer_addr = "127.0.0.1:4433".parse().unwrap();
        let alpn = "unsupported".to_string();

        // Handle new connection with unsupported ALPN
        let result = dispatcher
            .handle_new_connection(conn_id, peer_addr, alpn)
            .await;
        assert!(result.is_ok());

        // Check that no handler was registered
        assert!(!dispatcher.handlers.contains_key(&conn_id));

        // Check that close connection message was sent
        let message = to_protocol_rx.recv().await;
        assert!(message.is_some());
        match message.unwrap() {
            crate::messages::ApplicationToProtocol::CloseConnection {
                conn_id: closed_conn_id,
            } => {
                assert_eq!(closed_conn_id, conn_id);
            }
            _ => panic!("Expected CloseConnection message"),
        }
    }

    #[tokio::test]
    async fn test_dispatcher_message_forwarding() {
        let (from_protocol_tx, from_protocol_rx) = mpsc::unbounded_channel();
        let (to_protocol_tx, _to_protocol_rx) = mpsc::unbounded_channel();

        let mut dispatcher = ApplicationDispatcher::new(from_protocol_rx, to_protocol_tx).unwrap();

        let conn_id = 1;
        let peer_addr = "127.0.0.1:4433".parse().unwrap();
        let alpn = "h3".to_string();

        // First establish a connection
        dispatcher
            .handle_new_connection(conn_id, peer_addr, alpn)
            .await
            .unwrap();

        // Send a NewStream message
        let stream_id = 4;
        let new_stream_msg = ProtocolToApplication::NewStream {
            conn_id,
            stream_id,
            peer_addr,
            alpn: "h3".to_string(),
        };

        from_protocol_tx.send(new_stream_msg).unwrap();

        // Run dispatcher briefly to process the message
        let dispatcher_future = dispatcher.run();
        let timeout_result =
            tokio::time::timeout(std::time::Duration::from_millis(10), dispatcher_future).await;

        // The dispatcher should still be running (not completed)
        assert!(timeout_result.is_err());
    }

    #[tokio::test]
    async fn test_start_application_layer() {
        let (_from_protocol_tx, from_protocol_rx) = mpsc::unbounded_channel();
        let (to_protocol_tx, _) = mpsc::unbounded_channel();

        let result = start_application_layer(from_protocol_rx, to_protocol_tx);
        assert!(result.is_ok());
    }
}
