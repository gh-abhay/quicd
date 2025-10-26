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
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::{
    ApplicationContext, ApplicationError, ApplicationProtocol, ApplicationResult,
    content::{ContentHandler, create_h3_config},
    webtransport::WebTransportHandler,
    ToProtocolSender, FromProtocolReceiver,
};
use crate::messages::{ProtocolToApplication, ApplicationToProtocol};

/// Application dispatcher - routes streams to protocol handlers
pub struct ApplicationDispatcher {
    from_protocol: FromProtocolReceiver,
    to_protocol: ToProtocolSender,
    h3_config: Arc<quiche::h3::Config>,
    /// Map of connection ID to handler message sender
    handlers: HashMap<u64, mpsc::UnboundedSender<ProtocolToApplication>>,
}

impl ApplicationDispatcher {
    /// Create a new application dispatcher
    pub fn new(
        from_protocol: FromProtocolReceiver,
        to_protocol: ToProtocolSender,
    ) -> ApplicationResult<Self> {
        let h3_config = create_h3_config()?;

        Ok(Self {
            from_protocol,
            to_protocol,
            h3_config,
            handlers: HashMap::new(),
        })
    }

    /// Run the application dispatcher
    pub async fn run(mut self) -> ApplicationResult<()> {
        info!("Application dispatcher started");

        while let Some(message) = self.from_protocol.recv().await {
            match message {
                ProtocolToApplication::NewConnection { conn_id, peer_addr, alpn } => {
                    debug!("New connection established: conn {} from {} with ALPN {}",
                          conn_id, peer_addr, alpn);
                    self.handle_new_connection(conn_id, peer_addr, alpn).await?;
                }
                ProtocolToApplication::NewStream { conn_id, stream_id, peer_addr, alpn } => {
                    // Forward to connection handler
                    if let Some(handler_tx) = self.handlers.get(&conn_id) {
                        let msg = ProtocolToApplication::NewStream { conn_id, stream_id, peer_addr, alpn };
                        if let Err(_) = handler_tx.send(msg) {
                            warn!("Failed to forward NewStream to handler for conn {}", conn_id);
                            self.handlers.remove(&conn_id);
                        }
                    }
                }
                ProtocolToApplication::StreamData { conn_id, stream_id, data, fin } => {
                    // Forward to connection handler
                    if let Some(handler_tx) = self.handlers.get(&conn_id) {
                        let msg = ProtocolToApplication::StreamData { conn_id, stream_id, data, fin };
                        if let Err(_) = handler_tx.send(msg) {
                            warn!("Failed to forward StreamData to handler for conn {}", conn_id);
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
                self.to_protocol.send(crate::messages::ApplicationToProtocol::CloseConnection { conn_id })
                    .map_err(|e| ApplicationError::ChannelError(format!("Failed to close connection: {}", e)))?;
                return Ok(());
            }
        };

        info!("Starting {} handler for conn {} from {}", protocol.to_alpn(), conn_id, peer_addr);

        // Create context for the handler
        let context = ApplicationContext {
            conn_id,
            stream_id: 0, // Not used for per-connection handlers
            peer_addr,
            protocol: protocol.clone(),
        };

        // Create channels for the handler
        let (to_protocol_tx, _) = mpsc::unbounded_channel::<crate::messages::ApplicationToProtocol>();
        let (from_protocol_tx, from_protocol_rx) = mpsc::unbounded_channel::<crate::messages::ProtocolToApplication>();

        // Store the sender to forward messages to this handler
        self.handlers.insert(conn_id, from_protocol_tx);

        // Spawn the appropriate handler based on protocol
        match protocol {
            ApplicationProtocol::Http3Content => {
                let handler = ContentHandler::new(
                    context,
                    to_protocol_tx,
                    from_protocol_rx,
                );

                tokio::spawn(async move {
                    if let Err(e) = handler.run().await {
                        error!("HTTP/3 content handler error for conn {}: {}", conn_id, e);
                    }
                });
            }
            ApplicationProtocol::WebTransport => {
                let handler = WebTransportHandler::new(
                    context,
                    to_protocol_tx,
                    from_protocol_rx,
                );

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