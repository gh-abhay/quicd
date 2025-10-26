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

use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::{
    ApplicationContext, ApplicationError, ApplicationProtocol, ApplicationResult,
    http3::{Http3Handler, create_h3_config},
    ToProtocolSender, FromProtocolReceiver,
};
use crate::messages::{ProtocolToApplication, ApplicationToProtocol};

/// Application dispatcher - routes streams to protocol handlers
pub struct ApplicationDispatcher {
    from_protocol: FromProtocolReceiver,
    to_protocol: ToProtocolSender,
    h3_config: Arc<quiche::h3::Config>,
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
                }
                ProtocolToApplication::NewStream { conn_id, stream_id, peer_addr, alpn } => {
                    self.handle_new_stream(conn_id, stream_id, peer_addr, alpn).await?;
                }
                ProtocolToApplication::StreamData { conn_id, stream_id, data, fin } => {
                    // Forward data to appropriate handler (handlers manage their own channels)
                    debug!("Received stream data for conn {} stream {} ({} bytes, fin={})",
                          conn_id, stream_id, data.len(), fin);
                }
                ProtocolToApplication::ConnectionClosed { conn_id } => {
                    info!("Connection closed: conn {}", conn_id);
                }
            }
        }

        info!("Application dispatcher shutting down");
        Ok(())
    }

    /// Handle a new stream by spawning appropriate protocol handler
    async fn handle_new_stream(
        &self,
        conn_id: u64,
        stream_id: u64,
        peer_addr: std::net::SocketAddr,
        alpn: String,
    ) -> ApplicationResult<()> {
        // Parse ALPN to determine protocol
        let protocol = match ApplicationProtocol::from_alpn(&alpn) {
            Some(proto) => proto,
            None => {
                warn!("Unsupported ALPN protocol: {} for conn {} stream {}",
                     alpn, conn_id, stream_id);
                // Close the stream with an error
                self.to_protocol.send(ApplicationToProtocol::CloseConnection { conn_id })
                    .map_err(|e| ApplicationError::Protocol(format!("Failed to close connection: {}", e)))?;
                return Ok(());
            }
        };

        info!("Starting {} handler for conn {} stream {} from {}",
             protocol.to_alpn(), conn_id, stream_id, peer_addr);

        // Create context for the handler
        let context = ApplicationContext {
            conn_id,
            stream_id,
            peer_addr,
            protocol: protocol.clone(),
        };

        // Create channels for the handler
        let (to_handler_tx, to_handler_rx) = mpsc::unbounded_channel();
        let (from_handler_tx, from_handler_rx) = mpsc::unbounded_channel();

        // Spawn the appropriate handler based on protocol
        match protocol {
            ApplicationProtocol::Http3 => {
                let handler = Http3Handler::new(
                    context,
                    from_handler_tx,
                    to_handler_rx,
                    Arc::clone(&self.h3_config),
                );

                tokio::spawn(async move {
                    if let Err(e) = handler.run().await {
                        error!("HTTP/3 handler error for conn {} stream {}: {}",
                              conn_id, stream_id, e);
                    }
                });
            }
            ApplicationProtocol::WebSocket => {
                warn!("WebSocket handler not implemented yet for conn {} stream {}",
                     conn_id, stream_id);
                // For now, close the stream
                self.to_protocol.send(ApplicationToProtocol::CloseConnection { conn_id })
                    .map_err(|e| ApplicationError::Protocol(format!("Failed to close connection: {}", e)))?;
            }
            ApplicationProtocol::Custom(name) => {
                warn!("Custom protocol '{}' not implemented for conn {} stream {}",
                     name, conn_id, stream_id);
                // For now, close the stream
                self.to_protocol.send(ApplicationToProtocol::CloseConnection { conn_id })
                    .map_err(|e| ApplicationError::Protocol(format!("Failed to close connection: {}", e)))?;
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