//! QUIC to Service Integration
//!
//! This module bridges the QUIC protocol layer with the service layer.
//! Its primary role is to take the first packet of a new stream, determine
//! which service should handle it, and then spawn a task to run that service's
//! stream handler.

use bytes::Bytes;
use quiche::ConnectionId;
use service::ServiceRegistry;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, warn};

use crate::io::{QuicStream, StreamCommand};
use crate::stream_mux::StreamMultiplexer;
use crate::QuicEngine;

/// QUIC stream processor.
///
/// This struct is responsible for the initial processing of new streams.
/// It detects the protocol, finds the appropriate service, and hands off
/// the stream to the service for handling.
pub struct StreamProcessor {
    /// Stream multiplexer for protocol detection.
    mux: Arc<StreamMultiplexer>,

    /// Service registry for looking up service handlers.
    services: Arc<ServiceRegistry>,
}

impl StreamProcessor {
    /// Create a new stream processor.
    pub fn new(mux: Arc<StreamMultiplexer>, services: Arc<ServiceRegistry>) -> Self {
        Self { mux, services }
    }

    /// Process the first data chunk of a new stream.
    ///
    /// This method is called by the `ProtocolThread` only when a `StreamData`
    /// event is received for a stream that is not yet known.
    ///
    /// # Flow
    /// 1. Detect the protocol using the `StreamMultiplexer`.
    /// 2. Look up the corresponding service in the `ServiceRegistry`.
    /// 3. Create a new `QuicStream` and its associated channels.
    /// 4. Register the stream's command sender (`command_tx`) with the `ConnectionState`.
    /// 5. Spawn a new Tokio task to run the service's `handle_stream` method.
    /// 6. Send the initial data chunk to the newly created stream.
    pub async fn process_new_stream(
        &self,
        engine: Arc<Mutex<QuicEngine>>,
        conn_id: ConnectionId<'static>,
        stream_id: u64,
        initial_data: Bytes,
    ) {
        let mut engine_lock = engine.lock().await;
        let conn_state = match engine_lock.get_connection_state_mut(&conn_id) {
            Some(state) => state,
            None => {
                warn!("process_new_stream: Connection not found: {:?}", conn_id);
                return;
            }
        };

        // Get ALPN for protocol detection.
        let alpn = conn_state.conn.application_proto();

        // Detect protocol and get routing info.
        let route = self.mux.detect_protocol(alpn, &initial_data);

        debug!(
            conn_id = ?conn_id,
            stream_id = stream_id,
            service = route.service_name,
            "New stream detected, routing to service"
        );

        // Get the service handler.
        let service = match self.services.get(route.service_name) {
            Some(service) => service,
            None => {
                warn!("Service not found for protocol: {}", route.service_name);
                // TODO: Close the stream gracefully.
                return;
            }
        };

        // Create the channels for the QuicStream.
        let (read_tx, read_rx) = mpsc::channel(128);
        let (command_tx, mut command_rx) = mpsc::channel(128);

        // Create the QuicStream object that the service will use.
        let stream = QuicStream::new(read_rx, command_tx);

        // Register the read channel's sender with the connection state so the
        // ProtocolThread can forward data to it.
        conn_state.stream_data_tx.insert(stream_id, read_tx.clone());

        // Drop the lock before spawning tasks
        drop(engine_lock);

        // Spawn a task to manage the stream's command channel.
        let engine_clone = Arc::clone(&engine);
        tokio::spawn(async move {
            while let Some(command) = command_rx.recv().await {
                let mut engine_lock = engine_clone.lock().await;
                let conn_state = match engine_lock.get_connection_state_mut(&conn_id) {
                    Some(state) => state,
                    None => break, // Connection is gone
                };

                match command {
                    StreamCommand::Write(data) => {
                        if let Err(e) = conn_state.conn.stream_send(stream_id, &data, false) {
                            warn!("Failed to send data to stream {}: {}", stream_id, e);
                            break;
                        }
                    }
                    StreamCommand::Shutdown => {
                        if let Err(e) = conn_state.conn.stream_shutdown(stream_id, quiche::Shutdown::Write, 0) {
                            warn!("Failed to shutdown stream {}: {}", stream_id, e);
                        }
                        break; // Stop handling commands after shutdown
                    }
                    StreamCommand::Close => {
                        // The Drop implementation of QuicStream sends this.
                        // We can remove the stream's data channel here.
                        conn_state.stream_data_tx.remove(&stream_id);
                        break;
                    }
                }
            }
        });

        // Spawn the service handler task.
        tokio::spawn(async move {
            service.handle_stream(Box::new(stream)).await;
        });

        // Finally, send the initial data chunk to the stream.
        // If this fails, the service task has already terminated, so we just log it.
        if read_tx.send(initial_data).await.is_err() {
            debug!(
                "Initial data could not be sent to stream {}; service may have terminated early.",
                stream_id
            );
        }
    }

    /// Spawns a task to handle commands for a single stream.
    fn spawn_command_handler(
        _engine: Arc<Mutex<QuicEngine>>,
        _conn_id: ConnectionId<'static>,
        _stream_id: u64,
        _command_rx: mpsc::Receiver<StreamCommand>,
    ) {
        // This function is now empty as its logic has been moved into process_new_stream
        // to correctly handle the lifetime of the engine.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream_mux::StreamMultiplexer;
    use service::ServiceRegistry;

    #[test]
    fn test_stream_processor_new() {
        let mux = Arc::new(StreamMultiplexer::new());
        let services = Arc::new(ServiceRegistry::new());
        let _processor = StreamProcessor::new(mux, services);
    }
}
