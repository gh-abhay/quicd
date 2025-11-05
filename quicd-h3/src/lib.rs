//! HTTP/3 implementation for quicd server.
//!
//! This crate provides an HTTP/3 application that runs on top of the quicd QUIC server.

use async_trait::async_trait;
use futures::stream::StreamExt;
use quicd_x::{
    AppEvent, AppEventStream, ConnectionError, ConnectionHandle, QuicAppFactory, ShutdownFuture,
    TransportControls,
};
use tracing::{debug, info};

/// HTTP/3 application factory.
///
/// For now, this is a simple echo server for testing the quicd-x integration.
pub struct H3Factory;

impl H3Factory {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl QuicAppFactory for H3Factory {
    fn accepts_alpn(&self, alpn: &str) -> bool {
        matches!(alpn, "h3" | "h3-29")
    }

    async fn spawn_app(
        &self,
        alpn: String,
        handle: ConnectionHandle,
        mut events: AppEventStream,
        _transport: TransportControls,
        _shutdown: ShutdownFuture,
    ) -> Result<(), ConnectionError> {
        info!(
            alpn,
            connection_id = %handle.connection_id(),
            peer = %handle.peer_addr(),
            "H3 application task started"
        );

        // Simple event loop for testing
        while let Some(event) = events.next().await {
            match event {
                AppEvent::HandshakeCompleted { .. } => {
                    debug!("Handshake completed");
                }
                AppEvent::NewStream {
                    stream_id,
                    bidirectional,
                    mut recv_stream,
                    send_stream,
                } => {
                    info!(stream_id, bidirectional, "New stream opened");

                    // Echo back any data received
                    tokio::spawn(async move {
                        // Only echo on bidirectional streams
                        if let Some(send_stream) = send_stream {
                            while let Ok(Some(stream_data)) = recv_stream.read().await {
                                match stream_data {
                                    quicd_x::StreamData::Data(data) => {
                                        debug!(
                                            stream_id,
                                            bytes = data.len(),
                                            "Received data on stream"
                                        );

                                        // Echo back the data
                                        match send_stream.write(data, false).await {
                                            Ok(written) => {
                                                debug!(stream_id, written, "Echoed data back");
                                            }
                                            Err(e) => {
                                                debug!(stream_id, error = ?e, "Failed to echo data");
                                                break;
                                            }
                                        }
                                    }
                                    quicd_x::StreamData::Fin => {
                                        debug!(stream_id, "Received FIN on stream");
                                        break;
                                    }
                                }
                            }

                            // Close the send stream
                            if let Err(e) = send_stream.finish().await {
                                debug!(stream_id, error = ?e, "Failed to finish stream");
                            }
                        } else {
                            // Unidirectional recv stream - just consume data
                            while let Ok(Some(stream_data)) = recv_stream.read().await {
                                match stream_data {
                                    quicd_x::StreamData::Data(data) => {
                                        debug!(
                                            stream_id,
                                            bytes = data.len(),
                                            "Received data on uni stream"
                                        );
                                    }
                                    quicd_x::StreamData::Fin => {
                                        debug!(stream_id, "Received FIN on uni stream");
                                        break;
                                    }
                                }
                            }
                        }
                        debug!(stream_id, "Stream finished");
                    });
                }
                AppEvent::StreamFinished { stream_id } => {
                    debug!(stream_id, "Stream finished");
                }
                AppEvent::StreamClosed {
                    stream_id,
                    app_initiated,
                    error_code,
                } => {
                    debug!(stream_id, app_initiated, error_code, "Stream closed");
                }
                AppEvent::Datagram { payload } => {
                    debug!(bytes = payload.len(), "Received datagram");
                }
                AppEvent::ConnectionCapacityChanged => {
                    debug!("Connection capacity changed");
                }
                AppEvent::TransportEvent(event) => {
                    debug!(?event, "Transport event");
                }
                AppEvent::ConnectionClosing { error_code, reason } => {
                    info!(
                        error_code,
                        reason_len = reason.as_ref().map(|r| r.len()).unwrap_or(0),
                        "Connection closing"
                    );
                    break;
                }
                AppEvent::StreamOpened { request_id, result } => {
                    debug!(request_id, ?result, "Stream opened response");
                }
                AppEvent::UniStreamOpened { request_id, result } => {
                    debug!(request_id, ?result, "Uni stream opened response");
                }
                AppEvent::DatagramSent { request_id, result } => {
                    debug!(request_id, ?result, "Datagram sent response");
                }
                AppEvent::StreamReset { request_id, result } => {
                    debug!(request_id, ?result, "Stream reset response");
                }
                AppEvent::StatsReceived { request_id, result } => {
                    debug!(request_id, ?result, "Stats received response");
                }
            }
        }

        info!("H3 application task ended");
        Ok(())
    }
}
