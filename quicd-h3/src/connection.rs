//! HTTP/3 connection lifecycle and main event loop.
//!
//! This module implements the `QuicdApplication` trait from quicd-x, providing
//! the HTTP/3 protocol implementation that runs as a single Tokio task per connection.

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use quicd_x::{ConnectionHandle, QuicdApplication, StreamId};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::Duration;
use tracing::{debug, error, info, warn};

use crate::config::H3Config;
use crate::error::{Error, ErrorCode, Result};
use crate::frame::{Frame, FrameParser, SettingsFrame, Setting, SettingId, write_frame};
use crate::handler::FileHandler;
use crate::message::{HttpRequest, HttpResponse, parse_request_pseudo_headers, response_to_field_lines};
use crate::qpack_mgr::QpackManager;
use crate::stream_type::{StreamType, read_stream_type, write_stream_type};

/// HTTP/3 application implementing the QuicdApplication trait.
///
/// This is the entry point for HTTP/3 connections. Each connection spawns
/// exactly one task via `on_connection()`.
#[derive(Clone)]
pub struct H3Application {
    config: Arc<H3Config>,
}

impl H3Application {
    /// Create a new HTTP/3 application with the given configuration.
    pub fn new(config: H3Config) -> Self {
        // Validate configuration
        let errors = config.validate();
        if !errors.is_empty() {
            panic!("Invalid H3 configuration: {}", errors.join(", "));
        }

        Self {
            config: Arc::new(config),
        }
    }

    /// Get the configuration.
    pub fn config(&self) -> &H3Config {
        &self.config
    }
}

#[async_trait]
impl QuicdApplication for H3Application {
    /// Handle a new HTTP/3 connection.
    ///
    /// This method runs as a single Tokio task for the entire connection lifetime.
    /// It MUST NOT spawn additional tasks or threads.
    async fn on_connection(&self, conn: ConnectionHandle) {
        info!("HTTP/3 connection established: {:?}", conn.connection_id());

        let result = H3Connection::new(conn, self.config.clone())
            .run()
            .await;

        match result {
            Ok(()) => {
                info!("HTTP/3 connection closed normally");
            }
            Err(e) => {
                error!("HTTP/3 connection error: {}", e);
            }
        }
    }
}

/// Per-connection HTTP/3 state.
///
/// Manages all state for a single HTTP/3 connection within the single task.
struct H3Connection {
    conn: ConnectionHandle,
    config: Arc<H3Config>,
    qpack: QpackManager,
    handler: FileHandler,
    
    // Control stream state
    control_stream_sent: bool,
    control_stream_received: bool,
    peer_settings: Option<PeerSettings>,
    
    // Stream tracking
    request_streams: HashMap<StreamId, RequestStreamState>,
    
    // QPACK stream IDs
    our_encoder_stream: Option<StreamId>,
    our_decoder_stream: Option<StreamId>,
    peer_encoder_stream: Option<StreamId>,
    peer_decoder_stream: Option<StreamId>,
}

/// Peer's SETTINGS configuration.
#[derive(Debug, Clone)]
struct PeerSettings {
    qpack_max_table_capacity: u64,
    qpack_blocked_streams: u64,
    max_field_section_size: u64,
}

impl Default for PeerSettings {
    fn default() -> Self {
        Self {
            qpack_max_table_capacity: 0,
            qpack_blocked_streams: 0,
            max_field_section_size: u64::MAX,
        }
    }
}

/// State of an HTTP request/response stream.
struct RequestStreamState {
    stream_id: StreamId,
    parser: FrameParser,
    request: Option<HttpRequest>,
    body_buffer: BytesMut,
    headers_received: bool,
    fin_received: bool,
}

impl H3Connection {
    fn new(conn: ConnectionHandle, config: Arc<H3Config>) -> Self {
        let qpack = QpackManager::new(
            config.qpack.max_table_capacity,
            config.qpack.blocked_streams,
        );
        
        let handler = FileHandler::new(config.handler.clone());

        Self {
            conn,
            config,
            qpack,
            handler,
            control_stream_sent: false,
            control_stream_received: false,
            peer_settings: None,
            request_streams: HashMap::new(),
            our_encoder_stream: None,
            our_decoder_stream: None,
            peer_encoder_stream: None,
            peer_decoder_stream: None,
        }
    }

    /// Run the HTTP/3 connection event loop.
    ///
    /// This is the main event loop that processes all connection events
    /// using tokio::select! to multiplex I/O.
    async fn run(mut self) -> Result<()> {
        // Step 1: Open control stream and send SETTINGS
        self.open_control_stream().await?;

        // Step 2: Open QPACK encoder and decoder streams
        self.open_qpack_streams().await?;

        // Step 3: Main event loop
        loop {
            tokio::select! {
                // Accept incoming bidirectional streams (HTTP requests)
                stream_result = self.conn.accept_bi_stream() => {
                    match stream_result {
                        Ok(stream) => {
                            let stream_id = stream.stream_id();
                            debug!("Accepted bidirectional stream: {:?}", stream_id);
                            self.handle_new_request_stream(stream).await?;
                        }
                        Err(e) => {
                            warn!("Error accepting bidirectional stream: {}", e);
                            break;
                        }
                    }
                }

                // Accept incoming unidirectional streams (control, QPACK, etc.)
                stream_result = self.conn.accept_uni_stream() => {
                    match stream_result {
                        Ok(mut stream) => {
                            debug!("Accepted unidirectional stream");
                            // Read stream type
                            let mut type_buf = BytesMut::with_capacity(8);
                            if let Err(e) = stream.read_buf(&mut type_buf).await {
                                warn!("Error reading stream type: {}", e);
                                continue;
                            }
                            
                            match read_stream_type(&mut type_buf) {
                                Ok(stream_type) => {
                                    self.handle_unidirectional_stream(stream, stream_type).await?;
                                }
                                Err(e) => {
                                    error!("Invalid stream type: {}", e);
                                    return Err(e);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Error accepting unidirectional stream: {}", e);
                            break;
                        }
                    }
                }

                // Timeout if no activity (idle timeout)
                _ = tokio::time::sleep(Duration::from_secs(self.config.limits.idle_timeout_secs)) => {
                    info!("Connection idle timeout");
                    break;
                }
            }

            // Check if connection is closed
            if self.conn.is_closed() {
                info!("Connection closed by peer");
                break;
            }
        }

        Ok(())
    }

    /// Open our control stream and send SETTINGS frame.
    async fn open_control_stream(&mut self) -> Result<()> {
        let mut stream = self.conn.open_uni_stream().await
            .map_err(|e| Error::Io(e))?;

        // Write stream type
        let mut buf = BytesMut::new();
        write_stream_type(StreamType::Control, &mut buf)?;
        stream.write_all(&buf).await.map_err(|e| Error::Io(e))?;

        // Build and send SETTINGS frame
        let settings = SettingsFrame {
            settings: vec![
                Setting {
                    identifier: SettingId::QpackMaxTableCapacity,
                    value: self.config.qpack.max_table_capacity,
                },
                Setting {
                    identifier: SettingId::MaxFieldSectionSize,
                    value: self.config.limits.max_field_section_size,
                },
                Setting {
                    identifier: SettingId::QpackBlockedStreams,
                    value: self.config.qpack.blocked_streams,
                },
            ],
        };

        let mut frame_buf = BytesMut::new();
        write_frame(&Frame::Settings(settings), &mut frame_buf)?;
        stream.write_all(&frame_buf).await.map_err(|e| Error::Io(e))?;
        stream.shutdown().await.map_err(|e| Error::Io(e))?;

        self.control_stream_sent = true;
        debug!("Sent SETTINGS on control stream");

        Ok(())
    }

    /// Open QPACK encoder and decoder streams.
    async fn open_qpack_streams(&mut self) -> Result<()> {
        // Open encoder stream
        let mut encoder_stream = self.conn.open_uni_stream().await
            .map_err(|e| Error::Io(e))?;
        let encoder_stream_id = encoder_stream.stream_id();
        let mut buf = BytesMut::new();
        write_stream_type(StreamType::QpackEncoder, &mut buf)?;
        encoder_stream.write_all(&buf).await.map_err(|e| Error::Io(e))?;
        self.our_encoder_stream = Some(encoder_stream_id);

        // Open decoder stream
        let mut decoder_stream = self.conn.open_uni_stream().await
            .map_err(|e| Error::Io(e))?;
        let decoder_stream_id = decoder_stream.stream_id();
        let mut buf = BytesMut::new();
        write_stream_type(StreamType::QpackDecoder, &mut buf)?;
        decoder_stream.write_all(&buf).await.map_err(|e| Error::Io(e))?;
        self.our_decoder_stream = Some(decoder_stream_id);

        debug!("Opened QPACK encoder and decoder streams");
        Ok(())
    }

    /// Handle a new bidirectional stream (HTTP request).
    async fn handle_new_request_stream(&mut self, mut stream: quicd_x::QuicStream) -> Result<()> {
        let stream_id = stream.stream_id();

        // Create stream state
        self.request_streams.insert(stream_id, RequestStreamState {
            stream_id,
            parser: FrameParser::new(),
            request: None,
            body_buffer: BytesMut::new(),
            headers_received: false,
            fin_received: false,
        });

        // Read from stream in loop
        let mut buffer = BytesMut::with_capacity(8192);
        loop {
            match stream.read_buf(&mut buffer).await {
                Ok(0) => {
                    // EOF - process complete request
                    self.process_request_stream(stream_id, &mut stream, true).await?;
                    break;
                }
                Ok(n) => {
                    debug!("Read {} bytes from stream {:?}", n, stream_id);
                    self.process_request_stream(stream_id, &mut stream, false).await?;
                }
                Err(e) => {
                    error!("Error reading from stream {:?}: {}", stream_id, e);
                    return Err(Error::Io(e));
                }
            }
        }

        Ok(())
    }

    /// Process frames from a request stream.
    async fn process_request_stream(
        &mut self,
        stream_id: StreamId,
        stream: &mut quicd_x::QuicStream,
        fin: bool,
    ) -> Result<()> {
        let state = self.request_streams.get_mut(&stream_id)
            .ok_or_else(|| Error::Internal("stream state not found".to_string()))?;

        // Parse frames from buffer
        let frames = state.parser.parse(state.body_buffer.split().freeze())?;

        for frame in frames {
            match frame {
                Frame::Headers(headers_frame) => {
                    if state.headers_received {
                        // Trailers - not fully implemented yet
                        continue;
                    }

                    // Decode QPACK field section
                    let fields = self.qpack.decode_field_section(
                        stream_id.0,
                        &headers_frame.encoded_field_section,
                    )?;

                    // Parse pseudo-headers
                    let (method, uri, headers) = parse_request_pseudo_headers(&fields)?;

                    // Create request object
                    state.request = Some(HttpRequest {
                        method,
                        uri,
                        headers,
                        body: Bytes::new(),
                        trailers: None,
                    });

                    state.headers_received = true;
                    debug!("Received HEADERS frame on stream {:?}", stream_id);
                }

                Frame::Data(data_frame) => {
                    // Accumulate body data
                    if let Some(ref mut request) = state.request {
                        let mut body_vec = request.body.to_vec();
                        body_vec.extend_from_slice(&data_frame.payload);
                        request.body = Bytes::from(body_vec);
                    }
                    debug!("Received DATA frame ({} bytes) on stream {:?}",
                        data_frame.payload.len(), stream_id);
                }

                _ => {
                    // Other frames not expected on request streams
                    warn!("Unexpected frame type on request stream: {:?}", frame.frame_type());
                }
            }
        }

        // If FIN received and we have a complete request, handle it
        if fin && state.headers_received {
            if let Some(request) = state.request.clone() {
                self.handle_http_request(stream_id, stream, request).await?;
            }
        }

        Ok(())
    }

    /// Handle a complete HTTP request and send response.
    async fn handle_http_request(
        &mut self,
        stream_id: StreamId,
        stream: &mut quicd_x::QuicStream,
        request: HttpRequest,
    ) -> Result<()> {
        debug!("Handling HTTP request: {} {}", request.method, request.uri);

        // Invoke handler
        let response = self.handler.handle_request(&request).await?;

        // Send response
        self.send_http_response(stream, &response).await?;

        Ok(())
    }

    /// Send an HTTP response on a stream.
    async fn send_http_response(
        &mut self,
        stream: &mut quicd_x::QuicStream,
        response: &HttpResponse,
    ) -> Result<()> {
        // Convert response to field lines
        let fields = response_to_field_lines(response);

        // Encode with QPACK
        let stream_id = stream.stream_id();
        let encoded_fields = self.qpack.encode_field_section(stream_id.0, &fields)?;

        // Build HEADERS frame
        let headers_frame = Frame::Headers(crate::frame::HeadersFrame {
            encoded_field_section: encoded_fields,
        });

        let mut buf = BytesMut::new();
        write_frame(&headers_frame, &mut buf)?;
        stream.write_all(&buf).await.map_err(|e| Error::Io(e))?;

        // Send body in DATA frame if non-empty
        if !response.body.is_empty() {
            let data_frame = Frame::Data(crate::frame::DataFrame {
                payload: response.body.clone(),
            });

            let mut buf = BytesMut::new();
            write_frame(&data_frame, &mut buf)?;
            stream.write_all(&buf).await.map_err(|e| Error::Io(e))?;
        }

        // Close stream (FIN)
        stream.shutdown().await.map_err(|e| Error::Io(e))?;

        debug!("Sent HTTP response: {}", response.status);
        Ok(())
    }

    /// Handle a unidirectional stream based on its type.
    async fn handle_unidirectional_stream(
        &mut self,
        mut stream: quicd_x::QuicStream,
        stream_type: StreamType,
    ) -> Result<()> {
        match stream_type {
            StreamType::Control => {
                self.handle_control_stream(stream).await?;
            }
            StreamType::QpackEncoder => {
                let stream_id = stream.stream_id();
                self.peer_encoder_stream = Some(stream_id);
                self.handle_qpack_encoder_stream(stream).await?;
            }
            StreamType::QpackDecoder => {
                let stream_id = stream.stream_id();
                self.peer_decoder_stream = Some(stream_id);
                self.handle_qpack_decoder_stream(stream).await?;
            }
            StreamType::Push => {
                // Push streams not fully implemented
                warn!("Received push stream (not implemented)");
            }
        }

        Ok(())
    }

    /// Handle peer's control stream.
    async fn handle_control_stream(&mut self, mut stream: quicd_x::QuicStream) -> Result<()> {
        if self.control_stream_received {
            return Err(Error::protocol(
                ErrorCode::StreamCreationError,
                "duplicate control stream",
            ));
        }

        let mut parser = FrameParser::new();
        let mut buffer = BytesMut::with_capacity(4096);
        let mut settings_received = false;

        loop {
            match stream.read_buf(&mut buffer).await {
                Ok(0) => {
                    // Control stream closed - this is a connection error
                    return Err(Error::protocol(
                        ErrorCode::ClosedCriticalStream,
                        "control stream closed",
                    ));
                }
                Ok(_) => {
                    let frames = parser.parse(buffer.split().freeze())?;

                    for frame in frames {
                        match frame {
                            Frame::Settings(settings_frame) => {
                                if settings_received {
                                    return Err(Error::protocol(
                                        ErrorCode::FrameUnexpected,
                                        "duplicate SETTINGS frame",
                                    ));
                                }

                                self.process_settings_frame(&settings_frame)?;
                                settings_received = true;
                                self.control_stream_received = true;
                            }
                            Frame::Goaway(_) => {
                                // Peer is closing - handle gracefully
                                info!("Received GOAWAY from peer");
                                return Ok(());
                            }
                            _ => {
                                // Other control frames - log and continue
                                debug!("Received control frame: {:?}", frame.frame_type());
                            }
                        }
                    }
                }
                Err(e) => {
                    return Err(Error::Io(e));
                }
            }
        }
    }

    /// Process SETTINGS frame from peer.
    fn process_settings_frame(&mut self, settings: &SettingsFrame) -> Result<()> {
        let mut peer_settings = PeerSettings::default();

        for setting in &settings.settings {
            match setting.identifier {
                SettingId::QpackMaxTableCapacity => {
                    peer_settings.qpack_max_table_capacity = setting.value;
                }
                SettingId::MaxFieldSectionSize => {
                    peer_settings.max_field_section_size = setting.value;
                }
                SettingId::QpackBlockedStreams => {
                    peer_settings.qpack_blocked_streams = setting.value;
                }
                SettingId::Reserved(_) => {
                    // Ignore unknown settings per RFC
                }
            }
        }

        self.peer_settings = Some(peer_settings);
        debug!("Processed peer SETTINGS");

        Ok(())
    }

    /// Handle QPACK encoder stream (from peer).
    async fn handle_qpack_encoder_stream(&mut self, mut stream: quicd_x::QuicStream) -> Result<()> {
        let mut buffer = BytesMut::with_capacity(4096);

        loop {
            match stream.read_buf(&mut buffer).await {
                Ok(0) => break,
                Ok(_) => {
                    self.qpack.process_encoder_stream_data(&buffer)?;
                    buffer.clear();
                }
                Err(e) => {
                    return Err(Error::Io(e));
                }
            }
        }

        Ok(())
    }

    /// Handle QPACK decoder stream (from peer).
    async fn handle_qpack_decoder_stream(&mut self, mut stream: quicd_x::QuicStream) -> Result<()> {
        let mut buffer = BytesMut::with_capacity(4096);

        loop {
            match stream.read_buf(&mut buffer).await {
                Ok(0) => break,
                Ok(_) => {
                    self.qpack.process_decoder_stream_data(&buffer)?;
                    buffer.clear();
                }
                Err(e) => {
                    return Err(Error::Io(e));
                }
            }
        }

        Ok(())
    }
}
