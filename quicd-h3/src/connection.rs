//! HTTP/3 connection lifecycle and main event loop.
//!
//! This module implements the `QuicdApplication` trait from quicd-x, providing
//! the HTTP/3 protocol implementation that runs as a single Tokio task per connection.

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use quicd_x::{ConnectionHandle, QuicdApplication, StreamId};
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
    
    // QPACK stream IDs
    our_encoder_stream: Option<StreamId>,
    our_decoder_stream: Option<StreamId>,
    peer_encoder_stream: Option<StreamId>,
    peer_decoder_stream: Option<StreamId>,
    
    // Incremental parsing buffers for unidirectional streams
    control_stream_buffer: BytesMut,
    control_stream_parser: FrameParser,
    encoder_stream_buffer: BytesMut,
    decoder_stream_buffer: BytesMut,
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
            our_encoder_stream: None,
            our_decoder_stream: None,
            peer_encoder_stream: None,
            peer_decoder_stream: None,
            control_stream_buffer: BytesMut::new(),
            control_stream_parser: FrameParser::new(),
            encoder_stream_buffer: BytesMut::new(),
            decoder_stream_buffer: BytesMut::new(),
        }
    }

    /// Run the HTTP/3 connection event loop.
    ///
    /// This is the main event loop that processes all connection events
    /// using tokio::select! to multiplex I/O.
    ///
    /// Critical Architecture Note:
    /// We process streams inline to completion, which is safe since each stream
    /// operation (read, write) is async and yields control back to the event loop.
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
                        Ok(mut stream) => {
                            let stream_id = stream.stream_id();
                            debug!("Accepted bidirectional stream: {:?}", stream_id);
                            
                            // Process request stream inline
                            // Pass only the necessary mutable references, not &mut self
                            if let Err(e) = Self::process_request_stream(
                                &mut stream,
                                &mut self.qpack,
                                &self.handler,
                            ).await {
                                error!("Error handling request stream: {}", e);
                                if e.is_connection_error() {
                                    return Err(e);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Error accepting bidirectional stream: {}", e);
                            break;
                        }
                    }
                }

                // Accept incoming unidirectional streams (control, QPACK, push)
                stream_result = self.conn.accept_uni_stream() => {
                    match stream_result {
                        Ok(mut stream) => {
                            debug!("Accepted unidirectional stream");
                            
                            // Read stream type first (before we need to borrow self mutably)
                            let mut type_buffer = [0u8; 8];
                            match stream.read(&mut type_buffer).await {
                                Ok(0) => {
                                    warn!("Unidirectional stream closed before type could be read");
                                    continue;
                                }
                                Ok(n) => {
                                    let mut buf = BytesMut::from(&type_buffer[..n]);
                                    match read_stream_type(&mut buf) {
                                        Ok(stream_type) => {
                                            debug!("Unidirectional stream type: {:?}", stream_type);
                                            
                                            // Now process based on stream type
                                            // Pass only required fields, not &mut self
                                            let stream_id = stream.stream_id();
                                            let result = match stream_type {
                                                StreamType::Control => {
                                                    Self::process_control_stream(
                                                        &mut stream,
                                                        buf,
                                                        &mut self.control_stream_buffer,
                                                        &mut self.control_stream_parser,
                                                        &mut self.control_stream_received,
                                                        &mut self.peer_settings,
                                                    ).await
                                                }
                                                StreamType::QpackEncoder => {
                                                    Self::process_qpack_encoder_stream(
                                                        &mut stream,
                                                        stream_id,
                                                        buf,
                                                        &mut self.encoder_stream_buffer,
                                                        &mut self.peer_encoder_stream,
                                                        &mut self.qpack,
                                                    ).await
                                                }
                                                StreamType::QpackDecoder => {
                                                    Self::process_qpack_decoder_stream(
                                                        &mut stream,
                                                        stream_id,
                                                        buf,
                                                        &mut self.decoder_stream_buffer,
                                                        &mut self.peer_decoder_stream,
                                                        &mut self.qpack,
                                                    ).await
                                                }
                                                StreamType::Push => {
                                                    Self::process_push_stream(&mut stream).await
                                                }
                                            };
                                            
                                            if let Err(e) = result {
                                                error!("Error handling unidirectional stream: {}", e);
                                                if e.is_connection_error() {
                                                    return Err(e);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            error!("Failed to read stream type: {}", e);
                                            return Err(e);
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!("Error reading stream type: {}", e);
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

    /// Process a bidirectional request stream.
    ///
    /// Reads HTTP/3 frames from the stream, parses the request, and sends the response.
    async fn process_request_stream(
        stream: &mut quicd_x::QuicStream<'_>,
        qpack: &mut QpackManager,
        handler: &FileHandler,
    ) -> Result<()> {
        let stream_id = stream.stream_id();
        debug!("Processing request stream: {:?}", stream_id);

        // Create stream state
        let mut parser = FrameParser::new();
        let mut request: Option<HttpRequest> = None;
        let mut headers_received = false;

        // Read from stream
        let mut buffer = vec![0u8; 8192];
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => {
                    // EOF - process complete request if we have one
                    if headers_received {
                        if let Some(req) = request.take() {
                            Self::handle_http_request(stream, req, qpack, handler).await?;
                        }
                    }
                    break;
                }
                Ok(n) => {
                    debug!("Read {} bytes from stream {:?}", n, stream_id);
                    
                    // Parse frames from received data
                    let frames = parser.parse(Bytes::copy_from_slice(&buffer[..n]))?;

                    for frame in frames {
                        match frame {
                            Frame::Headers(headers_frame) => {
                                if headers_received {
                                    // Trailers - not fully implemented yet
                                    debug!("Received trailers on stream {:?}", stream_id);
                                    continue;
                                }

                                // Decode QPACK field section
                                let fields = qpack.decode_field_section(
                                    stream_id.0,
                                    &headers_frame.encoded_field_section,
                                )?;

                                // Parse pseudo-headers
                                let (method, uri, headers) = parse_request_pseudo_headers(&fields)?;

                                // Create request object
                                request = Some(HttpRequest {
                                    method,
                                    uri,
                                    headers,
                                    body: Bytes::new(),
                                    trailers: None,
                                });

                                headers_received = true;
                                debug!("Received HEADERS frame on stream {:?}", stream_id);
                            }

                            Frame::Data(data_frame) => {
                                // Accumulate body data
                                if let Some(ref mut req) = request {
                                    let mut body_vec = req.body.to_vec();
                                    body_vec.extend_from_slice(&data_frame.payload);
                                    req.body = Bytes::from(body_vec);
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
                }
                Err(e) => {
                    error!("Error reading from stream {:?}: {}", stream_id, e);
                    return Err(Error::Io(e));
                }
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

    /// Handle a complete HTTP request and send response (static method).
    async fn handle_http_request(
        stream: &mut quicd_x::QuicStream<'_>,
        request: HttpRequest,
        qpack: &mut QpackManager,
        handler: &FileHandler,
    ) -> Result<()> {
        debug!("Handling HTTP request: {} {}", request.method, request.uri);

        // Invoke handler
        let response = handler.handle_request(&request).await?;

        // Send response
        Self::send_http_response(stream, &response, qpack).await?;

        Ok(())
    }

    /// Send an HTTP response on a stream (static method).
    async fn send_http_response(
        stream: &mut quicd_x::QuicStream<'_>,
        response: &HttpResponse,
        qpack: &mut QpackManager,
    ) -> Result<()> {
        // Convert response to field lines
        let fields = response_to_field_lines(response);

        // Encode with QPACK
        let stream_id = stream.stream_id();
        let encoded_fields = qpack.encode_field_section(stream_id.0, &fields)?;

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

    /// Process the control stream (static method).
    async fn process_control_stream(
        stream: &mut quicd_x::QuicStream<'_>,
        remaining_data: BytesMut,
        control_stream_buffer: &mut BytesMut,
        control_stream_parser: &mut FrameParser,
        control_stream_received: &mut bool,
        peer_settings: &mut Option<PeerSettings>,
    ) -> Result<()> {
        // Ensure we haven't seen a control stream before
        if *control_stream_received {
            return Err(Error::protocol(
                ErrorCode::StreamCreationError,
                "duplicate control stream",
            ));
        }
        
        // Add any remaining data from type read
        control_stream_buffer.extend_from_slice(&remaining_data);
        
        // Read from stream until EOF
        let mut buffer = vec![0u8; 8192];
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => {
                    // Control stream closed
                    error!("Control stream closed by peer");
                    return Err(Error::protocol(
                        ErrorCode::ClosedCriticalStream,
                        "control stream closed",
                    ));
                }
                Ok(n) => {
                    control_stream_buffer.extend_from_slice(&buffer[..n]);
                    // Process any complete frames
                    Self::process_control_frames(
                        control_stream_buffer,
                        control_stream_parser,
                        control_stream_received,
                        peer_settings,
                    )?;
                }
                Err(e) => {
                    error!("Error reading control stream: {}", e);
                    return Err(Error::Io(e));
                }
            }
        }
    }

    /// Process frames from the control stream buffer (static method).
    fn process_control_frames(
        control_stream_buffer: &mut BytesMut,
        control_stream_parser: &mut FrameParser,
        control_stream_received: &mut bool,
        peer_settings: &mut Option<PeerSettings>,
    ) -> Result<()> {
        // Parse frames from accumulated buffer
        let frames = control_stream_parser.parse(control_stream_buffer.split().freeze())?;

        for frame in frames {
            match frame {
                Frame::Settings(settings_frame) => {
                    if *control_stream_received {
                        return Err(Error::protocol(
                            ErrorCode::FrameUnexpected,
                            "duplicate SETTINGS frame",
                        ));
                    }

                    let mut settings = PeerSettings::default();
                    for setting in &settings_frame.settings {
                        match setting.identifier {
                            SettingId::QpackMaxTableCapacity => {
                                settings.qpack_max_table_capacity = setting.value;
                            }
                            SettingId::MaxFieldSectionSize => {
                                settings.max_field_section_size = setting.value;
                            }
                            SettingId::QpackBlockedStreams => {
                                settings.qpack_blocked_streams = setting.value;
                            }
                            SettingId::Reserved(_) => {
                                // Ignore unknown settings per RFC
                            }
                        }
                    }

                    *peer_settings = Some(settings);
                    *control_stream_received = true;
                    debug!("Received and processed SETTINGS frame");
                }
                Frame::Goaway(_) => {
                    // Peer is closing - handle gracefully
                    info!("Received GOAWAY from peer");
                }
                _ => {
                    // Other control frames - log and continue
                    debug!("Received control frame: {:?}", frame.frame_type());
                }
            }
        }

        Ok(())
    }

    /// Process the QPACK encoder stream (static method).
    async fn process_qpack_encoder_stream(
        stream: &mut quicd_x::QuicStream<'_>,
        stream_id: StreamId,
        remaining_data: BytesMut,
        encoder_stream_buffer: &mut BytesMut,
        peer_encoder_stream: &mut Option<StreamId>,
        qpack: &mut QpackManager,
    ) -> Result<()> {
        *peer_encoder_stream = Some(stream_id);
        
        // Add any remaining data from type read
        encoder_stream_buffer.extend_from_slice(&remaining_data);
        
        let mut buffer = vec![0u8; 8192];
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => {
                    debug!("QPACK encoder stream closed");
                    break;
                }
                Ok(n) => {
                    encoder_stream_buffer.extend_from_slice(&buffer[..n]);
                    // Process encoder instructions
                    if let Err(e) = qpack.process_encoder_stream_data(encoder_stream_buffer) {
                        error!("Error processing encoder stream: {}", e);
                        return Err(e);
                    }
                    encoder_stream_buffer.clear();
                }
                Err(e) => {
                    warn!("Error reading encoder stream: {}", e);
                    break;
                }
            }
        }
        Ok(())
    }

    /// Process the QPACK decoder stream (static method).
    async fn process_qpack_decoder_stream(
        stream: &mut quicd_x::QuicStream<'_>,
        stream_id: StreamId,
        remaining_data: BytesMut,
        decoder_stream_buffer: &mut BytesMut,
        peer_decoder_stream: &mut Option<StreamId>,
        qpack: &mut QpackManager,
    ) -> Result<()> {
        *peer_decoder_stream = Some(stream_id);
        
        // Add any remaining data from type read
        decoder_stream_buffer.extend_from_slice(&remaining_data);
        
        let mut buffer = vec![0u8; 8192];
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => {
                    debug!("QPACK decoder stream closed");
                    break;
                }
                Ok(n) => {
                    decoder_stream_buffer.extend_from_slice(&buffer[..n]);
                    // Process decoder instructions
                    if let Err(e) = qpack.process_decoder_stream_data(decoder_stream_buffer) {
                        error!("Error processing decoder stream: {}", e);
                        return Err(e);
                    }
                    decoder_stream_buffer.clear();
                }
                Err(e) => {
                    warn!("Error reading decoder stream: {}", e);
                    break;
                }
            }
        }
        Ok(())
    }

    /// Process a push stream (not fully implemented) (static method).
    async fn process_push_stream(stream: &mut quicd_x::QuicStream<'_>) -> Result<()> {
        warn!("Received push stream (not implemented)");
        // Read and discard push stream data for now
        let mut buffer = vec![0u8; 8192];
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        Ok(())
    }
}
