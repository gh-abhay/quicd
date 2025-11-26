use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;

use quicd_x::{AppEvent, ConnectionHandle, QuicAppFactory, ShutdownFuture, TransportControls};

use crate::error::H3Error;
use crate::frames::{H3Frame, Setting};
use crate::qpack::QpackCodec;
use crate::session::{H3Handler, H3Request, H3ResponseSender};
use crate::stream_state::{StreamFrameParser, StreamState as FrameStreamState};
use crate::validation::{validate_request_headers, RequestPseudoHeaders};
use crate::qpack_streams::QpackStreamManager;
use crate::settings::{SettingsValidator, SettingsBuilder};
use crate::connect::{ConnectTunnel, validate_connect_request};
use crate::push::PushManager;

/// Core HTTP/3 session implementation.
///
/// Manages the HTTP/3 protocol state, including control streams, QPACK,
/// request/response handling, and integration with the underlying QUIC transport.
pub struct H3Session<H: H3Handler> {
    handle: ConnectionHandle,
    qpack: Arc<QpackCodec>,
    control_stream_id: Option<u64>,
    server_control_send: Option<quicd_x::SendStream>,
    streams: HashMap<u64, StreamState>,
    max_stream_id: u64,
    handler: Arc<H>,
    push_manager: Arc<tokio::sync::Mutex<PushManager>>,
    pending_control_stream_request: Option<u64>,
    pending_push_streams: HashMap<u64, u64>, // request_id -> push_id
    // New RFC-compliant components
    settings_validator: SettingsValidator,
    qpack_manager: QpackStreamManager,
    stream_parsers: HashMap<u64, StreamFrameParser>,
    connect_tunnels: HashMap<u64, ConnectTunnel>,
    // Server push state
    max_push_id: u64,
    _next_push_id: u64,
    _push_streams: HashMap<u64, PushStreamState>,
}

#[derive(Debug)]
enum StreamState {
    Control,
    QpackEncoder,
    QpackDecoder,
    Request { headers_received: bool, body: Vec<Bytes>, send_stream: quicd_x::SendStream },
}

#[derive(Debug)]
#[allow(dead_code)]
enum PushStreamState {
    Promised { headers: Vec<(String, String)>, send_stream: Option<quicd_x::SendStream> },
    Pushed { headers_sent: bool, body: Vec<Bytes> },
    Cancelled,
}

impl<H: H3Handler> H3Session<H> {
    pub fn new(handle: ConnectionHandle, handler: H) -> Self {
        // Create push manager for server push support
        let push_manager = Arc::new(tokio::sync::Mutex::new(PushManager::new()));
        
        Self {
            handle,
            qpack: Arc::new(QpackCodec::new()),
            control_stream_id: None,
            server_control_send: None,
            streams: HashMap::new(),
            max_stream_id: 0,
            handler: Arc::new(handler),
            push_manager,
            pending_control_stream_request: None,
            pending_push_streams: HashMap::new(),
            // New RFC-compliant components
            settings_validator: SettingsValidator::new(),
            qpack_manager: QpackStreamManager::new(),
            stream_parsers: HashMap::new(),
            connect_tunnels: HashMap::new(),
            // Server push state
            max_push_id: 0,
            _next_push_id: 0,
            _push_streams: HashMap::new(),
        }
    }

    /// Main event loop for the HTTP/3 session.
    pub async fn run(
        mut self,
        mut events: quicd_x::AppEventStream,
        mut shutdown: ShutdownFuture,
    ) -> Result<(), H3Error> {
        loop {
            tokio::select! {
                Some(event) = events.next() => {
                    if let Err(e) = self.handle_event(event).await {
                        eprintln!("Error handling event: {:?}", e);
                        // Continue processing other events
                    }
                }
                _ = &mut shutdown => {
                    // Graceful shutdown
                    self.send_goaway().await?;
                    self.handle.close(0, None).map_err(|e| H3Error::Connection(format!("close error: {:?}", e)))?;
                    break;
                }
            }
        }
        Ok(())
    }

    async fn handle_event(&mut self, event: AppEvent) -> Result<(), H3Error> {
        match event {
            AppEvent::HandshakeCompleted { alpn, .. } => {
                if alpn.starts_with("h3") {
                    // Initialize HTTP/3 session
                    self.initialize_session().await?;
                }
            }
            AppEvent::NewStream { stream_id, bidirectional, recv_stream, send_stream } => {
                self.max_stream_id = self.max_stream_id.max(stream_id);
                if bidirectional {
                    self.handle_bidirectional_stream(stream_id, recv_stream, send_stream).await?;
                } else {
                    // Unidirectional stream (push or control)
                    self.handle_unidirectional_stream(stream_id, recv_stream).await?;
                }
            }
            AppEvent::StreamReadable { stream_id } => {
                self.handle_stream_readable(stream_id).await?;
            }
            AppEvent::StreamFinished { stream_id: _ } => {
                // Handle stream end
            }
            AppEvent::ConnectionClosing { .. } => {
                // Cleanup
            }
            AppEvent::UniStreamOpened { request_id, result } => {
                if Some(request_id) == self.pending_control_stream_request {
                    // This is our server control stream
                    self.pending_control_stream_request = None;
                    if let Ok(send_stream) = result {
                        self.server_control_send = Some(send_stream);
                        // Send SETTINGS frame immediately as required by RFC 9114
                        self.send_settings().await?;
                    } else {
                        return Err(H3Error::Connection("failed to open server control stream".into()));
                    }
                } else if self.pending_push_streams.contains_key(&request_id) {
                    // This is a push stream
                    if let Ok(send_stream) = result {
                        let push_id = self.pending_push_streams.remove(&request_id).unwrap();
                        
                        // Write push stream type header (0x01) per RFC 9114 Section 6.2.2
                        let stream_type = vec![0x01];
                        send_stream.write(Bytes::from(stream_type), false).await
                            .map_err(|e| H3Error::Stream(format!("failed to write stream type: {:?}", e)))?;
                        
                        // Write push ID as varint
                        let push_id_bytes = self.encode_varint(push_id);
                        send_stream.write(Bytes::from(push_id_bytes), false).await
                            .map_err(|e| H3Error::Stream(format!("failed to write push ID: {:?}", e)))?;
                        
                        // Notify PushManager that stream opened
                        if let Ok(mut manager) = self.push_manager.try_lock() {
                            let stream_id = send_stream.stream_id;
                            manager.handle_stream_opened(request_id, stream_id)?;
                        }
                        
                        // TODO: Send the actual push response (status, headers, body)
                        // This would require storing the response data in the PushPromise
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn initialize_session(&mut self) -> Result<(), H3Error> {
        // Open server control stream (unidirectional, stream ID 2)
        // This must be the first unidirectional stream opened by the server
        let request_id = self.handle.open_uni()
            .map_err(|e| H3Error::Connection(format!("failed to open control stream: {:?}", e)))?;
        
        // Store the request ID to correlate with the UniStreamOpened event
        self.pending_control_stream_request = Some(request_id);
        
        Ok(())
    }

    async fn handle_bidirectional_stream(
        &mut self,
        stream_id: u64,
        mut recv_stream: quicd_x::RecvStream,
        send_stream: Option<quicd_x::SendStream>,
    ) -> Result<(), H3Error> {
        // RFC 9114 Section 6.1: Server MUST NOT process requests until client SETTINGS received
        if !self.settings_validator.is_received() {
            return Err(H3Error::MissingSettings);
        }
        
        // Initialize stream parser for this stream
        self.stream_parsers.insert(stream_id, StreamFrameParser::new(stream_id));
        
        self.streams.insert(stream_id, StreamState::Request {
            headers_received: false,
            body: Vec::new(),
            send_stream: send_stream.unwrap(), // bidirectional, so should have send_stream
        });

        // Read frames from the stream
        while let Ok(Some(data)) = recv_stream.read().await {
            match data {
                quicd_x::StreamData::Data(bytes) => {
                    self.process_stream_data(stream_id, bytes).await?;
                }
                quicd_x::StreamData::Fin => {
                    self.handle_request_complete(stream_id).await?;
                    break;
                }
            }
        }

        Ok(())
    }

    async fn handle_unidirectional_stream(
        &mut self,
        stream_id: u64,
        mut recv_stream: quicd_x::RecvStream,
    ) -> Result<(), H3Error> {
        // RFC 9114 Section 6.2: Read stream type from first bytes
        // "The purpose is indicated by a stream type, which is sent as a 
        // variable-length integer at the start of the stream."
        
        let stream_type = self.read_stream_type(&mut recv_stream).await?;
        
        match stream_type {
            0x00 => {
                // Control stream (RFC 9114 Section 6.2.1)
                if self.control_stream_id.is_some() {
                    return Err(H3Error::Connection(
                        "duplicate control stream".into()
                    ));
                }
                self.control_stream_id = Some(stream_id);
                self.streams.insert(stream_id, StreamState::Control);
                self.process_client_control_stream(stream_id, recv_stream).await?;
            }
            0x01 => {
                // Push stream (RFC 9114 Section 6.2.2)
                // Read push ID and process push stream
                self.process_push_stream(stream_id, recv_stream).await?;
            }
            0x02 => {
                // QPACK encoder stream (RFC 9204 Section 4.2)
                if self.qpack_manager.has_encoder_stream() {
                    return Err(H3Error::Connection(
                        "duplicate QPACK encoder stream".into()
                    ));
                }
                self.qpack_manager.set_encoder_stream(stream_id);
                self.streams.insert(stream_id, StreamState::QpackEncoder);
                self.process_qpack_stream(stream_id, recv_stream).await?;
            }
            0x03 => {
                // QPACK decoder stream (RFC 9204 Section 4.2)
                if self.qpack_manager.has_decoder_stream() {
                    return Err(H3Error::Connection(
                        "duplicate QPACK decoder stream".into()
                    ));
                }
                self.qpack_manager.set_decoder_stream(stream_id);
                self.streams.insert(stream_id, StreamState::QpackDecoder);
                self.process_qpack_stream(stream_id, recv_stream).await?;
            }
            0x21..=0x3f if (stream_type - 0x21) % 0x1f == 0 => {
                // Reserved stream types (RFC 9114 Section 6.2)
                // MUST be ignored but stream still consumes resources
                eprintln!("received reserved stream type: {:#x}", stream_type);
                self.consume_stream_silently(recv_stream).await;
            }
            _ => {
                // Unknown stream type (RFC 9114 Section 6.2)
                // MUST be consumed but not processed
                eprintln!("received unknown stream type: {:#x}, consuming silently", stream_type);
                self.consume_stream_silently(recv_stream).await;
            }
        }
        
        Ok(())
    }

    async fn process_client_control_stream(
        &mut self,
        _stream_id: u64,
        mut recv_stream: quicd_x::RecvStream,
    ) -> Result<(), H3Error> {
        // Read frames from the client control stream
        while let Ok(Some(data)) = recv_stream.read().await {
            match data {
                quicd_x::StreamData::Data(bytes) => {
                    self.process_control_frames(bytes).await?;
                }
                quicd_x::StreamData::Fin => {
                    // Control stream ended - this is an error per RFC 9114
                    return Err(H3Error::Http("client control stream ended unexpectedly".into()));
                }
            }
        }
        Ok(())
    }

    async fn process_qpack_stream(
        &mut self,
        _stream_id: u64,
        mut recv_stream: quicd_x::RecvStream,
    ) -> Result<(), H3Error> {
        // Read QPACK instructions from the stream
        while let Ok(Some(data)) = recv_stream.read().await {
            match data {
                quicd_x::StreamData::Data(bytes) => {
                    self.process_qpack_instructions(_stream_id, bytes).await?;
                }
                quicd_x::StreamData::Fin => {
                    // QPACK stream ended
                    break;
                }
            }
        }
        Ok(())
    }

    async fn handle_stream_readable(&mut self, _stream_id: u64) -> Result<(), H3Error> {
        // Stream has data available - this is edge-triggered
        // For now, we handle data in the main stream processing methods
        // This could be used for more sophisticated backpressure handling
        Ok(())
    }

    async fn send_settings(&mut self) -> Result<(), H3Error> {
        if let Some(send_stream) = &mut self.server_control_send {
            // Send SETTINGS frame
            let settings = H3Frame::Settings { settings: vec![
                Setting { identifier: 0x1, value: 4096 }, // SETTINGS_QPACK_MAX_TABLE_CAPACITY (4KB default)
                Setting { identifier: 0x6, value: 0 }, // SETTINGS_MAX_FIELD_SECTION_SIZE (unlimited)
                Setting { identifier: 0x7, value: 100 }, // SETTINGS_QPACK_BLOCKED_STREAMS (100 default)
            ]};
            let frame_data = settings.encode();
            send_stream.write(frame_data, false).await
                .map_err(|e| H3Error::Stream(format!("failed to send SETTINGS: {:?}", e)))?;
            
            // Send MAX_PUSH_ID frame (advertise that we can send pushes)
            let max_push_id = H3Frame::MaxPushId { push_id: 1000 }; // Allow up to 1000 pushes
            let push_id_data = max_push_id.encode();
            send_stream.write(push_id_data, false).await
                .map_err(|e| H3Error::Stream(format!("failed to send MAX_PUSH_ID: {:?}", e)))?;
        }
        Ok(())
    }

    async fn send_goaway(&mut self) -> Result<(), H3Error> {
        if let Some(send_stream) = &mut self.server_control_send {
            // Send GOAWAY frame with last stream ID
            let goaway = H3Frame::GoAway { stream_id: self.max_stream_id };
            let frame_data = goaway.encode();
            send_stream.write(frame_data, false).await
                .map_err(|e| H3Error::Stream(format!("failed to send GOAWAY: {:?}", e)))?;
        }
        Ok(())
    }

    async fn process_stream_data(&mut self, stream_id: u64, data: Bytes) -> Result<(), H3Error> {
        let mut request_to_handle = None;

        if let Some(StreamState::Request { headers_received, body, send_stream }) = self.streams.get_mut(&stream_id) {
            if !*headers_received {
                // Try to parse different frame types
                if let Ok((frame, _)) = H3Frame::parse(&data) {
                    match frame {
                        H3Frame::Headers { encoded_headers } => {
                            let headers = self.qpack.decode_headers(&encoded_headers)?;
                            *headers_received = true;
                            // Parse request outside the borrow
                            request_to_handle = Some((headers, send_stream.clone()));
                        }
                        H3Frame::Priority { priority } => {
                            // Handle priority update
                            self.handle_priority_frame(stream_id, priority).await?;
                        }
                        _ => {
                            // Other frames on request stream - ignore for now
                        }
                    }
                }
            } else {
                // Try to parse different frame types
                if let Ok((frame, _)) = H3Frame::parse(&data) {
                    match frame {
                        H3Frame::Data { data: body_data } => {
                            body.push(body_data);
                        }
                        H3Frame::Priority { priority } => {
                            // Handle priority update
                            self.handle_priority_frame(stream_id, priority).await?;
                        }
                        _ => {
                            // Other frames - ignore for now
                        }
                    }
                }
            }
        }

        if let Some((headers, send_stream)) = request_to_handle {
            let request = self.parse_request(headers)?;
            // Call handler
            let mut sender = H3ResponseSender {
                send_stream,
                qpack: self.qpack.clone(),
                push_manager: Some(self.push_manager.clone()),
                connection_handle: Some(self.handle.clone()),
                stream_id,
            };
            self.handler.handle_request(request, &mut sender).await?;
        }

        Ok(())
    }

    async fn handle_request_complete(&mut self, _stream_id: u64) -> Result<(), H3Error> {
        // Request finished
        Ok(())
    }

    async fn process_control_frames(&mut self, data: Bytes) -> Result<(), H3Error> {
        // Parse control frames
        if let Ok((frame, _)) = H3Frame::parse(&data) {
            // RFC 9114 Section 6.2.1: SETTINGS MUST be first frame on control stream
            match &frame {
                H3Frame::Settings { settings } => {
                    // Convert to HashMap for validator
                    let settings_map: HashMap<u64, u64> = settings.iter()
                        .map(|s| (s.identifier, s.value))
                        .collect();
                    
                    // Validate and process SETTINGS
                    self.settings_validator.validate_settings(settings_map.clone())?;
                    
                    // Update QPACK codec with settings (requires Arc::get_mut)
                    if let Some(qpack) = Arc::get_mut(&mut self.qpack) {
                        if let Some(&capacity) = settings_map.get(&0x1) {
                            qpack.set_max_table_capacity(capacity as usize);
                        }
                        if let Some(&blocked) = settings_map.get(&0x7) {
                            qpack.set_max_blocked_streams(blocked as usize);
                        }
                    }
                }
                _ => {
                    // Validate that SETTINGS was first frame
                    self.settings_validator.validate_first_frame()?;
                }
            }
            
            match frame {
                H3Frame::Settings { .. } => {
                    // Already processed above
                }
                H3Frame::MaxPushId { push_id } => {
                    // Client is advertising maximum push ID it will accept
                    self.max_push_id = push_id;
                    // Update push manager
                    if let Ok(mut manager) = self.push_manager.try_lock() {
                        manager.update_max_push_id(push_id);
                    }
                }
                H3Frame::CancelPush { push_id } => {
                    // Client wants to cancel a push
                    self.cancel_push(push_id).await?;
                }
                H3Frame::GoAway { stream_id: _ } => {
                    // Client is going away - stop processing new requests
                    // TODO: Implement graceful shutdown
                }
                _ => {
                    // Other control frames - ignore for now
                }
            }
        }
        Ok(())
    }

    async fn cancel_push(&mut self, push_id: u64) -> Result<(), H3Error> {
        // Use PushManager to handle cancellation
        if let Ok(mut manager) = self.push_manager.try_lock() {
            manager.cancel_push(push_id)?;
        }
        Ok(())
    }

    async fn handle_priority_frame(&mut self, _stream_id: u64, priority: crate::frames::Priority) -> Result<(), H3Error> {
        // Basic priority handling - for now, just log the priority information
        // In a full implementation, this would update request scheduling priorities
        
        match priority.prioritized_element_type {
            0x00 => {
                // Request stream prioritization
                // TODO: Implement request prioritization logic
                // For now, we acknowledge but don't change processing order
            }
            0x01 => {
                // Push stream prioritization
                // TODO: Implement push stream prioritization
            }
            _ => {
                // Unknown element type - ignore
            }
        }
        
        Ok(())
    }

    async fn process_qpack_instructions(&mut self, stream_id: u64, data: Bytes) -> Result<(), H3Error> {
        let instructions = data.as_ref();
        let mut cursor = 0;
        
        while cursor < instructions.len() {
            match self.qpack.decode_instruction(&instructions[cursor..]) {
                Ok((instruction, consumed)) => {
                    cursor += consumed;
                    self.handle_qpack_instruction(stream_id, instruction).await?;
                }
                Err(e) => {
                    // If we can't decode an instruction, we might have partial data
                    // For now, return error
                    return Err(e);
                }
            }
        }
        
        Ok(())
    }

    async fn handle_qpack_instruction(&mut self, _stream_id: u64, instruction: crate::qpack::QpackInstruction) -> Result<(), H3Error> {
        match instruction {
            crate::qpack::QpackInstruction::SetDynamicTableCapacity { capacity } => {
                // Update dynamic table capacity
                Arc::get_mut(&mut self.qpack)
                    .ok_or_else(|| H3Error::Qpack("cannot modify shared QPACK codec".into()))?
                    .set_max_table_capacity(capacity as usize);
            }
            crate::qpack::QpackInstruction::InsertWithNameReference { static_table, name_index, value } => {
                // Insert entry into dynamic table
                if let Some(qpack) = Arc::get_mut(&mut self.qpack) {
                    let name = if static_table {
                        if let Some((name, _)) = qpack.get_static_entry(name_index as usize) {
                            name.clone()
                        } else {
                            return Err(H3Error::Qpack("invalid static table index".into()));
                        }
                    } else {
                        if let Some((name, _)) = qpack.get_absolute(name_index as usize) {
                            name.clone()
                        } else {
                            return Err(H3Error::Qpack("invalid dynamic table index".into()));
                        }
                    };
                    
                    qpack.insert(name, value);
                }
            }
            crate::qpack::QpackInstruction::InsertWithLiteralName { name, value } => {
                // Insert entry into dynamic table
                if let Some(qpack) = Arc::get_mut(&mut self.qpack) {
                    qpack.insert(name, value);
                }
            }
            crate::qpack::QpackInstruction::Duplicate { index } => {
                // Duplicate entry in dynamic table
                if let Some(qpack) = Arc::get_mut(&mut self.qpack) {
                    qpack.duplicate(index as usize);
                }
            }
            crate::qpack::QpackInstruction::SectionAcknowledgment { stream_id: _ } => {
                // Acknowledge header section - for now, just update known received count
                if let Some(qpack) = Arc::get_mut(&mut self.qpack) {
                    // TODO: proper section acknowledgment handling
                    qpack.update_known_received_count(qpack.known_received_count() + 1);
                }
            }
            crate::qpack::QpackInstruction::StreamCancellation { stream_id: _ } => {
                // Cancel stream - for now, just log
                // TODO: proper stream cancellation
            }
            crate::qpack::QpackInstruction::InsertCountIncrement { increment } => {
                // Update known received count
                if let Some(qpack) = Arc::get_mut(&mut self.qpack) {
                    qpack.update_known_received_count(qpack.known_received_count() + increment as usize);
                }
            }
        }
        
        Ok(())
    }

    /// Parse headers into HTTP request (public for testing)
    pub fn parse_request(&self, headers: Vec<(String, String)>) -> Result<H3Request, H3Error> {
        // Parse headers into HTTP request
        // Simplified
        let mut method = None;
        let mut path = None;
        let mut scheme = None;
        let mut authority = None;
        let mut header_vec = Vec::new();

        for (name, value) in headers {
            match name.as_str() {
                ":method" => method = Some(value.parse().map_err(|_| H3Error::Http("invalid method".into()))?),
                ":path" => {
                    path = Some(value);
                }
                ":scheme" => scheme = Some(value),
                ":authority" => authority = Some(value),
                _ => {
                    header_vec.push((name, value));
                }
            }
        }

        let method = method.ok_or_else(|| H3Error::Http("missing :method".into()))?;
        let scheme = scheme.ok_or_else(|| H3Error::Http("missing :scheme".into()))?;
        let authority = authority.ok_or_else(|| H3Error::Http("missing :authority".into()))?;
        let path = path.unwrap_or_else(|| "/".to_string());
        
        // Construct URI from components
        let uri_string = format!("{}://{}{}", scheme, authority, path);
        let uri = uri_string.parse().map_err(|_| H3Error::Http("invalid uri construction".into()))?;

        Ok(H3Request {
            method,
            uri,
            headers: header_vec,
            body: None,
        })
    }

    /// Read stream type from the first bytes of a unidirectional stream (RFC 9114 Section 6.2)
    async fn read_stream_type(&self, recv_stream: &mut quicd_x::RecvStream) -> Result<u64, H3Error> {
        // Read first bytes for stream type varint
        let data = match recv_stream.read().await {
            Ok(Some(quicd_x::StreamData::Data(bytes))) => bytes,
            Ok(Some(quicd_x::StreamData::Fin)) => {
                return Err(H3Error::Connection("stream ended before stream type".into()));
            }
            Ok(None) => {
                return Err(H3Error::Connection("no data on stream".into()));
            }
            Err(e) => {
                return Err(H3Error::Stream(format!("failed to read stream type: {:?}", e)));
            }
        };

        let (stream_type, _consumed) = crate::frames::H3Frame::decode_varint(&data)
            .map_err(|e| H3Error::FrameParse(format!("invalid stream type varint: {:?}", e)))?;
        
        Ok(stream_type)
    }

    /// Process a push stream (RFC 9114 Section 6.2.2)
    async fn process_push_stream(&mut self, _stream_id: u64, mut recv_stream: quicd_x::RecvStream) -> Result<(), H3Error> {
        // Read push ID (varint)
        let data = match recv_stream.read().await {
            Ok(Some(quicd_x::StreamData::Data(bytes))) => bytes,
            _ => return Err(H3Error::Connection("failed to read push ID".into())),
        };

        let (push_id, _consumed) = crate::frames::H3Frame::decode_varint(&data)
            .map_err(|e| H3Error::FrameParse(format!("invalid push ID: {:?}", e)))?;

        // TODO: Properly handle push promise state and stream processing
        // Push streams are unidirectional, so we can't send responses back on them
        // They need to be associated with a push promise sent on a bidirectional stream
        eprintln!("Push stream with push ID {}: not fully implemented", push_id);
        
        // For now, consume the stream silently
        self.consume_stream_silently(recv_stream).await;
        
        Ok(())
    }

    /// Consume a stream silently (for reserved or unknown stream types)
    async fn consume_stream_silently(&self, mut recv_stream: quicd_x::RecvStream) {
        // Read and discard all data from the stream
        loop {
            match recv_stream.read().await {
                Ok(Some(quicd_x::StreamData::Data(_))) => {
                    // Discard data
                    continue;
                }
                Ok(Some(quicd_x::StreamData::Fin)) | Ok(None) | Err(_) => {
                    break;
                }
            }
        }
    }

    /// Send Section Acknowledgment on decoder stream (RFC 9204 Section 4.4.1)
    async fn _send_section_acknowledgment(&mut self, stream_id: u64) -> Result<(), H3Error> {
        // TODO: Open and track decoder stream to send acknowledgments
        // For now, this is a placeholder
        eprintln!("TODO: Send Section Acknowledgment for stream {}", stream_id);
        Ok(())
    }

    /// Send Stream Cancellation on decoder stream (RFC 9204 Section 4.4.2)
    async fn _send_stream_cancellation(&mut self, stream_id: u64) -> Result<(), H3Error> {
        // TODO: Open and track decoder stream to send cancellations
        // For now, this is a placeholder
        eprintln!("TODO: Send Stream Cancellation for stream {}", stream_id);
        Ok(())
    }

    /// Send Insert Count Increment on decoder stream (RFC 9204 Section 4.4.3)
    async fn _send_insert_count_increment(&mut self, increment: u64) -> Result<(), H3Error> {
        // TODO: Open and track decoder stream to send increments
        // For now, this is a placeholder
        eprintln!("TODO: Send Insert Count Increment: {}", increment);
        Ok(())
    }

    /// Encode a value as a QUIC variable-length integer.
    ///
    /// Per RFC 9000 Section 16: Variable-length integers are encoded using
    /// 1, 2, 4, or 8 bytes, with a 2-bit prefix indicating the length.
    fn encode_varint(&self, value: u64) -> Vec<u8> {
        if value < 64 {
            // 1-byte encoding: 00xxxxxx
            vec![value as u8]
        } else if value < 16384 {
            // 2-byte encoding: 01xxxxxx xxxxxxxx
            vec![
                (0x40 | (value >> 8)) as u8,
                (value & 0xff) as u8,
            ]
        } else if value < 1073741824 {
            // 4-byte encoding: 10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
            vec![
                (0x80 | (value >> 24)) as u8,
                ((value >> 16) & 0xff) as u8,
                ((value >> 8) & 0xff) as u8,
                (value & 0xff) as u8,
            ]
        } else {
            // 8-byte encoding: 11xxxxxx ... (8 bytes total)
            vec![
                (0xc0 | (value >> 56)) as u8,
                ((value >> 48) & 0xff) as u8,
                ((value >> 40) & 0xff) as u8,
                ((value >> 32) & 0xff) as u8,
                ((value >> 24) & 0xff) as u8,
                ((value >> 16) & 0xff) as u8,
                ((value >> 8) & 0xff) as u8,
                (value & 0xff) as u8,
            ]
        }
    }
}

/// Factory for creating HTTP/3 application instances.
pub struct H3Factory<H: H3Handler> {
    handler: H,
}

impl<H: H3Handler> H3Factory<H> {
    pub fn new(handler: H) -> Self {
        Self { handler }
    }
}

#[async_trait]
impl<H: H3Handler + Clone> QuicAppFactory for H3Factory<H> {
    fn accepts_alpn(&self, alpn: &str) -> bool {
        alpn == "h3" || alpn == "h3-29"
    }

    async fn spawn_app(
        &self,
        _alpn: String,
        handle: ConnectionHandle,
        events: quicd_x::AppEventStream,
        _transport: TransportControls,
        shutdown: ShutdownFuture,
    ) -> Result<(), quicd_x::ConnectionError> {
        let session = H3Session::new(handle, self.handler.clone());
        session.run(events, shutdown).await
            .map_err(|e| quicd_x::ConnectionError::App(format!("HTTP/3 error: {:?}", e)))
    }
}