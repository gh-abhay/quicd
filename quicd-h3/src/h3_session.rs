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

/// Core HTTP/3 session implementation.
///
/// Manages the HTTP/3 protocol state, including control streams, QPACK,
/// request/response handling, and integration with the underlying QUIC transport.
pub struct H3Session<H: H3Handler> {
    handle: ConnectionHandle,
    qpack: Arc<QpackCodec>,
    control_stream_id: Option<u64>,
    server_control_send: Option<quicd_x::SendStream>,
    qpack_encoder_stream_id: Option<u64>,
    qpack_decoder_stream_id: Option<u64>,
    streams: HashMap<u64, StreamState>,
    max_stream_id: u64,
    handler: Arc<H>,
    client_settings_received: bool,
    max_field_section_size: u64,
    // QPACK settings
    qpack_max_table_capacity: u64,
    qpack_blocked_streams: u64,
    // Server push state
    max_push_id: u64,
    next_push_id: u64,
    push_streams: HashMap<u64, PushStreamState>,
}

#[derive(Debug)]
enum StreamState {
    Control,
    QpackEncoder,
    QpackDecoder,
    Request { headers_received: bool, body: Vec<Bytes>, send_stream: quicd_x::SendStream },
}

#[derive(Debug)]
enum PushStreamState {
    Promised { headers: Vec<(String, String)>, send_stream: Option<quicd_x::SendStream> },
    Pushed { headers_sent: bool, body: Vec<Bytes> },
    Cancelled,
}

impl<H: H3Handler> H3Session<H> {
    pub fn new(handle: ConnectionHandle, handler: H) -> Self {
        Self {
            handle,
            qpack: Arc::new(QpackCodec::new()),
            control_stream_id: None,
            server_control_send: None,
            qpack_encoder_stream_id: None,
            qpack_decoder_stream_id: None,
            streams: HashMap::new(),
            max_stream_id: 0,
            handler: Arc::new(handler),
            client_settings_received: false,
            max_field_section_size: 0, // 0 means no limit
            qpack_max_table_capacity: 0, // 0 means no dynamic table
            qpack_blocked_streams: 0, // 0 means no blocked streams allowed
            max_push_id: 0, // 0 means no pushes allowed initially
            next_push_id: 0,
            push_streams: HashMap::new(),
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
            AppEvent::UniStreamOpened { request_id: _, result } => {
                if let Ok(send_stream) = result {
                    // Assume this is our server control stream
                    self.server_control_send = Some(send_stream);
                    // Send SETTINGS frame
                    self.send_settings().await?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn initialize_session(&mut self) -> Result<(), H3Error> {
        // Open server control stream (unidirectional)
        let _request_id = self.handle.open_uni()
            .map_err(|e| H3Error::Connection(format!("failed to open control stream: {:?}", e)))?;
        
        // Wait for the stream to be opened
        // For now, assume it's immediate, but in practice, we need to handle the event
        // This is simplified; in real implementation, we'd wait for UniStreamOpened event
        // But for this example, we'll assume the request_id is handled elsewhere
        // Actually, since this is async, we need to handle it properly.
        // For simplicity, let's send SETTINGS after opening.
        // But to make it work, perhaps store the request_id and handle in event.

        // For now, let's assume we get the send_stream immediately (not realistic)
        // In proper implementation, we'd modify to handle the async opening.

        // Since the API is async, we need to wait for the event.
        // But initialize_session is called synchronously.
        // Perhaps make initialize_session async and handle the opening there.

        // To simplify, let's open the stream and assume we get the send_stream via event.
        // But for SETTINGS, we can send it when we get the UniStreamOpened event.

        Ok(())
    }

    async fn handle_bidirectional_stream(
        &mut self,
        stream_id: u64,
        mut recv_stream: quicd_x::RecvStream,
        send_stream: Option<quicd_x::SendStream>,
    ) -> Result<(), H3Error> {
        // RFC 9114 Section 6.1: Server MUST NOT process requests until client SETTINGS received
        if !self.client_settings_received {
            return Err(H3Error::Http("client SETTINGS not received".into()));
        }
        
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
        // Determine stream type based on first byte or convention
        // For HTTP/3, control stream has type 0x00
        if let Ok(Some(quicd_x::StreamData::Data(bytes))) = recv_stream.read().await {
            if bytes.len() >= 1 {
                let stream_type = bytes[0];
                match stream_type {
                    0x00 => {
                        self.control_stream_id = Some(stream_id);
                        self.streams.insert(stream_id, StreamState::Control);
                        // Process SETTINGS frame
                        let settings_data = bytes.slice(1..);
                        self.process_settings(settings_data)?;
                    }
                    0x02 => {
                        self.qpack_encoder_stream_id = Some(stream_id);
                        self.streams.insert(stream_id, StreamState::QpackEncoder);
                        // Process remaining QPACK encoder instructions
                        let encoder_data = bytes.slice(1..);
                        if !encoder_data.is_empty() {
                            self.process_qpack_instructions(stream_id, encoder_data).await?;
                        }
                    }
                    0x03 => {
                        self.qpack_decoder_stream_id = Some(stream_id);
                        self.streams.insert(stream_id, StreamState::QpackDecoder);
                        // Process remaining QPACK decoder instructions
                        let decoder_data = bytes.slice(1..);
                        if !decoder_data.is_empty() {
                            self.process_qpack_instructions(stream_id, decoder_data).await?;
                        }
                    }
                    _ => {}
                }
            }
        }
        
        // Continue reading from control and QPACK streams
        if matches!(self.streams.get(&stream_id), Some(StreamState::Control) | Some(StreamState::QpackEncoder) | Some(StreamState::QpackDecoder)) {
            while let Ok(Some(data)) = recv_stream.read().await {
                match data {
                    quicd_x::StreamData::Data(bytes) => {
                        match self.streams.get(&stream_id) {
                            Some(StreamState::Control) => {
                                self.process_control_frames(bytes).await?;
                            }
                            Some(StreamState::QpackEncoder) | Some(StreamState::QpackDecoder) => {
                                self.process_qpack_instructions(stream_id, bytes).await?;
                            }
                            _ => {}
                        }
                    }
                    quicd_x::StreamData::Fin => {
                        // Stream ended
                        break;
                    }
                }
            }
        }
        
        Ok(())
    }

    async fn handle_stream_readable(&mut self, _stream_id: u64) -> Result<(), H3Error> {
        // Stream has data available
        // This is edge-triggered, so we can read now
        Ok(())
    }

    fn process_settings(&mut self, data: Bytes) -> Result<(), H3Error> {
        // Parse SETTINGS frame
        if let Ok((H3Frame::Settings { settings }, _)) = H3Frame::parse(&data) {
            self.client_settings_received = true;
            // Process settings
            for setting in settings {
                match setting.identifier {
                    0x1 => {
                        // SETTINGS_QPACK_MAX_TABLE_CAPACITY
                        self.qpack_max_table_capacity = setting.value;
                        // Update QPACK codec
                        if let Some(qpack) = Arc::get_mut(&mut self.qpack) {
                            qpack.set_max_table_capacity(setting.value as usize);
                        }
                    }
                    0x6 => {
                        // SETTINGS_MAX_FIELD_SECTION_SIZE
                        self.max_field_section_size = setting.value;
                    }
                    0x7 => {
                        // SETTINGS_QPACK_BLOCKED_STREAMS
                        self.qpack_blocked_streams = setting.value;
                        // Update QPACK codec
                        if let Some(qpack) = Arc::get_mut(&mut self.qpack) {
                            qpack.set_max_blocked_streams(setting.value as usize);
                        }
                    }
                    _ => {
                        // Unknown setting, ignore as per RFC
                    }
                }
            }
        }
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
            match frame {
                H3Frame::MaxPushId { push_id } => {
                    // Client is advertising maximum push ID it will accept
                    self.max_push_id = push_id;
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
        if let Some(push_state) = self.push_streams.get_mut(&push_id) {
            *push_state = PushStreamState::Cancelled;
            // TODO: Close the push stream if it's active
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