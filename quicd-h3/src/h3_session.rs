use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use tokio::sync::{Mutex as AsyncMutex, RwLock as AsyncRwLock};

use quicd_x::{AppEvent, ConnectionHandle, QuicAppFactory, ShutdownFuture, TransportControls};

use crate::error::H3Error;
use crate::frames::{H3Frame, Setting};
use crate::qpack::QpackCodec;
use crate::session::{H3Handler, H3Request, H3ResponseSender};
use crate::stream_state::StreamFrameParser;
use crate::qpack_streams::QpackStreamManager;
use crate::settings::SettingsValidator;
use crate::settings_storage::{InMemorySettingsStorage, Origin, SettingsStorage};
use crate::connect::validate_connect_request;
use crate::push::PushManager;
use crate::metrics::H3Metrics;
use crate::priority::PriorityTree;

/// Core HTTP/3 session implementation.
///
/// Manages the HTTP/3 protocol state, including control streams, QPACK,
/// request/response handling, and integration with the underlying QUIC transport.
pub struct H3Session<H: H3Handler> {
    handle: ConnectionHandle,
    qpack: Arc<AsyncRwLock<QpackCodec>>,
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
    // Server push state
    max_push_id: u64,
    _next_push_id: u64,
    _push_streams: HashMap<u64, PushStreamState>,
    // Phase 2: QPACK encoder/decoder streams
    encoder_stream_id: Option<u64>,
    decoder_stream_id: Option<u64>,
    pending_encoder_stream_request: Option<u64>,
    pending_decoder_stream_request: Option<u64>,
    // Encoder stream wrapped in Arc<Mutex> for sharing with H3ResponseSender
    encoder_send_stream: Arc<AsyncMutex<Option<quicd_x::SendStream>>>,
    decoder_send_stream: Option<quicd_x::SendStream>,
    // Phase 2: GOAWAY state
    goaway_sent: bool,
    goaway_received: bool,
    last_accepted_stream_id: u64,
    // RFC 9114 Section 5.2: Track max stream ID in sent GOAWAY for validation
    goaway_max_stream_id: Option<u64>,
    // Phase 2: Blocked streams tracking
    blocked_streams: HashMap<u64, BlockedStream>,
    // Priority queue for request processing (lower priority_id = higher priority)
    request_queue: std::collections::BinaryHeap<QueuedRequest>,
    // Track stream priorities
    stream_priorities: HashMap<u64, u64>, // stream_id -> priority_id
    // RFC 9218: Priority tree for extensible prioritization
    priority_tree: PriorityTree,
    // RFC 9204 Section 4.4.3: Track processed insert count for INSERT_COUNT_INCREMENT
    insert_count_processed: u64,
    // PERF #29: Batch QPACK decoder instructions to reduce lock contention
    pending_decoder_instructions: Vec<Bytes>,
    // Phase 1: Control stream lifecycle tracking (RFC 9114 Section 6.2.1)
    peer_control_stream_id: Option<u64>,
    peer_control_stream_received_settings: bool,
    peer_encoder_stream_id: Option<u64>,
    peer_decoder_stream_id: Option<u64>,
    // Phase 1: Stream type tracking for frame validation
    stream_types: HashMap<u64, StreamType>,
    // Phase 1: GOAWAY ID tracking for validation
    last_goaway_id: Option<u64>,
    // HTTP/3 operational metrics
    pub metrics: Arc<H3Metrics>,
    // 0-RTT settings storage (RFC 9114 Section 7.2.4.2)
    settings_storage: Arc<dyn SettingsStorage>,
    // Connection origin for settings storage
    origin: Option<Origin>,
    // RFC 9114 Section 5.1: Idle connection timeout tracking
    last_activity_time: std::time::Instant,
    idle_timeout: std::time::Duration,
}

/// Stream type context for validating frame associations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamType {
    Control,
    Request,
    QpackEncoder,
    QpackDecoder,
}

#[derive(Debug)]
enum StreamState {
    Control,
    QpackEncoder,
    QpackDecoder,
    Request { 
        headers_received: bool, 
        trailers_received: bool,
        body: Vec<Bytes>, 
        trailers: Option<Vec<(String, String)>>,
        send_stream: quicd_x::SendStream,
        // Phase 3: Content-Length validation (RFC 9114 Section 4.1.2)
        content_length: Option<u64>,  // From Content-Length header
        bytes_received: u64,          // Sum of DATA frame payload bytes
        // RFC 9204 Section 2.1.2: Track dynamic table references for this stream
        referenced_dynamic_entries: Vec<usize>,
    },
}

/// Blocked stream waiting for dynamic table entries
#[derive(Debug)]
struct BlockedStream {
    required_insert_count: usize,
    encoded_data: Bytes,
    send_stream: quicd_x::SendStream,
    stream_id: u64,
    blocked_at: std::time::Instant,
}

/// Queued request for priority-based processing
#[derive(Debug)]
struct QueuedRequest {
    priority_id: u64, // Lower values = higher priority
    stream_id: u64,
    headers: Vec<(String, String)>,
    send_stream: quicd_x::SendStream,
}

// Implement Ord for priority queue (lower urgency = higher priority per RFC 9218)
impl PartialOrd for QueuedRequest {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for QueuedRequest {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Reverse ordering: lower priority_id comes first (higher priority)
        other.priority_id.cmp(&self.priority_id)
            .then_with(|| self.stream_id.cmp(&other.stream_id))
    }
}

impl PartialEq for QueuedRequest {
    fn eq(&self, other: &Self) -> bool {
        self.priority_id == other.priority_id && self.stream_id == other.stream_id
    }
}

impl Eq for QueuedRequest {}

#[derive(Debug)]
#[allow(dead_code)]
enum PushStreamState {
    Promised { headers: Vec<(String, String)>, send_stream: Option<quicd_x::SendStream> },
    Pushed { headers_sent: bool, body: Vec<Bytes> },
    Cancelled,
}

impl<H: H3Handler> H3Session<H> {
    pub fn new(handle: ConnectionHandle, handler: H, settings_storage: Arc<dyn SettingsStorage>) -> Self {
        Self::with_origin(handle, handler, settings_storage, None)
    }

    pub fn with_origin(handle: ConnectionHandle, handler: H, settings_storage: Arc<dyn SettingsStorage>, origin: Option<Origin>) -> Self {
        // Create push manager for server push support
        let push_manager = Arc::new(AsyncMutex::new(PushManager::new()));
        
        // If we have an origin and remembered settings, create validator with them
        let settings_validator = if let Some(ref orig) = origin {
            if let Some(remembered) = settings_storage.retrieve(orig) {
                SettingsValidator::with_remembered_settings(remembered)
            } else {
                SettingsValidator::new()
            }
        } else {
            SettingsValidator::new()
        };
        
        Self {
            handle,
            qpack: Arc::new(AsyncRwLock::new(QpackCodec::new())),
            server_control_send: None,
            streams: HashMap::new(),
            max_stream_id: 0,
            handler: Arc::new(handler),
            push_manager,
            pending_control_stream_request: None,
            pending_push_streams: HashMap::new(),
            // New RFC-compliant components
            settings_validator,
            qpack_manager: QpackStreamManager::new(),
            stream_parsers: HashMap::new(),
            // Server push state
            max_push_id: 0,
            _next_push_id: 0,
            _push_streams: HashMap::new(),
            // Phase 2: QPACK encoder/decoder streams
            encoder_stream_id: None,
            decoder_stream_id: None,
            pending_encoder_stream_request: None,
            pending_decoder_stream_request: None,
            encoder_send_stream: Arc::new(AsyncMutex::new(None)),
            decoder_send_stream: None,
            // Phase 2: GOAWAY state
            goaway_sent: false,
            goaway_received: false,
            last_accepted_stream_id: u64::MAX,
            goaway_max_stream_id: None,
            // Phase 2: Blocked streams tracking
            blocked_streams: HashMap::new(),
            insert_count_processed: 0,
            pending_decoder_instructions: Vec::new(),
            // Phase 1: Control stream lifecycle tracking
            peer_control_stream_id: None,
            peer_control_stream_received_settings: false,
            peer_encoder_stream_id: None,
            peer_decoder_stream_id: None,
            // Phase 1: Stream type tracking
            stream_types: HashMap::new(),
            // Phase 1: GOAWAY tracking
            last_goaway_id: None,
            // Priority queue for request processing
            request_queue: std::collections::BinaryHeap::new(),
            // Track stream priorities
            stream_priorities: HashMap::new(),
            // RFC 9218: Priority tree
            priority_tree: PriorityTree::new(),
            // HTTP/3 operational metrics
            metrics: H3Metrics::new(),
            // 0-RTT settings storage
            settings_storage,
            origin,
            // RFC 9114 Section 5.1: Idle timeout tracking (default 30 seconds)
            last_activity_time: std::time::Instant::now(),
            idle_timeout: std::time::Duration::from_secs(30),
        }
    }

    /// Main event loop for the HTTP/3 session.
    pub async fn run(
        mut self,
        mut events: quicd_x::AppEventStream,
        mut shutdown: ShutdownFuture,
    ) -> Result<(), H3Error> {
        // RFC 9204 Section 2.1.4: Check for blocked stream timeouts periodically
        // We check every 10 seconds to catch streams that have been blocked > 60 seconds
        let mut timeout_check_interval = tokio::time::interval(std::time::Duration::from_secs(10));
        timeout_check_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        
        loop {
            tokio::select! {
                Some(event) = events.next() => {
                    if let Err(e) = self.handle_event(event).await {
                        eprintln!("Error handling event: {:?}", e);
                        // Continue processing other events
                    }
                }
                _ = timeout_check_interval.tick() => {
                    // RFC 9204 Section 2.1.4: Enforce global timeout for QPACK blocked streams
                    // "Implementations SHOULD impose a timeout on blocked streams"
                    if let Err(e) = self.check_blocked_stream_timeouts().await {
                        eprintln!("Error checking blocked stream timeouts: {:?}", e);
                    }
                    
                    // RFC 9114 Section 5.1: Check for idle connection timeout
                    if self.last_activity_time.elapsed() > self.idle_timeout {
                        eprintln!("Connection idle for {:?}, sending GOAWAY", self.last_activity_time.elapsed());
                        if !self.goaway_sent {
                            if let Err(e) = self.send_goaway().await {
                                eprintln!("Error sending GOAWAY on idle timeout: {:?}", e);
                            }
                        }
                    }
                }
                _ = &mut shutdown => {
                    // Graceful shutdown
                    self.send_goaway().await?;
                    // RFC 9114 Section 8: Close connection with H3_NO_ERROR for graceful shutdown
                    let error_code = crate::error::H3ErrorCode::NoError.to_u64();
                    self.handle.close(error_code, Some(Bytes::from("graceful shutdown")))
                        .map_err(|e| H3Error::Connection(format!("close error: {:?}", e)))?;
                    break;
                }
            }
        }
        Ok(())
    }

    async fn handle_event(&mut self, event: AppEvent) -> Result<(), H3Error> {
        // RFC 9114 Section 5.1: Update activity timestamp on any event
        self.last_activity_time = std::time::Instant::now();
        
        match event {
            AppEvent::HandshakeCompleted { alpn, .. } => {
                if alpn.starts_with("h3") {
                    // GAP FIX: RFC 9114 Section 7.2.4.2: Check if connection is using 0-RTT
                    // If so, we need to validate that received settings are compatible
                    // with the remembered settings from the previous session
                    let is_0rtt = self.handle.is_in_early_data().await.unwrap_or(false);
                    
                    if is_0rtt {
                        // Mark that we're in 0-RTT mode for settings validation
                        // The actual validation happens when SETTINGS frame is received
                        eprintln!("Connection using 0-RTT - will validate settings compatibility");
                    }
                    
                    // Initialize HTTP/3 session
                    self.initialize_session().await?;
                }
            }
            AppEvent::NewStream { stream_id, bidirectional, recv_stream, send_stream } => {
                self.max_stream_id = self.max_stream_id.max(stream_id);
                
                // Check GOAWAY state before processing
                if !self.should_accept_stream(stream_id) {
                    // Silently drop streams beyond GOAWAY
                    return Ok(());
                }
                
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
            AppEvent::StreamClosed { stream_id, app_initiated, error_code } => {
                // RFC 9114 Section 4.1.1: Stream was reset
                // Clean up stream state and notify QPACK decoder if needed
                self.handle_stream_closed(stream_id, app_initiated, error_code).await?;
                
                // Periodically clean up completed/cancelled pushes
                self.cleanup_pushes().await;
            }
            AppEvent::StreamReset { request_id, result } => {
                // Response to our reset_stream() call
                if let Err(e) = result {
                    eprintln!("Failed to reset stream (request {}): {:?}", request_id, e);
                }
            }
            AppEvent::ConnectionClosing { .. } => {
                // Send GOAWAY if not already sent
                if !self.goaway_sent {
                    let _ = self.send_goaway().await;
                }
            }
            AppEvent::UniStreamOpened { request_id, result } => {
                if Some(request_id) == self.pending_control_stream_request {
                    // This is our server control stream
                    self.pending_control_stream_request = None;
                    if let Ok(send_stream) = result {
                        // RFC 9114 Section 6.2.1: Write control stream type (0x00)
                        send_stream.write(Bytes::from(vec![0x00]), false).await
                            .map_err(|e| H3Error::Stream(format!("failed to write control stream type: {:?}", e)))?;
                        self.server_control_send = Some(send_stream);
                        // Send SETTINGS frame immediately as required by RFC 9114
                        self.send_settings().await?;
                    } else {
                        return Err(H3Error::Connection("failed to open server control stream".into()));
                    }
                } else if Some(request_id) == self.pending_encoder_stream_request {
                    // RFC 9204 Section 4.2: This is our QPACK encoder stream
                    self.pending_encoder_stream_request = None;
                    if let Ok(send_stream) = result {
                        // Write encoder stream type (0x02)
                        send_stream.write(Bytes::from(vec![0x02]), false).await
                            .map_err(|e| H3Error::Stream(format!("failed to write encoder stream type: {:?}", e)))?;
                        self.encoder_stream_id = Some(send_stream.stream_id);
                        *self.encoder_send_stream.lock().await = Some(send_stream);
                    } else {
                        return Err(H3Error::Connection("failed to open encoder stream".into()));
                    }
                } else if Some(request_id) == self.pending_decoder_stream_request {
                    // RFC 9204 Section 4.2: This is our QPACK decoder stream
                    self.pending_decoder_stream_request = None;
                    if let Ok(send_stream) = result {
                        // Write decoder stream type (0x03)
                        send_stream.write(Bytes::from(vec![0x03]), false).await
                            .map_err(|e| H3Error::Stream(format!("failed to write decoder stream type: {:?}", e)))?;
                        self.decoder_stream_id = Some(send_stream.stream_id);
                        self.decoder_send_stream = Some(send_stream);
                    } else {
                        return Err(H3Error::Connection("failed to open decoder stream".into()));
                    }
                } else if self.pending_push_streams.contains_key(&request_id) {
                    // This is a push stream
                    let push_id = self.pending_push_streams.remove(&request_id).unwrap();
                    
                    match result {
                        Ok(send_stream) => {
                            // Stream opened successfully - send push response
                            if let Err(e) = self.send_push_response_on_stream(push_id, send_stream, request_id).await {
                                // Push failed - already sent CANCEL_PUSH in send_push_response_on_stream if needed
                                return Err(e);
                            }
                        }
                        Err(_) => {
                            // Failed to open push stream - send CANCEL_PUSH
                            let _ = self.send_cancel_push_frame(push_id).await;
                        }
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn initialize_session(&mut self) -> Result<(), H3Error> {
        // RFC 9114 Section 6.2.1: Open server control stream (must be first)
        let control_request_id = self.handle.open_uni()
            .map_err(|e| H3Error::Connection(format!("failed to open control stream: {:?}", e)))?;
        self.pending_control_stream_request = Some(control_request_id);
        
        // RFC 9204 Section 4.2: Create QPACK encoder stream
        // "Each endpoint MUST initiate, at most, one encoder stream"
        let encoder_request_id = self.handle.open_uni()
            .map_err(|e| H3Error::Connection(format!("failed to open encoder stream: {:?}", e)))?;
        self.pending_encoder_stream_request = Some(encoder_request_id);
        
        // RFC 9204 Section 4.2: Create QPACK decoder stream
        // "Each endpoint MUST initiate, at most, one decoder stream"
        let decoder_request_id = self.handle.open_uni()
            .map_err(|e| H3Error::Connection(format!("failed to open decoder stream: {:?}", e)))?;
        self.pending_decoder_stream_request = Some(decoder_request_id);
        
        Ok(())
    }

    fn should_accept_stream(&self, stream_id: u64) -> bool {
        // RFC 9114 Section 5.2: Don't accept new streams after GOAWAY
        if self.goaway_received && stream_id > self.last_accepted_stream_id {
            return false;
        }
        true
    }
    
    async fn handle_bidirectional_stream(
        &mut self,
        stream_id: u64,
        mut recv_stream: quicd_x::RecvStream,
        send_stream: Option<quicd_x::SendStream>,
    ) -> Result<(), H3Error> {
        // RFC 9114 Section 7.2.8: Periodically send reserved frames for greasing
        if Self::should_grease() {
            let _ = self.send_reserved_frame().await; // Best effort, don't fail stream on error
        }
        
        // RFC 9114 Section 5.2: Check if we should accept this stream
        if !self.should_accept_stream(stream_id) {
            // Silently ignore streams beyond GOAWAY point
            return Ok(());
        }
        
        // GAP #2 FIX: Reject new streams after GOAWAY sent
        // RFC 9114 Section 5.2: Server MUST NOT process requests after sending GOAWAY
        if self.goaway_sent && stream_id > self.last_accepted_stream_id {
            // Reset the stream with H3_REQUEST_REJECTED to allow client retry
            let _ = self.handle.reset_stream(stream_id, 0x010B);
            return Ok(()); // Don't treat as error, just ignore the stream
        }
        
        // RFC 9114 Section 6.1: Server MUST NOT process requests until client SETTINGS received
        if !self.settings_validator.is_received() {
            return Err(H3Error::MissingSettings);
        }
        
        // Track the last accepted stream for our GOAWAY
        self.last_accepted_stream_id = self.last_accepted_stream_id.max(stream_id);
        
        // Initialize stream parser for proper frame buffering per RFC 9114
        self.stream_parsers.insert(stream_id, StreamFrameParser::new(stream_id));
        let parser = self.stream_parsers.get_mut(&stream_id).unwrap();
        parser.mark_open();
        
        // Track stream type for frame validation
        self.stream_types.insert(stream_id, StreamType::Request);
        
        self.streams.insert(stream_id, StreamState::Request {
            headers_received: false,
            trailers_received: false,
            body: Vec::new(),
            trailers: None,
            send_stream: send_stream.unwrap(), // bidirectional, so should have send_stream
            // Phase 3: Initialize Content-Length tracking
            content_length: None,
            bytes_received: 0,
            // RFC 9204 Section 2.1.2: Track dynamic table references
            referenced_dynamic_entries: Vec::new(),
        });

        // Read frames from the stream with proper buffering
        while let Ok(Some(data)) = recv_stream.read().await {
            match data {
                quicd_x::StreamData::Data(bytes) => {
                    // Use StreamFrameParser for proper frame buffering
                    // Collect frames first to avoid borrow checker issues
                    let frames = if let Some(parser) = self.stream_parsers.get_mut(&stream_id) {
                        // PERF #32: add_data now returns Result for buffer size limit
                        parser.add_data(bytes)?;
                        
                        let mut collected_frames = Vec::new();
                        while let Some(frame) = parser.parse_next_frame()? {
                            collected_frames.push(frame);
                        }
                        collected_frames
                    } else {
                        Vec::new()
                    };
                    
                    // Process all collected frames
                    for frame in frames {
                        self.process_frame_on_request_stream(stream_id, frame).await?;
                    }
                }
                quicd_x::StreamData::Fin => {
                    if let Some(parser) = self.stream_parsers.get_mut(&stream_id) {
                        parser.mark_half_closed_remote();
                    }
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
                // "Only one control stream per peer is permitted; receipt of a second stream
                // claiming to be a control stream MUST be treated as a connection error of
                // type H3_STREAM_CREATION_ERROR"
                if self.peer_control_stream_id.is_some() {
                    return Err(H3Error::Connection(
                        "duplicate control stream from peer - H3_STREAM_CREATION_ERROR".into()
                    ));
                }
                self.peer_control_stream_id = Some(stream_id);
                self.stream_types.insert(stream_id, StreamType::Control);
                self.streams.insert(stream_id, StreamState::Control);
                self.process_client_control_stream(stream_id, recv_stream).await?;
            }
            0x01 => {
                // Push stream (RFC 9114 Section 6.2.2)
                // RFC 9114 Section 6.2.2: Push streams are unidirectional streams opened by servers
                // A server MUST NOT open a push stream. If a client receives a push stream, it is
                // acceptable. However, if a SERVER receives a push stream from a client, this is
                // a protocol violation.
                //
                // Note: This implementation is a server, so receiving push streams from clients
                // is a protocol error per RFC 9114.
                return Err(H3Error::Connection(
                    "H3_STREAM_CREATION_ERROR: push stream received by server (only servers can push)".into()
                ));
                // Client implementation would call: self.process_push_stream(stream_id, recv_stream).await?;
            }
            0x02 => {
                // QPACK encoder stream (RFC 9204 Section 4.2)
                if self.peer_encoder_stream_id.is_some() {
                    return Err(H3Error::Connection(
                        "duplicate QPACK encoder stream from peer - H3_STREAM_CREATION_ERROR".into()
                    ));
                }
                self.peer_encoder_stream_id = Some(stream_id);
                self.stream_types.insert(stream_id, StreamType::QpackEncoder);
                self.qpack_manager.set_encoder_stream(stream_id);
                self.streams.insert(stream_id, StreamState::QpackEncoder);
                self.process_qpack_stream(stream_id, recv_stream).await?;
            }
            0x03 => {
                // QPACK decoder stream (RFC 9204 Section 4.2)
                if self.peer_decoder_stream_id.is_some() {
                    return Err(H3Error::Connection(
                        "duplicate QPACK decoder stream from peer - H3_STREAM_CREATION_ERROR".into()
                    ));
                }
                self.peer_decoder_stream_id = Some(stream_id);
                self.stream_types.insert(stream_id, StreamType::QpackDecoder);
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
                    // RFC 9114 Section 6.2.1: Control stream closure MUST be treated as
                    // a connection error of type H3_CLOSED_CRITICAL_STREAM
                    return Err(H3Error::ClosedCriticalStream);
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
                    // RFC 9114 Section 6.2.3 & RFC 9204 Section 4.2:
                    // "Closure of either unidirectional stream type MUST be treated as a
                    // connection error of type H3_CLOSED_CRITICAL_STREAM"
                    return Err(H3Error::ClosedCriticalStream);
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
            // Build settings list
            let mut settings = vec![
                Setting { identifier: 0x1, value: 4096 }, // SETTINGS_QPACK_MAX_TABLE_CAPACITY (4KB default)
                Setting { identifier: 0x6, value: 0 }, // SETTINGS_MAX_FIELD_SECTION_SIZE (unlimited)
                Setting { identifier: 0x7, value: 100 }, // SETTINGS_QPACK_BLOCKED_STREAMS (100 default)
            ];
            
            // RFC 9114 Section 4.4: SETTINGS_ENABLE_CONNECT_PROTOCOL for extended CONNECT
            if self.settings_validator.enable_connect_protocol() {
                settings.push(Setting { identifier: 0x8, value: 1 }); // SETTINGS_ENABLE_CONNECT_PROTOCOL
            }
            
            // RFC 9114 Section 7.2.4.1: Grease with reserved settings
            // Format: 0x1f * N + 0x21, where N >= 0
            // Use with ~10% probability to avoid ossification
            if Self::should_grease() {
                let grease_id = Self::generate_reserved_setting_id();
                settings.push(Setting { identifier: grease_id, value: 0 });
            }
            
            // Send SETTINGS frame
            let settings_frame = H3Frame::Settings { settings };
            let frame_data = settings_frame.encode();
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
        // RFC 9114 Section 5.2: Graceful shutdown with GOAWAY
        if self.goaway_sent {
            return Ok(()); // Already sent
        }
        
        // GAP #2 FIX: Validate GOAWAY sequence - stream_id must not increase
        let stream_id = self.last_accepted_stream_id;
        if let Some(prev_id) = self.goaway_max_stream_id {
            if stream_id > prev_id {
                return Err(H3Error::Connection(
                    "Cannot send GOAWAY with stream_id greater than previous GOAWAY".into()
                ));
            }
        }
        
        if let Some(send_stream) = &mut self.server_control_send {
            // Send GOAWAY frame with last accepted stream ID
            let goaway = H3Frame::GoAway { stream_id };
            let frame_data = goaway.encode();
            send_stream.write(frame_data, false).await
                .map_err(|e| H3Error::Stream(format!("failed to send GOAWAY: {:?}", e)))?;
            self.goaway_sent = true;
            self.goaway_max_stream_id = Some(stream_id);
        }
        Ok(())
    }

    /// Send a reserved frame type for greasing per RFC 9114 Section 7.2.8
    /// 
    /// RFC 9114: Implementations SHOULD send reserved frame types occasionally
    /// to prevent intermediaries from ossifying on the current protocol.
    async fn send_reserved_frame(&mut self) -> Result<(), H3Error> {
        if let Some(send_stream) = &mut self.server_control_send {
            let frame_type = Self::generate_reserved_frame_type();
            
            // Encode frame: type (varint) + length (varint) + payload (empty)
            // Use a helper to encode the varint
            let frame_type_bytes = Self::encode_varint_static(frame_type);
            let mut frame_data = frame_type_bytes;
            frame_data.extend_from_slice(&[0x00]); // length = 0
            
            send_stream.write(Bytes::from(frame_data), false).await
                .map_err(|e| H3Error::Stream(format!("failed to send reserved frame: {:?}", e)))?;
        }
        Ok(())
    }
    
    async fn handle_goaway_received(&mut self, stream_id: u64) -> Result<(), H3Error> {
        // RFC 9114 Section 5.2: "An endpoint MAY send multiple GOAWAY frames indicating
        // different identifiers, but the identifier in each frame MUST NOT be greater than
        // the identifier in any previous frame, since clients might already have retried
        // unprocessed requests on another HTTP connection. Receiving a GOAWAY containing a
        // larger identifier than previously received MUST be treated as a connection error
        // of type H3_ID_ERROR."
        
        // GAP #2 FIX: Validate GOAWAY stream ID sequence
        if let Some(last_id) = self.last_goaway_id {
            if stream_id > last_id {
                return Err(H3Error::Connection(
                    "H3_ID_ERROR: GOAWAY stream_id increased from previous GOAWAY".into()
                ));
            }
        }
        
        self.goaway_received = true;
        self.last_goaway_id = Some(stream_id);
        self.last_accepted_stream_id = stream_id;
        
        // GAP #2: Stop accepting new requests with stream_id > goaway stream_id
        // Existing requests can continue
        // Note: Stream creation will be blocked in handle_stream_opened
        Ok(())
    }

    /// Process a complete frame on a request stream.
    /// This is called after StreamFrameParser extracts a complete frame.
    async fn process_frame_on_request_stream(&mut self, stream_id: u64, frame: H3Frame) -> Result<(), H3Error> {
        // RFC 9114 Section 7.2: Validate frame is allowed on request stream (before any borrows)
        self.validate_frame_on_stream(&frame, StreamType::Request)?;
        
        let mut send_ack = false;

        if let Some(StreamState::Request { headers_received, trailers_received, body, trailers, send_stream, content_length, bytes_received, referenced_dynamic_entries }) = 
            self.streams.get_mut(&stream_id) 
        {
            // RFC 9114 Section 4.1: Process frame on request stream
            match frame {
                H3Frame::Headers { encoded_headers } => {
                    if !*headers_received {
                        // Initial HEADERS frame
                        let encoded_size = encoded_headers.len();
                        let (headers, ref_entries) = match self.qpack.read().await.decode_headers(&encoded_headers) {
                            Ok(result) => result,
                            Err(H3Error::QpackBlocked(required_insert_count)) => {
                                // RFC 9204 Section 2.1.4: Stream is blocked waiting for dynamic table updates
                                // Check if we would exceed MAX_BLOCKED_STREAMS
                                if self.blocked_streams.len() >= self.qpack.read().await.table_capacity() {
                                    return Err(H3Error::Qpack(
                                        "would exceed SETTINGS_QPACK_BLOCKED_STREAMS limit".into()
                                    ));
                                }
                                
                                // RFC 9204 Section 2.1.4: Store this stream as blocked
                                self.blocked_streams.insert(stream_id, BlockedStream {
                                    required_insert_count,
                                    encoded_data: encoded_headers.clone(),
                                    send_stream: send_stream.clone(),
                                    stream_id,
                                    blocked_at: std::time::Instant::now(),
                                });
                                
                                // Don't process this stream further - will retry later
                                return Ok(());
                            }
                            Err(e) => return Err(e),
                        };
                        
                        // Phase 3: Validate request headers per RFC 9114 Section 4.1
                        // This validates: pseudo-header ordering, uppercase rejection, connection-specific headers,
                        // required pseudo-headers, Content-Length uniqueness, TE validation, and more
                        let _pseudo_headers = crate::validation::validate_request_headers(&headers)?;
                        
                        // Phase 3: Extract Content-Length for validation (RFC 9114 Section 4.1.2)
                        *content_length = Self::extract_content_length_static(&headers)?;
                        
                        // Record QPACK decode metrics
                        let uncompressed_size: usize = headers.iter().map(|(n, v)| n.len() + v.len()).sum();
                        self.metrics.record_qpack_decode(uncompressed_size, encoded_size);
                        self.metrics.header_bytes_received.fetch_add(encoded_size as u64, Ordering::Relaxed);
                        
                        // RFC 9204 Section 2.1.2: Add references to dynamic table entries and track for release
                        {
                            let mut qpack = self.qpack.write().await;
                            for index in &ref_entries {
                                qpack.add_reference(*index);
                            }
                        }
                        referenced_dynamic_entries.extend(ref_entries);
                        
                        // Mark that we need to send Section Acknowledgment
                        send_ack = true;
                        
                        // Record metrics
                        self.metrics.record_request_received();
                        self.metrics.frames_headers_received.fetch_add(1, Ordering::Relaxed);
                        
                        *headers_received = true;
                        // Queue request for priority-based processing instead of handling immediately
                        let priority_id = self.stream_priorities.get(&stream_id).copied().unwrap_or(255); // Default priority
                        let queued_request = QueuedRequest {
                            priority_id,
                            stream_id,
                            headers: headers.clone(),
                            send_stream: send_stream.clone(),
                        };
                        self.request_queue.push(queued_request);
                        
                        // Try to process the highest priority request
                        self.process_next_request().await?;
                    } else if !*trailers_received {
                        // RFC 9114 Section 4.1: Trailing HEADERS frame (trailers)
                        let (trailer_headers, trailer_refs) = self.qpack.read().await.decode_headers(&encoded_headers)?;
                        
                        // RFC 9114 Section 4.1: Validate trailer headers
                        crate::validation::validate_trailer_headers(&trailer_headers)?;
                        
                        // RFC 9204 Section 2.1.2: Add references and track for release
                        {
                            let mut qpack = self.qpack.write().await;
                            for index in &trailer_refs {
                                qpack.add_reference(*index);
                            }
                        }
                        referenced_dynamic_entries.extend(trailer_refs);
                        
                        // Phase 3: Validate Content-Length matches received bytes (RFC 9114 Section 4.1.2)
                        if let Some(expected) = content_length {
                            if *bytes_received != *expected {
                                return Err(H3Error::MessageError);
                            }
                        }
                        
                        // Mark that we need to send Section Acknowledgment
                        send_ack = true;
                        
                        *trailers_received = true;
                        *trailers = Some(trailer_headers);
                    } else {
                        // Multiple trailer frames not allowed
                        return Err(H3Error::FrameUnexpected);
                    }
                }
                H3Frame::Data { data: body_data } => {
                    if !*headers_received {
                        return Err(H3Error::Http("DATA before HEADERS".into()));
                    }
                    if *trailers_received {
                        return Err(H3Error::Http("DATA after trailers".into()));
                    }
                    
                    // GAP FIX: Handle empty DATA frames properly
                    // RFC 9114 Section 7.2.1: Empty DATA frames are allowed but should not
                    // be used unnecessarily. We accept them but don't store empty buffers.
                    let frame_bytes = body_data.len() as u64;
                    
                    // Phase 3: Track received bytes (RFC 9114 Section 4.1.2)
                    *bytes_received += frame_bytes;
                    
                    // Phase 3: Validate against Content-Length if present
                    if let Some(expected) = content_length {
                        if *bytes_received > *expected {
                            return Err(H3Error::MessageError);
                        }
                    }
                    
                    // Record metrics
                    self.metrics.frames_data_received.fetch_add(1, Ordering::Relaxed);
                    self.metrics.request_bytes_received.fetch_add(frame_bytes, Ordering::Relaxed);
                    
                    // Only store non-empty DATA frames
                    if !body_data.is_empty() {
                        body.push(body_data);
                    }
                }
                H3Frame::Priority { priority } => {
                    // Handle priority update (can appear any time)
                    self.handle_priority_frame(stream_id, priority).await?;
                }
                H3Frame::PriorityUpdate { element_id, priority_field_value } => {
                    // RFC 9218: Handle priority update (can appear on any stream)
                    self.metrics.frames_priority_update_received.fetch_add(1, Ordering::Relaxed);
                    self.handle_priority_update_frame(stream_id, element_id, priority_field_value.clone()).await?;
                }
                // RFC 9114: These frames MUST NOT appear on request streams
                H3Frame::PushPromise { .. } => {
                    return Err(H3Error::FrameUnexpected);
                }
                H3Frame::GoAway { .. } | H3Frame::MaxPushId { .. } | H3Frame::Settings { .. } => {
                    return Err(H3Error::FrameUnexpected);
                }
                _ => {
                    // Unknown/reserved frames - ignore per RFC 9114
                }
            }
        }
        
        // RFC 9204 Section 4.4.1: Send Section Acknowledgment after successful decode
        if send_ack {
            self.send_section_acknowledgment(stream_id).await?;
        }

        Ok(())
    }

    /// Process the next highest priority request from the queue
    async fn process_next_request(&mut self) -> Result<(), H3Error> {
        // Try to use the priority tree for RFC 9218 compliant scheduling
        // If no priority information exists, fall back to BinaryHeap order
        let selected_stream_id = self.priority_tree.get_next_priority().map(|(stream_id, _urgency)| stream_id);
        
        let queued_request = if let Some(priority_stream_id) = selected_stream_id {
            // Find the request with this stream_id in the queue
            // Since BinaryHeap doesn't support efficient removal by predicate,
            // we need to temporarily drain and rebuild
            let mut temp_queue = Vec::new();
            let mut selected = None;
            
            while let Some(req) = self.request_queue.pop() {
                if req.stream_id == priority_stream_id && selected.is_none() {
                    selected = Some(req);
                } else {
                    temp_queue.push(req);
                }
            }
            
            // Rebuild queue
            for req in temp_queue {
                self.request_queue.push(req);
            }
            
            // If we found the prioritized request, use it; otherwise fall back to queue order
            selected.or_else(|| self.request_queue.pop())
        } else {
            // No priority information, use normal queue order
            self.request_queue.pop()
        };
        
        if let Some(queued_request) = queued_request {
            let request = self.parse_request(queued_request.headers)?;
            
            // RFC 9204 Section 2.1.2: Create Arc to track response header references
            let response_references = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
            
            // Call handler
            let mut sender = H3ResponseSender {
                send_stream: queued_request.send_stream,
                qpack: self.qpack.clone(),
                push_manager: Some(self.push_manager.clone()),
                connection_handle: Some(self.handle.clone()),
                stream_id: queued_request.stream_id,
                encoder_send_stream: self.encoder_send_stream.clone(),
                response_references: response_references.clone(),
            };
            self.handler.handle_request(request, &mut sender).await?;
            
            // RFC 9204 Section 2.1.2: Store response references in stream state for cleanup
            if let Some(StreamState::Request { referenced_dynamic_entries, .. }) = self.streams.get_mut(&queued_request.stream_id) {
                let response_refs = response_references.lock().await;
                referenced_dynamic_entries.extend(response_refs.iter());
            }
        }
        
        Ok(())
    }

    async fn handle_request_complete(&mut self, _stream_id: u64) -> Result<(), H3Error> {
        // Request finished
        Ok(())
    }

    /// Validates that a frame type is allowed on a given stream type.
    /// RFC 9114 Section 7.2: Different frame types are permitted on different stream types.
    fn validate_frame_on_stream(&self, frame: &H3Frame, stream_type: StreamType) -> Result<(), H3Error> {
        match (frame, stream_type) {
            // DATA and HEADERS only on request streams (RFC 9114 Section 7.2.1, 7.2.2)
            (H3Frame::Data { .. }, StreamType::Request) => Ok(()),
            (H3Frame::Headers { .. }, StreamType::Request) => Ok(()),
            (H3Frame::Data { .. }, _) => Err(H3Error::Connection(
                "FRAME_UNEXPECTED: DATA frame not allowed on control stream".into()
            )),
            (H3Frame::Headers { .. }, _) => Err(H3Error::Connection(
                "FRAME_UNEXPECTED: HEADERS frame not allowed on control stream".into()
            )),
            
            // Control stream only frames (RFC 9114 Section 7.2.3-7.2.7)
            (H3Frame::CancelPush { .. }, StreamType::Control) => Ok(()),
            (H3Frame::Settings { .. }, StreamType::Control) => Ok(()),
            (H3Frame::GoAway { .. }, StreamType::Control) => Ok(()),
            (H3Frame::MaxPushId { .. }, StreamType::Control) => Ok(()),
            (H3Frame::CancelPush { .. }, _) => Err(H3Error::Connection(
                "FRAME_UNEXPECTED: CANCEL_PUSH only allowed on control stream".into()
            )),
            (H3Frame::Settings { .. }, _) => Err(H3Error::Connection(
                "FRAME_UNEXPECTED: SETTINGS only allowed on control stream".into()
            )),
            (H3Frame::GoAway { .. }, _) => Err(H3Error::Connection(
                "FRAME_UNEXPECTED: GOAWAY only allowed on control stream".into()
            )),
            (H3Frame::MaxPushId { .. }, _) => Err(H3Error::Connection(
                "FRAME_UNEXPECTED: MAX_PUSH_ID only allowed on control stream".into()
            )),
            
            // PUSH_PROMISE only on request streams (RFC 9114 Section 7.2.5)
            (H3Frame::PushPromise { .. }, StreamType::Request) => Ok(()),
            (H3Frame::PushPromise { .. }, _) => Err(H3Error::Connection(
                "FRAME_UNEXPECTED: PUSH_PROMISE only allowed on request streams".into()
            )),
            
            // PRIORITY can appear on request streams (RFC 9114 Section 7.2.3)
            (H3Frame::Priority { .. }, StreamType::Request) => Ok(()),
            
            // PRIORITY_UPDATE can appear on any stream (RFC 9218 Section 7.1)
            (H3Frame::PriorityUpdate { .. }, _) => Ok(()),
            
            // Reserved and unknown frames can appear anywhere (RFC 9114 Section 7.2.8)
            (H3Frame::Reserved { .. }, _) => Ok(()),
            (H3Frame::DuplicatePush { .. }, _) => Ok(()), // Treated as reserved
            
            // Default: if not explicitly allowed, reject
            _ => Err(H3Error::Connection(
                format!("FRAME_UNEXPECTED: frame type not allowed on this stream type")
            )),
        }
    }

    async fn process_control_frames(&mut self, data: Bytes) -> Result<(), H3Error> {
        // PERF: Use parse_bytes() for zero-copy frame parsing
        if let Ok((frame, _)) = H3Frame::parse_bytes(&data) {
            // Validate frame is allowed on control stream
            self.validate_frame_on_stream(&frame, StreamType::Control)?;
            // RFC 9114 Section 6.2.1: SETTINGS MUST be first frame on control stream
            match &frame {
                H3Frame::Settings { settings } => {
                    // RFC 9114 Section 7.2.4: "If an endpoint receives a second SETTINGS frame
                    // on the control stream, the endpoint MUST respond with a connection error
                    // of type H3_FRAME_UNEXPECTED"
                    if self.peer_control_stream_received_settings {
                        return Err(H3Error::Connection(
                            "FRAME_UNEXPECTED: duplicate SETTINGS frame on control stream".into()
                        ));
                    }
                    self.peer_control_stream_received_settings = true;
                    
                    // Convert to HashMap for validator
                    let settings_map: HashMap<u64, u64> = settings.iter()
                        .map(|s| (s.identifier, s.value))
                        .collect();
                    
                    // GAP FIX: RFC 9114 Section 7.2.4.2: Validate 0-RTT settings compatibility
                    // If this connection used 0-RTT and we have remembered settings,
                    // ensure the new settings don't reduce limits or change incompatibly
                    // NOTE: We check this even if is_in_early_data() returns false, because
                    // by the time SETTINGS arrives, 0-RTT may have completed but we still
                    // need to validate compatibility with remembered settings
                    if self.settings_validator.get_remembered_settings().is_some() {
                        // We have remembered settings - validate compatibility
                        if let Err(e) = self.settings_validator.validate_0rtt_compatibility(&settings_map) {
                            // RFC 9114 Section 7.2.4.2:
                            // "If a server accepts 0-RTT but then sends settings that are not
                            // compatible with the previously specified settings, this MUST be
                            // treated as a connection error of type H3_SETTINGS_ERROR."
                            eprintln!("0-RTT settings validation failed: {:?}", e);
                            return Err(e);
                        }
                    }
                    
                    // Validate and process SETTINGS
                    self.settings_validator.validate_settings(settings_map.clone())?;
                    
                    // RFC 9114 Section 7.2.4.2: Remember settings for future 0-RTT connections
                    // "Clients SHOULD store the settings the server provided in the HTTP/3
                    // connection where resumption information was provided"
                    self.settings_validator.remember_settings();
                    
                    // RFC 9114 Section 7.2.4.2: Store settings persistently if we have an origin
                    // This enables proper 0-RTT validation on future connections
                    if let Some(ref origin) = self.origin {
                        self.settings_storage.store(origin.clone(), settings_map.clone());
                    }
                    
                    // Update QPACK codec with settings
                    let mut qpack = self.qpack.write().await;
                    if let Some(&capacity) = settings_map.get(&0x1) {
                        qpack.set_max_table_capacity(capacity as usize);
                    }
                    if let Some(&blocked) = settings_map.get(&0x7) {
                        qpack.set_max_blocked_streams(blocked as usize);
                    }
                    // RFC 9114 Section 7.2.4.2: Enforce MAX_FIELD_SECTION_SIZE
                    if let Some(&max_size) = settings_map.get(&0x6) {
                        if max_size > 0 {
                            qpack.set_max_field_section_size(Some(max_size as usize));
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
                    // RFC 9114 Section 7.2.7: MAX_PUSH_ID MUST NOT decrease
                    // "A MAX_PUSH_ID frame cannot reduce the maximum push ID; receipt of a
                    // MAX_PUSH_ID frame that contains a smaller value than previously received
                    // MUST be treated as a connection error of type H3_ID_ERROR"
                    if push_id < self.max_push_id {
                        return Err(H3Error::Connection("MAX_PUSH_ID cannot decrease".into()));
                    }
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
                H3Frame::GoAway { stream_id } => {
                    // RFC 9114 Section 5.2: Client is going away
                    // "A server MUST NOT increase the stream ID indicated in a GOAWAY frame"
                    self.handle_goaway_received(stream_id).await?;
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

    /// Send CANCEL_PUSH frame to peer (server-initiated cancellation)
    /// Per RFC 9114 Section 7.2.5: Either endpoint can send CANCEL_PUSH
    async fn send_cancel_push_frame(&mut self, push_id: u64) -> Result<(), H3Error> {
        // Send CANCEL_PUSH on control stream
        if let Some(control_stream) = &mut self.server_control_send {
            let cancel_frame = H3Frame::CancelPush { push_id };
            let frame_data = cancel_frame.encode();
            control_stream.write(frame_data, false).await
                .map_err(|e| H3Error::Stream(format!("failed to send CANCEL_PUSH: {:?}", e)))?;
        }
        
        // Mark as cancelled in PushManager
        if let Ok(mut manager) = self.push_manager.try_lock() {
            manager.cancel_push(push_id)?;
        }
        
        Ok(())
    }

    async fn handle_priority_frame(&mut self, _stream_id: u64, priority: crate::frames::Priority) -> Result<(), H3Error> {
        // RFC 9218 Section 5: Handle extensible priority updates
        
        use crate::priority::PriorityNode;
        
        match priority.prioritized_element_type {
            0x00 | 0x01 => {
                // Request or push stream prioritization
                // Store priority information for request scheduling
                self.stream_priorities.insert(priority.element_id, priority.urgency as u64);
                
                // RFC 9218 Section 5.3: Build priority tree
                let node = PriorityNode {
                    element_id: priority.element_id,
                    element_type: priority.prioritized_element_type,
                    urgency: priority.urgency,
                    incremental: priority.incremental,
                    parent_id: priority.parent_element_id,
                    children: vec![],
                };
                
                self.priority_tree.insert(node);
                
                // If this stream is already in the request queue, we can't easily re-prioritize it
                // The BinaryHeap doesn't support efficient priority updates
                // In a production system, this would require a more sophisticated data structure
                eprintln!("{} stream {} priority: urgency={}, incremental={}, parent_type={}, parent_id={:?}",
                    if priority.prioritized_element_type == 0 { "Request" } else { "Push" },
                    priority.element_id, priority.urgency, priority.incremental, 
                    priority.parent_element_type, priority.parent_element_id);
            }
            _ => {
                // Unknown element type - ignore per RFC 9218
                eprintln!("Unknown priority element type: {}", priority.prioritized_element_type);
            }
        }
        
        Ok(())
    }

    /// RFC 9218 Section 7.1: Handle PRIORITY_UPDATE frame
    async fn handle_priority_update_frame(&mut self, _stream_id: u64, element_id: u64, priority_field_value: String) -> Result<(), H3Error> {
        // RFC 9218 Section 7.1: Parse priority field value
        // Format: "u=<urgency>[,i][,a=<element_id>]"
        
        let mut urgency = None;
        let mut incremental = false;
        let mut parent_element_id = None;
        
        for param in priority_field_value.split(',') {
            let param = param.trim();
            if param.starts_with("u=") {
                if let Ok(u) = param[2..].parse::<u8>() {
                    if u <= 7 {
                        urgency = Some(u);
                    } else {
                        return Err(H3Error::Http(format!("Invalid urgency value: {}", u)));
                    }
                } else {
                    return Err(H3Error::Http(format!("Invalid urgency parameter: {}", param)));
                }
            } else if param == "i" {
                incremental = true;
            } else if param.starts_with("a=") {
                if let Ok(id) = param[2..].parse::<u64>() {
                    parent_element_id = Some(id);
                } else {
                    return Err(H3Error::Http(format!("Invalid element ID parameter: {}", param)));
                }
            } else {
                return Err(H3Error::Http(format!("Unknown priority parameter: {}", param)));
            }
        }
        
        let urgency = urgency.ok_or_else(|| H3Error::Http("Missing urgency parameter in PRIORITY_UPDATE".into()))?;
        
        // Update stream priority
        self.stream_priorities.insert(element_id, urgency as u64);
        
        // RFC 9218 Section 5.3: Update priority tree
        use crate::priority::PriorityNode;
        
        let node = PriorityNode {
            element_id,
            element_type: 0, // Assume request stream (0x00)
            urgency,
            incremental,
            parent_id: parent_element_id,
            children: vec![],
        };
        
        self.priority_tree.insert(node);
        
        eprintln!("PRIORITY_UPDATE for stream {}: urgency={}, incremental={}, parent_id={:?}",
            element_id, urgency, incremental, parent_element_id);
        
        Ok(())
    }

    /// RFC 9114 Section 4.1.1: Handle stream closure/reset
    async fn handle_stream_closed(&mut self, stream_id: u64, app_initiated: bool, error_code: u64) -> Result<(), H3Error> {
        // RFC 9114 Section 4.1.2: Validate Content-Length against received bytes on stream close
        if app_initiated && error_code == 0 {
            // Normal close (not reset) - validate Content-Length
            if let Some(StreamState::Request { content_length, bytes_received, .. }) = self.streams.get(&stream_id) {
                if let Some(expected) = content_length {
                    if *bytes_received != *expected {
                        // RFC 9114 Section 4.1.2: Content-Length mismatch is a H3_MESSAGE_ERROR
                        // Close the stream with error
                        let _ = self.handle.reset_stream(stream_id, crate::error::H3ErrorCode::MessageError.to_u64());
                        return Err(H3Error::MessageError);
                    }
                }
            }
        }
        
        // RFC 9204 Section 4.4.2: If stream is cancelled, send Stream Cancellation instruction
        // BEFORE cleaning up state to ensure the instruction is sent
        // GAP #1 FIX: Moved cancellation before cleanup
        if !app_initiated && error_code != 0 {
            // Peer reset the stream - notify via QPACK decoder stream
            self.send_stream_cancellation(stream_id).await?;
        }
        
        // RFC 9204 Section 2.1.2: Release all dynamic table references held by this stream
        // This includes both request header references and response header references
        if let Some(StreamState::Request { referenced_dynamic_entries, .. }) = self.streams.get(&stream_id) {
            let mut qpack = self.qpack.write().await;
            for index in referenced_dynamic_entries {
                qpack.release_reference(*index);
            }
            // Note: Response references are already merged into referenced_dynamic_entries
            // after handle_request() completes in process_request_stream()
        }
        
        // Clean up stream state after cancellation sent and references released
        self.streams.remove(&stream_id);
        self.stream_parsers.remove(&stream_id);
        
        // Remove from blocked streams if present
        self.blocked_streams.remove(&stream_id);
        
        Ok(())
    }

    /// Cancel a stream with an application error code
    /// RFC 9114 Section 4.1.1: Applications can cancel streams via RESET_STREAM
    pub async fn cancel_stream(&mut self, stream_id: u64, error_code: u64) -> Result<(), H3Error> {
        // Clean up our stream state first
        self.streams.remove(&stream_id);
        self.blocked_streams.remove(&stream_id);
        
        // Send RESET_STREAM to peer (synchronous call, returns request_id)
        let _request_id = self.handle.reset_stream(stream_id, error_code)
            .map_err(|e| H3Error::Connection(format!("Failed to reset stream: {:?}", e)))?;
        
        // The StreamReset event will be delivered asynchronously
        Ok(())
    }

    /// Cancel a server push and send CANCEL_PUSH frame to peer
    /// Per RFC 9114 Section 7.2.5: Server can cancel its own promised push
    pub async fn cancel_server_push(&mut self, push_id: u64) -> Result<(), H3Error> {
        // Send CANCEL_PUSH frame and update state
        self.send_cancel_push_frame(push_id).await?;
        
        // If push stream is already opened, reset it
        let stream_id = {
            let manager = self.push_manager.lock().await;
            manager.get_promise(push_id).and_then(|p| p.push_stream_id())
        };
        
        if let Some(stream_id) = stream_id {
            // Reset the push stream with H3_REQUEST_CANCELLED error code
            let _ = self.cancel_stream(stream_id, 0x010C).await;
        }
        
        Ok(())
    }

    /// Clean up completed and cancelled push promises
    /// Should be called periodically to prevent memory leaks
    pub async fn cleanup_pushes(&mut self) {
        let mut manager = self.push_manager.lock().await;
        manager.cleanup();
    }

    async fn process_qpack_instructions(&mut self, stream_id: u64, data: Bytes) -> Result<(), H3Error> {
        let instructions = data.as_ref();
        let mut cursor = 0;
        
        // Determine stream type for context-aware instruction decoding
        let is_encoder_stream = Some(stream_id) == self.peer_encoder_stream_id;
        let is_decoder_stream = Some(stream_id) == self.peer_decoder_stream_id;
        
        if !is_encoder_stream && !is_decoder_stream {
            return Err(H3Error::Qpack(format!(
                "QPACK instructions on non-QPACK stream {}",
                stream_id
            )));
        }
        
        while cursor < instructions.len() {
            let qpack = self.qpack.read().await;
            // RFC 9204 GAP FIX: Use context-aware decoding for proper Duplicate/InsertCountIncrement disambiguation
            match qpack.decode_instruction_with_context(&instructions[cursor..], is_encoder_stream) {
                Ok((mut instruction, consumed)) => {
                    drop(qpack); // Release lock before handling
                    cursor += consumed;
                    
                    // Validate instruction is on correct stream type
                    instruction = self.disambiguate_qpack_instruction(
                        instruction, 
                        stream_id, 
                        is_encoder_stream
                    )?;
                    
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

    /// Disambiguate QPACK instruction based on stream context.
    /// 
    /// RFC 9204: Both Duplicate and InsertCountIncrement start with 0x00.
    /// The stream type determines which one it actually is.
    fn disambiguate_qpack_instruction(
        &self,
        instruction: crate::qpack::QpackInstruction,
        stream_id: u64,
        is_encoder_stream: bool,
    ) -> Result<crate::qpack::QpackInstruction, H3Error> {
        use crate::qpack::QpackInstruction;
        
        match &instruction {
            // Encoder-only instructions
            QpackInstruction::SetDynamicTableCapacity { .. }
            | QpackInstruction::InsertWithNameReference { .. }
            | QpackInstruction::InsertWithLiteralName { .. }
            | QpackInstruction::Duplicate { .. } => {
                if !is_encoder_stream {
                    return Err(H3Error::Qpack(format!(
                        "H3_QPACK_ENCODER_STREAM_ERROR: encoder instruction on stream {}",
                        stream_id
                    )));
                }
            }
            
            // Decoder-only instructions
            QpackInstruction::SectionAcknowledgment { .. }
            | QpackInstruction::StreamCancellation { .. }
            | QpackInstruction::InsertCountIncrement { .. } => {
                if is_encoder_stream {
                    return Err(H3Error::Qpack(format!(
                        "H3_QPACK_DECODER_STREAM_ERROR: decoder instruction on stream {}",
                        stream_id
                    )));
                }
            }
        }
        
        Ok(instruction)
    }

    async fn handle_qpack_instruction(&mut self, _stream_id: u64, instruction: crate::qpack::QpackInstruction) -> Result<(), H3Error> {
        let table_changed = matches!(
            instruction,
            crate::qpack::QpackInstruction::InsertWithNameReference { .. }
            | crate::qpack::QpackInstruction::InsertWithLiteralName { .. }
            | crate::qpack::QpackInstruction::Duplicate { .. }
        );
        
        let mut qpack = self.qpack.write().await;
        
        match instruction {
            crate::qpack::QpackInstruction::SetDynamicTableCapacity { capacity } => {
                // Update dynamic table capacity
                qpack.set_max_table_capacity(capacity as usize);
            }
            crate::qpack::QpackInstruction::InsertWithNameReference { static_table, name_index, value } => {
                // Insert entry into dynamic table
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
                // GAP #21: Track insertions for INSERT_COUNT_INCREMENT
                self.insert_count_processed += 1;
            }
            crate::qpack::QpackInstruction::InsertWithLiteralName { name, value } => {
                // Insert entry into dynamic table
                qpack.insert(name, value);
                // GAP #21: Track insertions for INSERT_COUNT_INCREMENT
                self.insert_count_processed += 1;
            }
            crate::qpack::QpackInstruction::Duplicate { index } => {
                // Duplicate entry in dynamic table
                qpack.duplicate(index as usize);
                // GAP #21: Track insertions for INSERT_COUNT_INCREMENT
                self.insert_count_processed += 1;
            }
            crate::qpack::QpackInstruction::SectionAcknowledgment { stream_id: acked_stream_id } => {
                // RFC 9204 Section 4.4.1: Section Acknowledgment
                // Update known received count and unblock the stream
                let count = qpack.known_received_count();
                qpack.update_known_received_count(count + 1);
                
                // RFC 9204 Section 2.1.4: Unblock the stream
                qpack.unblock_stream();
                
                // Remove from blocked streams
                self.blocked_streams.remove(&acked_stream_id);
            }
            crate::qpack::QpackInstruction::StreamCancellation { stream_id: cancelled_stream_id } => {
                // RFC 9204 Section 4.4.2: Stream Cancellation
                // Unblock the stream if it was blocked
                if self.blocked_streams.remove(&cancelled_stream_id).is_some() {
                    qpack.unblock_stream();
                }
            }
            crate::qpack::QpackInstruction::InsertCountIncrement { increment } => {
                // GAP #6 FIX: Validate increment per RFC 9204 §4.4.3
                // "The new Known Received Count MUST NOT exceed the current value of 
                // the insert count at the decoder"
                let current_known = qpack.known_received_count();
                let current_insert = qpack.insert_count();
                let new_known = current_known + increment as usize;
                
                if new_known > current_insert {
                    return Err(H3Error::Qpack(format!(
                        "INSERT_COUNT_INCREMENT {} would exceed insert count (known={}, insert={})",
                        increment, current_known, current_insert
                    )));
                }
                
                // Update known received count
                qpack.update_known_received_count(new_known);
            }
        }
        
        drop(qpack); // Release lock before retry
        
        // GAP #21 FIX: Send INSERT_COUNT_INCREMENT to acknowledge processed insertions
        // RFC 9204 Section 4.4.3: Decoder MUST send INSERT_COUNT_INCREMENT after processing
        if table_changed {
            // Send acknowledgment for the insertion we just processed
            // Each insertion instruction increments by 1
            self.send_insert_count_increment(1).await?;
            
            // RFC 9204 Section 2.1.4: Retry blocked streams if dynamic table changed
            self.retry_blocked_streams().await?;
        }
        
        Ok(())
    }

    /// Parse headers into HTTP request (public for testing)
    pub fn parse_request(&mut self, headers: Vec<(String, String)>) -> Result<H3Request, H3Error> {
        // Parse headers into HTTP request
        let mut method = None;
        let mut path = None;
        let mut scheme = None;
        let mut authority = None;
        let mut protocol = None;
        let mut header_vec = Vec::new();

        for (name, value) in headers {
            match name.as_str() {
                ":method" => method = Some(value),
                ":path" => {
                    path = Some(value);
                }
                ":scheme" => scheme = Some(value),
                ":authority" => authority = Some(value),
                ":protocol" => protocol = Some(value),
                _ => {
                    header_vec.push((name, value));
                }
            }
        }

        let method_str = method.ok_or_else(|| H3Error::Http("missing :method".into()))?;
        
        // RFC 9114 Section 4.4: CONNECT validation
        if method_str.to_uppercase() == "CONNECT" {
            let pseudo_headers = crate::validation::RequestPseudoHeaders {
                method: method_str.clone(),
                scheme: scheme.clone(),
                authority: authority.clone(),
                path: path.clone(),
                protocol: protocol.clone(),
            };
            
            // Check if extended CONNECT is enabled
            let enable_connect_protocol = self.settings_validator.enable_connect_protocol();
            validate_connect_request(&pseudo_headers, enable_connect_protocol)?;
        }
        
        let method = method_str.parse().map_err(|_| H3Error::Http("invalid method".into()))?;
        let scheme = scheme.ok_or_else(|| H3Error::Http("missing :scheme".into()))?;
        let authority = authority.ok_or_else(|| H3Error::Http("missing :authority".into()))?;
        let path = path.unwrap_or_else(|| "/".to_string());
        
        // RFC 9114 Section 7.2.4.2: Extract origin for settings storage
        // Do this on first request to enable 0-RTT settings validation
        if self.origin.is_none() {
            if let Ok(origin) = Origin::from_authority(scheme.clone(), &authority) {
                self.origin = Some(origin);
            }
        }
        
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

    /// Phase 3: Extract Content-Length value from headers (RFC 9114 Section 4.1.2)
    fn extract_content_length_static(headers: &[(String, String)]) -> Result<Option<u64>, H3Error> {
        for (name, value) in headers {
            if name == "content-length" {
                let length = value.parse::<u64>()
                    .map_err(|_| H3Error::MessageError)?;
                return Ok(Some(length));
            }
        }
        Ok(None)
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
    /// Note: This would be used in a client implementation. Servers don't receive push streams.
    #[allow(dead_code)]
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
    /// PERF #29: Batches instruction encoding with single lock acquisition
    async fn send_section_acknowledgment(&mut self, stream_id: u64) -> Result<(), H3Error> {
        // Create Section Acknowledgment instruction
        let instruction = crate::qpack::QpackInstruction::SectionAcknowledgment { stream_id };
        let instruction_bytes = self.qpack.read().await.encode_instruction(&instruction)?;
        
        // Add to pending buffer instead of sending immediately
        self.pending_decoder_instructions.push(instruction_bytes);
        
        // Flush if buffer is getting large (configurable threshold)
        if self.pending_decoder_instructions.len() >= 8 {
            self.flush_decoder_instructions().await?;
        }
        Ok(())
    }

    /// Send Stream Cancellation on decoder stream (RFC 9204 Section 4.4.2)
    /// PERF #29: Batches instruction, but flushes immediately for critical signaling
    async fn send_stream_cancellation(&mut self, stream_id: u64) -> Result<(), H3Error> {
        // Create Stream Cancellation instruction
        let instruction = crate::qpack::QpackInstruction::StreamCancellation { stream_id };
        let instruction_bytes = self.qpack.read().await.encode_instruction(&instruction)?;
        
        // Add to pending buffer
        self.pending_decoder_instructions.push(instruction_bytes);
        
        // Flush immediately for cancellation (critical for encoder state cleanup)
        self.flush_decoder_instructions().await?;
        Ok(())
    }

    /// Send Insert Count Increment on decoder stream (RFC 9204 Section 4.4.3)
    /// PERF #29: Batches instruction encoding
    async fn send_insert_count_increment(&mut self, increment: u64) -> Result<(), H3Error> {
        // Create Insert Count Increment instruction
        let instruction = crate::qpack::QpackInstruction::InsertCountIncrement { increment };
        let instruction_bytes = self.qpack.read().await.encode_instruction(&instruction)?;
        
        // Add to pending buffer
        self.pending_decoder_instructions.push(instruction_bytes);
        
        // Flush immediately for INSERT_COUNT_INCREMENT (required for unblocking)
        self.flush_decoder_instructions().await?;
        Ok(())
    }
    
    /// Flush all pending decoder instructions in a single write
    /// PERF #29: Reduces system call overhead by batching writes
    async fn flush_decoder_instructions(&mut self) -> Result<(), H3Error> {
        if self.pending_decoder_instructions.is_empty() {
            return Ok(());
        }
        
        if let Some(decoder_send) = &mut self.decoder_send_stream {
            // Combine all pending instructions into a single buffer
            let total_size: usize = self.pending_decoder_instructions.iter().map(|b| b.len()).sum();
            let mut combined = bytes::BytesMut::with_capacity(total_size);
            
            for instruction_bytes in self.pending_decoder_instructions.drain(..) {
                combined.extend_from_slice(&instruction_bytes);
            }
            
            // Single write for all instructions
            decoder_send.write(combined.freeze(), false).await
                .map_err(|e| H3Error::Stream(format!("failed to flush decoder instructions: {:?}", e)))?;
        } else {
            // Clear buffer even if no stream (avoid memory leak)
            self.pending_decoder_instructions.clear();
        }
        
        Ok(())
    }

    /// Retry blocked streams after dynamic table update
    /// 
    /// RFC 9204 Section 2.1.4: Enforce global timeout for QPACK blocked streams.
    /// 
    /// This is called periodically (every 10 seconds) from the main event loop to ensure
    /// that blocked streams are timed out even if no encoder instructions arrive.
    /// 
    /// "Implementations SHOULD impose a timeout on blocked streams. If a stream remains
    /// blocked for longer than this timeout, the implementation can cancel the stream with
    /// an error code of H3_QPACK_DECOMPRESSION_FAILED."
    async fn check_blocked_stream_timeouts(&mut self) -> Result<(), H3Error> {
        const BLOCKED_STREAM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
        
        let now = std::time::Instant::now();
        let mut streams_to_timeout = Vec::new();
        
        // Find streams that have been blocked too long
        for (stream_id, blocked_stream) in &self.blocked_streams {
            if now.duration_since(blocked_stream.blocked_at) > BLOCKED_STREAM_TIMEOUT {
                streams_to_timeout.push(*stream_id);
            }
        }
        
        // Timeout streams that have exceeded the limit
        for stream_id in streams_to_timeout {
            self.blocked_streams.remove(&stream_id);
            // RFC 9204 Section 2.2.2.2: Close stream with H3_QPACK_DECOMPRESSION_FAILED
            let _ = self.handle.reset_stream(stream_id, crate::error::H3ErrorCode::QpackDecompressionFailed.to_u64());
            eprintln!("QPACK blocked stream {} timed out after 60 seconds", stream_id);
        }
        
        Ok(())
    }

    /// RFC 9204 Section 2.1.4: When decoder instructions arrive and update the dynamic table,
    /// check if any blocked streams can now be decoded.
    /// 
    /// Should be called after processing encoder stream instructions that insert dynamic table entries.
    async fn retry_blocked_streams(&mut self) -> Result<(), H3Error> {
        let current_insert_count = self.qpack.read().await.insert_count();
        let now = std::time::Instant::now();
        let mut streams_to_retry = Vec::new();
        
        // Find all streams that can now be unblocked
        // Note: Timeout checking is now handled by check_blocked_stream_timeouts()
        for (stream_id, blocked_stream) in &self.blocked_streams {
            if blocked_stream.required_insert_count <= current_insert_count {
                streams_to_retry.push(*stream_id);
            }
        }
        
        // Retry each unblocked stream
        let mut requests_to_process = Vec::new();
        
        for stream_id in streams_to_retry {
            if let Some(blocked) = self.blocked_streams.remove(&stream_id) {
                // Try to decode headers again
                match self.qpack.read().await.decode_headers(&blocked.encoded_data) {
                    Ok((headers, referenced_entries)) => {
                        // Successfully decoded - add references for cleanup
                        {
                            let mut qpack = self.qpack.write().await;
                            for index in &referenced_entries {
                                qpack.add_reference(*index);
                            }
                            qpack.unblock_stream(); // Decrement blocked stream count
                        }
                        
                        // Queue the request for later processing (avoid borrow checker issues)
                        requests_to_process.push((stream_id, headers, blocked.send_stream));
                    }
                    Err(H3Error::QpackBlocked(new_required)) => {
                        // Still blocked (shouldn't happen if logic is correct)
                        // Re-insert with updated requirement
                        self.blocked_streams.insert(stream_id, BlockedStream {
                            required_insert_count: new_required,
                            encoded_data: blocked.encoded_data,
                            send_stream: blocked.send_stream,
                            stream_id: blocked.stream_id,
                            blocked_at: now, // Reset the timer
                        });
                    }
                    Err(e) => {
                        // Decoding failed - send error to stream
                        return Err(e);
                    }
                }
            }
        }
        
        // Process all unblocked requests
        for (stream_id, headers, send_stream) in requests_to_process {
            // Queue the request
            let priority_id = 0;
            self.request_queue.push(QueuedRequest {
                priority_id,
                stream_id,
                headers,
                send_stream,
            });
            
            // Process it immediately
            self.process_next_request().await?;
            
            // RFC 9204 Section 4.4.1: Send Section Acknowledgment
            self.send_section_acknowledgment(stream_id).await?;
        }
        
        Ok(())
    }

    /// Check if we should grease (use reserved identifiers)
    /// 
    /// RFC 9114: Implementations should send reserved identifiers occasionally
    /// to prevent intermediaries from ossifying on current protocol.
    /// Returns true ~10% of the time.
    fn should_grease() -> bool {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hash, Hasher};
        
        let s = RandomState::new();
        let mut hasher = s.build_hasher();
        std::time::SystemTime::now().hash(&mut hasher);
        (hasher.finish() % 10) == 0
    }
    
    /// Generate a reserved setting identifier
    /// 
    /// RFC 9114 Section 7.2.4.1: Reserved identifiers have form 0x1f * N + 0x21
    fn generate_reserved_setting_id() -> u64 {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hash, Hasher};
        
        let s = RandomState::new();
        let mut hasher = s.build_hasher();
        std::time::SystemTime::now().hash(&mut hasher);
        let n = (hasher.finish() % 10) as u64; // Use N in range 0-9
        0x1f * n + 0x21
    }
    
    /// Generate a reserved frame type
    /// 
    /// RFC 9114 Section 7.2.8: Reserved frame types have form 0x1f * N + 0x21
    fn generate_reserved_frame_type() -> u64 {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hash, Hasher};
        
        let s = RandomState::new();
        let mut hasher = s.build_hasher();
        std::time::SystemTime::now().hash(&mut hasher);
        let n = (hasher.finish() % 10) as u64;
        0x1f * n + 0x21
    }

    /// Encode a value as a QUIC variable-length integer.
    ///
    /// Per RFC 9000 Section 16: Variable-length integers are encoded using
    /// 1, 2, 4, or 8 bytes, with a 2-bit prefix indicating the length.
    fn encode_varint_static(value: u64) -> Vec<u8> {
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

    /// Wrapper for encode_varint_static for backwards compatibility
    fn encode_varint(&self, value: u64) -> Vec<u8> {
        Self::encode_varint_static(value)
    }

    /// Send a push response on an opened push stream.
    /// 
    /// RFC 9114 Section 4.6: Push responses are sent on unidirectional push streams
    /// initiated by the server. The stream begins with the push stream type (0x01)
    /// and push ID, followed by the response.
    async fn send_push_response_on_stream(
        &mut self,
        push_id: u64,
        send_stream: quicd_x::SendStream,
        request_id: u64,
    ) -> Result<(), H3Error> {
        // Check if push was cancelled before opening stream
        {
            let manager = self.push_manager.lock().await;
            if let Some(promise) = manager.get_promise(push_id) {
                if promise.is_cancelled() {
                    // Push was cancelled - don't send anything
                    return Err(H3Error::Http(format!("push {} was cancelled", push_id)));
                }
            }
        }
        
        // Write push stream type header (0x01) per RFC 9114 Section 6.2.2
        let stream_type = vec![0x01];
        send_stream.write(Bytes::from(stream_type), false).await
            .map_err(|e| H3Error::Stream(format!("failed to write stream type: {:?}", e)))?;
        
        // Write push ID as varint
        let push_id_bytes = self.encode_varint(push_id);
        send_stream.write(Bytes::from(push_id_bytes), false).await
            .map_err(|e| H3Error::Stream(format!("failed to write push ID: {:?}", e)))?;
        
        // Notify PushManager that stream opened
        let mut manager = self.push_manager.lock().await;
        let stream_id = send_stream.stream_id;
        manager.handle_stream_opened(request_id, stream_id)?;
        
        // Get the push response if available
        let response_data = manager.get_promise(push_id)
            .and_then(|promise| promise.response().cloned());
        
        drop(manager); // Release lock before encoding
        
        if let Some(response) = response_data {
            // Encode response headers
            let mut all_headers = vec![
                (":status".to_string(), response.status.to_string()),
            ];
            all_headers.extend(response.headers);
            
            let (encoded_headers, encoder_instructions, referenced_entries) = {
                let mut qpack = self.qpack.write().await;
                let result = qpack.encode_headers(&all_headers)
                    .map_err(|_| H3Error::Qpack("encoding failed".into()))?;
                // RFC 9204 Section 2.1.2: Add references
                for index in &result.2 {
                    qpack.add_reference(*index);
                }
                result
            };
            
            // Send encoder instructions to encoder stream if any
            if !encoder_instructions.is_empty() {
                let mut encoder_stream_guard = self.encoder_send_stream.lock().await;
                if let Some(encoder_stream) = encoder_stream_guard.as_mut() {
                    // Batch all instructions into a single write
                    let total_size: usize = encoder_instructions.iter().map(|b| b.len()).sum();
                    let mut combined = bytes::BytesMut::with_capacity(total_size);
                    for instruction in encoder_instructions {
                        combined.extend_from_slice(&instruction);
                    }
                    encoder_stream.write(combined.freeze(), false).await
                        .map_err(|e| H3Error::Stream(format!("failed to write encoder instructions: {:?}", e)))?;
                }
            }
            
            // Send HEADERS frame
            let headers_frame = H3Frame::Headers { encoded_headers };
            let frame_data = headers_frame.encode();
            send_stream.write(frame_data, false).await
                .map_err(|e| H3Error::Stream(format!("write failed: {:?}", e)))?;
            
            // Send DATA frame with FIN
            let data_frame = H3Frame::Data { data: response.body };
            let data_frame_data = data_frame.encode();
            send_stream.write(data_frame_data, true).await
                .map_err(|e| H3Error::Stream(format!("write failed: {:?}", e)))?;
            
            // Mark push as completed and release references
            let mut manager = self.push_manager.lock().await;
            if let Some(promise) = manager.get_promise_mut(push_id) {
                promise.mark_completed();
            }
            
            // Release QPACK dynamic table references when push completes
            let mut qpack = self.qpack.write().await;
            for index in referenced_entries {
                qpack.release_reference(index);
            }
        } else {
            // No response data available - send CANCEL_PUSH and close stream
            let _ = self.send_cancel_push_frame(push_id).await;
            return Err(H3Error::Http(format!("no response data for push ID {}", push_id)));
        }
        
        Ok(())
    }
}

/// Factory for creating HTTP/3 application instances.
pub struct H3Factory<H: H3Handler> {
    handler: H,
    settings_storage: Arc<dyn SettingsStorage>,
}

impl<H: H3Handler> H3Factory<H> {
    pub fn new(handler: H) -> Self {
        Self { 
            handler,
            settings_storage: Arc::new(InMemorySettingsStorage::new()),
        }
    }

    pub fn with_settings_storage(handler: H, settings_storage: Arc<dyn SettingsStorage>) -> Self {
        Self { handler, settings_storage }
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
        let session = H3Session::new(handle, self.handler.clone(), self.settings_storage.clone());
        session.run(events, shutdown).await
            .map_err(|e| quicd_x::ConnectionError::App(format!("HTTP/3 error: {:?}", e)))
    }
}