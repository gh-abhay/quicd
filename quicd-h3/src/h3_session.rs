use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use slab::Slab;
use tokio::sync::Mutex as AsyncMutex;

use quicd_qpack::{AsyncDecoder, AsyncEncoder};
use quicd_x::{AppEvent, ConnectionHandle, QuicAppFactory, ShutdownFuture, TransportControls};

use crate::connect::validate_connect_request;
use crate::error::H3Error;
use crate::frames::{H3Frame, Setting};
use crate::metrics::H3Metrics;
use crate::priority::PriorityTree;
use crate::push::PushManager;
use crate::session::{H3Handler, H3Request, H3ResponseSender};
use crate::settings::{known, SettingsValidator};
use crate::settings_storage::{InMemorySettingsStorage, Origin, SettingsStorage};
use crate::stream_state::StreamFrameParser;

/// Core HTTP/3 session implementation.
///
/// Manages the HTTP/3 protocol state, including control streams, QPACK,
/// request/response handling, and integration with the underlying QUIC transport.
pub struct H3Session<H: H3Handler> {
    handle: ConnectionHandle,
    // GAP #6: HTTP/3 configuration
    config: crate::config::H3Config,
    // QPACK encoder and decoder
    qpack_encoder: Arc<AsyncMutex<AsyncEncoder>>,
    qpack_decoder: AsyncDecoder,
    server_control_send: Option<quicd_x::SendStream>,
    // Stream state tracking using slab for O(1) access
    streams: Slab<StreamState>,
    // Stream ID to slab key mapping
    stream_id_to_key: HashMap<u64, usize>,
    handler: Arc<H>,
    push_manager: Arc<tokio::sync::Mutex<PushManager>>,
    pending_control_stream_request: Option<u64>,
    pending_push_streams: HashMap<u64, u64>, // request_id -> push_id
    // New RFC-compliant components
    settings_validator: SettingsValidator,
    // Server push state
    max_push_id: u64,
    _next_push_id: u64,
    _push_streams: HashMap<u64, PushStreamState>,
    // QPACK streams
    encoder_stream_id: Option<u64>,
    decoder_stream_id: Option<u64>,
    pending_encoder_stream_request: Option<u64>,
    pending_decoder_stream_request: Option<u64>,
    encoder_send_stream: Arc<AsyncMutex<Option<quicd_x::SendStream>>>,
    decoder_send_stream: Option<quicd_x::SendStream>,
    // Peer QPACK stream IDs for validation (streams are processed in background tasks)
    peer_encoder_stream_id: Option<u64>,
    peer_decoder_stream_id: Option<u64>,
    // Peer control stream
    peer_control_stream_id: Option<u64>,
    peer_control_stream_received_settings: bool,
    // Stream types for validation
    stream_types: HashMap<u64, StreamType>,
    // GOAWAY tracking
    last_goaway_id: Option<u64>,
    // GOAWAY state
    goaway_sent: bool,
    goaway_received: bool,
    last_accepted_stream_id: u64,
    goaway_max_stream_id: Option<u64>,
    // Blocked streams tracking
    blocked_streams: HashMap<u64, BlockedStream>,
    // Priority queue for request processing (lower priority_id = higher priority)
    request_queue: std::collections::BinaryHeap<QueuedRequest>,
    // Track stream priorities
    stream_priorities: HashMap<u64, u64>, // stream_id -> priority_id
    // RFC 9218: Priority tree for extensible prioritization
    priority_tree: PriorityTree,
    // HTTP/3 operational metrics
    pub metrics: Arc<H3Metrics>,
    // 0-RTT settings storage (RFC 9114 Section 7.2.4.2)
    settings_storage: Arc<dyn SettingsStorage>,
    // Connection origin for settings storage
    origin: Option<Origin>,
    // RFC 9114 Section 5.1: Idle connection timeout tracking
    last_activity_time: std::time::Instant,
    idle_timeout: std::time::Duration,
    // RFC 9114 Section 3.3: SETTINGS frame must be first on control stream
    // Track deadline for receiving peer SETTINGS
    settings_deadline: Option<tokio::time::Instant>,
    // GAP #3: RFC 9114 Section 6.1: Stream ID validation
    // Track highest client-initiated bidirectional stream ID seen
    max_client_bidi_stream_id: u64,
    // Track highest client-initiated unidirectional stream ID seen
    max_client_uni_stream_id: u64,
    // Event-driven stream reading: Store RecvStream handles for non-blocking I/O
    // Maps stream_id -> (RecvStream, buffer for partial frames)
    active_recv_streams: HashMap<u64, ActiveRecvStream>,
}

/// Active receive stream state for event-driven, non-blocking reading
struct ActiveRecvStream {
    recv_stream: quicd_x::RecvStream,
    // Buffered data that hasn't been fully parsed yet
    buffer: bytes::BytesMut,
}

/// Stream type context for validating frame associations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // All variants used for frame validation
enum StreamType {
    Control,
    Request,
    QpackEncoder,
    QpackDecoder,
}

/// RFC 9114 Section 4.1: Stream processing phases for proper frame sequencing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamPhase {
    /// Waiting for initial HEADERS frame
    Initial,
    /// HEADERS received, processing DATA frames
    ReceivedHeaders,
    /// All DATA frames received, may receive trailing HEADERS
    ReceivedBody,
    /// Trailing HEADERS received, stream complete
    ReceivedTrailers,
    /// Final response sent, stream closing
    Complete,
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
        content_length: Option<u64>, // From Content-Length header
        bytes_received: u64,         // Sum of DATA frame payload bytes
        // QPACK blocking is handled internally by quicd-qpack
        // RFC 9114 Section 4.1: Explicit phase tracking for frame sequencing
        phase: StreamPhase,
        // RFC 9114 Section 4.1: Track if this is a CONNECT request (no DATA allowed for standard CONNECT)
        is_connect: bool,
        // RFC 9114 Section 4.4: Track if this is extended CONNECT with :protocol
        is_extended_connect: bool,
        // RFC 9114 Section 4.1.2: Track number of responses received (must be exactly 1 final)
        // RFC 9114 Section 4.1: Track responses to detect multiple final responses
        #[allow(dead_code)] // Will be used for multi-response validation
        response_count: u32,
        #[allow(dead_code)] // Will be used for interim response limits
        interim_response_count: u32,
    },
}

/// Blocked stream waiting for dynamic table entries
#[derive(Debug)]
#[allow(dead_code)] // Used for future QPACK blocking implementation
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
        other
            .priority_id
            .cmp(&self.priority_id)
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
    Promised {
        headers: Vec<(String, String)>,
        send_stream: Option<quicd_x::SendStream>,
    },
    Pushed {
        headers_sent: bool,
        body: Vec<Bytes>,
    },
    Cancelled,
}

impl<H: H3Handler> H3Session<H> {
    pub fn new(
        handle: ConnectionHandle,
        handler: H,
        settings_storage: Arc<dyn SettingsStorage>,
    ) -> Self {
        Self::with_config(
            handle,
            handler,
            settings_storage,
            crate::config::H3Config::default(),
        )
    }

    pub fn with_config(
        handle: ConnectionHandle,
        handler: H,
        settings_storage: Arc<dyn SettingsStorage>,
        config: crate::config::H3Config,
    ) -> Self {
        Self::with_origin_and_config(handle, handler, settings_storage, None, config)
    }

    pub fn with_origin(
        handle: ConnectionHandle,
        handler: H,
        settings_storage: Arc<dyn SettingsStorage>,
        origin: Option<Origin>,
    ) -> Self {
        Self::with_origin_and_config(
            handle,
            handler,
            settings_storage,
            origin,
            crate::config::H3Config::default(),
        )
    }

    pub fn with_origin_and_config(
        handle: ConnectionHandle,
        handler: H,
        settings_storage: Arc<dyn SettingsStorage>,
        origin: Option<Origin>,
        config: crate::config::H3Config,
    ) -> Self {
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

        let idle_timeout = config.idle_timeout;

        // RFC 9204: Initialize QPACK with configured table sizes
        // These must match the SETTINGS we will send to the peer
        let qpack_max_table_capacity = config.qpack_max_table_capacity as usize;
        let qpack_blocked_streams = config.qpack_blocked_streams as usize;
        let qpack_blocked_stream_timeout = config.qpack_blocked_stream_timeout;

        Self {
            handle,
            // Use provided configuration
            config,
            // RFC 9204: QPACK encoder/decoder with configured table sizes
            // Must match SETTINGS_QPACK_MAX_TABLE_CAPACITY and SETTINGS_QPACK_BLOCKED_STREAMS
            qpack_encoder: Arc::new(AsyncMutex::new(AsyncEncoder::new(
                qpack_max_table_capacity,
                qpack_blocked_streams,
            ))),
            qpack_decoder: AsyncDecoder::with_timeout(
                qpack_max_table_capacity,
                qpack_blocked_streams,
                qpack_blocked_stream_timeout,
            ),
            server_control_send: None,
            streams: Slab::new(),
            stream_id_to_key: HashMap::new(),
            handler: Arc::new(handler),
            push_manager,
            pending_control_stream_request: None,
            pending_push_streams: HashMap::new(),
            // New RFC-compliant components
            settings_validator,
            // Server push state
            max_push_id: 0,
            _next_push_id: 0,
            _push_streams: HashMap::new(),
            // QPACK streams
            encoder_stream_id: None,
            decoder_stream_id: None,
            pending_encoder_stream_request: None,
            pending_decoder_stream_request: None,
            encoder_send_stream: Arc::new(AsyncMutex::new(None)),
            decoder_send_stream: None,
            // Peer QPACK stream IDs for validation (streams are processed in background tasks)
            peer_encoder_stream_id: None,
            peer_decoder_stream_id: None,
            // Peer control stream
            peer_control_stream_id: None,
            peer_control_stream_received_settings: false,
            // Stream types for validation
            stream_types: HashMap::new(),
            // GOAWAY tracking
            last_goaway_id: None,
            // GOAWAY state
            goaway_sent: false,
            goaway_received: false,
            last_accepted_stream_id: u64::MAX,
            goaway_max_stream_id: None,
            // Blocked streams tracking
            blocked_streams: HashMap::new(),
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
            // RFC 9114 Section 5.1: Idle timeout tracking from config
            last_activity_time: std::time::Instant::now(),
            idle_timeout,
            // RFC 9114 Section 3.3: SETTINGS must arrive within configured deadline
            settings_deadline: None,
            // GAP #3: Initialize stream ID tracking (no streams seen yet)
            max_client_bidi_stream_id: 0,
            max_client_uni_stream_id: 0,
            // Event-driven stream reading
            active_recv_streams: HashMap::new(),
        }
    }

    /// Main event loop for the HTTP/3 session.
    pub async fn run(
        mut self,
        mut events: quicd_x::AppEventStream,
        mut shutdown: ShutdownFuture,
    ) -> Result<(), H3Error> {
        // RFC 9204 Section 2.1.4: Check for blocked stream timeouts periodically
        // Use configured interval from H3Config
        let mut timeout_check_interval =
            tokio::time::interval(self.config.blocked_stream_check_interval);
        timeout_check_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // GAP FIX #3: RFC 9114 Section 5.1: Check for idle timeout
        // Use configured interval from H3Config
        let mut idle_check_interval = tokio::time::interval(self.config.idle_check_interval);
        idle_check_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                Some(event) = events.next() => {
                    if let Err(e) = self.handle_event(event).await {
                        eprintln!("Error handling event: {:?}", e);
                        // Continue processing other events
                    }
                }
                _ = timeout_check_interval.tick() => {
                    // RFC 9204 Section 2.1.4: Check for QPACK blocked stream timeouts
                    if let Err(e) = self.check_blocked_stream_timeouts().await {
                        eprintln!("Error checking blocked stream timeouts: {:?}", e);
                    }
                }
                _ = idle_check_interval.tick() => {
                    // GAP FIX #2: RFC 9114 Section 3.3: Check SETTINGS deadline
                    if let Some(deadline) = self.settings_deadline {
                        if tokio::time::Instant::now() >= deadline {
                            eprintln!("SETTINGS frame not received within timeout");
                            // RFC 9114 Section 3.3: Connection error H3_MISSING_SETTINGS
                            return Err(H3Error::MissingSettings);
                        }
                    }

                    // GAP FIX #3: RFC 9114 Section 5.1: Check for idle timeout
                    if let Err(e) = self.check_idle_timeout().await {
                        eprintln!("Error checking idle timeout: {:?}", e);
                        // Idle timeout is fatal - close connection
                        break;
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
                    // RFC 9114 Section 7.2.4.2: Check if connection is using 0-RTT
                    // "When a 0-RTT QUIC connection is being used, the initial value of each
                    // server setting is the value used in the previous session."
                    // The settings validator already has remembered settings if available from storage.
                    // Actual 0-RTT validation occurs when peer SETTINGS frame arrives.
                    let is_0rtt = self.handle.is_in_early_data().await.unwrap_or(false);

                    if is_0rtt {
                        // Mark that we're in 0-RTT mode for settings validation
                        // The actual validation happens when SETTINGS frame is received
                        eprintln!("Connection using 0-RTT - will validate settings compatibility against remembered values");
                    } // Initialize HTTP/3 session
                    self.initialize_session().await?;
                }
            }
            AppEvent::NewStream {
                stream_id,
                bidirectional,
                recv_stream,
                send_stream,
            } => {
                // Check GOAWAY state before processing
                if !self.should_accept_stream(stream_id) {
                    // Silently drop streams beyond GOAWAY
                    return Ok(());
                }

                if bidirectional {
                    self.handle_bidirectional_stream(stream_id, recv_stream, send_stream)
                        .await?;
                } else {
                    // Unidirectional stream (push or control)
                    // Register the stream - don't block on reading
                    self.handle_unidirectional_stream(stream_id, recv_stream)
                        .await?;
                    
                    // Now that stream is registered, read the stream type (first byte)
                    // This is needed to identify what kind of stream it is
                    self.process_new_unidirectional_stream(stream_id).await?;
                }
            }
            AppEvent::StreamReadable { stream_id } => {
                self.handle_stream_readable(stream_id).await?;
            }
            AppEvent::StreamFinished { stream_id: _ } => {
                // Handle stream end
            }
            AppEvent::StreamClosed {
                stream_id,
                app_initiated,
                error_code,
            } => {
                // RFC 9114 Section 6.2.1: Critical stream closure is fatal
                if Some(stream_id) == self.peer_control_stream_id {
                    // Peer's control stream closed - H3_CLOSED_CRITICAL_STREAM
                    eprintln!("Peer control stream {} closed - fatal error", stream_id);
                    let error_code = crate::error::H3ErrorCode::ClosedCriticalStream.to_u64();
                    self.handle
                        .close(error_code, Some(Bytes::from("peer control stream closed")))
                        .map_err(|e| H3Error::Connection(format!("close error: {:?}", e)))?;
                    return Err(H3Error::Connection(
                        "H3_CLOSED_CRITICAL_STREAM: peer control stream closed".into(),
                    ));
                }

                // Check if our QPACK streams closed
                if Some(stream_id) == self.peer_encoder_stream_id
                    || Some(stream_id) == self.peer_decoder_stream_id
                {
                    eprintln!("Peer QPACK stream {} closed - fatal error", stream_id);
                    let error_code = crate::error::H3ErrorCode::ClosedCriticalStream.to_u64();
                    self.handle
                        .close(error_code, Some(Bytes::from("peer QPACK stream closed")))
                        .map_err(|e| H3Error::Connection(format!("close error: {:?}", e)))?;
                    return Err(H3Error::Connection(
                        "H3_CLOSED_CRITICAL_STREAM: peer QPACK stream closed".into(),
                    ));
                }

                // RFC 9114 Section 4.1.1: Stream was reset
                // Clean up stream state and notify QPACK decoder if needed
                self.handle_stream_closed(stream_id, app_initiated, error_code)
                    .await?;

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
                        send_stream
                            .write(Bytes::from(vec![0x00]), false)
                            .await
                            .map_err(|e| {
                                H3Error::Stream(format!(
                                    "failed to write control stream type: {:?}",
                                    e
                                ))
                            })?;
                        self.server_control_send = Some(send_stream);
                        // Send SETTINGS frame immediately as required by RFC 9114
                        self.send_settings().await?;
                    } else {
                        return Err(H3Error::Connection(
                            "failed to open server control stream".into(),
                        ));
                    }
                } else if Some(request_id) == self.pending_encoder_stream_request {
                    // RFC 9204 Section 4.2: This is our QPACK encoder stream
                    self.pending_encoder_stream_request = None;
                    if let Ok(send_stream) = result {
                        // Write encoder stream type (0x02)
                        send_stream
                            .write(Bytes::from(vec![0x02]), false)
                            .await
                            .map_err(|e| {
                                H3Error::Stream(format!(
                                    "failed to write encoder stream type: {:?}",
                                    e
                                ))
                            })?;
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
                        send_stream
                            .write(Bytes::from(vec![0x03]), false)
                            .await
                            .map_err(|e| {
                                H3Error::Stream(format!(
                                    "failed to write decoder stream type: {:?}",
                                    e
                                ))
                            })?;
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
                            if let Err(e) = self
                                .send_push_response_on_stream(push_id, send_stream, request_id)
                                .await
                            {
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
            AppEvent::Datagram { payload } => {
                // RFC 9114 Section 2.1.2: HTTP/3 Datagrams
                // Datagrams are only allowed if H3_DATAGRAM setting is enabled
                if self.settings_validator.get(known::H3_DATAGRAM).unwrap_or(0) != 1 {
                    // Datagrams not supported - silently ignore per RFC 9114
                    self.metrics
                        .datagrams_received
                        .fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }

                // RFC 9297 Section 2: Parse flow ID (Quarter Stream ID) as varint
                // "The payload of an HTTP/3 datagram consists of a variable-length integer
                // field followed by the datagram payload"
                let (flow_id, consumed) = if !payload.is_empty() {
                    match crate::frames::H3Frame::decode_varint(&payload) {
                        Ok((id, len)) => (id, len),
                        Err(_) => {
                            // Invalid datagram format - drop it
                            eprintln!("Datagram with invalid flow ID encoding");
                            self.metrics
                                .datagrams_received
                                .fetch_add(1, Ordering::Relaxed);
                            return Ok(());
                        }
                    }
                } else {
                    // Empty datagram - malformed per RFC 9297
                    eprintln!("Empty datagram received");
                    self.metrics
                        .datagrams_received
                        .fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                };

                // Extract datagram payload (after flow ID)
                let datagram_payload = payload.slice(consumed..);

                // Forward to application handler
                let handler = Arc::clone(&self.handler);
                if let Err(e) = handler.handle_datagram(flow_id, datagram_payload).await {
                    eprintln!("Datagram handler error: {:?}", e);
                }
                self.metrics
                    .datagrams_received
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
        Ok(())
    }

    async fn initialize_session(&mut self) -> Result<(), H3Error> {
        // RFC 9114 Section 3.3: Set deadline for receiving peer SETTINGS frame from config
        self.settings_deadline = Some(tokio::time::Instant::now() + self.config.settings_deadline);

        // RFC 9114 Section 6.2.1: Open server control stream (must be first)
        let control_request_id = self
            .handle
            .open_uni()
            .map_err(|e| H3Error::Connection(format!("failed to open control stream: {:?}", e)))?;
        self.pending_control_stream_request = Some(control_request_id);

        // RFC 9204 Section 4.2: Create QPACK encoder stream
        // "Each endpoint MUST initiate, at most, one encoder stream"
        let encoder_request_id = self
            .handle
            .open_uni()
            .map_err(|e| H3Error::Connection(format!("failed to open encoder stream: {:?}", e)))?;
        self.pending_encoder_stream_request = Some(encoder_request_id);

        // RFC 9204 Section 4.2: Create QPACK decoder stream
        // "Each endpoint MUST initiate, at most, one decoder stream"
        let decoder_request_id = self
            .handle
            .open_uni()
            .map_err(|e| H3Error::Connection(format!("failed to open decoder stream: {:?}", e)))?;
        self.pending_decoder_stream_request = Some(decoder_request_id);

        Ok(())
    }

    fn should_accept_stream(&self, stream_id: u64) -> bool {
        // GAP FIX #8: RFC 9114 Section 5.2: Don't accept new streams after GOAWAY
        // This prevents the race condition where a client opens a new stream
        // just as we're processing a GOAWAY frame
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
        // GAP FIX #3: RFC 9114 Section 6.1: Comprehensive stream ID validation
        // 1. Validate stream initiator (client vs server)
        crate::stream_validation::validate_client_bidirectional_stream(stream_id, true)?;

        // 2. Validate stream ID monotonicity (must be > previous)
        // RFC 9114 Section 6.1: "Stream IDs are used to identify streams within a connection."
        // Client-initiated bidirectional streams must have odd IDs and increase monotonically
        if stream_id <= self.max_client_bidi_stream_id && self.max_client_bidi_stream_id > 0 {
            return Err(H3Error::Connection(format!(
                "H3_ID_ERROR: stream_id {} not greater than previous {}",
                stream_id, self.max_client_bidi_stream_id
            )));
        }
        self.max_client_bidi_stream_id = stream_id;

        // GAP FIX #5: RFC 9114 Section 7.2.8: Periodically send reserved frames for greasing
        // This is called per request stream to ensure systematic greasing distribution
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

        // GAP #6: Initialize stream parser with configurable buffer limits per RFC 9114
        let mut frame_parser = StreamFrameParser::new(
            stream_id,
            self.config.stream_buffer_initial_capacity,
            self.config.stream_buffer_max_size,
        );
        frame_parser.mark_open();

        // Track stream type for frame validation
        self.stream_types.insert(stream_id, StreamType::Request);

        let stream_key = self.streams.insert(StreamState::Request {
            headers_received: false,
            trailers_received: false,
            body: Vec::new(),
            trailers: None,
            send_stream: send_stream.unwrap(), // bidirectional, so should have send_stream
            // Phase 3: Initialize Content-Length tracking
            content_length: None,
            bytes_received: 0,
            // QPACK blocking is handled internally by quicd-qpack
            // RFC 9114 Section 4.1: Initialize stream phase tracking
            phase: StreamPhase::Initial,
            is_connect: false,
            is_extended_connect: false,
            response_count: 0,
            interim_response_count: 0,
        });
        self.stream_id_to_key.insert(stream_id, stream_key);

        // Read frames from the stream with proper buffering
        while let Ok(Some(data)) = recv_stream.read().await {
            match data {
                quicd_x::StreamData::Data(bytes) => {
                    // Use StreamFrameParser for proper frame buffering
                    // Collect frames first to avoid borrow checker issues
                    frame_parser.add_data(bytes)?;

                    let mut collected_frames = Vec::new();
                    while let Some(frame) = frame_parser.parse_next_frame()? {
                        collected_frames.push(frame);
                    }

                    // Process all collected frames
                    for frame in collected_frames {
                        self.process_frame_on_request_stream(stream_id, frame)
                            .await?;
                    }
                }
                quicd_x::StreamData::Fin => {
                    frame_parser.mark_half_closed_remote();
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
        recv_stream: quicd_x::RecvStream,
    ) -> Result<(), H3Error> {
        // GAP FIX #3: RFC 9114 Section 6.1: Validate stream ID monotonicity
        // Client-initiated unidirectional streams must have increasing IDs
        if stream_id <= self.max_client_uni_stream_id && self.max_client_uni_stream_id > 0 {
            return Err(H3Error::Connection(format!(
                "H3_ID_ERROR: uni stream_id {} not greater than previous {}",
                stream_id, self.max_client_uni_stream_id
            )));
        }
        self.max_client_uni_stream_id = stream_id;

        // RFC 9114 Section 6.2: Read stream type from first bytes
        // "The purpose is indicated by a stream type, which is sent as a
        // variable-length integer at the start of the stream."
        
        // Store the stream for event-driven reading - do NOT block on read
        // The stream type will be read when StreamReadable event arrives
        self.active_recv_streams.insert(
            stream_id,
            ActiveRecvStream {
                recv_stream,
                buffer: bytes::BytesMut::new(),
            },
        );

        // Return immediately - data will be processed in handle_stream_readable
        Ok(())
    }

    /// Read and process stream type for a newly registered unidirectional stream
    async fn process_new_unidirectional_stream(&mut self, stream_id: u64) -> Result<(), H3Error> {
        // Get the active stream (should exist since we just registered it)
        let active_stream = match self.active_recv_streams.get_mut(&stream_id) {
            Some(s) => s,
            None => return Ok(()), // Stream was already removed
        };

        // Try to read stream type byte
        let stream_type = match active_stream.recv_stream.read().await {
            Ok(Some(quicd_x::StreamData::Data(bytes))) => {
                // Parse stream type varint from the first bytes
                let (stream_type, consumed) = crate::frames::H3Frame::decode_varint(&bytes)
                    .map_err(|e| H3Error::FrameParse(format!("invalid stream type varint: {:?}", e)))?;
                
                // Store any remaining bytes in the buffer
                if consumed < bytes.len() {
                    active_stream.buffer.extend_from_slice(&bytes[consumed..]);
                }
                
                stream_type
            }
            Ok(Some(quicd_x::StreamData::Fin)) => {
                // Stream ended before type byte - error
                self.active_recv_streams.remove(&stream_id);
                return Err(H3Error::Connection(
                    "stream ended before stream type".into(),
                ));
            }
            Ok(None) => {
                // Channel closed
                self.active_recv_streams.remove(&stream_id);
                return Err(H3Error::Connection("no data on stream".into()));
            }
            Err(e) => {
                self.active_recv_streams.remove(&stream_id);
                return Err(H3Error::Stream(format!(
                    "failed to read stream type: {:?}",
                    e
                )));
            }
        };

        // Validate unidirectional stream initiator based on stream type
        crate::stream_validation::validate_unidirectional_stream_initiator(
            stream_id,
            stream_type,
            true,
        )?;

        match stream_type {
            0x00 => {
                // Control stream (RFC 9114 Section 6.2.1)
                // "Only one control stream per peer is permitted; receipt of a second stream
                // claiming to be a control stream MUST be treated as a connection error of
                // type H3_STREAM_CREATION_ERROR"
                if self.peer_control_stream_id.is_some() {
                    self.active_recv_streams.remove(&stream_id);
                    return Err(H3Error::Connection(
                        "duplicate control stream from peer - H3_STREAM_CREATION_ERROR".into(),
                    ));
                }
                self.peer_control_stream_id = Some(stream_id);
                self.stream_types.insert(stream_id, StreamType::Control);
                let key = self.streams.insert(StreamState::Control);
                self.stream_id_to_key.insert(stream_id, key);
                // Stream is now registered and ready for StreamReadable events
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
                self.active_recv_streams.remove(&stream_id);
                return Err(H3Error::Connection(
                    "H3_STREAM_CREATION_ERROR: push stream received by server (only servers can push)".into()
                ));
            }
            0x02 => {
                // QPACK encoder stream (RFC 9204 Section 4.2)
                if self.peer_encoder_stream_id.is_some() {
                    self.active_recv_streams.remove(&stream_id);
                    return Err(H3Error::Connection(
                        "duplicate QPACK encoder stream from peer - H3_STREAM_CREATION_ERROR"
                            .into(),
                    ));
                }
                self.peer_encoder_stream_id = Some(stream_id);
                let key = self.streams.insert(StreamState::QpackEncoder);
                self.stream_id_to_key.insert(stream_id, key);
                // Stream is now registered and ready for StreamReadable events
            }
            0x03 => {
                // QPACK decoder stream (RFC 9204 Section 4.2)
                if self.peer_decoder_stream_id.is_some() {
                    self.active_recv_streams.remove(&stream_id);
                    return Err(H3Error::Connection(
                        "duplicate QPACK decoder stream from peer - H3_STREAM_CREATION_ERROR"
                            .into(),
                    ));
                }
                self.peer_decoder_stream_id = Some(stream_id);
                let key = self.streams.insert(StreamState::QpackDecoder);
                self.stream_id_to_key.insert(stream_id, key);
                // Stream is now registered and ready for StreamReadable events
            }
            _ if crate::frames::H3Frame::is_reserved_stream_type(stream_type) => {
                // RFC 9114 Section 6.2.3: Reserved stream types for greasing
                // "Stream types of the format 0x1f * N + 0x21 for non-negative integer
                // values of N are reserved to exercise the requirement that unknown
                // types be ignored. These streams have no semantics, and they can be
                // sent when application-layer padding is desired."
                //
                // MUST be ignored but stream still consumes resources
                self.metrics
                    .reserved_streams_received
                    .fetch_add(1, Ordering::Relaxed);
                // Remove from active streams - we'll silently discard
                self.active_recv_streams.remove(&stream_id);
            }
            _ => {
                // RFC 9114 Section 6.2: Unknown stream type
                // "If the stream header indicates a stream type that is not supported by
                // the recipient, the remainder of the stream cannot be consumed as the
                // semantics are unknown. Recipients of unknown stream types MUST either
                // abort reading of the stream or discard incoming data without further
                // processing."
                //
                // We choose to discard incoming data for better interoperability
                self.metrics
                    .unknown_streams_received
                    .fetch_add(1, Ordering::Relaxed);
                // Remove from active streams - we'll silently discard
                self.active_recv_streams.remove(&stream_id);
            }
        }

        Ok(())
    }



    async fn handle_stream_readable(&mut self, stream_id: u64) -> Result<(), H3Error> {
        // Stream has data available - this is edge-triggered
        // Read available data without blocking and process it
        
        // Check if this is a stream we're tracking
        if !self.active_recv_streams.contains_key(&stream_id) {
            // Not a stream we're tracking (bidirectional streams handle their own reading)
            return Ok(());
        }

        // Identify stream type and delegate to appropriate handler
        let stream_type = self.stream_types.get(&stream_id).copied();
        
        match stream_type {
            Some(StreamType::Control) => {
                self.read_control_stream_data(stream_id).await?;
            }
            Some(StreamType::QpackEncoder) => {
                self.read_qpack_encoder_stream_data(stream_id).await?;
            }
            Some(StreamType::QpackDecoder) => {
                self.read_qpack_decoder_stream_data(stream_id).await?;
            }
            Some(StreamType::Request) | None => {
                // Bidirectional request streams handle their own reading
                // in handle_bidirectional_stream via blocking read loop
                // (will be fixed in a future iteration)
            }
        }

        Ok(())
    }

    /// Read and process available data from control stream
    async fn read_control_stream_data(&mut self, stream_id: u64) -> Result<(), H3Error> {
        let active_stream = match self.active_recv_streams.get_mut(&stream_id) {
            Some(s) => s,
            None => return Ok(()), // Stream was removed
        };

        // Read available data (non-blocking since StreamReadable event fired)
        match active_stream.recv_stream.read().await {
            Ok(Some(quicd_x::StreamData::Data(bytes))) => {
                // Append to buffer
                active_stream.buffer.extend_from_slice(&bytes);
                
                // Process frames from buffered data
                let buffer_bytes = active_stream.buffer.split().freeze();
                self.process_control_frames(buffer_bytes).await?;
            }
            Ok(Some(quicd_x::StreamData::Fin)) => {
                // RFC 9114 Section 6.2.1: Control stream closure MUST be treated as
                // a connection error of type H3_CLOSED_CRITICAL_STREAM
                self.active_recv_streams.remove(&stream_id);
                return Err(H3Error::ClosedCriticalStream);
            }
            Ok(None) => {
                // Channel closed - treat as FIN
                self.active_recv_streams.remove(&stream_id);
                return Err(H3Error::ClosedCriticalStream);
            }
            Err(e) => {
                self.active_recv_streams.remove(&stream_id);
                return Err(H3Error::Stream(format!("control stream read error: {:?}", e)));
            }
        }

        Ok(())
    }

    /// Read and process available data from QPACK encoder stream
    async fn read_qpack_encoder_stream_data(&mut self, stream_id: u64) -> Result<(), H3Error> {
        let active_stream = match self.active_recv_streams.get_mut(&stream_id) {
            Some(s) => s,
            None => return Ok(()), // Stream was removed
        };

        // Read available data (non-blocking since StreamReadable event fired)
        match active_stream.recv_stream.read().await {
            Ok(Some(quicd_x::StreamData::Data(bytes))) => {
                // RFC 9204: Encoder stream contains instructions for our decoder
                self.qpack_decoder
                    .process_encoder_instruction(bytes.as_ref())
                    .await
                    .map_err(|e| {
                        H3Error::Qpack(format!("encoder stream instruction error: {:?}", e))
                    })?;

                // PERF FIX: Batch decoder instructions from encoder stream processing
                let mut decoder_instructions = Vec::new();
                while let Some(inst) = self.qpack_decoder.decoder_mut().poll_decoder_stream() {
                    decoder_instructions.push(inst);
                }
                if !decoder_instructions.is_empty() {
                    if let Some(ref stream) = self.decoder_send_stream {
                        let mut batch = bytes::BytesMut::new();
                        for inst in decoder_instructions {
                            batch.extend_from_slice(&inst);
                        }
                        let _ = stream.write(batch.freeze(), false).await;
                    }
                }

                // GAP FIX #5: RFC 9204 Section 2.1.4: Retry blocked streams now that table entries arrived
                let _ = self.retry_blocked_streams().await;
            }
            Ok(Some(quicd_x::StreamData::Fin)) => {
                // RFC 9114 Section 6.2.3 & RFC 9204 Section 4.2:
                // "Closure of either unidirectional stream type MUST be treated as a
                // connection error of type H3_CLOSED_CRITICAL_STREAM"
                self.active_recv_streams.remove(&stream_id);
                return Err(H3Error::ClosedCriticalStream);
            }
            Ok(None) => {
                // Channel closed - treat as FIN
                self.active_recv_streams.remove(&stream_id);
                return Err(H3Error::ClosedCriticalStream);
            }
            Err(e) => {
                self.active_recv_streams.remove(&stream_id);
                return Err(H3Error::Stream(format!("encoder stream read error: {:?}", e)));
            }
        }

        Ok(())
    }

    /// Read and process available data from QPACK decoder stream
    async fn read_qpack_decoder_stream_data(&mut self, stream_id: u64) -> Result<(), H3Error> {
        let active_stream = match self.active_recv_streams.get_mut(&stream_id) {
            Some(s) => s,
            None => return Ok(()), // Stream was removed
        };

        // Read available data (non-blocking since StreamReadable event fired)
        match active_stream.recv_stream.read().await {
            Ok(Some(quicd_x::StreamData::Data(bytes))) => {
                // RFC 9204: Decoder stream contains instructions for our encoder
                self.qpack_encoder
                    .lock()
                    .await
                    .process_decoder_instruction(bytes.as_ref())
                    .await
                    .map_err(|e| {
                        H3Error::Qpack(format!("decoder stream instruction error: {:?}", e))
                    })?;

                // RFC 9204 Section 2.1.4: Decoder acknowledgments received
                // This allows encoder to evict table entries that are no longer needed
                // Blocked streams are managed separately in check_blocked_stream_timeouts
            }
            Ok(Some(quicd_x::StreamData::Fin)) => {
                // RFC 9114 Section 6.2.3 & RFC 9204 Section 4.2:
                // "Closure of either unidirectional stream type MUST be treated as a
                // connection error of type H3_CLOSED_CRITICAL_STREAM"
                self.active_recv_streams.remove(&stream_id);
                return Err(H3Error::ClosedCriticalStream);
            }
            Ok(None) => {
                // Channel closed - treat as FIN
                self.active_recv_streams.remove(&stream_id);
                return Err(H3Error::ClosedCriticalStream);
            }
            Err(e) => {
                self.active_recv_streams.remove(&stream_id);
                return Err(H3Error::Stream(format!("decoder stream read error: {:?}", e)));
            }
        }

        Ok(())
    }

    async fn send_settings(&mut self) -> Result<(), H3Error> {
        if let Some(send_stream) = &mut self.server_control_send {
            // Build settings list from configuration
            let mut settings = vec![
                Setting {
                    identifier: 0x1,
                    value: self.config.qpack_max_table_capacity,
                }, // SETTINGS_QPACK_MAX_TABLE_CAPACITY
                Setting {
                    identifier: 0x6,
                    value: self.config.max_field_section_size,
                }, // SETTINGS_MAX_FIELD_SECTION_SIZE
                Setting {
                    identifier: 0x7,
                    value: self.config.qpack_blocked_streams,
                }, // SETTINGS_QPACK_BLOCKED_STREAMS
            ];

            // RFC 9114 Section 4.4: SETTINGS_ENABLE_CONNECT_PROTOCOL for extended CONNECT
            if self.config.enable_connect_protocol {
                settings.push(Setting {
                    identifier: 0x8,
                    value: 1,
                }); // SETTINGS_ENABLE_CONNECT_PROTOCOL
            }

            // RFC 9297: H3_DATAGRAM setting for datagram support
            // Send if datagrams are enabled in configuration
            // "An endpoint that supports HTTP Datagrams and uses HTTP/3 Datagrams MUST
            // include SETTINGS_H3_DATAGRAM in the HTTP/3 SETTINGS frame."
            if self.config.enable_datagrams {
                settings.push(Setting {
                    identifier: known::H3_DATAGRAM,
                    value: 1,
                });
            }

            // GAP FIX #5: RFC 9114 Section 7.2.4.1: Grease with reserved settings
            // Format: 0x1f * N + 0x21, where N >= 0
            // Use with configured probability to avoid ossification
            if Self::should_grease() {
                let grease_id = Self::generate_reserved_setting_id();
                settings.push(Setting {
                    identifier: grease_id,
                    value: 0,
                });
            }

            // Send SETTINGS frame
            let settings_frame = H3Frame::Settings { settings };
            let frame_data = settings_frame.encode();
            send_stream
                .write(frame_data, false)
                .await
                .map_err(|e| H3Error::Stream(format!("failed to send SETTINGS: {:?}", e)))?;

            // RFC 9114 Section 7.2.7: MAX_PUSH_ID frame MUST NOT be sent by servers.
            // Only clients send MAX_PUSH_ID to control the number of pushes they accept.
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
                    "Cannot send GOAWAY with stream_id greater than previous GOAWAY".into(),
                ));
            }
        }

        if let Some(send_stream) = &mut self.server_control_send {
            // Send GOAWAY frame with last accepted stream ID
            let goaway = H3Frame::GoAway { stream_id };
            let frame_data = goaway.encode();
            send_stream
                .write(frame_data, false)
                .await
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

            send_stream
                .write(Bytes::from(frame_data), false)
                .await
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
                    "H3_ID_ERROR: GOAWAY stream_id increased from previous GOAWAY".into(),
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
    async fn process_frame_on_request_stream(
        &mut self,
        stream_id: u64,
        frame: H3Frame,
    ) -> Result<(), H3Error> {
        // RFC 9114 Section 7.2: Validate frame is allowed on request stream (before any borrows)
        self.validate_frame_on_stream(&frame, StreamType::Request)?;

        // RFC 9114 Section 4.1: Validate frame sequence based on current phase
        if let Some(key) = self.stream_id_to_key.get(&stream_id) {
            if let Some(StreamState::Request { phase, .. }) = self.streams.get(*key) {
                match (&frame, phase) {
                    // DATA before HEADERS is malformed
                    (H3Frame::Data { .. }, StreamPhase::Initial) => {
                        return Err(H3Error::MessageError);
                    }
                    // Multiple final HEADERS frames not allowed (trailers after trailers)
                    (H3Frame::Headers { .. }, StreamPhase::ReceivedTrailers) => {
                        return Err(H3Error::MessageError);
                    }
                    // DATA after trailers not allowed
                    (H3Frame::Data { .. }, StreamPhase::ReceivedTrailers) => {
                        return Err(H3Error::MessageError);
                    }
                    _ => {} // Other sequences are valid
                }
            }
        }

        if let Some(StreamState::Request {
            headers_received,
            trailers_received,
            body,
            trailers,
            send_stream,
            content_length,
            bytes_received,
            phase,
            is_connect,
            is_extended_connect,
            response_count: _,
            interim_response_count: _,
        }) = self.streams.get_mut(self.stream_id_to_key[&stream_id])
        {
            // RFC 9114 Section 4.1: Process frame on request stream
            match frame {
                H3Frame::Headers { encoded_headers } => {
                    if !*headers_received {
                        // Initial HEADERS frame
                        let encoded_size = encoded_headers.len();
                        let header_fields = match self
                            .qpack_decoder
                            .decoder_mut()
                            .decode(stream_id, encoded_headers.clone())
                        {
                            Ok(fields) => fields,
                            Err(_) => {
                                // Blocking is handled internally by quicd-qpack
                                return Err(H3Error::Qpack("header decoding failed".into()));
                            }
                        };

                        // Convert HeaderField to (String, String)
                        let headers: Vec<(String, String)> = header_fields
                            .into_iter()
                            .map(|field| {
                                (
                                    String::from_utf8_lossy(&field.name).to_string(),
                                    String::from_utf8_lossy(&field.value).to_string(),
                                )
                            })
                            .collect();

                        // RFC 9114 Section 4.4: Detect CONNECT method
                        let method_opt = headers
                            .iter()
                            .find(|(n, _)| n == ":method")
                            .map(|(_, v)| v.as_str());
                        let has_protocol = headers.iter().any(|(n, _)| n == ":protocol");
                        *is_connect = method_opt == Some("CONNECT");
                        *is_extended_connect = *is_connect && has_protocol;

                        // PERF FIX: Batch decoder instructions to reduce syscalls
                        // RFC 9204: Batching improves throughput
                        let mut decoder_instructions = Vec::new();
                        while let Some(inst) =
                            self.qpack_decoder.decoder_mut().poll_decoder_stream()
                        {
                            decoder_instructions.push(inst);
                        }
                        if !decoder_instructions.is_empty() {
                            if let Some(ref stream) = self.decoder_send_stream {
                                let mut batch = bytes::BytesMut::new();
                                for inst in decoder_instructions {
                                    batch.extend_from_slice(&inst);
                                }
                                let _ = stream.write(batch.freeze(), false).await;
                            }
                        }

                        // Phase 3: Validate request headers per RFC 9114 Section 4.1
                        // This validates: pseudo-header ordering, uppercase rejection, connection-specific headers,
                        // required pseudo-headers, Content-Length uniqueness, TE validation, and more
                        let _pseudo_headers =
                            crate::validation::validate_request_headers(&headers)?;

                        // GAP FIX #7: RFC 9114 Section 4.2.2: Validate field section size
                        // "An endpoint that receives a field section larger than it is willing to handle
                        // MUST respond with HTTP status code 431 (Request Header Fields Too Large)."
                        if let Some(max_size) = self.settings_validator.max_field_section_size() {
                            crate::validation::validate_field_section_size(
                                &headers,
                                max_size as u64,
                            )?;
                        }

                        // Phase 3: Extract Content-Length for validation (RFC 9114 Section 4.1.2)
                        *content_length = Self::extract_content_length_static(&headers)?;

                        // Record QPACK decode metrics
                        let uncompressed_size: usize =
                            headers.iter().map(|(n, v)| n.len() + v.len()).sum();
                        self.metrics
                            .record_qpack_decode(uncompressed_size, encoded_size);
                        self.metrics
                            .header_bytes_received
                            .fetch_add(encoded_size as u64, Ordering::Relaxed);

                        // QPACK blocking and references are handled internally by quicd-qpack

                        // QPACK blocking and acknowledgments are handled internally by quicd-qpack

                        // Record metrics
                        self.metrics.record_request_received();
                        self.metrics
                            .frames_headers_received
                            .fetch_add(1, Ordering::Relaxed);

                        *headers_received = true;
                        // RFC 9114 Section 4.1: Update phase after initial HEADERS
                        *phase = StreamPhase::ReceivedHeaders;
                        // Queue request for priority-based processing instead of handling immediately
                        let priority_id = self
                            .stream_priorities
                            .get(&stream_id)
                            .copied()
                            .unwrap_or(255); // Default priority
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
                        let trailer_header_fields = match self
                            .qpack_decoder
                            .decoder_mut()
                            .decode(stream_id, encoded_headers.clone())
                        {
                            Ok(fields) => fields,
                            Err(_) => {
                                return Err(H3Error::Qpack("trailer decoding failed".into()));
                            }
                        };

                        let trailer_headers: Vec<(String, String)> = trailer_header_fields
                            .into_iter()
                            .map(|field| {
                                (
                                    String::from_utf8_lossy(&field.name).to_string(),
                                    String::from_utf8_lossy(&field.value).to_string(),
                                )
                            })
                            .collect();

                        // PERF FIX: Send decoder instructions in batch (trailers path)
                        let mut decoder_instructions = Vec::new();
                        while let Some(inst) =
                            self.qpack_decoder.decoder_mut().poll_decoder_stream()
                        {
                            decoder_instructions.push(inst);
                        }
                        if !decoder_instructions.is_empty() {
                            if let Some(ref stream) = self.decoder_send_stream {
                                let mut batch = bytes::BytesMut::new();
                                for inst in decoder_instructions {
                                    batch.extend_from_slice(&inst);
                                }
                                let _ = stream.write(batch.freeze(), false).await;
                            }
                        }

                        // RFC 9114 Section 4.1: Validate trailer headers
                        crate::validation::validate_trailer_headers(&trailer_headers)?;

                        // ISSUE FIX #2: Validate trailer field section size
                        if let Some(max_size) = self.settings_validator.max_field_section_size() {
                            crate::validation::validate_trailer_section_size(
                                &trailer_headers,
                                max_size as u64,
                            )?;
                        }

                        // QPACK blocking and references are handled internally by quicd-qpack

                        // Phase 3: Validate Content-Length matches received bytes (RFC 9114 Section 4.1.2)
                        if let Some(expected) = content_length {
                            if *bytes_received != *expected {
                                return Err(H3Error::MessageError);
                            }
                        }

                        // QPACK blocking and acknowledgments are handled internally by quicd-qpack

                        *trailers_received = true;
                        *trailers = Some(trailer_headers);
                        // RFC 9114 Section 4.1: Update phase after trailers
                        *phase = StreamPhase::ReceivedTrailers;
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

                    // RFC 9114 Section 4.4: Standard CONNECT MUST NOT have body
                    // Extended CONNECT (with :protocol) MAY have body
                    if *is_connect && !*is_extended_connect {
                        return Err(H3Error::MessageError);
                    }

                    // GAP FIX: Handle empty DATA frames properly
                    // RFC 9114 Section 7.2.1: Empty DATA frames are allowed but should not
                    // be used unnecessarily. We accept them but don't store empty buffers.
                    let frame_bytes = body_data.len() as u64;

                    // Phase 3: Track received bytes (RFC 9114 Section 4.1.2)
                    *bytes_received += frame_bytes;

                    // GAP #8: RFC 9218: Track bandwidth for priority scheduling
                    self.priority_tree.record_bytes_sent(stream_id, frame_bytes);

                    // Phase 3: Validate against Content-Length if present
                    if let Some(expected) = content_length {
                        if *bytes_received > *expected {
                            return Err(H3Error::MessageError);
                        }
                    }

                    // Record metrics
                    self.metrics
                        .frames_data_received
                        .fetch_add(1, Ordering::Relaxed);
                    self.metrics
                        .request_bytes_received
                        .fetch_add(frame_bytes, Ordering::Relaxed);

                    // Only store non-empty DATA frames
                    if !body_data.is_empty() {
                        body.push(body_data);
                    }

                    // RFC 9114 Section 4.1: Transition to ReceivedBody if Content-Length satisfied
                    if let Some(expected) = content_length {
                        if *bytes_received == *expected && *phase == StreamPhase::ReceivedHeaders {
                            *phase = StreamPhase::ReceivedBody;
                        }
                    }
                }
                H3Frame::Priority { priority } => {
                    // Handle priority update (can appear any time)
                    self.handle_priority_frame(stream_id, priority).await?;
                }
                H3Frame::PriorityUpdate {
                    element_id,
                    priority_field_value,
                } => {
                    // RFC 9218: Handle priority update (can appear on any stream)
                    self.metrics
                        .frames_priority_update_received
                        .fetch_add(1, Ordering::Relaxed);
                    self.handle_priority_update_frame(
                        stream_id,
                        element_id,
                        priority_field_value.clone(),
                    )
                    .await?;
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

        // QPACK blocking and acknowledgments are handled internally by quicd-qpack

        Ok(())
    }

    /// Process the next highest priority request from the queue
    ///
    /// PERFORMANCE OPTIMIZATION: Uses RFC 9218 priority tree for O(1) scheduling
    /// instead of O(n) queue rebuild. Priority tree maintains active streams
    /// grouped by urgency level with round-robin fairness within each level.
    async fn process_next_request(&mut self) -> Result<(), H3Error> {
        // RFC 9218: Use priority tree for compliant O(1) scheduling
        // Priority tree returns highest priority (lowest urgency) active stream
        let selected_stream_id = self
            .priority_tree
            .get_next_priority()
            .map(|(stream_id, _urgency, _weight)| stream_id);

        let queued_request = if let Some(priority_stream_id) = selected_stream_id {
            // PERF IMPROVEMENT: Instead of scanning the entire heap, use a HashMap
            // to map stream_id -> request for O(1) lookup. However, BinaryHeap doesn't
            // support efficient removal of arbitrary elements.
            //
            // Compromise: Scan heap until we find the target stream (expected early
            // in heap for high-priority streams), restore scanned items.
            // This is O(k) where k = position in heap, better than O(n) queue rebuild.
            let mut found = None;
            let mut temp = Vec::with_capacity(16); // Pre-allocate for typical case

            // Scan up to 32 items (reasonable limit to prevent long stalls)
            const MAX_SCAN: usize = 32;
            let mut scanned = 0;

            while let Some(req) = self.request_queue.pop() {
                if req.stream_id == priority_stream_id {
                    found = Some(req);
                    break; // Early exit optimization
                } else {
                    temp.push(req);
                    scanned += 1;
                    if scanned >= MAX_SCAN {
                        // Fallback: Process top of heap instead
                        break;
                    }
                }
            }

            // Restore queue - O(k log n) where k = scanned items
            for req in temp {
                self.request_queue.push(req);
            }

            // Mark stream as processed (inactive) after selection
            if let Some(ref req) = found {
                self.priority_tree.mark_active(req.stream_id, false);
            }

            found.or_else(|| self.request_queue.pop())
        } else {
            // No active priority streams, fall back to heap order
            self.request_queue.pop()
        };

        if let Some(queued_request) = queued_request {
            let request = self.parse_request(queued_request.headers)?;

            // RFC 9204 Section 2.1.2: Create Arc to track response header references
            // QPACK blocking and references are handled internally by quicd-qpack

            // Call handler
            let mut sender = H3ResponseSender {
                send_stream: queued_request.send_stream,
                qpack_encoder: self.qpack_encoder.clone(),
                push_manager: Some(self.push_manager.clone()),
                connection_handle: Some(self.handle.clone()),
                stream_id: queued_request.stream_id,
                encoder_send_stream: self.encoder_send_stream.clone(),
            };
            self.handler.handle_request(request, &mut sender).await?;

            // RFC 9114 Section 4.1: Transition to Complete phase after response sent
            if let Some(key) = self.stream_id_to_key.get(&queued_request.stream_id) {
                if let Some(StreamState::Request { phase, .. }) = self.streams.get_mut(*key) {
                    *phase = StreamPhase::Complete;
                }
            }

            // QPACK blocking and references are handled internally by quicd-qpack
        }

        Ok(())
    }

    async fn handle_request_complete(&mut self, stream_id: u64) -> Result<(), H3Error> {
        // RFC 9114 Section 4.1.2: Validate Content-Length when stream finishes
        // This is called when we receive FIN on the stream

        if let Some(key) = self.stream_id_to_key.get(&stream_id) {
            if let Some(StreamState::Request {
                content_length,
                bytes_received,
                phase,
                ..
            }) = self.streams.get_mut(*key)
            {
                // GAP FIX #2: Validate Content-Length against received bytes
                if let Some(expected) = content_length {
                    if *bytes_received != *expected {
                        // RFC 9114 Section 4.1.2: Mismatch is H3_MESSAGE_ERROR
                        let _ = self.handle.reset_stream(
                            stream_id,
                            crate::error::H3ErrorCode::MessageError.to_u64(),
                        );
                        return Err(H3Error::MessageError);
                    }
                }

                // RFC 9114 Section 4.1: Transition to ReceivedBody if not already there
                // This handles cases where Content-Length was not provided
                if *phase == StreamPhase::ReceivedHeaders {
                    *phase = StreamPhase::ReceivedBody;
                }
            }
        }

        Ok(())
    }

    /// Validates that a frame type is allowed on a given stream type.
    /// RFC 9114 Section 7.2: Different frame types are permitted on different stream types.
    fn validate_frame_on_stream(
        &self,
        frame: &H3Frame,
        stream_type: StreamType,
    ) -> Result<(), H3Error> {
        match (frame, stream_type) {
            // DATA and HEADERS only on request streams (RFC 9114 Section 7.2.1, 7.2.2)
            (H3Frame::Data { .. }, StreamType::Request) => Ok(()),
            (H3Frame::Headers { .. }, StreamType::Request) => Ok(()),
            (H3Frame::Data { .. }, _) => Err(H3Error::Connection(
                "FRAME_UNEXPECTED: DATA frame not allowed on control stream".into(),
            )),
            (H3Frame::Headers { .. }, _) => Err(H3Error::Connection(
                "FRAME_UNEXPECTED: HEADERS frame not allowed on control stream".into(),
            )),

            // Control stream only frames (RFC 9114 Section 7.2.3-7.2.7)
            (H3Frame::CancelPush { .. }, StreamType::Control) => Ok(()),
            (H3Frame::Settings { .. }, StreamType::Control) => Ok(()),
            (H3Frame::GoAway { .. }, StreamType::Control) => Ok(()),
            (H3Frame::MaxPushId { .. }, StreamType::Control) => Ok(()),
            (H3Frame::CancelPush { .. }, _) => Err(H3Error::Connection(
                "FRAME_UNEXPECTED: CANCEL_PUSH only allowed on control stream".into(),
            )),
            (H3Frame::Settings { .. }, _) => Err(H3Error::Connection(
                "FRAME_UNEXPECTED: SETTINGS only allowed on control stream".into(),
            )),
            (H3Frame::GoAway { .. }, _) => Err(H3Error::Connection(
                "FRAME_UNEXPECTED: GOAWAY only allowed on control stream".into(),
            )),
            (H3Frame::MaxPushId { .. }, _) => Err(H3Error::Connection(
                "FRAME_UNEXPECTED: MAX_PUSH_ID only allowed on control stream".into(),
            )),

            // PUSH_PROMISE only on request streams (RFC 9114 Section 7.2.5)
            (H3Frame::PushPromise { .. }, StreamType::Request) => Ok(()),
            (H3Frame::PushPromise { .. }, _) => Err(H3Error::Connection(
                "FRAME_UNEXPECTED: PUSH_PROMISE only allowed on request streams".into(),
            )),

            // PRIORITY can appear on request streams (RFC 9114 Section 7.2.3)
            (H3Frame::Priority { .. }, StreamType::Request) => Ok(()),

            // PRIORITY_UPDATE can appear on any stream (RFC 9218 Section 7.1)
            (H3Frame::PriorityUpdate { .. }, _) => Ok(()),

            // Reserved and unknown frames can appear anywhere (RFC 9114 Section 7.2.8)
            (H3Frame::Reserved { .. }, _) => Ok(()),
            (H3Frame::DuplicatePush { .. }, _) => Ok(()), // Treated as reserved

            // Default: if not explicitly allowed, reject
            _ => Err(H3Error::Connection(format!(
                "FRAME_UNEXPECTED: frame type not allowed on this stream type"
            ))),
        }
    }

    async fn process_control_frames(&mut self, data: Bytes) -> Result<(), H3Error> {
        // PERF #1: Use parse_bytes() for zero-copy frame parsing
        // PERF #2: Try to parse multiple frames if available
        if let Ok((frames, _)) = H3Frame::parse_multiple(&data) {
            for frame in frames {
                // RFC 9114 Section 7.2.1: DATA frames MUST NOT appear on control stream
                if matches!(frame, H3Frame::Data { .. }) {
                    return Err(H3Error::Connection(
                        "FRAME_UNEXPECTED: DATA frame on control stream".into(),
                    ));
                }

                // RFC 9114 Section 7.2.2: HEADERS frames MUST NOT appear on control stream
                if matches!(frame, H3Frame::Headers { .. }) {
                    return Err(H3Error::Connection(
                        "FRAME_UNEXPECTED: HEADERS frame on control stream".into(),
                    ));
                }

                // RFC 9114 Section 7.2.5: PUSH_PROMISE frames MUST NOT appear on control stream
                if matches!(frame, H3Frame::PushPromise { .. }) {
                    return Err(H3Error::Connection(
                        "FRAME_UNEXPECTED: PUSH_PROMISE frame on control stream".into(),
                    ));
                }

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
                                "FRAME_UNEXPECTED: duplicate SETTINGS frame on control stream"
                                    .into(),
                            ));
                        }
                        self.peer_control_stream_received_settings = true;
                        // RFC 9114 Section 3.3: SETTINGS received, clear deadline
                        self.settings_deadline = None;

                        // Convert to HashMap for validator
                        let settings_map: HashMap<u64, u64> =
                            settings.iter().map(|s| (s.identifier, s.value)).collect();

                        // GAP FIX: RFC 9114 Section 7.2.4.2: Validate 0-RTT settings compatibility
                        // If this connection used 0-RTT and we have remembered settings,
                        // ensure the new settings don't reduce limits or change incompatibly
                        // NOTE: We check this even if is_in_early_data() returns false, because
                        // by the time SETTINGS arrives, 0-RTT may have completed but we still
                        // need to validate compatibility with remembered settings
                        if self.settings_validator.get_remembered_settings().is_some() {
                            // We have remembered settings - validate compatibility
                            if let Err(e) = self
                                .settings_validator
                                .validate_0rtt_compatibility(&settings_map)
                            {
                                // RFC 9114 Section 7.2.4.2:
                                // "If a server accepts 0-RTT but then sends settings that are not
                                // compatible with the previously specified settings, this MUST be
                                // treated as a connection error of type H3_SETTINGS_ERROR."
                                eprintln!("0-RTT settings validation failed: {:?}", e);
                                return Err(e);
                            }
                        }

                        // Validate and process SETTINGS
                        self.settings_validator
                            .validate_settings(settings_map.clone())?;

                        // RFC 9204 Section 3.2.3: Update QPACK encoder with peer's table capacity
                        if let Some(&peer_capacity) =
                            settings_map.get(&known::QPACK_MAX_TABLE_CAPACITY)
                        {
                            // Update our encoder's dynamic table capacity to match peer's decoder capacity
                            if let Err(e) = self
                                .qpack_encoder
                                .lock()
                                .await
                                .encoder_mut()
                                .set_capacity(peer_capacity as usize)
                            {
                                eprintln!("Failed to update QPACK encoder capacity: {:?}", e);
                            }
                        }

                        // RFC 9204 Section 2.1.4: Update maximum blocked streams limit
                        if let Some(&peer_blocked) = settings_map.get(&known::QPACK_BLOCKED_STREAMS)
                        {
                            // Note: This limits how many streams WE can have blocked waiting for
                            // acknowledgments from the peer. The peer's setting limits how many
                            // of THEIR streams can be blocked waiting for OUR table updates.
                            // Our encoder already tracks this internally.
                            eprintln!("Peer allows {} blocked streams", peer_blocked);
                        }

                        // RFC 9114 Section 7.2.4.2: Remember settings for future 0-RTT connections
                        // "Clients SHOULD store the settings the server provided in the HTTP/3
                        // connection where resumption information was provided"
                        self.settings_validator.remember_settings();

                        // RFC 9114 Section 7.2.4.2: Store settings persistently if we have an origin
                        // This enables proper 0-RTT validation on future connections
                        if let Some(ref origin) = self.origin {
                            self.settings_storage
                                .store(origin.clone(), settings_map.clone());
                        }

                        // RFC 9114 Section 7.2.4.2: Validate no omitted non-default settings
                        // "The server MUST include all settings that differ from their default values"
                        if self.settings_validator.get_remembered_settings().is_some() {
                            // This is a 0-RTT connection - ensure all non-default settings are present
                            // The validator already checked compatibility, but we log for monitoring
                            if settings_map.len() < 2 {
                                eprintln!("Warning: 0-RTT SETTINGS frame may be missing non-default settings");
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
                            return Err(H3Error::Connection(
                                "H3_ID_ERROR: MAX_PUSH_ID cannot decrease".into(),
                            ));
                        }

                        // GAP FIX: RFC 9114 Section 7.2.7: Validate MAX_PUSH_ID against reasonable limits
                        // Prevent DoS from excessive push ID space allocation
                        const MAX_REASONABLE_PUSH_ID: u64 = 1_000_000; // Configurable limit
                        if push_id > MAX_REASONABLE_PUSH_ID {
                            eprintln!("Warning: Client set MAX_PUSH_ID to {}, which exceeds reasonable limit {}",
                            push_id, MAX_REASONABLE_PUSH_ID);
                            // We accept it but log for monitoring purposes
                        }

                        self.max_push_id = push_id;
                        // Update push manager
                        if let Ok(mut manager) = self.push_manager.try_lock() {
                            manager.update_max_push_id(push_id);
                        }

                        // Record metrics
                        self.metrics
                            .frames_max_push_id_received
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    H3Frame::CancelPush { push_id } => {
                        // Client wants to cancel a push
                        self.cancel_push(push_id).await?;
                        self.metrics
                            .frames_cancel_push_received
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    H3Frame::DuplicatePush { push_id } => {
                        // GAP FIX: RFC 9114 Section 7.2.8 - DUPLICATE_PUSH frame handling
                        // This frame type (0x0E) exists but has no defined semantics
                        // RFC 9114 Section 9: Unknown frame types MUST be ignored
                        eprintln!("Received DUPLICATE_PUSH frame with push_id {}: treating as reserved/unknown frame", push_id);
                        self.metrics
                            .frames_duplicate_push_received
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    H3Frame::GoAway { stream_id } => {
                        // RFC 9114 Section 5.2: Client is going away
                        // "A server MUST NOT increase the stream ID indicated in a GOAWAY frame"
                        self.handle_goaway_received(stream_id).await?;
                        self.metrics
                            .frames_goaway_received
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    H3Frame::Reserved { frame_type, .. } => {
                        // RFC 9114 Section 7.2.8: Reserved frames for greasing
                        // These MUST be ignored but stream still consumes resources
                        eprintln!(
                            "Received reserved frame type {:#x} for greasing",
                            frame_type
                        );
                        self.metrics
                            .reserved_frames_received
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {
                        // RFC 9114 Section 9: Unknown frame types MUST be ignored
                        self.metrics
                            .unknown_frames_received
                            .fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
        Ok(())
    }

    async fn cancel_push(&mut self, push_id: u64) -> Result<(), H3Error> {
        // GAP FIX #4: RFC 9114 Section 7.2.3: Validate push_id <= max_push_id
        // "A client MUST NOT send a push ID that is larger than the maximum push ID
        // that the server has advertised."
        if push_id > self.max_push_id {
            // Client sent CANCEL_PUSH for a push_id beyond our limit - protocol violation
            // RFC 9114 Section 8.1: H3_ID_ERROR for ID out of range
            return Err(H3Error::Connection(format!(
                "H3_ID_ERROR: CANCEL_PUSH with push_id {} exceeds MAX_PUSH_ID {}",
                push_id, self.max_push_id
            )));
        }

        // GAP FIX #4: Abort the push stream if it's already opened
        let stream_id_to_abort = {
            let manager = self.push_manager.lock().await;
            manager
                .get_promise(push_id)
                .and_then(|p| p.push_stream_id())
        };

        if let Some(stream_id) = stream_id_to_abort {
            // RFC 9114 Section 4.6: Abort the push stream immediately
            // Use H3_REQUEST_CANCELLED error code
            let _ = self.cancel_stream(stream_id, 0x010C).await;
        }

        // GAP FIX #4: Clean up _push_streams HashMap
        self._push_streams.remove(&push_id);

        // Use PushManager to handle cancellation state
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
            control_stream
                .write(frame_data, false)
                .await
                .map_err(|e| H3Error::Stream(format!("failed to send CANCEL_PUSH: {:?}", e)))?;
        }

        // Mark as cancelled in PushManager
        if let Ok(mut manager) = self.push_manager.try_lock() {
            manager.cancel_push(push_id)?;
        }

        Ok(())
    }

    async fn handle_priority_frame(
        &mut self,
        _stream_id: u64,
        priority: crate::frames::Priority,
    ) -> Result<(), H3Error> {
        // RFC 9218 Section 5: Handle extensible priority updates

        use crate::priority::PriorityNode;

        match priority.prioritized_element_type {
            0x00 | 0x01 => {
                // Request or push stream prioritization
                // Store priority information for request scheduling
                self.stream_priorities
                    .insert(priority.element_id, priority.urgency as u64);

                // RFC 9218 Section 5.3: Build priority tree
                let node = PriorityNode {
                    element_id: priority.element_id,
                    element_type: priority.prioritized_element_type,
                    urgency: priority.urgency,
                    incremental: priority.incremental,
                    parent_id: priority.parent_element_id,
                    children: vec![],
                    weight: 0, // Will be calculated by insert()
                    bytes_sent: 0,
                    active: true, // Assume active when priority is set
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
                eprintln!(
                    "Unknown priority element type: {}",
                    priority.prioritized_element_type
                );
            }
        }

        Ok(())
    }

    /// RFC 9218 Section 7.1: Handle PRIORITY_UPDATE frame
    async fn handle_priority_update_frame(
        &mut self,
        _stream_id: u64,
        element_id: u64,
        priority_field_value: String,
    ) -> Result<(), H3Error> {
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
                    return Err(H3Error::Http(format!(
                        "Invalid urgency parameter: {}",
                        param
                    )));
                }
            } else if param == "i" {
                incremental = true;
            } else if param.starts_with("a=") {
                if let Ok(id) = param[2..].parse::<u64>() {
                    parent_element_id = Some(id);
                } else {
                    return Err(H3Error::Http(format!(
                        "Invalid element ID parameter: {}",
                        param
                    )));
                }
            } else {
                // RFC 9218 Section 7.1: Unknown parameters are ignored
                // This allows for future extensions without breaking compatibility
                continue;
            }
        }

        let urgency = urgency
            .ok_or_else(|| H3Error::Http("Missing urgency parameter in PRIORITY_UPDATE".into()))?;

        // GAP FIX #1: Detect element type from stream state
        // RFC 9218: element_type 0x00 = request, 0x01 = push
        let element_type = if self._push_streams.contains_key(&element_id) {
            1 // Push stream
        } else {
            0 // Request stream (default)
        };

        // Update stream priority
        self.stream_priorities.insert(element_id, urgency as u64);

        // GAP #8: RFC 9218 Section 5.3: Update priority tree with full scheduling support
        use crate::priority::PriorityNode;

        let node = PriorityNode {
            element_id,
            element_type,
            urgency,
            incremental,
            parent_id: parent_element_id,
            children: vec![],
            weight: 0, // Will be calculated by insert()
            bytes_sent: 0,
            active: true, // Assume active when priority update received
        };

        self.priority_tree.insert(node);

        // GAP FIX #2: Reorder request queue if this stream is already queued
        // RFC 9218 Section 7.1: Priority updates should affect scheduling immediately
        self.reorder_request_queue(element_id, urgency).await;

        // Record metrics
        self.metrics
            .frames_priority_update_received
            .fetch_add(1, Ordering::Relaxed);

        eprintln!(
            "PRIORITY_UPDATE for {} {} {}: urgency={}, incremental={}, parent_id={:?}",
            if element_type == 0 { "request" } else { "push" },
            "stream",
            element_id,
            urgency,
            incremental,
            parent_element_id
        );

        Ok(())
    }

    /// Reorder request queue when priority changes for a queued request
    async fn reorder_request_queue(&mut self, element_id: u64, new_urgency: u8) {
        // RFC 9218: Priority changes should take effect immediately for queued requests
        // BinaryHeap doesn't support efficient priority updates, so we need to:
        // 1. Extract all requests from the heap
        // 2. Update the priority of the target request
        // 3. Rebuild the heap

        let mut temp_requests = Vec::new();
        let mut found = false;

        while let Some(mut req) = self.request_queue.pop() {
            if req.stream_id == element_id {
                // Update priority
                req.priority_id = new_urgency as u64;
                found = true;
            }
            temp_requests.push(req);
        }

        // Rebuild queue
        for req in temp_requests {
            self.request_queue.push(req);
        }

        if found {
            eprintln!(
                "Reordered request queue: stream {} now has urgency {}",
                element_id, new_urgency
            );
        }
    }

    /// RFC 9114 Section 4.1.1: Handle stream closure/reset
    async fn handle_stream_closed(
        &mut self,
        stream_id: u64,
        app_initiated: bool,
        error_code: u64,
    ) -> Result<(), H3Error> {
        // RFC 9114 Section 4.1.2: Validate Content-Length against received bytes on stream close
        if app_initiated && error_code == 0 {
            // Normal close (not reset) - validate Content-Length
            if let Some(StreamState::Request {
                content_length,
                bytes_received,
                ..
            }) = self.streams.get(self.stream_id_to_key[&stream_id])
            {
                if let Some(expected) = content_length {
                    if *bytes_received != *expected {
                        // RFC 9114 Section 4.1.2: Content-Length mismatch is a H3_MESSAGE_ERROR
                        // Close the stream with error
                        let _ = self.handle.reset_stream(
                            stream_id,
                            crate::error::H3ErrorCode::MessageError.to_u64(),
                        );
                        return Err(H3Error::MessageError);
                    }
                }
            }
        }

        // RFC 9204 Section 4.5: Send Stream Cancellation on decoder stream
        // This notifies the encoder that it can stop referencing this stream's
        // dynamic table entries in future header blocks.
        self.qpack_decoder.decoder_mut().cancel_stream(stream_id);

        // PERF FIX: Batch decoder instructions including Stream Cancellation
        let mut decoder_instructions = Vec::new();
        while let Some(inst) = self.qpack_decoder.decoder_mut().poll_decoder_stream() {
            decoder_instructions.push(inst);
        }
        if !decoder_instructions.is_empty() {
            if let Some(ref stream) = self.decoder_send_stream {
                let mut batch = bytes::BytesMut::new();
                for inst in decoder_instructions {
                    batch.extend_from_slice(&inst);
                }
                let _ = stream.write(batch.freeze(), false).await;
            }
        }

        // Clean up stream state after cancellation sent and references released
        if let Some(key) = self.stream_id_to_key.remove(&stream_id) {
            self.streams.remove(key);
        }

        // Remove from blocked streams if present
        self.blocked_streams.remove(&stream_id);

        // RFC 9218: Remove from priority tree when stream closes
        self.priority_tree.remove(stream_id);

        Ok(())
    }

    /// Cancel a stream with an application error code
    /// RFC 9114 Section 4.1.1: Applications can cancel streams via RESET_STREAM
    pub async fn cancel_stream(&mut self, stream_id: u64, error_code: u64) -> Result<(), H3Error> {
        // Clean up our stream state first
        if let Some(key) = self.stream_id_to_key.remove(&stream_id) {
            self.streams.remove(key);
        }
        self.blocked_streams.remove(&stream_id);

        // GAP #8: RFC 9218: Mark stream inactive and remove from priority tree
        self.priority_tree.mark_active(stream_id, false);

        // RFC 9218: Remove from priority tree when stream is cancelled
        self.priority_tree.remove(stream_id);

        // Send RESET_STREAM to peer (synchronous call, returns request_id)
        let _request_id = self
            .handle
            .reset_stream(stream_id, error_code)
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
            manager
                .get_promise(push_id)
                .and_then(|p| p.push_stream_id())
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

        // ISSUE FIX #3: RFC 9114 Section 4.4: CONNECT validation
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

            // RFC 9114 Section 4.4: Standard CONNECT MUST NOT include message body
            // Note: Extended CONNECT (with :protocol) MAY include body
            // This validation happens during frame processing (DATA after HEADERS)
        }

        let method = method_str
            .parse()
            .map_err(|_| H3Error::Http("invalid method".into()))?;
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
        let uri = uri_string
            .parse()
            .map_err(|_| H3Error::Http("invalid uri construction".into()))?;

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
                let length = value.parse::<u64>().map_err(|_| H3Error::MessageError)?;
                return Ok(Some(length));
            }
        }
        Ok(None)
    }



    /// Process a push stream (RFC 9114 Section 6.2.2)
    ///
    /// **Client-side feature only** - Servers never receive push streams per RFC 9114 Section 6.2.2.
    ///
    /// This stub is provided for API completeness. A full client implementation would:
    ///
    /// 1. **Validate push_id** against previously received PUSH_PROMISE frames
    ///    - RFC 9114 Section 4.6: Send H3_ID_ERROR if push_id not promised
    ///    - Track promised IDs via PushManager
    ///
    /// 2. **Parse stream frames** following RFC 9114 Section 4.6:
    ///    - First varint: push_id
    ///    - Followed by HEADERS frame (required)
    ///    - Zero or more DATA frames
    ///    - Optional trailing HEADERS
    ///    - Any other frame type is H3_FRAME_UNEXPECTED
    ///
    /// 3. **Decode QPACK headers** using `qpack_decoder.decode_header_block()`
    ///    - Pass stream_id for proper blocking semantics
    ///    - Send Section Ack when processing completes
    ///
    /// 4. **Validate response semantics**:
    ///    - Must have :status pseudo-header
    ///    - Cannot have request pseudo-headers (:method, :scheme, :authority, :path)
    ///    - Content-Length must match actual payload if present
    ///
    /// 5. **Deliver to application**:
    ///    - Match with promised request headers
    ///    - Provide via H3Handler callback or similar API
    ///    - Update metrics (push_streams_received, push_bytes_received)
    ///
    /// 6. **Update PushManager state**:
    ///    - Mark stream as opened (Promised -> Sending)
    ///    - Mark as completed when FIN received
    ///    - Handle CANCEL_PUSH or stream reset appropriately
    #[allow(dead_code)]
    async fn process_push_stream(
        &mut self,
        _stream_id: u64,
        mut recv_stream: quicd_x::RecvStream,
    ) -> Result<(), H3Error> {
        // Read push ID (varint) - RFC 9114 Section 4.6
        let data = match recv_stream.read().await {
            Ok(Some(quicd_x::StreamData::Data(bytes))) => bytes,
            _ => return Err(H3Error::Connection("failed to read push ID".into())),
        };

        let (push_id, _consumed) = crate::frames::H3Frame::decode_varint(&data)
            .map_err(|e| H3Error::FrameParse(format!("invalid push ID: {:?}", e)))?;

        // Stub: In a real client, this would validate the push_id was promised,
        // parse frames, decode QPACK headers, and deliver to the application.
        // See documentation above for full implementation requirements.
        eprintln!(
            "Push stream with push ID {}: client support not implemented (server-side only)",
            push_id
        );

        // Consume stream to prevent blocking
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

    /// GAP FIX #5: Check if we should grease (use reserved identifiers)
    ///
    /// RFC 9114 Section 7.2.8: Implementations SHOULD send reserved identifiers occasionally
    /// to prevent intermediaries from ossifying on current protocol.
    /// Returns true ~2% of the time (1 in 50) for systematic greasing without excessive overhead.
    fn should_grease() -> bool {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hash, Hasher};

        let s = RandomState::new();
        let mut hasher = s.build_hasher();
        std::time::SystemTime::now().hash(&mut hasher);
        (hasher.finish() % 50) == 0
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
            vec![(0x40 | (value >> 8)) as u8, (value & 0xff) as u8]
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
        // GAP FIX #4: RFC 9114 Section 7.2.7: Validate push_id against MAX_PUSH_ID
        // "A server MUST NOT send a push stream with a push ID that is greater than
        // the maximum push ID that the client has advertised."
        if push_id > self.max_push_id {
            return Err(H3Error::Connection(format!(
                "H3_ID_ERROR: push_id {} exceeds client MAX_PUSH_ID {}",
                push_id, self.max_push_id
            )));
        }

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
        send_stream
            .write(Bytes::from(stream_type), false)
            .await
            .map_err(|e| H3Error::Stream(format!("failed to write stream type: {:?}", e)))?;

        // Write push ID as varint
        let push_id_bytes = self.encode_varint(push_id);
        send_stream
            .write(Bytes::from(push_id_bytes), false)
            .await
            .map_err(|e| H3Error::Stream(format!("failed to write push ID: {:?}", e)))?;

        // Notify PushManager that stream opened
        let mut manager = self.push_manager.lock().await;
        let stream_id = send_stream.stream_id;
        manager.handle_stream_opened(request_id, stream_id)?;

        // Get the push response if available
        let response_data = manager
            .get_promise(push_id)
            .and_then(|promise| promise.response().cloned());

        drop(manager); // Release lock before encoding

        if let Some(response) = response_data {
            // Encode response headers
            let status_str = response.status.to_string();
            let mut all_headers = vec![(b":status".as_slice(), status_str.as_bytes())];
            for (name, value) in &response.headers {
                all_headers.push((name.as_bytes(), value.as_bytes()));
            }

            let mut encoder_guard = self.qpack_encoder.lock().await;
            let encoded_headers = encoder_guard
                .encoder_mut()
                .encode(stream_id, &all_headers)
                .map_err(|_| H3Error::Qpack("encoding failed".into()))?;

            // PERF FIX: Send pending encoder instructions in batch to reduce syscalls
            // RFC 9204: Batching encoder stream instructions improves throughput
            if let Some(batched_instructions) =
                encoder_guard.encoder_mut().poll_encoder_stream_batch(16)
            {
                if let Some(encoder_stream) = self.encoder_send_stream.lock().await.as_mut() {
                    let _ = encoder_stream.write(batched_instructions, false).await;
                }
            }

            // Send HEADERS frame
            let headers_frame = H3Frame::Headers { encoded_headers };
            let frame_data = headers_frame.encode();
            send_stream
                .write(frame_data, false)
                .await
                .map_err(|e| H3Error::Stream(format!("write failed: {:?}", e)))?;

            // Send DATA frame with FIN
            let data_frame = H3Frame::Data {
                data: response.body,
            };
            let data_frame_data = data_frame.encode();
            send_stream
                .write(data_frame_data, true)
                .await
                .map_err(|e| H3Error::Stream(format!("write failed: {:?}", e)))?;

            // Mark push as completed and release references
            let mut manager = self.push_manager.lock().await;
            if let Some(promise) = manager.get_promise_mut(push_id) {
                promise.mark_completed();
            }

            // QPACK references are handled internally by quicd-qpack
        } else {
            // No response data available - send CANCEL_PUSH and close stream
            let _ = self.send_cancel_push_frame(push_id).await;
            return Err(H3Error::Http(format!(
                "no response data for push ID {}",
                push_id
            )));
        }

        Ok(())
    }

    /// GAP FIX #3: RFC 9114 Section 5.1: Check for idle connection timeout
    /// This should be called periodically from the event loop
    async fn check_idle_timeout(&mut self) -> Result<(), H3Error> {
        let elapsed = self.last_activity_time.elapsed();

        if elapsed >= self.idle_timeout {
            // RFC 9114 Section 5.1: Idle timeout exceeded
            // Send GOAWAY before closing to allow graceful shutdown
            if !self.goaway_sent {
                eprintln!(
                    "Idle timeout exceeded ({:?} >= {:?}) - sending GOAWAY",
                    elapsed, self.idle_timeout
                );
                self.send_goaway().await?;

                // Wait a short grace period for in-flight requests to complete
                tokio::time::sleep(self.config.idle_grace_period).await;
            }

            // Close connection with H3_NO_ERROR per RFC 9114 Section 8
            let error_code = crate::error::H3ErrorCode::NoError.to_u64();
            self.handle
                .close(error_code, Some(Bytes::from("idle timeout")))
                .map_err(|e| H3Error::Connection(format!("close error: {:?}", e)))?;

            return Err(H3Error::Connection("idle timeout".into()));
        }

        Ok(())
    }

    /// GAP FIX #5: RFC 9204 Section 2.1.4: Retry blocked streams when dynamic table entries arrive
    async fn retry_blocked_streams(&mut self) -> Result<(), H3Error> {
        let current_insert_count = self.qpack_decoder.decoder().table().insert_count() as u64;
        let mut streams_to_retry = Vec::new();

        // Find streams that can now be unblocked
        for (stream_id, blocked_stream) in &self.blocked_streams {
            if (blocked_stream.required_insert_count as u64) <= current_insert_count {
                streams_to_retry.push(*stream_id);
            }
        }

        // Retry unblocked streams
        for stream_id in streams_to_retry {
            if let Some(blocked) = self.blocked_streams.remove(&stream_id) {
                eprintln!("Retrying previously blocked stream {} (required_insert_count: {}, current: {})",
                    stream_id, blocked.required_insert_count, current_insert_count);

                // Try to decode again
                match self
                    .qpack_decoder
                    .decoder_mut()
                    .decode(stream_id, blocked.encoded_data.clone())
                {
                    Ok(header_fields) => {
                        // Success! Convert and process headers
                        let headers: Vec<(String, String)> = header_fields
                            .into_iter()
                            .map(|field| {
                                (
                                    String::from_utf8_lossy(&field.name).to_string(),
                                    String::from_utf8_lossy(&field.value).to_string(),
                                )
                            })
                            .collect();

                        // Send decoder acknowledgments
                        while let Some(inst) =
                            self.qpack_decoder.decoder_mut().poll_decoder_stream()
                        {
                            if let Some(ref stream) = self.decoder_send_stream {
                                let _ = stream.write(inst, false).await;
                            }
                        }

                        // Queue for processing with send_stream from blocked state
                        let priority_id = self
                            .stream_priorities
                            .get(&stream_id)
                            .copied()
                            .unwrap_or(255);
                        let queued_request = QueuedRequest {
                            priority_id,
                            stream_id,
                            headers,
                            send_stream: blocked.send_stream,
                        };
                        self.request_queue.push(queued_request);

                        // Process immediately
                        self.process_next_request().await?;
                    }
                    Err(_) => {
                        // Still blocked, put back in queue
                        self.blocked_streams.insert(stream_id, blocked);
                    }
                }
            }
        }

        Ok(())
    }

    /// GAP FIX #6: RFC 9204 Section 2.1.4: Check for QPACK blocked stream timeouts
    /// Streams blocked for > configured timeout should be aborted with H3_REQUEST_CANCELLED
    async fn check_blocked_stream_timeouts(&mut self) -> Result<(), H3Error> {
        let blocked_timeout = self.config.qpack_blocked_stream_timeout;
        let now = std::time::Instant::now();
        let mut streams_to_abort = Vec::new();

        // Find streams that have been blocked too long
        for (stream_id, blocked_stream) in &self.blocked_streams {
            let blocked_duration = now.duration_since(blocked_stream.blocked_at);
            if blocked_duration > blocked_timeout {
                streams_to_abort.push(*stream_id);
            }
        }

        // Abort timed-out streams
        for stream_id in streams_to_abort {
            eprintln!(
                "Aborting stream {} - QPACK blocked timeout exceeded",
                stream_id
            );

            // RFC 9204 Section 2.1.4: Abort with H3_REQUEST_CANCELLED
            let error_code = 0x010C; // H3_REQUEST_CANCELLED
            let _ = self.handle.reset_stream(stream_id, error_code);

            // Clean up stream state
            self.blocked_streams.remove(&stream_id);
            if let Some(key) = self.stream_id_to_key.remove(&stream_id) {
                self.streams.remove(key);
            }
        }

        Ok(())
    }
}

/// Factory for creating HTTP/3 application instances.
pub struct H3Factory<H: H3Handler> {
    handler: H,
    settings_storage: Arc<dyn SettingsStorage>,
    config: crate::config::H3Config,
}

impl<H: H3Handler> H3Factory<H> {
    pub fn new(handler: H) -> Self {
        let config = crate::config::H3Config::default();
        Self {
            handler,
            settings_storage: Arc::new(InMemorySettingsStorage::with_ttl(config.settings_ttl)),
            config,
        }
    }

    pub fn with_config(handler: H, config: crate::config::H3Config) -> Self {
        Self {
            handler,
            settings_storage: Arc::new(InMemorySettingsStorage::with_ttl(config.settings_ttl)),
            config,
        }
    }

    pub fn with_settings_storage(handler: H, settings_storage: Arc<dyn SettingsStorage>) -> Self {
        Self {
            handler,
            settings_storage,
            config: crate::config::H3Config::default(),
        }
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
        let session = H3Session::with_config(
            handle,
            self.handler.clone(),
            self.settings_storage.clone(),
            self.config.clone(),
        );
        session
            .run(events, shutdown)
            .await
            .map_err(|e| quicd_x::ConnectionError::App(format!("HTTP/3 error: {:?}", e)))
    }
}
