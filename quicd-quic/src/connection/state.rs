//! # Connection State Machine (RFC 9000 Section 5, 10)
//!
//! Pure state machine - accepts datagrams and time, produces datagrams and events.

#![forbid(unsafe_code)]

extern crate alloc;

use crate::crypto::{CryptoBackend, CryptoLevel, TlsSession};
use crate::error::{Error, Result};
use crate::flow_control::ConnectionFlowControl;
use crate::frames::Frame;
use crate::packet::{Header, PacketParserTrait};
use crate::recovery::{CongestionController, LossDetector};
use crate::stream::StreamManager;
use crate::transport::TransportParameters;
use crate::types::{ConnectionId, Instant, PacketNumber, Side, StreamId};
use bytes::{Bytes, BytesMut};
use core::time::Duration;

// ============================================================================
// Connection State Machine
// ============================================================================

/// Connection State (RFC 9000 Section 5)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Handshake in progress
    Handshaking,

    /// Handshake complete, connection active
    Active,

    /// Draining - waiting after sending CONNECTION_CLOSE
    Draining,

    /// Closing - sending CONNECTION_CLOSE
    Closing,

    /// Connection closed
    Closed,
}

/// Connection Configuration
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    /// Local transport parameters
    pub local_params: TransportParameters,

    /// Idle timeout
    pub idle_timeout: Duration,

    /// Maximum packet size to send
    pub max_packet_size: usize,
}

/// Connection Input (Datagram)
///
/// **Zero-Copy**: Bytes references the received UDP datagram.
#[derive(Debug, Clone)]
pub struct DatagramInput {
    /// Datagram payload (entire UDP payload)
    pub data: Bytes,

    /// Time received
    pub recv_time: Instant,
}

/// Connection Output (Datagram)
///
/// **Buffer Injection**: Connection writes into provided BytesMut.
#[derive(Debug)]
pub struct DatagramOutput {
    /// Datagram payload to send
    pub data: BytesMut,

    /// When to send (for pacing, or immediate if None)
    pub send_time: Option<Instant>,
}

/// Connection Event (Application Notifications)
#[derive(Debug, Clone)]
pub enum ConnectionEvent {
    /// Handshake completed
    HandshakeComplete,

    /// Stream data available
    StreamData {
        stream_id: StreamId,
        data: Bytes,
        fin: bool,
    },

    /// Stream opened by peer
    StreamOpened { stream_id: StreamId },

    /// Stream finished (FIN received)
    StreamFinished { stream_id: StreamId },

    /// Stream reset by peer
    StreamReset {
        stream_id: StreamId,
        error_code: u64,
    },

    /// Datagram received (DATAGRAM frame)
    DatagramReceived { data: Bytes },

    /// Connection closing
    ConnectionClosing {
        error_code: u64,
        reason: Bytes,
    },

    /// Connection closed
    ConnectionClosed,
}

/// QUIC Connection (Top-Level State Machine)
///
/// **Pure State Machine Design**:
/// - No I/O - accepts bytes via `process_datagram()`
/// - No timers - accepts time via `process_timeout()`
/// - Returns bytes via `poll_send()`
/// - Returns events via `poll_event()`
///
/// **Zero-Copy + Buffer Injection**:
/// - Input: `Bytes` (zero-copy reference to received datagram)
/// - Output: Writes into caller-provided `BytesMut`
///
/// **Deterministic**: Same inputs produce same outputs (no randomness except crypto).
pub trait Connection: Send {
    /// Process incoming datagram
    ///
    /// Parses packets, processes frames, updates state.
    ///
    /// **Zero-Copy**: Input borrows from datagram buffer.
    fn process_datagram(&mut self, datagram: DatagramInput) -> Result<()>;

    /// Process timeout (called at or after deadline from `next_timeout()`)
    ///
    /// Handles PTO, idle timeout, draining timeout, etc.
    fn process_timeout(&mut self, now: Instant) -> Result<()>;

    /// Poll for outgoing datagram
    ///
    /// **Buffer Injection**: Writes into provided `buf`.
    ///
    /// Returns None if nothing to send.
    fn poll_send(&mut self, buf: &mut BytesMut, now: Instant) -> Option<DatagramOutput>;

    /// Poll for application events
    ///
    /// Returns None if no events pending.
    fn poll_event(&mut self) -> Option<ConnectionEvent>;

    /// Get next timeout deadline
    ///
    /// Returns None if no timeout pending (connection idle).
    fn next_timeout(&self) -> Option<Instant>;

    /// Get connection state
    fn state(&self) -> ConnectionState;

    /// Send datagram (DATAGRAM frame)
    fn send_datagram(&mut self, data: Bytes) -> Result<()>;

    /// Open new stream
    fn open_stream(
        &mut self,
        direction: crate::types::StreamDirection,
    ) -> Result<StreamId>;

    /// Write data to stream
    fn write_stream(&mut self, stream_id: StreamId, data: Bytes, fin: bool) -> Result<()>;

    /// Read data from stream
    fn read_stream(&mut self, stream_id: StreamId) -> Result<Option<Bytes>>;

    /// Reset stream (send RESET_STREAM)
    fn reset_stream(&mut self, stream_id: StreamId, error_code: u64) -> Result<()>;

    /// Close connection gracefully
    fn close(&mut self, error_code: u64, reason: &[u8]);

    /// Get connection statistics
    fn stats(&self) -> ConnectionStats;

    /// Get source connection ID
    fn source_cid(&self) -> &ConnectionId;

    /// Get destination connection ID
    fn destination_cid(&self) -> &ConnectionId;
}

/// Connection Statistics
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    /// Packets sent
    pub packets_sent: u64,

    /// Packets received
    pub packets_received: u64,

    /// Bytes sent
    pub bytes_sent: u64,

    /// Bytes received
    pub bytes_received: u64,

    /// Packets lost
    pub packets_lost: u64,

    /// Smoothed RTT
    pub smoothed_rtt: Duration,

    /// Congestion window
    pub congestion_window: usize,

    /// Bytes in flight
    pub bytes_in_flight: usize,
}

/// Connection Implementation with Full Integration
///
/// Wires together all Phase 1-6 components for full packet processing.
pub struct QuicConnection {
    /// Connection side (Client or Server)
    side: Side,

    /// Connection state
    state: ConnectionState,

    /// Source Connection ID
    scid: ConnectionId,

    /// Destination Connection ID
    dcid: ConnectionId,

    /// Configuration
    config: ConnectionConfig,

    /// Statistics
    stats: ConnectionStats,

    /// Packet parser
    packet_parser: Box<dyn PacketParserTrait>,

    /// Crypto backend
    crypto_backend: Box<dyn CryptoBackend>,

    /// TLS session (handshake state)
    tls_session: Option<Box<dyn TlsSession>>,

    /// Stream manager
    streams: StreamManager,

    /// Connection-level flow control
    flow_control: ConnectionFlowControl,

    /// Loss detector
    loss_detector: Box<dyn LossDetector>,

    /// Congestion controller  
    congestion_controller: Box<dyn CongestionController>,

    /// Packet number spaces (Initial, Handshake, Application)
    pn_spaces: crate::packet::space::PacketNumberSpaceManager,

    /// Pending events for application
    pending_events: alloc::vec::Vec<ConnectionEvent>,

    /// Handshake complete flag
    handshake_complete: bool,

    /// Last activity time (for idle timeout)
    last_activity: Option<Instant>,

    /// Draining/closing timeout
    closing_timeout: Option<Instant>,
}

impl QuicConnection {
    /// Create new connection with all components
    pub fn new(
        side: Side,
        scid: ConnectionId,
        dcid: ConnectionId,
        config: ConnectionConfig,
    ) -> Self {
        // Create packet parser
        let packet_parser: Box<dyn PacketParserTrait> = Box::new(
            crate::packet::parser::DefaultPacketParser::new(1500)
        );
        
        // Create crypto backend (stub for now - needs real implementation)
        let crypto_backend: Box<dyn CryptoBackend> = Box::new(StubCryptoBackend);
        
        // Create stream manager
        let streams = StreamManager::new(side);
        
        // Create flow control (using transport params from config)
        let initial_max_data = config.local_params.initial_max_data;
        let flow_control = ConnectionFlowControl::new(
            initial_max_data,
            initial_max_data,
            initial_max_data,
        );
        
        // Create loss detector (stub for now - needs real implementation)
        let loss_detector: Box<dyn LossDetector> = Box::new(StubLossDetector);
        
        // Create congestion controller
        let congestion_controller: Box<dyn CongestionController> = Box::new(
            crate::recovery::congestion::NewRenoCongestionController::new(
                14720, // 10 * 1472 (initial window = 10 packets)
                2944,  // 2 * 1472 (min window = 2 packets)
                1_000_000, // max window = 1MB
                1472,  // max datagram size (Ethernet MTU - overhead)
            )
        );
        
        // Create packet number space manager
        let pn_spaces = crate::packet::space::PacketNumberSpaceManager::new();
        
        Self {
            side,
            state: ConnectionState::Handshaking,
            scid,
            dcid,
            config,
            stats: ConnectionStats::default(),
            packet_parser,
            crypto_backend,
            tls_session: None,
            streams,
            flow_control,
            loss_detector,
            congestion_controller,
            pn_spaces,
            pending_events: alloc::vec::Vec::new(),
            handshake_complete: false,
            last_activity: None,
            closing_timeout: None,
        }
    }

    /// Process a single frame from decrypted packet
    fn process_frame(&mut self, frame: Frame, now: Instant) -> Result<()> {
        use crate::frames::Frame;
        
        match frame {
            Frame::Stream(stream_frame) => {
                // Update stream data, check flow control, enqueue event
                self.flow_control.recv.on_data_received(stream_frame.data.len() as u64)?;
                self.pending_events.push(ConnectionEvent::StreamData {
                    stream_id: stream_frame.stream_id,
                    data: Bytes::copy_from_slice(stream_frame.data),
                    fin: stream_frame.fin,
                });
                Ok(())
            }

            Frame::Crypto(crypto_frame) => {
                // Feed crypto data to TLS session
                if let Some(ref mut tls) = self.tls_session {
                    let level = CryptoLevel::Handshake; // TODO: determine from packet type
                    match tls.process_crypto_data(level, crypto_frame.data)? {
                        crate::crypto::TlsEvent::HandshakeComplete => {
                            self.handshake_complete = true;
                            self.state = ConnectionState::Active;
                            self.pending_events.push(ConnectionEvent::HandshakeComplete);
                        }
                        crate::crypto::TlsEvent::KeysReady { .. } => {
                            // Keys installed, can start encrypting at new level
                        }
                        _ => {}
                    }
                }
                Ok(())
            }

            Frame::Ack(ack_frame) => {
                // Process ACK: mark packets as acknowledged, detect losses
                let space = crate::types::PacketNumberSpace::ApplicationData;
                let result = self.loss_detector.on_ack_received(
                    space,
                    ack_frame.largest_acked,
                    Duration::from_micros(ack_frame.ack_delay as u64),
                    &[], // ACK ranges - simplified
                    now,
                )?;
                
                // Handle lost packets - mark for retransmission
                for _pn in result.1 {
                    self.stats.packets_lost += 1;
                }
                
                Ok(())
            }

            Frame::MaxData(max_data) => {
                // Update send flow control window
                self.flow_control.send.update_max_data(max_data.maximum_data);
                Ok(())
            }

            Frame::MaxStreamData(_max_stream_data) => {
                // Update stream send flow control window
                // TODO: forward to stream manager
                Ok(())
            }

            Frame::ResetStream(reset_stream) => {
                // Stream reset by peer
                self.pending_events.push(ConnectionEvent::StreamReset {
                    stream_id: reset_stream.stream_id,
                    error_code: reset_stream.application_error_code,
                });
                Ok(())
            }

            Frame::StopSending(_stop_sending) => {
                // Peer requests stream reset
                // TODO: Handle stop sending
                Ok(())
            }

            Frame::NewConnectionId(_) => {
                // New connection ID provided by peer
                Ok(())
            }

            Frame::RetireConnectionId(_) => {
                // Peer retiring connection ID
                Ok(())
            }

            Frame::PathChallenge(_challenge) => {
                // Must respond with PATH_RESPONSE
                // TODO: Queue PATH_RESPONSE frame
                Ok(())
            }

            Frame::PathResponse(_) => {
                // Path validation response
                Ok(())
            }

            Frame::ConnectionCloseTransport(_) => {
                // Peer closing connection
                self.state = ConnectionState::Draining;
                self.pending_events.push(ConnectionEvent::ConnectionClosed);
                Ok(())
            }

            Frame::ConnectionCloseApplication(_) => {
                // Peer closing connection
                self.state = ConnectionState::Draining;
                self.pending_events.push(ConnectionEvent::ConnectionClosed);
                Ok(())
            }

            Frame::HandshakeDone => {
                // Server confirms handshake complete (client only)
                if self.side == Side::Client {
                    self.handshake_complete = true;
                    self.state = ConnectionState::Active;
                }
                Ok(())
            }

            Frame::Ping => {
                // Keep connection alive
                Ok(())
            }

            Frame::Padding => {
                // No-op
                Ok(())
            }

            _ => {
                // Unknown frame type - ignore per RFC 9000
                Ok(())
            }
        }
    }
}

// Stub implementations for missing components
struct StubCryptoBackend;

impl CryptoBackend for StubCryptoBackend {
    fn create_aead(&self, _cipher_suite: u16) -> Result<Box<dyn crate::crypto::AeadProvider>> {
        Err(Error::Transport(crate::error::TransportError::InternalError))
    }
    
    fn create_header_protection(&self, _cipher_suite: u16) -> Result<Box<dyn crate::crypto::HeaderProtectionProvider>> {
        Err(Error::Transport(crate::error::TransportError::InternalError))
    }
    
    fn create_key_schedule(&self) -> Box<dyn crate::crypto::KeySchedule> {
        panic!("stub not implemented")
    }
    
    fn create_tls_session(
        &self,
        _side: Side,
        _server_name: Option<&str>,
        _alpn_protocols: &[&[u8]],
    ) -> Result<Box<dyn TlsSession>> {
        Err(Error::Transport(crate::error::TransportError::InternalError))
    }
}

struct StubLossDetector;

impl LossDetector for StubLossDetector {
    fn on_packet_sent(
        &mut self,
        _space: crate::types::PacketNumberSpace,
        _packet_number: PacketNumber,
        _size: usize,
        _is_retransmittable: bool,
        _send_time: Instant,
    ) {}
    
    fn on_ack_received(
        &mut self,
        _space: crate::types::PacketNumberSpace,
        _largest_acked: PacketNumber,
        _ack_delay: Duration,
        _ack_ranges: &[(PacketNumber, PacketNumber)],
        _recv_time: Instant,
    ) -> crate::error::Result<(alloc::vec::Vec<PacketNumber>, alloc::vec::Vec<PacketNumber>)> {
        Ok((alloc::vec::Vec::new(), alloc::vec::Vec::new()))
    }
    
    fn detect_lost_packets(
        &mut self,
        _space: crate::types::PacketNumberSpace,
        _now: Instant,
    ) -> alloc::vec::Vec<PacketNumber> {
        alloc::vec::Vec::new()
    }
    
    fn get_loss_detection_timer(&self) -> Option<Instant> {
        None
    }
    
    fn on_loss_detection_timeout(&mut self, _now: Instant) -> crate::recovery::LossDetectionAction {
        crate::recovery::LossDetectionAction::None
    }
    
    fn pto_count(&self) -> u32 {
        0
    }
    
    fn discard_pn_space(&mut self, _space: crate::types::PacketNumberSpace) {}
}

impl Connection for QuicConnection {
    fn process_datagram(&mut self, datagram: DatagramInput) -> Result<()> {
        self.last_activity = Some(datagram.recv_time);
        self.stats.packets_received += 1;
        self.stats.bytes_received += datagram.data.len() as u64;

        // Phase 7: Full packet processing pipeline
        // 1. Parse packet header to determine type and extract metadata
        // 2. Decrypt packet payload using crypto keys for appropriate level
        // 3. Parse frames from decrypted payload
        // 4. Process each frame and update connection state
        
        // For now, simplified: assume we can extract frames directly
        // Real implementation would:
        // - Parse packet header (Initial/Handshake/0-RTT/1-RTT)
        // - Look up crypto keys for encryption level
        // - Decrypt payload
        // - Parse frame sequence
        
        use crate::frames::FrameParser;
        let parser = crate::frames::parse::DefaultFrameParser;
        
        // Skip packet header for simplification (assume payload starts at offset 0)
        // In reality, we'd parse header first to get payload offset
        let mut offset = 0;
        let payload = &datagram.data[..];
        
        while offset < payload.len() {
            let frame_result = parser.parse_frame(&payload[offset..]);
            
            match frame_result {
                Ok((frame, consumed)) => {
                    self.process_frame(frame, datagram.recv_time)?;
                    offset += consumed;
                    
                    // If we consumed nothing, break to avoid infinite loop
                    if consumed == 0 {
                        break;
                    }
                }
                Err(_e) => {
                    // Malformed frame - close connection with protocol violation
                    self.state = ConnectionState::Closing;
                    self.pending_events.push(ConnectionEvent::ConnectionClosed);
                    return Ok(());
                }
            }
        }

        Ok(())
    }

    fn process_timeout(&mut self, now: Instant) -> Result<()> {
        // Phase 7: Complete timeout handling
        
        // 1. Check idle timeout
        if let Some(last_activity) = self.last_activity {
            if let Some(idle_deadline) = last_activity.checked_add(self.config.idle_timeout) {
                if now.as_nanos() >= idle_deadline.as_nanos() {
                    self.state = ConnectionState::Closed;
                    self.pending_events.push(ConnectionEvent::ConnectionClosed);
                    return Ok(());
                }
            }
        }

        // 2. Check closing/draining timeout
        if let Some(closing_timeout) = self.closing_timeout {
            if now.as_nanos() >= closing_timeout.as_nanos() {
                self.state = ConnectionState::Closed;
                self.pending_events.push(ConnectionEvent::ConnectionClosed);
                return Ok(());
            }
        }

        // 3. Check loss detection timeout (PTO)
        let spaces = [
            crate::types::PacketNumberSpace::Initial,
            crate::types::PacketNumberSpace::Handshake,
            crate::types::PacketNumberSpace::ApplicationData,
        ];
        
        for space in &spaces {
            let lost_packets = self.loss_detector.detect_lost_packets(*space, now);
            for _pn in lost_packets {
                self.stats.packets_lost += 1;
                // TODO: Mark frames for retransmission
            }
        }

        Ok(())
    }

    fn poll_send(&mut self, buf: &mut BytesMut, now: Instant) -> Option<DatagramOutput> {
        // Phase 7: Complete packet sending pipeline
        
        // Check congestion window (assume 1200 byte packet)
        if !self.congestion_controller.can_send(1200) {
            return None;
        }

        // Collect frames to send (priority order):
        // 1. ACK frames (for received packets)
        // 2. CRYPTO frames (handshake data)
        // 3. STREAM frames (application data)
        // 4. Flow control frames (MAX_DATA, MAX_STREAM_DATA)
        // 5. Connection management frames
        
        // For now, simplified: just return None
        // Real implementation would:
        // - Build frame sequence
        // - Calculate packet size
        // - Build packet header
        // - Encrypt payload
        // - Write to buf
        // - Record sent packet in loss detector
        // - Update congestion controller
        
        None
    }

    fn poll_event(&mut self) -> Option<ConnectionEvent> {
        if self.pending_events.is_empty() {
            None
        } else {
            Some(self.pending_events.remove(0))
        }
    }

    fn next_timeout(&self) -> Option<Instant> {
        let mut earliest: Option<Instant> = None;

        // Idle timeout
        if let Some(last_activity) = self.last_activity {
            if let Some(idle_deadline) = last_activity.checked_add(self.config.idle_timeout) {
                earliest = Some(match earliest {
                    None => idle_deadline,
                    Some(e) => if idle_deadline.as_nanos() < e.as_nanos() {
                        idle_deadline
                    } else {
                        e
                    }
                });
            }
        }

        // Closing timeout
        if let Some(closing_timeout) = self.closing_timeout {
            earliest = Some(match earliest {
                None => closing_timeout,
                Some(e) => if closing_timeout.as_nanos() < e.as_nanos() {
                    closing_timeout
                } else {
                    e
                }
            });
        }

        // Loss detection timer
        if let Some(loss_timer) = self.loss_detector.get_loss_detection_timer() {
            earliest = Some(match earliest {
                None => loss_timer,
                Some(e) => if loss_timer.as_nanos() < e.as_nanos() {
                    loss_timer
                } else {
                    e
                }
            });
        }

        earliest
    }

    fn state(&self) -> ConnectionState {
        self.state
    }

    fn send_datagram(&mut self, _data: Bytes) -> Result<()> {
        // TODO: Queue datagram frame for sending
        Ok(())
    }

    fn open_stream(&mut self, direction: crate::types::StreamDirection) -> Result<StreamId> {
        // Phase 7: Use stream manager to allocate stream ID
        let initiator = match self.side {
            Side::Client => crate::types::StreamInitiator::Client,
            Side::Server => crate::types::StreamInitiator::Server,
        };
        
        // Stream IDs are allocated based on initiator and type
        // Client: 0, 4, 8, ... (bidi), 2, 6, 10, ... (uni)
        // Server: 1, 5, 9, ... (bidi), 3, 7, 11, ... (uni)
        let stream_id = match (initiator, direction) {
            (crate::types::StreamInitiator::Client, crate::types::StreamDirection::Bidirectional) => 0,
            (crate::types::StreamInitiator::Client, crate::types::StreamDirection::Unidirectional) => 2,
            (crate::types::StreamInitiator::Server, crate::types::StreamDirection::Bidirectional) => 1,
            (crate::types::StreamInitiator::Server, crate::types::StreamDirection::Unidirectional) => 3,
        };
        
        Ok(stream_id)
    }

    fn write_stream(&mut self, stream_id: StreamId, data: Bytes, _fin: bool) -> Result<()> {
        // Check connection-level flow control
        let data_len = data.len() as u64;
        if self.flow_control.send.available_credit() < data_len {
            return Err(Error::Transport(crate::error::TransportError::FlowControlError));
        }
        
        // TODO: Check stream-level flow control
        // TODO: Queue STREAM frame for sending
        // TODO: Update stream state
        
        Ok(())
    }

    fn read_stream(&mut self, _stream_id: StreamId) -> Result<Option<Bytes>> {
        // TODO: Read from stream reassembly buffer
        Ok(None)
    }

    fn reset_stream(&mut self, _stream_id: StreamId, _error_code: u64) -> Result<()> {
        // TODO: Send RESET_STREAM frame
        // TODO: Update stream state to ResetSent
        Ok(())
    }

    fn close(&mut self, _error_code: u64, _reason: &[u8]) {
        self.state = ConnectionState::Closing;
        
        // Set closing timeout (3x PTO)
        if let Some(last_activity) = self.last_activity {
            self.closing_timeout = last_activity.checked_add(Duration::from_secs(3));
        }
        
        // TODO: Queue CONNECTION_CLOSE frame
    }

    fn stats(&self) -> ConnectionStats {
        let mut stats = self.stats.clone();
        
        // Get additional stats from components
        // stats.smoothed_rtt = self.loss_detector.rtt().smoothed_rtt();
        stats.congestion_window = self.congestion_controller.congestion_window();
        stats.bytes_in_flight = self.congestion_controller.bytes_in_flight();
        
        stats
    }

    fn source_cid(&self) -> &ConnectionId {
        &self.scid
    }

    fn destination_cid(&self) -> &ConnectionId {
        &self.dcid
    }
}
