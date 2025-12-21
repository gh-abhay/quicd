//! # quicd-quic: Pure State Machine QUIC Implementation
//!
//! This crate provides a `#![no_std]` compatible, zero-copy, zero-allocation QUIC protocol
//! implementation based on:
//! - RFC 8999: Version-Independent Properties of QUIC
//! - RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport
//! - RFC 9001: Using TLS to Secure QUIC
//! - RFC 9002: QUIC Loss Detection and Congestion Control
//!
//! ## Architecture Principles
//!
//! 1. **Pure State Machine**: No I/O, sockets, or event loops. The library processes input
//!    bytes/events and produces output bytes/events.
//!
//! 2. **Zero-Copy**: All parsing operates on borrowed slices (`&[u8]`). Return types use
//!    lifetime parameters to ensure data references the original input.
//!
//! 3. **Zero-Allocation (Runtime)**: No heap allocations in hot paths. Callers provide
//!    pre-allocated buffers via `&mut [u8]` for output operations.
//!
//! 4. **Deterministic**: State transitions are purely deterministic based on inputs and time.
//!
//! 5. **Pluggable Backends**: Crypto and congestion control are abstracted via traits.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

use core::fmt;
use core::time::Duration;

// ============================================================================
// RFC 8999: Version-Independent Properties
// ============================================================================

/// Connection ID as defined in RFC 8999 Section 5.1.
/// 
/// Connection IDs are opaque fields of between 0 and 20 bytes in length.
/// They are version-independent and used for routing packets to connections.
///
/// **Design**: Uses a lifetime to reference the underlying buffer without copying.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId<'a> {
    bytes: &'a [u8],
}

impl<'a> ConnectionId<'a> {
    /// Maximum length of a Connection ID per RFC 9000 Section 17.2.
    pub const MAX_LENGTH: usize = 20;

    /// Creates a ConnectionId from a byte slice.
    /// 
    /// Returns `None` if the length exceeds `MAX_LENGTH`.
    pub fn new(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() <= Self::MAX_LENGTH {
            Some(Self { bytes })
        } else {
            None
        }
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// QUIC Version number (RFC 8999 Section 5.2).
///
/// Version 0x00000000 is reserved for version negotiation.
/// Version 0x00000001 represents QUIC v1 (RFC 9000).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Version(pub u32);

impl Version {
    pub const NEGOTIATION: Version = Version(0x00000000);
    pub const V1: Version = Version(0x00000001);
}

// ============================================================================
// RFC 9000: Core Transport Types
// ============================================================================

/// Variable-Length Integer (RFC 9000 Section 16).
///
/// QUIC uses a variable-length encoding for integers up to 2^62-1.
pub type VarInt = u64;

/// Stream Identifier (RFC 9000 Section 2.1).
///
/// Streams are identified by a 62-bit integer. The two least significant bits
/// indicate the stream type and initiator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(pub VarInt);

impl StreamId {
    /// Returns true if this is a client-initiated stream.
    pub fn is_client_initiated(self) -> bool {
        (self.0 & 0x1) == 0
    }

    /// Returns true if this is a server-initiated stream.
    pub fn is_server_initiated(self) -> bool {
        !self.is_client_initiated()
    }

    /// Returns true if this is a bidirectional stream.
    pub fn is_bidirectional(self) -> bool {
        (self.0 & 0x2) == 0
    }

    /// Returns true if this is a unidirectional stream.
    pub fn is_unidirectional(self) -> bool {
        !self.is_bidirectional()
    }
}

/// Packet Number (RFC 9000 Section 17.1).
///
/// Packet numbers are integers in the range 0 to 2^62-1. They are encoded
/// in 1-4 bytes using truncated encoding.
pub type PacketNumber = u64;

/// Timestamp abstraction for time-based operations.
///
/// **Design**: Uses `Duration` since an epoch to remain `no_std` compatible.
/// Callers must provide monotonic time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant(pub Duration);

impl Instant {
    pub fn duration_since(&self, earlier: Instant) -> Duration {
        self.0.saturating_sub(earlier.0)
    }

    pub fn checked_add(&self, duration: Duration) -> Option<Instant> {
        self.0.checked_add(duration).map(Instant)
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// Transport-level errors (RFC 9000 Section 20).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    NoError,
    InternalError,
    ConnectionRefused,
    FlowControlError,
    StreamLimitError,
    StreamStateError,
    FinalSizeError,
    FrameEncodingError,
    TransportParameterError,
    ConnectionIdLimitError,
    ProtocolViolation,
    InvalidToken,
    ApplicationError,
    CryptoBufferExceeded,
    KeyUpdateError,
    AeadLimitReached,
    NoViablePath,
}

/// Parsing and processing errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Input buffer too small to parse.
    BufferTooShort,
    /// Invalid frame or packet encoding.
    InvalidEncoding,
    /// Transport protocol violation.
    TransportError(TransportError),
    /// Cryptographic operation failed.
    CryptoError,
    /// Invalid state for this operation.
    InvalidState,
    /// Insufficient buffer space for output.
    InsufficientBuffer,
    /// Operation would block (not ready).
    WouldBlock,
}

pub type Result<T> = core::result::Result<T, Error>;

// ============================================================================
// RFC 9000 Section 12: Frames
// ============================================================================

/// QUIC Frame types (RFC 9000 Section 12.4).
///
/// **Design**: Uses zero-copy references. Frame data references the input buffer
/// via lifetime parameter `'a`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame<'a> {
    /// PADDING frame (0x00).
    Padding,

    /// PING frame (0x01).
    Ping,

    /// ACK frame (0x02, 0x03) - RFC 9000 Section 19.3.
    Ack {
        largest_acknowledged: PacketNumber,
        ack_delay: VarInt,
        /// ACK ranges encoded as (gap, range) tuples.
        ranges: &'a [u8],
        ecn_counts: Option<EcnCounts>,
    },

    /// RESET_STREAM frame (0x04).
    ResetStream {
        stream_id: StreamId,
        app_error_code: VarInt,
        final_size: VarInt,
    },

    /// STOP_SENDING frame (0x05).
    StopSending {
        stream_id: StreamId,
        app_error_code: VarInt,
    },

    /// CRYPTO frame (0x06) - carries handshake data.
    Crypto {
        offset: VarInt,
        data: &'a [u8],
    },

    /// NEW_TOKEN frame (0x07) - server issues address validation token.
    NewToken {
        token: &'a [u8],
    },

    /// STREAM frame (0x08-0x0f) - RFC 9000 Section 19.8.
    Stream {
        stream_id: StreamId,
        offset: VarInt,
        data: &'a [u8],
        fin: bool,
    },

    /// MAX_DATA frame (0x10) - connection-level flow control.
    MaxData {
        maximum_data: VarInt,
    },

    /// MAX_STREAM_DATA frame (0x11) - stream-level flow control.
    MaxStreamData {
        stream_id: StreamId,
        maximum_stream_data: VarInt,
    },

    /// MAX_STREAMS frame (0x12, 0x13).
    MaxStreams {
        maximum_streams: VarInt,
        bidirectional: bool,
    },

    /// DATA_BLOCKED frame (0x14).
    DataBlocked {
        limit: VarInt,
    },

    /// STREAM_DATA_BLOCKED frame (0x15).
    StreamDataBlocked {
        stream_id: StreamId,
        limit: VarInt,
    },

    /// STREAMS_BLOCKED frame (0x16, 0x17).
    StreamsBlocked {
        limit: VarInt,
        bidirectional: bool,
    },

    /// NEW_CONNECTION_ID frame (0x18) - provides new CID to peer.
    NewConnectionId {
        sequence_number: VarInt,
        retire_prior_to: VarInt,
        connection_id: ConnectionId<'a>,
        stateless_reset_token: &'a [u8; 16],
    },

    /// RETIRE_CONNECTION_ID frame (0x19).
    RetireConnectionId {
        sequence_number: VarInt,
    },

    /// PATH_CHALLENGE frame (0x1a).
    PathChallenge {
        data: &'a [u8; 8],
    },

    /// PATH_RESPONSE frame (0x1b).
    PathResponse {
        data: &'a [u8; 8],
    },

    /// CONNECTION_CLOSE frame (0x1c, 0x1d) - RFC 9000 Section 19.19.
    ConnectionClose {
        error_code: VarInt,
        frame_type: Option<VarInt>,
        reason: &'a [u8],
    },

    /// HANDSHAKE_DONE frame (0x1e) - server signals handshake completion.
    HandshakeDone,
}

/// ECN (Explicit Congestion Notification) counts (RFC 9000 Section 19.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcnCounts {
    pub ect0_count: VarInt,
    pub ect1_count: VarInt,
    pub ecn_ce_count: VarInt,
}

// ============================================================================
// RFC 9000 Section 17: Packets
// ============================================================================

/// Packet type determines encryption level and processing rules (RFC 9000 Section 17.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    /// Initial packet - first packet in handshake.
    Initial,
    /// 0-RTT packet - early data before handshake completes.
    ZeroRtt,
    /// Handshake packet - completes cryptographic handshake.
    Handshake,
    /// Retry packet - server forces address validation.
    Retry,
    /// 1-RTT packet - application data after handshake.
    OneRtt,
    /// Version Negotiation packet (not encrypted).
    VersionNegotiation,
}

/// Parsed packet header (RFC 9000 Section 17).
///
/// **Design**: Zero-copy structure. All slices reference the input buffer.
#[derive(Debug, Clone)]
pub struct PacketHeader<'a> {
    pub packet_type: PacketType,
    pub version: Version,
    pub dcid: ConnectionId<'a>,
    pub scid: ConnectionId<'a>,
    /// Token for Initial packets (address validation).
    pub token: Option<&'a [u8]>,
    /// Packet number (after decoding from truncated form).
    pub packet_number: PacketNumber,
    /// Remaining payload length.
    pub payload_length: usize,
}

// ============================================================================
// Trait: PacketParser (RFC 9000 Section 17 + RFC 9001 Section 5)
// ============================================================================

/// Zero-copy packet parser.
///
/// **RFC 9000 Section 17**: Defines packet structure (header + payload).
/// **RFC 9001 Section 5**: Header protection must be removed before parsing.
///
/// **Design Philosophy**:
/// - Input: `&[u8]` with lifetime `'a`
/// - Output: `PacketHeader<'a>` + payload slice `&'a [u8]`
/// - No allocations: All parsing happens on borrowed data
/// - Header protection removal may require mutable access or external decryption
pub trait PacketParser {
    /// Parse a QUIC packet from raw bytes.
    ///
    /// **RFC 9000 Section 17.2**: Long headers (Initial, 0-RTT, Handshake, Retry)
    /// and short headers (1-RTT) have different formats.
    ///
    /// Returns:
    /// - `PacketHeader<'a>`: Parsed header with references to input buffer
    /// - `&'a [u8]`: Protected payload (caller must decrypt with crypto backend)
    /// - Remaining unconsumed bytes
    fn parse_packet<'a>(
        &self,
        data: &'a [u8],
    ) -> Result<(PacketHeader<'a>, &'a [u8], &'a [u8])>;

    /// Decode the packet number from truncated encoding (RFC 9000 Section 17.1).
    ///
    /// **Design**: Requires the largest acknowledged packet number to reconstruct
    /// the full packet number from 1-4 bytes.
    fn decode_packet_number(
        &self,
        truncated: u32,
        largest_acked: PacketNumber,
    ) -> PacketNumber;
}

// ============================================================================
// Trait: FrameParser (RFC 9000 Section 12)
// ============================================================================

/// Zero-copy frame parser.
///
/// **RFC 9000 Section 12**: Frames are the building blocks of QUIC packets.
/// Multiple frames can exist in a single packet.
pub trait FrameParser {
    /// Parse a single frame from decrypted payload.
    ///
    /// **Design**: Returns `Frame<'a>` borrowing from input buffer and remaining bytes.
    fn parse_frame<'a>(&self, data: &'a [u8]) -> Result<(Frame<'a>, &'a [u8])>;

    /// Parse all frames from a packet payload.
    ///
    /// **Design**: Visitor pattern to avoid allocation. Caller provides a callback
    /// that receives each parsed frame.
    fn parse_all_frames<'a, F>(&self, mut data: &'a [u8], mut visitor: F) -> Result<()>
    where
        F: FnMut(Frame<'a>) -> Result<()>,
    {
        while !data.is_empty() {
            let (frame, remaining) = self.parse_frame(data)?;
            visitor(frame)?;
            data = remaining;
        }
        Ok(())
    }
}

// ============================================================================
// Trait: PacketWriter (Output Buffer Injection)
// ============================================================================

/// Packet serialization with caller-provided buffers.
///
/// **Design Philosophy**: No `Vec<u8>` returns. Caller provides `&mut [u8]` and
/// writer returns the number of bytes written.
pub trait PacketWriter {
    /// Serialize a packet header into the provided buffer.
    ///
    /// Returns the number of bytes written, or `Error::InsufficientBuffer` if
    /// the buffer is too small.
    fn write_header(
        &self,
        buffer: &mut [u8],
        header: &PacketHeader,
    ) -> Result<usize>;

    /// Serialize a frame into the provided buffer.
    fn write_frame(&self, buffer: &mut [u8], frame: &Frame) -> Result<usize>;

    /// Construct a complete packet: header + frames + padding.
    ///
    /// **RFC 9000 Section 14.1**: Initial packets must be at least 1200 bytes.
    fn write_packet(
        &self,
        buffer: &mut [u8],
        header: &PacketHeader,
        frames: &[Frame],
        min_size: Option<usize>,
    ) -> Result<usize>;
}

// ============================================================================
// RFC 9001: Cryptographic Backend Abstraction
// ============================================================================

/// Encryption level for packet protection (RFC 9001 Section 4).
///
/// QUIC uses different keys for different packet types during the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncryptionLevel {
    /// Initial packets use keys derived from client's Destination CID.
    Initial,
    /// 0-RTT packets use early data keys from previous connection.
    EarlyData,
    /// Handshake packets use keys from TLS handshake.
    Handshake,
    /// 1-RTT packets use application data keys.
    Application,
}

/// Cryptographic operations provider (RFC 9001).
///
/// **Design Philosophy**: This trait abstracts over the TLS stack (rustls, boring, etc.).
/// The QUIC state machine calls these methods but does not implement crypto itself.
///
/// **Zero-Copy**: Encryption/decryption operate on mutable slices in-place where possible.
pub trait CryptoBackend {
    /// Remove header protection (RFC 9001 Section 5.4).
    ///
    /// **Input**:
    /// - `packet`: Mutable buffer containing the protected packet
    /// - `sample_offset`: Offset to the sample for header protection
    /// - `level`: Encryption level to determine which keys to use
    ///
    /// **Output**: Modifies packet in-place, returns the unprotected header length.
    fn unprotect_header(
        &self,
        packet: &mut [u8],
        sample_offset: usize,
        level: EncryptionLevel,
    ) -> Result<usize>;

    /// Apply header protection (RFC 9001 Section 5.4).
    fn protect_header(
        &self,
        packet: &mut [u8],
        sample_offset: usize,
        level: EncryptionLevel,
    ) -> Result<()>;

    /// Decrypt packet payload (RFC 9001 Section 5.3).
    ///
    /// **Design**: Decryption happens in-place. The `payload` slice is modified
    /// to contain plaintext, and the authentication tag is verified.
    ///
    /// Returns the length of plaintext (excluding tag).
    fn decrypt_payload(
        &self,
        payload: &mut [u8],
        packet_number: PacketNumber,
        header: &[u8],
        level: EncryptionLevel,
    ) -> Result<usize>;

    /// Encrypt packet payload (RFC 9001 Section 5.3).
    ///
    /// **Design**: Encryption happens in-place. Additional space must be reserved
    /// for the authentication tag (typically 16 bytes).
    ///
    /// Returns the total length (plaintext + tag).
    fn encrypt_payload(
        &self,
        payload: &mut [u8],
        packet_number: PacketNumber,
        header: &[u8],
        level: EncryptionLevel,
    ) -> Result<usize>;

    /// Process incoming handshake data from CRYPTO frames.
    ///
    /// **RFC 9001 Section 4**: TLS handshake messages are carried in CRYPTO frames.
    ///
    /// Returns `true` if new keys are available (key update).
    fn process_handshake_data(&mut self, data: &[u8], level: EncryptionLevel) -> Result<bool>;

    /// Get outgoing handshake data to send in CRYPTO frames.
    ///
    /// **Buffer Injection**: Caller provides buffer, returns bytes written.
    fn get_handshake_data(&mut self, buffer: &mut [u8], level: EncryptionLevel) -> Result<usize>;

    /// Check if handshake is complete (RFC 9001 Section 4.1.2).
    fn is_handshake_complete(&self) -> bool;

    /// Derive initial secrets from Destination Connection ID (RFC 9001 Section 5.2).
    fn derive_initial_secrets(&mut self, dcid: &ConnectionId) -> Result<()>;
}

// ============================================================================
// RFC 9002: Loss Detection and Congestion Control
// ============================================================================

/// Packet space for loss detection (RFC 9002 Section 3).
///
/// QUIC maintains separate packet number spaces for different encryption levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketSpace {
    Initial,
    Handshake,
    ApplicationData,
}

/// Information about a sent packet (RFC 9002 Appendix A.1).
#[derive(Debug, Clone)]
pub struct SentPacket {
    pub packet_number: PacketNumber,
    pub time_sent: Instant,
    pub ack_eliciting: bool,
    pub in_flight: bool,
    pub size: usize,
    pub packet_space: PacketSpace,
}

/// ACK information received from peer (RFC 9002 Section 2).
#[derive(Debug, Clone)]
pub struct AckInfo {
    pub packet_number: PacketNumber,
    pub time_received: Instant,
}

/// Loss detection events (RFC 9002 Section 6).
pub enum LossEvent {
    PacketAcked {
        packet: SentPacket,
        ack_time: Instant,
    },
    PacketLost {
        packet: SentPacket,
    },
    /// Timer expired (PTO or loss detection timer).
    TimerExpired,
}

/// Loss Detection manager (RFC 9002 Section 6).
///
/// **Design**: Separated from congestion control per RFC 9002.
/// Tracks sent packets and determines when packets should be considered lost.
pub trait LossDetector {
    /// Record a packet sent.
    fn on_packet_sent(&mut self, packet: SentPacket, now: Instant);

    /// Process an ACK frame.
    ///
    /// **Returns**: Iterator of loss events (packets acked or declared lost).
    fn on_ack_received(
        &mut self,
        ack: &Frame,
        packet_space: PacketSpace,
        now: Instant,
    ) -> impl Iterator<Item = LossEvent>;

    /// Get the next timer deadline.
    ///
    /// **RFC 9002 Section 6.2**: Returns when the next PTO or loss detection
    /// timer should fire.
    fn next_timeout(&self) -> Option<Instant>;

    /// Handle timer expiration.
    fn on_timeout(&mut self, now: Instant) -> impl Iterator<Item = LossEvent>;
}

/// Congestion control algorithm (RFC 9002 Appendix B).
///
/// **Design**: Strategy pattern. Allows swapping algorithms (NewReno, Cubic, BBR)
/// without changing the transport logic.
pub trait CongestionController {
    /// Get the current congestion window (in bytes).
    fn congestion_window(&self) -> usize;

    /// Get the number of bytes in flight.
    fn bytes_in_flight(&self) -> usize;

    /// Returns true if sending is allowed (cwnd not exceeded).
    fn can_send(&self) -> bool {
        self.bytes_in_flight() < self.congestion_window()
    }

    /// Record a packet sent (increases bytes in flight).
    fn on_packet_sent(&mut self, size: usize, now: Instant);

    /// Record a packet acknowledged (RFC 9002 Section 7).
    fn on_packet_acked(&mut self, size: usize, now: Instant);

    /// Record packets lost (RFC 9002 Section 7).
    fn on_packets_lost(&mut self, lost_bytes: usize, now: Instant);

    /// Enter persistent congestion (RFC 9002 Section 7.6).
    fn on_persistent_congestion(&mut self, now: Instant);
}

// ============================================================================
// Stream Management (RFC 9000 Section 2)
// ============================================================================

/// Stream state machine (RFC 9000 Section 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Ready to send/receive (bidirectional).
    Idle,
    /// Opened, can send data.
    Open,
    /// Local side sent FIN.
    SendClosed,
    /// Remote side sent FIN.
    RecvClosed,
    /// Both sides closed.
    Closed,
    /// Stream reset by peer.
    ResetRecvd,
    /// Stream reset by local.
    ResetSent,
}

/// Stream data access using visitor pattern (zero-copy).
///
/// **Design Philosophy**: Avoid copying stream data into intermediate buffers.
/// Applications read directly from reassembly buffer via slices.
pub trait StreamReader {
    /// Read available contiguous data from stream.
    ///
    /// **Returns**: `&[u8]` slice of available data and the offset.
    /// Caller must call `consume()` after processing.
    fn peek(&self, stream_id: StreamId) -> Result<(u64, &[u8])>;

    /// Mark bytes as consumed (advances read offset).
    fn consume(&mut self, stream_id: StreamId, count: usize) -> Result<()>;

    /// Check if FIN has been received and all data read.
    fn is_finished(&self, stream_id: StreamId) -> bool;
}

/// Stream data writer (buffer injection).
pub trait StreamWriter {
    /// Queue data to send on a stream.
    ///
    /// **Design**: Does not copy data immediately. Accepts a reference and may
    /// use reference counting (like `bytes::Bytes`) internally.
    ///
    /// Returns the number of bytes accepted (may be less due to flow control).
    fn write(&mut self, stream_id: StreamId, data: &[u8], fin: bool) -> Result<usize>;

    /// Check if stream has buffered data to send.
    fn has_pending_data(&self, stream_id: StreamId) -> bool;

    /// Get writable bytes (flow control limit - buffered data).
    fn writable_bytes(&self, stream_id: StreamId) -> usize;
}

/// Combined stream management interface.
pub trait StreamController: StreamReader + StreamWriter {
    /// Open a new stream (client or server).
    fn open_stream(&mut self, bidirectional: bool) -> Result<StreamId>;

    /// Process incoming STREAM frame (reassembly).
    fn on_stream_frame(&mut self, frame: &Frame, now: Instant) -> Result<()>;

    /// Process flow control frames (MAX_STREAM_DATA).
    fn on_max_stream_data(&mut self, stream_id: StreamId, limit: VarInt) -> Result<()>;

    /// Reset a stream (send RESET_STREAM).
    fn reset_stream(&mut self, stream_id: StreamId, error_code: VarInt) -> Result<()>;
}

// ============================================================================
// Connection State Machine (RFC 9000 Section 5)
// ============================================================================

/// Connection state (RFC 9000 Section 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Attempting connection (client sending Initial).
    Connecting,
    /// Handshake in progress.
    Handshaking,
    /// Handshake complete, can send/receive application data.
    Established,
    /// Closing (CONNECTION_CLOSE sent, draining timer active).
    Closing,
    /// Draining (CONNECTION_CLOSE received).
    Draining,
    /// Connection closed.
    Closed,
}

/// Transport parameters negotiated during handshake (RFC 9000 Section 18).
#[derive(Debug, Clone)]
pub struct TransportParameters {
    pub max_idle_timeout: Duration,
    pub max_udp_payload_size: VarInt,
    pub initial_max_data: VarInt,
    pub initial_max_stream_data_bidi_local: VarInt,
    pub initial_max_stream_data_bidi_remote: VarInt,
    pub initial_max_stream_data_uni: VarInt,
    pub initial_max_streams_bidi: VarInt,
    pub initial_max_streams_uni: VarInt,
    pub ack_delay_exponent: u8,
    pub max_ack_delay: Duration,
    pub disable_active_migration: bool,
    pub active_connection_id_limit: VarInt,
}

/// Connection role (client or server).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

// ============================================================================
// The Core Connection State Machine
// ============================================================================

/// Output events from the connection (what the application/worker must do).
#[derive(Debug)]
pub enum ConnectionEvent<'a> {
    /// Datagram ready to send.
    SendDatagram {
        data: &'a [u8],
    },

    /// Stream data available to read.
    StreamReadable {
        stream_id: StreamId,
    },

    /// Stream is writable (flow control increased).
    StreamWritable {
        stream_id: StreamId,
    },

    /// New stream opened by peer.
    StreamOpened {
        stream_id: StreamId,
    },

    /// Stream was reset by peer.
    StreamReset {
        stream_id: StreamId,
        error_code: VarInt,
    },

    /// Connection closed (locally or by peer).
    ConnectionClosed {
        error_code: VarInt,
        reason: &'a [u8],
    },

    /// Handshake completed successfully.
    HandshakeComplete,
}

/// The main QUIC connection state machine.
///
/// **Design Philosophy**:
/// - Pure state machine: input bytes/events → state transitions → output events
/// - No I/O: caller handles socket operations
/// - No event loop: caller drives via `poll()` method
/// - Deterministic: same inputs produce same outputs
///
/// **Lifetime Management**:
/// - Connection owns long-lived state (packet buffers, crypto keys)
/// - Methods borrow input with `'a` and return events bound by `'a`
/// - Caller is responsible for I/O and event loop
pub trait Connection {
    /// Process an incoming UDP datagram.
    ///
    /// **RFC 9000 Section 17**: Parse packet, decrypt, process frames.
    ///
    /// **Design**: Returns an iterator of events. Caller must handle all events
    /// before next call.
    fn on_datagram<'a>(
        &mut self,
        data: &'a [u8],
        now: Instant,
    ) -> Result<impl Iterator<Item = ConnectionEvent<'a>>>;

    /// Poll for outgoing datagrams and timer updates.
    ///
    /// **Design**: Caller provides output buffer. Returns number of bytes written.
    /// Call repeatedly until returns 0 (no more data to send).
    fn poll_send(&mut self, buffer: &mut [u8], now: Instant) -> Result<usize>;

    /// Get the next timer deadline.
    ///
    /// **RFC 9002**: Loss detection, idle timeout, key updates all use timers.
    fn next_timeout(&self) -> Option<Instant>;

    /// Handle timer expiration.
    fn on_timeout(&mut self, now: Instant) -> Result<()>;

    /// Get current connection state.
    fn state(&self) -> ConnectionState;

    /// Check if connection is established.
    fn is_established(&self) -> bool {
        self.state() == ConnectionState::Established
    }

    /// Check if connection is closed.
    fn is_closed(&self) -> bool {
        matches!(self.state(), ConnectionState::Closed)
    }

    /// Get connection statistics (bytes sent/received, RTT, etc.).
    fn stats(&self) -> ConnectionStats;

    /// Close the connection gracefully.
    fn close(&mut self, error_code: VarInt, reason: &[u8]) -> Result<()>;
}

/// Connection statistics.
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub packets_lost: u64,
    /// Smoothed round-trip time (RFC 9002 Appendix A.3).
    pub rtt: Duration,
    pub cwnd: usize,
}

// ============================================================================
// Connection Builder (Factory Pattern)
// ============================================================================

/// Builder for creating QUIC connections.
///
/// **Design**: Provides a type-safe way to configure connections before creation.
pub trait ConnectionBuilder {
    type Connection: Connection;

    /// Set the connection role (client or server).
    fn with_role(self, role: Role) -> Self;

    /// Set transport parameters.
    fn with_transport_params(self, params: TransportParameters) -> Self;

    /// Set the crypto backend.
    fn with_crypto_backend(self, crypto: impl CryptoBackend) -> Self;

    /// Set the congestion controller.
    fn with_congestion_controller(self, cc: impl CongestionController) -> Self;

    /// Build the connection.
    fn build(self) -> Result<Self::Connection>;
}

// ============================================================================
// Module Organization
// ============================================================================

pub mod packet {
    //! Packet parsing and serialization (RFC 9000 Section 17).
}

pub mod frame {
    //! Frame parsing and serialization (RFC 9000 Section 12).
}

pub mod crypto {
    //! Cryptographic abstractions (RFC 9001).
}

pub mod recovery {
    //! Loss detection and congestion control (RFC 9002).
}

pub mod stream {
    //! Stream management (RFC 9000 Section 2-3).
}

pub mod connection {
    //! Connection state machine (RFC 9000 Section 5).
}

pub mod varint {
    //! Variable-length integer encoding/decoding (RFC 9000 Section 16).
    
    use super::{Error, Result, VarInt};
    
    /// Decode a variable-length integer from bytes.
    ///
    /// Returns the decoded value and number of bytes consumed.
    pub fn decode(data: &[u8]) -> Result<(VarInt, usize)> {
        if data.is_empty() {
            return Err(Error::BufferTooShort);
        }

        let first = data[0];
        let len = 1 << (first >> 6);
        
        if data.len() < len {
            return Err(Error::BufferTooShort);
        }

        let value = match len {
            1 => (first & 0x3f) as u64,
            2 => {
                let mut buf = [0u8; 2];
                buf.copy_from_slice(&data[..2]);
                ((u16::from_be_bytes(buf) & 0x3fff) as u64)
            }
            4 => {
                let mut buf = [0u8; 4];
                buf.copy_from_slice(&data[..4]);
                ((u32::from_be_bytes(buf) & 0x3fffffff) as u64)
            }
            8 => {
                let mut buf = [0u8; 8];
                buf.copy_from_slice(&data[..8]);
                (u64::from_be_bytes(buf) & 0x3fffffffffffffff)
            }
            _ => unreachable!(),
        };

        Ok((value, len))
    }

    /// Encode a variable-length integer into bytes.
    ///
    /// Returns the number of bytes written.
    pub fn encode(value: VarInt, buffer: &mut [u8]) -> Result<usize> {
        let len = encoding_length(value);
        
        if buffer.len() < len {
            return Err(Error::InsufficientBuffer);
        }

        match len {
            1 => {
                buffer[0] = value as u8;
            }
            2 => {
                let bytes = ((value as u16) | 0x4000).to_be_bytes();
                buffer[..2].copy_from_slice(&bytes);
            }
            4 => {
                let bytes = ((value as u32) | 0x80000000).to_be_bytes();
                buffer[..4].copy_from_slice(&bytes);
            }
            8 => {
                let bytes = (value | 0xc000000000000000).to_be_bytes();
                buffer[..8].copy_from_slice(&bytes);
            }
            _ => unreachable!(),
        }

        Ok(len)
    }

    /// Get the encoding length for a value.
    pub const fn encoding_length(value: VarInt) -> usize {
        if value < 64 {
            1
        } else if value < 16384 {
            2
        } else if value < 1073741824 {
            4
        } else {
            8
        }
    }
}
