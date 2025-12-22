//! # QUIC Frame Types (RFC 9000 Section 19)
//!
//! This module defines all QUIC frame types and their zero-copy parsing.
//! QUIC packets contain one or more frames carrying control or application data.
//!
//! ## Frame Classification:
//! - **ACK-eliciting**: STREAM, CRYPTO, etc. (require acknowledgment)
//! - **Non-ACK-eliciting**: ACK, CONNECTION_CLOSE, PADDING
//!
//! ## Zero-Copy Design:
//! Frame parsing returns structures with lifetime-bound references to
//! the original packet buffer, avoiding memory copies.

#![forbid(unsafe_code)]

use crate::error::Result;
use crate::types::{ConnectionId, ErrorCode, PacketNumber, StreamId, StreamOffset, VarInt};
use bytes::Bytes;

/// Frame Type Constants (RFC 9000 Section 19)
///
/// The first byte of each frame identifies its type.
pub const FRAME_TYPE_PADDING: u8 = 0x00;
pub const FRAME_TYPE_PING: u8 = 0x01;
pub const FRAME_TYPE_ACK: u8 = 0x02;
pub const FRAME_TYPE_ACK_ECN: u8 = 0x03;
pub const FRAME_TYPE_RESET_STREAM: u8 = 0x04;
pub const FRAME_TYPE_STOP_SENDING: u8 = 0x05;
pub const FRAME_TYPE_CRYPTO: u8 = 0x06;
pub const FRAME_TYPE_NEW_TOKEN: u8 = 0x07;
pub const FRAME_TYPE_STREAM_BASE: u8 = 0x08; // 0x08-0x0f
pub const FRAME_TYPE_MAX_DATA: u8 = 0x10;
pub const FRAME_TYPE_MAX_STREAM_DATA: u8 = 0x11;
pub const FRAME_TYPE_MAX_STREAMS_BIDI: u8 = 0x12;
pub const FRAME_TYPE_MAX_STREAMS_UNI: u8 = 0x13;
pub const FRAME_TYPE_DATA_BLOCKED: u8 = 0x14;
pub const FRAME_TYPE_STREAM_DATA_BLOCKED: u8 = 0x15;
pub const FRAME_TYPE_STREAMS_BLOCKED_BIDI: u8 = 0x16;
pub const FRAME_TYPE_STREAMS_BLOCKED_UNI: u8 = 0x17;
pub const FRAME_TYPE_NEW_CONNECTION_ID: u8 = 0x18;
pub const FRAME_TYPE_RETIRE_CONNECTION_ID: u8 = 0x19;
pub const FRAME_TYPE_PATH_CHALLENGE: u8 = 0x1a;
pub const FRAME_TYPE_PATH_RESPONSE: u8 = 0x1b;
pub const FRAME_TYPE_CONNECTION_CLOSE_QUIC: u8 = 0x1c;
pub const FRAME_TYPE_CONNECTION_CLOSE_APP: u8 = 0x1d;
pub const FRAME_TYPE_HANDSHAKE_DONE: u8 = 0x1e;

/// STREAM Frame Flag Bits (RFC 9000 Section 19.8)
///
/// The STREAM frame type has flags encoded in the type byte (0x08-0x0f):
/// - Bit 0 (FIN): Last frame in stream
/// - Bit 1 (LEN): Length field present
/// - Bit 2 (OFF): Offset field present
pub const STREAM_FRAME_BIT_FIN: u8 = 0x01;
pub const STREAM_FRAME_BIT_LEN: u8 = 0x02;
pub const STREAM_FRAME_BIT_OFF: u8 = 0x04;

/// ACK Frame (RFC 9000 Section 19.3)
///
/// Acknowledges receipt of packets. Contains ranges of acknowledged packet numbers.
#[derive(Debug, Clone)]
pub struct AckFrame {
    /// Largest packet number being acknowledged
    pub largest_ack: PacketNumber,

    /// Time delta (microseconds) since largest_ack packet was received
    pub ack_delay: VarInt,

    /// Number of ACK Range fields
    pub ack_range_count: VarInt,

    /// First ACK Range (number of packets before largest_ack)
    pub first_ack_range: VarInt,

    /// Additional ACK Ranges (Gap, Range pairs)
    /// Each range describes a gap followed by acknowledged packets
    pub ack_ranges: tinyvec::TinyVec<[AckRange; 8]>,

    /// ECN counts (only present in ACK_ECN frames)
    pub ecn_counts: Option<EcnCounts>,
}

/// ACK Range (RFC 9000 Section 19.3.1)
///
/// Describes a gap followed by a range of acknowledged packets.
#[derive(Debug, Clone, Copy, Default)]
pub struct AckRange {
    /// Gap before this range (packet numbers NOT acknowledged)
    pub gap: VarInt,

    /// Length of this range (packet numbers acknowledged)
    pub length: VarInt,
}

/// ECN Counts (RFC 9000 Section 19.3.2)
///
/// Explicit Congestion Notification counters reported in ACK frames.
#[derive(Debug, Clone, Copy)]
pub struct EcnCounts {
    /// ECT(0) marked packets received
    pub ect0_count: VarInt,

    /// ECT(1) marked packets received
    pub ect1_count: VarInt,

    /// ECN-CE marked packets received
    pub ce_count: VarInt,
}

/// RESET_STREAM Frame (RFC 9000 Section 19.4)
///
/// Abruptly terminates sending on a stream.
#[derive(Debug, Clone, Copy)]
pub struct ResetStreamFrame {
    /// Stream ID being reset
    pub stream_id: StreamId,

    /// Application-defined error code
    pub error_code: ErrorCode,

    /// Final size of the stream in bytes
    pub final_size: VarInt,
}

/// STOP_SENDING Frame (RFC 9000 Section 19.5)
///
/// Requests peer to stop sending on a stream.
#[derive(Debug, Clone, Copy)]
pub struct StopSendingFrame {
    /// Stream ID to stop sending on
    pub stream_id: StreamId,

    /// Application-defined error code
    pub error_code: ErrorCode,
}

/// CRYPTO Frame (RFC 9000 Section 19.6)
///
/// Carries cryptographic handshake messages.
/// Similar to STREAM frame but for the crypto stream.
#[derive(Debug, Clone)]
pub struct CryptoFrame<'a> {
    /// Byte offset in the crypto stream
    pub offset: VarInt,

    /// Length of crypto data
    pub length: VarInt,

    /// Crypto data (lifetime-bound reference to packet buffer)
    pub data: &'a [u8],
}

/// NEW_TOKEN Frame (RFC 9000 Section 19.7)
///
/// Provides token for address validation in future connections.
#[derive(Debug, Clone)]
pub struct NewTokenFrame {
    /// Token data
    pub token: Bytes,
}

/// STREAM Frame (RFC 9000 Section 19.8)
///
/// Carries application data on a stream. This is the primary data-carrying frame.
#[derive(Debug, Clone)]
pub struct StreamFrame<'a> {
    /// Stream ID
    pub stream_id: StreamId,

    /// Byte offset in stream (0 if OFF bit not set)
    pub offset: StreamOffset,

    /// Length of stream data (implicit if LEN bit not set)
    pub length: Option<VarInt>,

    /// FIN bit: indicates final frame in stream
    pub fin: bool,

    /// Stream data (lifetime-bound reference to packet buffer)
    pub data: &'a [u8],
}

/// MAX_DATA Frame (RFC 9000 Section 19.9)
///
/// Informs peer of maximum data bytes it can send on entire connection.
#[derive(Debug, Clone, Copy)]
pub struct MaxDataFrame {
    /// Maximum data in bytes
    pub maximum_data: VarInt,
}

/// MAX_STREAM_DATA Frame (RFC 9000 Section 19.10)
///
/// Informs peer of maximum data bytes it can send on a stream.
#[derive(Debug, Clone, Copy)]
pub struct MaxStreamDataFrame {
    /// Stream ID
    pub stream_id: StreamId,

    /// Maximum stream data in bytes
    pub maximum_stream_data: VarInt,
}

/// MAX_STREAMS Frame (RFC 9000 Section 19.11)
///
/// Informs peer of maximum number of streams it can open.
#[derive(Debug, Clone, Copy)]
pub struct MaxStreamsFrame {
    /// Maximum number of streams
    pub maximum_streams: VarInt,

    /// True for bidirectional, false for unidirectional
    pub bidirectional: bool,
}

/// DATA_BLOCKED Frame (RFC 9000 Section 19.12)
///
/// Indicates sender is blocked by connection-level flow control.
#[derive(Debug, Clone, Copy)]
pub struct DataBlockedFrame {
    /// Connection data limit at which blocking occurred
    pub data_limit: VarInt,
}

/// STREAM_DATA_BLOCKED Frame (RFC 9000 Section 19.13)
///
/// Indicates sender is blocked by stream-level flow control.
#[derive(Debug, Clone, Copy)]
pub struct StreamDataBlockedFrame {
    /// Stream ID
    pub stream_id: StreamId,

    /// Stream data limit at which blocking occurred
    pub stream_data_limit: VarInt,
}

/// STREAMS_BLOCKED Frame (RFC 9000 Section 19.14)
///
/// Indicates sender is blocked from opening streams.
#[derive(Debug, Clone, Copy)]
pub struct StreamsBlockedFrame {
    /// Maximum stream ID at which blocking occurred
    pub stream_limit: VarInt,

    /// True for bidirectional, false for unidirectional
    pub bidirectional: bool,
}

/// NEW_CONNECTION_ID Frame (RFC 9000 Section 19.15)
///
/// Provides peer with alternative Connection IDs for migration.
#[derive(Debug, Clone)]
pub struct NewConnectionIdFrame {
    /// Sequence number for this Connection ID
    pub sequence_number: VarInt,

    /// Retire prior to this sequence number
    pub retire_prior_to: VarInt,

    /// Connection ID
    pub connection_id: ConnectionId,

    /// Stateless reset token (16 bytes)
    pub stateless_reset_token: [u8; 16],
}

/// RETIRE_CONNECTION_ID Frame (RFC 9000 Section 19.16)
///
/// Indicates Connection ID will no longer be used.
#[derive(Debug, Clone, Copy)]
pub struct RetireConnectionIdFrame {
    /// Sequence number of Connection ID being retired
    pub sequence_number: VarInt,
}

/// PATH_CHALLENGE Frame (RFC 9000 Section 19.17)
///
/// Validates path during connection migration.
#[derive(Debug, Clone, Copy)]
pub struct PathChallengeFrame {
    /// 8-byte arbitrary data
    pub data: [u8; 8],
}

/// PATH_RESPONSE Frame (RFC 9000 Section 19.18)
///
/// Responds to PATH_CHALLENGE.
#[derive(Debug, Clone, Copy)]
pub struct PathResponseFrame {
    /// 8-byte data copied from PATH_CHALLENGE
    pub data: [u8; 8],
}

/// CONNECTION_CLOSE Frame (RFC 9000 Section 19.19)
///
/// Indicates connection is being closed.
#[derive(Debug, Clone)]
pub struct ConnectionCloseFrame {
    /// Error code
    pub error_code: VarInt,

    /// Frame type that triggered close (only for QUIC-level close)
    pub frame_type: Option<VarInt>,

    /// Human-readable reason (UTF-8)
    pub reason: Bytes,

    /// True if application-level close (0x1d), false if QUIC-level (0x1c)
    pub application_close: bool,
}

/// Unified Frame Type (RFC 9000 Section 19)
///
/// Discriminated union of all QUIC frame types.
#[derive(Debug, Clone)]
pub enum Frame<'a> {
    /// PADDING frame (0x00)
    Padding,

    /// PING frame (0x01)
    Ping,

    /// ACK frame (0x02 or 0x03)
    Ack(AckFrame),

    /// RESET_STREAM frame (0x04)
    ResetStream(ResetStreamFrame),

    /// STOP_SENDING frame (0x05)
    StopSending(StopSendingFrame),

    /// CRYPTO frame (0x06)
    Crypto(CryptoFrame<'a>),

    /// NEW_TOKEN frame (0x07)
    NewToken(NewTokenFrame),

    /// STREAM frame (0x08-0x0f)
    Stream(StreamFrame<'a>),

    /// MAX_DATA frame (0x10)
    MaxData(MaxDataFrame),

    /// MAX_STREAM_DATA frame (0x11)
    MaxStreamData(MaxStreamDataFrame),

    /// MAX_STREAMS frame (0x12 or 0x13)
    MaxStreams(MaxStreamsFrame),

    /// DATA_BLOCKED frame (0x14)
    DataBlocked(DataBlockedFrame),

    /// STREAM_DATA_BLOCKED frame (0x15)
    StreamDataBlocked(StreamDataBlockedFrame),

    /// STREAMS_BLOCKED frame (0x16 or 0x17)
    StreamsBlocked(StreamsBlockedFrame),

    /// NEW_CONNECTION_ID frame (0x18)
    NewConnectionId(NewConnectionIdFrame),

    /// RETIRE_CONNECTION_ID frame (0x19)
    RetireConnectionId(RetireConnectionIdFrame),

    /// PATH_CHALLENGE frame (0x1a)
    PathChallenge(PathChallengeFrame),

    /// PATH_RESPONSE frame (0x1b)
    PathResponse(PathResponseFrame),

    /// CONNECTION_CLOSE frame (0x1c or 0x1d)
    ConnectionClose(ConnectionCloseFrame),

    /// HANDSHAKE_DONE frame (0x1e)
    HandshakeDone,
}

impl<'a> Frame<'a> {
    /// Returns true if this frame is ACK-eliciting (RFC 9000 Section 13.2)
    ///
    /// ACK-eliciting frames require the peer to send an acknowledgment.
    /// PADDING, ACK, and CONNECTION_CLOSE are not ACK-eliciting.
    pub fn is_ack_eliciting(&self) -> bool {
        !matches!(
            self,
            Frame::Padding | Frame::Ack(_) | Frame::ConnectionClose(_)
        )
    }

    /// Returns true if this frame is retransmittable (RFC 9000 Section 13.3)
    ///
    /// Most frames are retransmitted if lost, except ACK and CONNECTION_CLOSE.
    pub fn is_retransmittable(&self) -> bool {
        !matches!(
            self,
            Frame::Padding | Frame::Ack(_) | Frame::ConnectionClose(_)
        )
    }
}

/// Frame Parser Trait (Zero-Copy)
///
/// Defines the interface for parsing frames from packet payloads.
/// All parsing returns lifetime-bound references to the input buffer.
pub trait FrameParser {
    /// Parse a single frame from the buffer.
    ///
    /// Returns (Frame, bytes_consumed) on success.
    /// The Frame may contain references into the input buffer.
    ///
    /// # Errors
    /// Returns Error::FrameEncodingError if frame is malformed.
    fn parse_frame<'a>(&self, buf: &'a [u8]) -> Result<(Frame<'a>, usize)>;

    /// Parse all frames from a packet payload.
    ///
    /// Returns a vector of frames (may allocate for the Vec itself,
    /// but frame data references the input buffer).
    fn parse_all_frames<'a>(&self, buf: &'a [u8]) -> Result<Vec<Frame<'a>>>;
}

/// Frame Builder Trait (Zero-Allocation)
///
/// Defines the interface for serializing frames into buffers.
pub trait FrameBuilder {
    /// Serialize a frame into the provided buffer.
    ///
    /// Returns the number of bytes written on success.
    ///
    /// # Errors
    /// Returns Error::InternalError if buffer is too small.
    fn build_frame(&self, buf: &mut [u8], frame: &Frame) -> Result<usize>;

    /// Calculate the serialized size of a frame.
    fn frame_size(&self, frame: &Frame) -> usize;
}
