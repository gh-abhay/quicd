//! # QUIC Frame Types (RFC 9000 Section 19)
//!
//! All frame types with zero-copy parsing (lifetime-bound payloads).

#![forbid(unsafe_code)]

use crate::error::{ApplicationError, TransportError};
use crate::types::{
    PacketNumber, StatelessResetToken, StreamId, StreamOffset, VarInt,
};

// ============================================================================
// Frame Type Constants (RFC 9000 Section 19)
// ============================================================================

pub const FRAME_TYPE_PADDING: u64 = 0x00;
pub const FRAME_TYPE_PING: u64 = 0x01;
pub const FRAME_TYPE_ACK: u64 = 0x02;
pub const FRAME_TYPE_ACK_ECN: u64 = 0x03;
pub const FRAME_TYPE_RESET_STREAM: u64 = 0x04;
pub const FRAME_TYPE_STOP_SENDING: u64 = 0x05;
pub const FRAME_TYPE_CRYPTO: u64 = 0x06;
pub const FRAME_TYPE_NEW_TOKEN: u64 = 0x07;
pub const FRAME_TYPE_STREAM: u64 = 0x08; // Base type, flags in lower bits
pub const FRAME_TYPE_MAX_DATA: u64 = 0x10;
pub const FRAME_TYPE_MAX_STREAM_DATA: u64 = 0x11;
pub const FRAME_TYPE_MAX_STREAMS_BIDI: u64 = 0x12;
pub const FRAME_TYPE_MAX_STREAMS_UNI: u64 = 0x13;
pub const FRAME_TYPE_DATA_BLOCKED: u64 = 0x14;
pub const FRAME_TYPE_STREAM_DATA_BLOCKED: u64 = 0x15;
pub const FRAME_TYPE_STREAMS_BLOCKED_BIDI: u64 = 0x16;
pub const FRAME_TYPE_STREAMS_BLOCKED_UNI: u64 = 0x17;
pub const FRAME_TYPE_NEW_CONNECTION_ID: u64 = 0x18;
pub const FRAME_TYPE_RETIRE_CONNECTION_ID: u64 = 0x19;
pub const FRAME_TYPE_PATH_CHALLENGE: u64 = 0x1a;
pub const FRAME_TYPE_PATH_RESPONSE: u64 = 0x1b;
pub const FRAME_TYPE_CONNECTION_CLOSE_TRANSPORT: u64 = 0x1c;
pub const FRAME_TYPE_CONNECTION_CLOSE_APPLICATION: u64 = 0x1d;
pub const FRAME_TYPE_HANDSHAKE_DONE: u64 = 0x1e;

/// STREAM frame flag bits (RFC 9000 Section 19.8)
pub const STREAM_FRAME_BIT_FIN: u64 = 0x01;
pub const STREAM_FRAME_BIT_LEN: u64 = 0x02;
pub const STREAM_FRAME_BIT_OFF: u64 = 0x04;

// ============================================================================
// Frame Enum (Unified Type for All Frames)
// ============================================================================

/// QUIC Frame (RFC 9000 Section 12.4)
///
/// Represents all possible QUIC frame types with zero-copy payloads.
/// Lifetime 'a binds data references to the original packet buffer.
#[derive(Debug, Clone)]
pub enum Frame<'a> {
    /// PADDING frame (0x00) - No payload
    Padding,

    /// PING frame (0x01) - No payload, ACK-eliciting
    Ping,

    /// ACK frame (0x02)
    Ack(AckFrame<'a>),

    /// ACK frame with ECN counts (0x03)
    AckEcn(AckEcnFrame<'a>),

    /// RESET_STREAM frame (0x04)
    ResetStream(ResetStreamFrame),

    /// STOP_SENDING frame (0x05)
    StopSending(StopSendingFrame),

    /// CRYPTO frame (0x06) - Handshake data
    Crypto(CryptoFrame<'a>),

    /// NEW_TOKEN frame (0x07) - Address validation token
    NewToken(NewTokenFrame<'a>),

    /// STREAM frame (0x08-0x0f) - Application data
    Stream(StreamFrame<'a>),

    /// MAX_DATA frame (0x10) - Connection-level flow control
    MaxData(MaxDataFrame),

    /// MAX_STREAM_DATA frame (0x11) - Stream-level flow control
    MaxStreamData(MaxStreamDataFrame),

    /// MAX_STREAMS frame for bidirectional streams (0x12)
    MaxStreamsBidi(MaxStreamsFrame),

    /// MAX_STREAMS frame for unidirectional streams (0x13)
    MaxStreamsUni(MaxStreamsFrame),

    /// DATA_BLOCKED frame (0x14) - Connection-level blocked
    DataBlocked(DataBlockedFrame),

    /// STREAM_DATA_BLOCKED frame (0x15) - Stream-level blocked
    StreamDataBlocked(StreamDataBlockedFrame),

    /// STREAMS_BLOCKED frame for bidirectional streams (0x16)
    StreamsBlockedBidi(StreamsBlockedFrame),

    /// STREAMS_BLOCKED frame for unidirectional streams (0x17)
    StreamsBlockedUni(StreamsBlockedFrame),

    /// NEW_CONNECTION_ID frame (0x18) - Provide new CID
    NewConnectionId(NewConnectionIdFrame<'a>),

    /// RETIRE_CONNECTION_ID frame (0x19) - Retire old CID
    RetireConnectionId(RetireConnectionIdFrame),

    /// PATH_CHALLENGE frame (0x1a) - Path validation
    PathChallenge(PathChallengeFrame),

    /// PATH_RESPONSE frame (0x1b) - Path validation response
    PathResponse(PathResponseFrame),

    /// CONNECTION_CLOSE frame for transport errors (0x1c)
    ConnectionCloseTransport(ConnectionCloseTransportFrame<'a>),

    /// CONNECTION_CLOSE frame for application errors (0x1d)
    ConnectionCloseApplication(ConnectionCloseApplicationFrame<'a>),

    /// HANDSHAKE_DONE frame (0x1e) - Server confirms handshake complete
    HandshakeDone,
}

impl<'a> Frame<'a> {
    /// Returns true if this frame is ACK-eliciting (RFC 9000 Section 13.2.1)
    ///
    /// ACK-eliciting frames require the peer to send an ACK.
    pub fn is_ack_eliciting(&self) -> bool {
        !matches!(self, Frame::Padding | Frame::Ack(_) | Frame::AckEcn(_) | Frame::ConnectionCloseTransport(_) | Frame::ConnectionCloseApplication(_))
    }

    /// Returns the frame type code
    pub fn frame_type(&self) -> u64 {
        match self {
            Frame::Padding => FRAME_TYPE_PADDING,
            Frame::Ping => FRAME_TYPE_PING,
            Frame::Ack(_) => FRAME_TYPE_ACK,
            Frame::AckEcn(_) => FRAME_TYPE_ACK_ECN,
            Frame::ResetStream(_) => FRAME_TYPE_RESET_STREAM,
            Frame::StopSending(_) => FRAME_TYPE_STOP_SENDING,
            Frame::Crypto(_) => FRAME_TYPE_CRYPTO,
            Frame::NewToken(_) => FRAME_TYPE_NEW_TOKEN,
            Frame::Stream(s) => {
                FRAME_TYPE_STREAM
                    | (if s.fin { STREAM_FRAME_BIT_FIN } else { 0 })
                    | (if s.offset > 0 { STREAM_FRAME_BIT_OFF } else { 0 })
                    | STREAM_FRAME_BIT_LEN // Always include length
            }
            Frame::MaxData(_) => FRAME_TYPE_MAX_DATA,
            Frame::MaxStreamData(_) => FRAME_TYPE_MAX_STREAM_DATA,
            Frame::MaxStreamsBidi(_) => FRAME_TYPE_MAX_STREAMS_BIDI,
            Frame::MaxStreamsUni(_) => FRAME_TYPE_MAX_STREAMS_UNI,
            Frame::DataBlocked(_) => FRAME_TYPE_DATA_BLOCKED,
            Frame::StreamDataBlocked(_) => FRAME_TYPE_STREAM_DATA_BLOCKED,
            Frame::StreamsBlockedBidi(_) => FRAME_TYPE_STREAMS_BLOCKED_BIDI,
            Frame::StreamsBlockedUni(_) => FRAME_TYPE_STREAMS_BLOCKED_UNI,
            Frame::NewConnectionId(_) => FRAME_TYPE_NEW_CONNECTION_ID,
            Frame::RetireConnectionId(_) => FRAME_TYPE_RETIRE_CONNECTION_ID,
            Frame::PathChallenge(_) => FRAME_TYPE_PATH_CHALLENGE,
            Frame::PathResponse(_) => FRAME_TYPE_PATH_RESPONSE,
            Frame::ConnectionCloseTransport(_) => FRAME_TYPE_CONNECTION_CLOSE_TRANSPORT,
            Frame::ConnectionCloseApplication(_) => {
                FRAME_TYPE_CONNECTION_CLOSE_APPLICATION
            }
            Frame::HandshakeDone => FRAME_TYPE_HANDSHAKE_DONE,
        }
    }
}

// ============================================================================
// Individual Frame Structures
// ============================================================================

/// ACK Frame (RFC 9000 Section 19.3)
#[derive(Debug, Clone)]
pub struct AckFrame<'a> {
    /// Largest packet number being acknowledged
    pub largest_acked: PacketNumber,

    /// ACK Delay in microseconds (scaled by ack_delay_exponent)
    pub ack_delay: VarInt,

    /// Number of ACK range blocks
    pub ack_range_count: VarInt,

    /// First ACK range (contiguous packets before largest_acked)
    pub first_ack_range: VarInt,

    /// Additional ACK ranges (gap, ack_range) pairs
    /// Lifetime-bound to avoid copying ranges
    pub ack_ranges: &'a [(VarInt, VarInt)],
}

/// ACK Frame with ECN Counts (RFC 9000 Section 19.3)
#[derive(Debug, Clone)]
pub struct AckEcnFrame<'a> {
    /// Base ACK frame fields
    pub ack: AckFrame<'a>,

    /// ECN counters (RFC 9000 Section 13.4)
    pub ect0_count: VarInt,
    pub ect1_count: VarInt,
    pub ecn_ce_count: VarInt,
}

/// RESET_STREAM Frame (RFC 9000 Section 19.4)
#[derive(Debug, Clone, Copy)]
pub struct ResetStreamFrame {
    pub stream_id: StreamId,
    pub application_error_code: u64,
    pub final_size: VarInt,
}

/// STOP_SENDING Frame (RFC 9000 Section 19.5)
#[derive(Debug, Clone, Copy)]
pub struct StopSendingFrame {
    pub stream_id: StreamId,
    pub application_error_code: u64,
}

/// CRYPTO Frame (RFC 9000 Section 19.6)
#[derive(Debug, Clone)]
pub struct CryptoFrame<'a> {
    /// Byte offset in the crypto stream
    pub offset: VarInt,

    /// Crypto handshake data (zero-copy reference)
    pub data: &'a [u8],
}

/// NEW_TOKEN Frame (RFC 9000 Section 19.7)
#[derive(Debug, Clone)]
pub struct NewTokenFrame<'a> {
    /// Opaque token for address validation (zero-copy)
    pub token: &'a [u8],
}

/// STREAM Frame (RFC 9000 Section 19.8)
#[derive(Debug, Clone)]
pub struct StreamFrame<'a> {
    /// Stream ID
    pub stream_id: StreamId,

    /// Byte offset in the stream
    pub offset: StreamOffset,

    /// FIN bit - indicates end of stream
    pub fin: bool,

    /// Stream data (zero-copy reference to packet buffer)
    pub data: &'a [u8],
}

/// MAX_DATA Frame (RFC 9000 Section 19.9)
#[derive(Debug, Clone, Copy)]
pub struct MaxDataFrame {
    /// Maximum data bytes that can be sent on connection
    pub maximum_data: VarInt,
}

/// MAX_STREAM_DATA Frame (RFC 9000 Section 19.10)
#[derive(Debug, Clone, Copy)]
pub struct MaxStreamDataFrame {
    pub stream_id: StreamId,
    /// Maximum data bytes that can be sent on stream
    pub maximum_stream_data: VarInt,
}

/// MAX_STREAMS Frame (RFC 9000 Section 19.11)
#[derive(Debug, Clone, Copy)]
pub struct MaxStreamsFrame {
    /// Maximum number of streams that can be opened
    pub maximum_streams: VarInt,
}

/// DATA_BLOCKED Frame (RFC 9000 Section 19.12)
#[derive(Debug, Clone, Copy)]
pub struct DataBlockedFrame {
    /// Connection-level data limit that is causing blocking
    pub maximum_data: VarInt,
}

/// STREAM_DATA_BLOCKED Frame (RFC 9000 Section 19.13)
#[derive(Debug, Clone, Copy)]
pub struct StreamDataBlockedFrame {
    pub stream_id: StreamId,
    /// Stream-level data limit that is causing blocking
    pub maximum_stream_data: VarInt,
}

/// STREAMS_BLOCKED Frame (RFC 9000 Section 19.14)
#[derive(Debug, Clone, Copy)]
pub struct StreamsBlockedFrame {
    /// Stream limit that is causing blocking
    pub maximum_streams: VarInt,
}

/// NEW_CONNECTION_ID Frame (RFC 9000 Section 19.15)
#[derive(Debug, Clone)]
pub struct NewConnectionIdFrame<'a> {
    /// Sequence number of this Connection ID
    pub sequence_number: VarInt,

    /// Sequence number of CID to retire
    pub retire_prior_to: VarInt,

    /// New Connection ID (zero-copy)
    pub connection_id: &'a [u8],

    /// Stateless Reset Token for this CID
    pub stateless_reset_token: StatelessResetToken,
}

/// RETIRE_CONNECTION_ID Frame (RFC 9000 Section 19.16)
#[derive(Debug, Clone, Copy)]
pub struct RetireConnectionIdFrame {
    /// Sequence number of CID to retire
    pub sequence_number: VarInt,
}

/// PATH_CHALLENGE Frame (RFC 9000 Section 19.17)
#[derive(Debug, Clone, Copy)]
pub struct PathChallengeFrame {
    /// 8-byte random data for path validation
    pub data: [u8; 8],
}

/// PATH_RESPONSE Frame (RFC 9000 Section 19.18)
#[derive(Debug, Clone, Copy)]
pub struct PathResponseFrame {
    /// Echo of PATH_CHALLENGE data
    pub data: [u8; 8],
}

/// CONNECTION_CLOSE Frame for Transport Errors (RFC 9000 Section 19.19)
#[derive(Debug, Clone)]
pub struct ConnectionCloseTransportFrame<'a> {
    /// Transport error code
    pub error_code: TransportError,

    /// Frame type that triggered the error (or 0)
    pub frame_type: VarInt,

    /// Human-readable error reason (zero-copy)
    pub reason_phrase: &'a [u8],
}

/// CONNECTION_CLOSE Frame for Application Errors (RFC 9000 Section 19.19)
#[derive(Debug, Clone)]
pub struct ConnectionCloseApplicationFrame<'a> {
    /// Application error code
    pub error_code: ApplicationError,

    /// Human-readable error reason (zero-copy)
    pub reason_phrase: &'a [u8],
}
