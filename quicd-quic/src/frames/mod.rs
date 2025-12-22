//! # QUIC Frames (RFC 9000 Section 12.4)
//!
//! This module defines all QUIC frame types and provides **zero-copy parsing**
//! for reading frames from incoming packets.
//!
//! ## Frame Types
//!
//! RFC 9000 defines the following frame types:
//!
//! | Type | Name                 | Ack-Eliciting | Purpose                          |
//! |------|---------------------|---------------|----------------------------------|
//! | 0x00 | PADDING             | No            | Padding to increase packet size  |
//! | 0x01 | PING                | Yes           | Keep-alive / RTT measurement     |
//! | 0x02-0x03 | ACK             | No            | Acknowledge received packets     |
//! | 0x04 | RESET_STREAM        | Yes           | Abruptly terminate a stream      |
//! | 0x05 | STOP_SENDING        | Yes           | Request peer to stop sending     |
//! | 0x06 | CRYPTO              | Yes           | TLS handshake data               |
//! | 0x07 | NEW_TOKEN           | Yes           | Address validation token         |
//! | 0x08-0x0f | STREAM          | Yes           | Stream data                      |
//! | 0x10 | MAX_DATA            | Yes           | Connection flow control          |
//! | 0x11 | MAX_STREAM_DATA     | Yes           | Stream flow control              |
//! | 0x12-0x13 | MAX_STREAMS     | Yes           | Stream limit increase            |
//! | 0x14 | DATA_BLOCKED        | Yes           | Connection blocked by flow ctrl  |
//! | 0x15 | STREAM_DATA_BLOCKED | Yes           | Stream blocked by flow ctrl      |
//! | 0x16-0x17 | STREAMS_BLOCKED | Yes           | Stream limit reached             |
//! | 0x18 | NEW_CONNECTION_ID   | Yes           | Provide new connection ID        |
//! | 0x19 | RETIRE_CONNECTION_ID| Yes           | Retire old connection ID         |
//! | 0x1a | PATH_CHALLENGE      | Yes           | Path validation                  |
//! | 0x1b | PATH_RESPONSE       | Yes           | Path validation response         |
//! | 0x1c-0x1d | CONNECTION_CLOSE| No            | Connection termination           |
//! | 0x1e | HANDSHAKE_DONE      | Yes           | Handshake confirmed              |
//!
//! ## Zero-Copy Parsing
//!
//! All frame parsing operates on borrowed slices (`&'a [u8]`), returning structures
//! that reference the original packet data. This avoids copying payload data.

use core::fmt;

pub mod parse;
pub mod types;

// ============================================================================
// Core Types
// ============================================================================

/// Stream ID (RFC 9000 Section 2.1)
///
/// Stream IDs are 62-bit integers that identify bidirectional or unidirectional
/// streams. The two least significant bits encode the stream type and initiator:
///
/// ```text
/// Bits 0-1:
///   0x0: Client-Initiated, Bidirectional
///   0x1: Server-Initiated, Bidirectional
///   0x2: Client-Initiated, Unidirectional
///   0x3: Server-Initiated, Unidirectional
/// ```
pub type StreamId = u64;

/// Variable-Length Integer (RFC 9000 Section 16)
///
/// QUIC uses variable-length encoding for integers (1, 2, 4, or 8 bytes).
/// The two most significant bits of the first byte indicate the length.
pub type VarInt = u64;

// ============================================================================
// Frame Enum (All Frame Types)
// ============================================================================

/// QUIC Frame (RFC 9000 Section 12.4)
///
/// This enum represents all possible QUIC frame types. Frames use lifetime `'a`
/// to borrow data from the original packet buffer (zero-copy).
///
/// **Parsing**: Use `Frame::parse()` to decode from a byte slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frame<'a> {
    /// PADDING frame (0x00) - RFC 9000 Section 19.1
    Padding {
        /// Number of consecutive PADDING frames
        length: usize,
    },
    
    /// PING frame (0x01) - RFC 9000 Section 19.2
    ///
    /// Used for keep-alive and RTT measurement. Has no payload.
    Ping,
    
    /// ACK frame (0x02-0x03) - RFC 9000 Section 19.3
    Ack {
        /// Largest packet number being acknowledged
        largest_acked: u64,
        
        /// ACK delay in microseconds (multiplied by ack_delay_exponent)
        ack_delay: u64,
        
        /// Ranges of acknowledged packet numbers
        ack_ranges: &'a [u8], // Zero-copy reference to encoded ranges
        
        /// ECN counts (only present for ACK frame type 0x03)
        ecn_counts: Option<EcnCounts>,
    },
    
    /// RESET_STREAM frame (0x04) - RFC 9000 Section 19.4
    ResetStream {
        stream_id: StreamId,
        application_error_code: u64,
        final_size: u64,
    },
    
    /// STOP_SENDING frame (0x05) - RFC 9000 Section 19.5
    StopSending {
        stream_id: StreamId,
        application_error_code: u64,
    },
    
    /// CRYPTO frame (0x06) - RFC 9000 Section 19.6
    ///
    /// Carries TLS handshake data. Similar to STREAM frames but for the crypto stream.
    Crypto {
        offset: u64,
        data: &'a [u8], // Zero-copy reference to crypto data
    },
    
    /// NEW_TOKEN frame (0x07) - RFC 9000 Section 19.7
    ///
    /// Server provides a token for future address validation.
    NewToken {
        token: &'a [u8], // Zero-copy reference to token
    },
    
    /// STREAM frame (0x08-0x0f) - RFC 9000 Section 19.8
    ///
    /// The frame type byte encodes flags:
    /// - Bit 0 (FIN): Final data on this stream
    /// - Bit 1 (LEN): Length field present
    /// - Bit 2 (OFF): Offset field present
    Stream {
        stream_id: StreamId,
        offset: u64,
        data: &'a [u8], // Zero-copy reference to stream data
        fin: bool,      // FIN bit: last data on stream
    },
    
    /// MAX_DATA frame (0x10) - RFC 9000 Section 19.9
    ///
    /// Connection-level flow control limit.
    MaxData {
        maximum_data: u64,
    },
    
    /// MAX_STREAM_DATA frame (0x11) - RFC 9000 Section 19.10
    ///
    /// Stream-level flow control limit.
    MaxStreamData {
        stream_id: StreamId,
        maximum_stream_data: u64,
    },
    
    /// MAX_STREAMS frame (0x12-0x13) - RFC 9000 Section 19.11
    ///
    /// Increases the limit on concurrent streams.
    /// Type 0x12 is for bidirectional streams, 0x13 for unidirectional.
    MaxStreams {
        maximum_streams: u64,
        bidirectional: bool,
    },
    
    /// DATA_BLOCKED frame (0x14) - RFC 9000 Section 19.12
    DataBlocked {
        maximum_data: u64,
    },
    
    /// STREAM_DATA_BLOCKED frame (0x15) - RFC 9000 Section 19.13
    StreamDataBlocked {
        stream_id: StreamId,
        maximum_stream_data: u64,
    },
    
    /// STREAMS_BLOCKED frame (0x16-0x17) - RFC 9000 Section 19.14
    StreamsBlocked {
        maximum_streams: u64,
        bidirectional: bool,
    },
    
    /// NEW_CONNECTION_ID frame (0x18) - RFC 9000 Section 19.15
    NewConnectionId {
        sequence_number: u64,
        retire_prior_to: u64,
        connection_id: &'a [u8], // Zero-copy reference to connection ID
        stateless_reset_token: [u8; 16],
    },
    
    /// RETIRE_CONNECTION_ID frame (0x19) - RFC 9000 Section 19.16
    RetireConnectionId {
        sequence_number: u64,
    },
    
    /// PATH_CHALLENGE frame (0x1a) - RFC 9000 Section 19.17
    PathChallenge {
        data: [u8; 8],
    },
    
    /// PATH_RESPONSE frame (0x1b) - RFC 9000 Section 19.18
    PathResponse {
        data: [u8; 8],
    },
    
    /// CONNECTION_CLOSE frame (0x1c-0x1d) - RFC 9000 Section 19.19
    ///
    /// Type 0x1c: Transport error (QUIC layer)
    /// Type 0x1d: Application error (application layer)
    ConnectionClose {
        error_code: u64,
        frame_type: Option<u64>, // Only present for transport errors
        reason: &'a [u8],         // Zero-copy reference to reason phrase
    },
    
    /// HANDSHAKE_DONE frame (0x1e) - RFC 9000 Section 19.20
    ///
    /// Server signals that the handshake is confirmed.
    HandshakeDone,
}

/// ECN Counts (RFC 9000 Section 19.3.2)
///
/// Explicit Congestion Notification counts reported in ACK frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EcnCounts {
    pub ect0_count: u64, // ECT(0) marked packets
    pub ect1_count: u64, // ECT(1) marked packets
    pub ce_count: u64,   // CE (Congestion Experienced) marked packets
}

// ============================================================================
// Frame Properties
// ============================================================================

impl<'a> Frame<'a> {
    /// Check if this frame is ack-eliciting (RFC 9002 Section 2)
    ///
    /// Ack-eliciting frames require the peer to send an ACK. Frames that are
    /// NOT ack-eliciting: PADDING, ACK, CONNECTION_CLOSE.
    pub fn is_ack_eliciting(&self) -> bool {
        !matches!(self, Frame::Padding { .. } | Frame::Ack { .. } | Frame::ConnectionClose { .. })
    }
    
    /// Get the frame type ID (RFC 9000 Section 12.4)
    pub fn frame_type(&self) -> u64 {
        match self {
            Frame::Padding { .. } => 0x00,
            Frame::Ping => 0x01,
            Frame::Ack { ecn_counts: None, .. } => 0x02,
            Frame::Ack { ecn_counts: Some(_), .. } => 0x03,
            Frame::ResetStream { .. } => 0x04,
            Frame::StopSending { .. } => 0x05,
            Frame::Crypto { .. } => 0x06,
            Frame::NewToken { .. } => 0x07,
            Frame::Stream { stream_id, offset, data, fin } => {
                let mut ty = 0x08;
                if *fin { ty |= 0x01; }
                if !data.is_empty() { ty |= 0x02; } // LEN bit
                if *offset > 0 { ty |= 0x04; } // OFF bit
                ty
            }
            Frame::MaxData { .. } => 0x10,
            Frame::MaxStreamData { .. } => 0x11,
            Frame::MaxStreams { bidirectional: true, .. } => 0x12,
            Frame::MaxStreams { bidirectional: false, .. } => 0x13,
            Frame::DataBlocked { .. } => 0x14,
            Frame::StreamDataBlocked { .. } => 0x15,
            Frame::StreamsBlocked { bidirectional: true, .. } => 0x16,
            Frame::StreamsBlocked { bidirectional: false, .. } => 0x17,
            Frame::NewConnectionId { .. } => 0x18,
            Frame::RetireConnectionId { .. } => 0x19,
            Frame::PathChallenge { .. } => 0x1a,
            Frame::PathResponse { .. } => 0x1b,
            Frame::ConnectionClose { frame_type: Some(_), .. } => 0x1c,
            Frame::ConnectionClose { frame_type: None, .. } => 0x1d,
            Frame::HandshakeDone => 0x1e,
        }
    }
}

// ============================================================================
// Stream ID Helpers
// ============================================================================

/// Stream ID type bits (RFC 9000 Section 2.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamType {
    ClientBidirectional,
    ServerBidirectional,
    ClientUnidirectional,
    ServerUnidirectional,
}

impl StreamType {
    /// Extract stream type from stream ID
    pub fn from_stream_id(id: StreamId) -> Self {
        match id & 0x03 {
            0x0 => StreamType::ClientBidirectional,
            0x1 => StreamType::ServerBidirectional,
            0x2 => StreamType::ClientUnidirectional,
            0x3 => StreamType::ServerUnidirectional,
            _ => unreachable!(),
        }
    }
    
    /// Check if stream is bidirectional
    pub fn is_bidirectional(&self) -> bool {
        matches!(self, StreamType::ClientBidirectional | StreamType::ServerBidirectional)
    }
    
    /// Check if stream is unidirectional
    pub fn is_unidirectional(&self) -> bool {
        !self.is_bidirectional()
    }
    
    /// Check if stream is client-initiated
    pub fn is_client_initiated(&self) -> bool {
        matches!(self, StreamType::ClientBidirectional | StreamType::ClientUnidirectional)
    }
    
    /// Check if stream is server-initiated
    pub fn is_server_initiated(&self) -> bool {
        !self.is_client_initiated()
    }
}

// ============================================================================
// Display Implementation
// ============================================================================

impl<'a> fmt::Display for Frame<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Frame::Padding { length } => write!(f, "PADDING({})", length),
            Frame::Ping => write!(f, "PING"),
            Frame::Ack { largest_acked, .. } => write!(f, "ACK(largest={})", largest_acked),
            Frame::ResetStream { stream_id, .. } => write!(f, "RESET_STREAM({})", stream_id),
            Frame::StopSending { stream_id, .. } => write!(f, "STOP_SENDING({})", stream_id),
            Frame::Crypto { offset, data } => write!(f, "CRYPTO(off={}, len={})", offset, data.len()),
            Frame::NewToken { token } => write!(f, "NEW_TOKEN(len={})", token.len()),
            Frame::Stream { stream_id, offset, data, fin } => {
                write!(f, "STREAM(id={}, off={}, len={}, fin={})", stream_id, offset, data.len(), fin)
            }
            Frame::MaxData { maximum_data } => write!(f, "MAX_DATA({})", maximum_data),
            Frame::MaxStreamData { stream_id, maximum_stream_data } => {
                write!(f, "MAX_STREAM_DATA(id={}, max={})", stream_id, maximum_stream_data)
            }
            Frame::MaxStreams { maximum_streams, bidirectional } => {
                write!(f, "MAX_STREAMS(max={}, bidi={})", maximum_streams, bidirectional)
            }
            Frame::DataBlocked { maximum_data } => write!(f, "DATA_BLOCKED({})", maximum_data),
            Frame::StreamDataBlocked { stream_id, .. } => write!(f, "STREAM_DATA_BLOCKED({})", stream_id),
            Frame::StreamsBlocked { maximum_streams, bidirectional } => {
                write!(f, "STREAMS_BLOCKED(max={}, bidi={})", maximum_streams, bidirectional)
            }
            Frame::NewConnectionId { sequence_number, .. } => {
                write!(f, "NEW_CONNECTION_ID(seq={})", sequence_number)
            }
            Frame::RetireConnectionId { sequence_number } => {
                write!(f, "RETIRE_CONNECTION_ID({})", sequence_number)
            }
            Frame::PathChallenge { .. } => write!(f, "PATH_CHALLENGE"),
            Frame::PathResponse { .. } => write!(f, "PATH_RESPONSE"),
            Frame::ConnectionClose { error_code, .. } => write!(f, "CONNECTION_CLOSE(code={})", error_code),
            Frame::HandshakeDone => write!(f, "HANDSHAKE_DONE"),
        }
    }
}
