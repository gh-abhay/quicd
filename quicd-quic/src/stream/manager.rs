//! # Stream Management (RFC 9000 Sections 2, 3, 4)
//!
//! This module defines the stream state machine and management interfaces.
//! QUIC streams provide reliable, in-order delivery of data.
//!
//! ## Stream Types:
//! - **Bidirectional**: Both endpoints can send data
//! - **Unidirectional**: Only initiator can send data
//!
//! ## Stream States (RFC 9000 Section 3):
//! Sending side: Idle → Open → Send → Data Sent → Reset Sent → Reset Recvd
//! Receiving side: Idle → Recv → Size Known → Data Recvd → Data Read → Reset Recvd

#![forbid(unsafe_code)]

use crate::error::{Error, Result};
use crate::types::{ErrorCode, Side, StreamDirection, StreamId, StreamInitiator, StreamOffset, VarInt};
use bytes::{Bytes, BytesMut};

/// Maximum Stream Data (Flow Control Limit)
///
/// Used to advertise flow control windows to the peer.
pub type MaxStreamData = u64;

/// Stream Send State (RFC 9000 Section 3.1)
///
/// State machine for the sending side of a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamSendState {
    /// No frames sent yet (initial state for sender-initiated streams)
    Idle,

    /// Stream is open, ready to send data
    Ready,

    /// All data sent, waiting for acknowledgment
    Send,

    /// All data acknowledged by peer
    DataSent,

    /// RESET_STREAM sent
    ResetSent,

    /// RESET_STREAM acknowledged
    ResetRecvd,
}

/// Stream Receive State (RFC 9000 Section 3.2)
///
/// State machine for the receiving side of a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamRecvState {
    /// No frames received yet (initial state for peer-initiated streams)
    Idle,

    /// Stream is open, receiving data
    Recv,

    /// Received FIN, know final size, may have gaps
    SizeKnown,

    /// All data received, no gaps
    DataRecvd,

    /// All data read by application
    DataRead,

    /// RESET_STREAM received
    ResetRecvd,
}

/// Bidirectional Stream State (RFC 9000 Section 3.3)
///
/// Combines send and receive states for bidirectional streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BidiStreamState {
    /// Sending side state
    pub send: StreamSendState,

    /// Receiving side state
    pub recv: StreamRecvState,
}

/// Unidirectional Stream State (RFC 9000 Section 3.4)
///
/// For unidirectional streams, only one side exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UniStreamState {
    /// Sending-only (for locally-initiated unidirectional streams)
    Send(StreamSendState),

    /// Receiving-only (for peer-initiated unidirectional streams)
    Recv(StreamRecvState),
}

/// Stream State (unified)
///
/// Discriminated union for bidirectional and unidirectional streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Bidirectional stream
    Bidi(BidiStreamState),

    /// Unidirectional stream
    Uni(UniStreamState),
}

/// Stream Priority (RFC 9218 - Extensible Priorities)
///
/// Note: RFC 9218 defines HTTP/3-specific priorities.
/// This is a placeholder for generic stream prioritization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamPriority {
    /// Urgency level (0-7, lower = higher priority)
    pub urgency: u8,

    /// Incremental flag
    pub incremental: bool,
}

impl Default for StreamPriority {
    fn default() -> Self {
        Self {
            urgency: 3, // Default urgency per RFC 9218
            incremental: false,
        }
    }
}

/// Stream Data Chunk (Zero-Copy)
///
/// Represents a contiguous chunk of stream data with offset.
#[derive(Debug, Clone)]
pub struct StreamChunk {
    /// Byte offset in stream
    pub offset: StreamOffset,

    /// Data bytes (reference-counted, zero-copy)
    pub data: Bytes,

    /// True if this is the final chunk (FIN flag)
    pub fin: bool,
}

/// Stream Read Result
///
/// Result of reading data from a stream.
#[derive(Debug)]
pub enum StreamReadResult {
    /// Data available (offset, bytes, fin)
    Data {
        offset: StreamOffset,
        data: Bytes,
        fin: bool,
    },

    /// Stream was reset by peer
    Reset { error_code: ErrorCode },

    /// No data available (would block)
    WouldBlock,

    /// Stream closed gracefully
    Finished,
}

/// Stream Write Result
///
/// Result of writing data to a stream.
#[derive(Debug, Clone, Copy)]
pub enum StreamWriteResult {
    /// Bytes accepted (may be less than requested due to flow control)
    Written { bytes: usize },

    /// Blocked by flow control (buffer full)
    Blocked,

    /// Stream closed, cannot write
    Closed,
}

/// Stream Controller Trait
///
/// Manages the lifecycle and data flow of a single stream.
///
/// ## Design Notes:
/// - Zero-copy: Uses `Bytes` for all data operations
/// - Visitor pattern: Allows reading without copying into intermediate buffer
/// - Flow control: Enforces stream and connection-level limits
pub trait StreamController {
    /// Get the stream ID
    fn stream_id(&self) -> StreamId;

    /// Get the current stream state
    fn state(&self) -> StreamState;

    /// Write data to the stream's send buffer.
    ///
    /// # Flow Control
    /// May accept fewer bytes than provided if flow control limit reached.
    ///
    /// # Errors
    /// Returns Error::StreamStateError if stream is not in a sendable state.
    fn write(&mut self, data: Bytes, fin: bool) -> Result<StreamWriteResult>;

    /// Read data from the stream's receive buffer.
    ///
    /// Returns the next available contiguous chunk of data.
    /// Application must call this repeatedly until WouldBlock or Finished.
    fn read(&mut self) -> Result<StreamReadResult>;

    /// Peek at available data without consuming it.
    ///
    /// Useful for parsers that need to look ahead.
    fn peek(&self) -> Result<StreamReadResult>;

    /// Reset the sending side of the stream.
    ///
    /// # RFC 9000 Section 3.1
    /// Sends RESET_STREAM frame to peer, discarding unsent data.
    fn reset_send(&mut self, error_code: ErrorCode) -> Result<()>;

    /// Stop the receiving side of the stream.
    ///
    /// # RFC 9000 Section 3.5
    /// Sends STOP_SENDING frame to peer, discarding unreceived data.
    fn stop_recv(&mut self, error_code: ErrorCode) -> Result<()>;

    /// Get the current send offset (next byte to send)
    fn send_offset(&self) -> StreamOffset;

    /// Get the current receive offset (next byte expected)
    fn recv_offset(&self) -> StreamOffset;

    /// Get the flow control limit for this stream
    fn max_stream_data(&self) -> MaxStreamData;

    /// Update the flow control limit (from MAX_STREAM_DATA frame)
    fn update_max_stream_data(&mut self, limit: MaxStreamData);

    /// Check if stream has data ready to send
    fn has_data_to_send(&self) -> bool;

    /// Check if stream can accept more data to write
    fn can_write(&self) -> bool;
}

/// Stream Manager Trait
///
/// Manages the collection of all streams on a connection.
///
/// ## Design Notes:
/// - Enforces stream limits (MAX_STREAMS)
/// - Tracks stream state across all streams
/// - Provides iterator/visitor access to avoid copying stream metadata
pub trait StreamManager {
    /// Open a new stream (bidirectional or unidirectional).
    ///
    /// # Errors
    /// Returns Error::StreamLimitError if stream limit exceeded.
    fn open_stream(&mut self, direction: StreamDirection) -> Result<StreamId>;

    /// Get a stream controller for an existing stream.
    ///
    /// Returns None if stream doesn't exist.
    fn get_stream(&mut self, stream_id: StreamId) -> Option<&mut dyn StreamController>;

    /// Accept a new peer-initiated stream.
    ///
    /// Returns None if no streams are ready to accept.
    fn accept_stream(&mut self, direction: StreamDirection) -> Option<StreamId>;

    /// Handle incoming STREAM frame.
    ///
    /// Creates stream if it doesn't exist (peer-initiated).
    fn handle_stream_frame(
        &mut self,
        stream_id: StreamId,
        offset: StreamOffset,
        data: Bytes,
        fin: bool,
    ) -> Result<()>;

    /// Handle incoming MAX_STREAM_DATA frame.
    fn handle_max_stream_data(&mut self, stream_id: StreamId, limit: MaxStreamData) -> Result<()>;

    /// Handle incoming RESET_STREAM frame.
    fn handle_reset_stream(
        &mut self,
        stream_id: StreamId,
        error_code: ErrorCode,
        final_size: VarInt,
    ) -> Result<()>;

    /// Handle incoming STOP_SENDING frame.
    fn handle_stop_sending(&mut self, stream_id: StreamId, error_code: ErrorCode) -> Result<()>;

    /// Update stream limits (from MAX_STREAMS frame).
    fn update_max_streams(&mut self, limit: VarInt, bidirectional: bool);

    /// Get current stream count.
    fn stream_count(&self, direction: StreamDirection) -> usize;

    /// Visit all streams with pending data.
    ///
    /// Visitor pattern avoids allocating a Vec of stream IDs.
    fn visit_writable_streams<F>(&mut self, visitor: F)
    where
        F: FnMut(StreamId, &mut dyn StreamController);

    /// Visit all streams with received data ready to read.
    fn visit_readable_streams<F>(&mut self, visitor: F)
    where
        F: FnMut(StreamId, &mut dyn StreamController);

    /// Check if any streams are writable
    fn has_writable_streams(&self) -> bool;

    /// Check if any streams are readable
    fn has_readable_streams(&self) -> bool;
}

/// Stream Reassembly Buffer
///
/// Handles out-of-order stream data reception.
///
/// ## RFC 9000 Section 2.2:
/// Stream data may arrive out of order. The receiver must buffer
/// data until all prior data has been received.
pub trait StreamReassembler {
    /// Insert a chunk of data at a specific offset.
    ///
    /// May create gaps if data arrives out of order.
    fn insert(&mut self, offset: StreamOffset, data: Bytes) -> Result<()>;

    /// Read the next contiguous chunk of data.
    ///
    /// Returns None if there's a gap at the current offset.
    fn read_next(&mut self) -> Option<Bytes>;

    /// Check if data is available at the current offset
    fn has_contiguous_data(&self) -> bool;

    /// Get the current read offset
    fn read_offset(&self) -> StreamOffset;

    /// Set the final size (from FIN flag).
    ///
    /// Returns Error::FinalSizeError if conflicts with previously received data.
    fn set_final_size(&mut self, size: StreamOffset) -> Result<()>;

    /// Check if all data up to final size has been received
    fn is_complete(&self) -> bool;
}
