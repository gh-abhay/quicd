//! # Stream Management and State Machine (RFC 9000 Section 2-3)
//!
//! This module defines traits and types for QUIC stream lifecycle management.
//!
//! ## Stream States (RFC 9000 Section 3)
//!
//! Bidirectional streams have separate send/receive state machines:
//! - **Send States**: Ready → Send → Data Sent → Reset Sent/Reset Recvd
//! - **Receive States**: Recv → Size Known → Data Recvd → Data Read → Reset Recvd
//!
//! Unidirectional streams only have one direction active.
//!
//! ## Zero-Copy Data Handling
//!
//! Stream data is processed using references to avoid copying:
//! - Incoming STREAM frames reference the packet buffer (lifetime 'a)
//! - Reassembly buffer stores out-of-order data as Bytes (reference-counted)
//! - Application reads use cursors over the reassembly buffer

extern crate alloc;

use crate::types::*;
use crate::error::*;
use bytes::{Bytes, BytesMut};

/// Stream Send State (RFC 9000 Section 3.1)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendStreamState {
    /// Ready - Stream created but no data sent
    Ready,
    
    /// Send - Sending data
    Send,
    
    /// Data Sent - All data sent, waiting for acknowledgment
    DataSent,
    
    /// Data Recvd - All data acknowledged
    DataRecvd,
    
    /// Reset Sent - RESET_STREAM sent
    ResetSent,
    
    /// Reset Recvd - RESET_STREAM acknowledged
    ResetRecvd,
}

/// Stream Receive State (RFC 9000 Section 3.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvStreamState {
    /// Recv - Receiving data
    Recv,
    
    /// Size Known - Final size known (FIN received)
    SizeKnown,
    
    /// Data Recvd - All data received
    DataRecvd,
    
    /// Data Read - All data delivered to application
    DataRead,
    
    /// Reset Recvd - RESET_STREAM received
    ResetRecvd,
}

/// Bidirectional Stream State
///
/// Combines send and receive state machines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BidiStreamState {
    /// Send direction state
    pub send: SendStreamState,
    
    /// Receive direction state
    pub recv: RecvStreamState,
}

/// Stream Priority (extensible)
///
/// Placeholder for stream prioritization mechanisms.
/// RFC 9000 does not mandate a specific prioritization scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct StreamPriority {
    /// Urgency level (0 = highest priority, 7 = lowest)
    pub urgency: u8,
    
    /// Incremental flag (for HTTP/3 prioritization)
    pub incremental: bool,
}

impl Default for StreamPriority {
    fn default() -> Self {
        Self {
            urgency: 3,
            incremental: false,
        }
    }
}

/// Stream Data Chunk
///
/// Represents a contiguous chunk of stream data with offset.
#[derive(Debug, Clone)]
pub struct StreamDataChunk {
    /// Offset in the stream
    pub offset: StreamOffset,
    
    /// Data (reference-counted, zero-copy)
    pub data: Bytes,
    
    /// Whether this is the final chunk (FIN)
    pub fin: bool,
}

/// Stream Reassembly Buffer Trait
///
/// Handles out-of-order stream data reception and reassembly.
/// This is critical for efficient zero-copy stream data handling.
pub trait StreamReassemblyBuffer: Send {
    /// Insert a stream data chunk
    ///
    /// Handles out-of-order data by buffering until contiguous.
    /// Returns the new contiguous read offset after insertion.
    fn insert(&mut self, chunk: StreamDataChunk) -> Result<StreamOffset>;
    
    /// Read contiguous data from the buffer
    ///
    /// Returns data starting from the read offset, up to `max_len` bytes.
    /// Advances the read offset by the amount read.
    ///
    /// This is zero-copy: returns Bytes references to the internal buffer.
    fn read(&mut self, max_len: usize) -> Option<Bytes>;
    
    /// Peek at contiguous data without advancing read offset
    fn peek(&self, max_len: usize) -> Option<Bytes>;
    
    /// Get the current read offset
    fn read_offset(&self) -> StreamOffset;
    
    /// Get the final size (if known)
    fn final_size(&self) -> Option<StreamOffset>;
    
    /// Set the final size (when FIN is received)
    fn set_final_size(&mut self, size: StreamOffset) -> Result<()>;
    
    /// Check if all data has been received
    fn is_complete(&self) -> bool;
    
    /// Get the number of bytes buffered (not yet read)
    fn buffered_bytes(&self) -> usize;
}

/// Stream Send Buffer Trait
///
/// Manages outgoing stream data with retransmission support.
pub trait StreamSendBuffer: Send {
    /// Write data to the send buffer
    ///
    /// Returns the offset where data was written.
    fn write(&mut self, data: Bytes) -> Result<StreamOffset>;
    
    /// Get data to send in the next packet
    ///
    /// Returns (offset, data, fin) for the next chunk to transmit.
    /// The `max_len` parameter limits the chunk size.
    ///
    /// This is zero-copy: returns Bytes references.
    fn get_data_to_send(&mut self, max_len: usize) -> Option<(StreamOffset, Bytes, bool)>;
    
    /// Mark a range as acknowledged
    ///
    /// Called when a STREAM frame is acknowledged.
    fn on_data_acked(&mut self, offset: StreamOffset, length: usize);
    
    /// Mark a range as lost
    ///
    /// Called when a packet containing this range is lost.
    fn on_data_lost(&mut self, offset: StreamOffset, length: usize);
    
    /// Get the current write offset
    fn write_offset(&self) -> StreamOffset;
    
    /// Get the number of bytes in flight (sent but not acked)
    fn bytes_in_flight(&self) -> usize;
    
    /// Check if all data has been sent
    fn is_complete(&self) -> bool;
    
    /// Finish the stream (set FIN)
    fn finish(&mut self) -> Result<()>;
}

/// Stream Controller Trait
///
/// Manages the lifecycle and state transitions of a single stream.
/// This is the core abstraction for stream handling.
pub trait StreamController: Send {
    /// Get the stream ID
    fn stream_id(&self) -> StreamId;
    
    /// Get the stream type
    fn stream_type(&self) -> StreamType;
    
    /// Get send state (if applicable)
    fn send_state(&self) -> Option<SendStreamState>;
    
    /// Get receive state (if applicable)
    fn recv_state(&self) -> Option<RecvStreamState>;
    
    /// Process a received STREAM frame
    ///
    /// Updates the receive buffer and state machine.
    fn on_stream_frame(&mut self, offset: StreamOffset, data: Bytes, fin: bool) -> Result<()>;
    
    /// Process a received RESET_STREAM frame
    fn on_reset_stream(&mut self, error_code: VarInt, final_size: VarInt) -> Result<()>;
    
    /// Process a received STOP_SENDING frame
    fn on_stop_sending(&mut self, error_code: VarInt) -> Result<()>;
    
    /// Process a received MAX_STREAM_DATA frame
    fn on_max_stream_data(&mut self, max_data: VarInt) -> Result<()>;
    
    /// Write data to the stream
    ///
    /// Application-facing write method. Data is buffered for transmission.
    fn write(&mut self, data: Bytes) -> Result<usize>;
    
    /// Finish the stream (send FIN)
    fn finish(&mut self) -> Result<()>;
    
    /// Reset the stream (send RESET_STREAM)
    fn reset(&mut self, error_code: VarInt) -> Result<()>;
    
    /// Read data from the stream
    ///
    /// Application-facing read method. Returns contiguous received data.
    fn read(&mut self, max_len: usize) -> Result<Option<Bytes>>;
    
    /// Get the current flow control limit
    fn send_capacity(&self) -> u64;
    
    /// Check if the stream can send data
    fn can_send(&self) -> bool;
    
    /// Check if the stream has data ready to read
    fn has_data_to_read(&self) -> bool;
    
    /// Check if the stream is finished
    fn is_finished(&self) -> bool;
}

/// Stream Map Trait
///
/// Manages the collection of all streams in a connection.
pub trait StreamMap: Send {
    /// Create a new stream
    ///
    /// Returns the assigned stream ID.
    fn create_stream(
        &mut self,
        stream_type: StreamType,
    ) -> Result<StreamId>;
    
    /// Get a stream controller by ID
    fn get_stream(&mut self, stream_id: StreamId) -> Option<&mut dyn StreamController>;
    
    /// Remove a stream (when fully closed)
    fn remove_stream(&mut self, stream_id: StreamId);
    
    /// Get all active stream IDs
    fn active_streams(&self) -> alloc::vec::Vec<StreamId>;
    
    /// Get the next stream ID for a given type
    fn next_stream_id(&self, stream_type: StreamType) -> StreamId;
    
    /// Check if a stream ID is valid to receive
    ///
    /// Validates against max_streams limits.
    fn is_valid_incoming_stream(&self, stream_id: StreamId) -> bool;
    
    /// Get count of active streams by type
    fn stream_count(&self, stream_type: StreamType) -> usize;
}

/// Stream Events
///
/// Events emitted by the stream layer for the connection to handle.
#[derive(Debug, Clone)]
pub enum StreamEvent {
    /// New stream created by peer
    StreamOpened {
        stream_id: StreamId,
        stream_type: StreamType,
    },
    
    /// Stream has data ready to read
    DataAvailable {
        stream_id: StreamId,
    },
    
    /// Stream finished (FIN received)
    StreamFinished {
        stream_id: StreamId,
    },
    
    /// Stream reset by peer
    StreamReset {
        stream_id: StreamId,
        error_code: VarInt,
        final_size: VarInt,
    },
    
    /// Peer requested stop sending
    StopSending {
        stream_id: StreamId,
        error_code: VarInt,
    },
    
    /// Stream flow control limit reached
    StreamBlocked {
        stream_id: StreamId,
        limit: VarInt,
    },
}

/// Stream Limits Configuration
///
/// Enforces RFC 9000 stream limits.
#[derive(Debug, Clone, Copy)]
pub struct StreamLimits {
    /// Maximum concurrent bidirectional streams (local)
    pub max_streams_bidi_local: u64,
    
    /// Maximum concurrent unidirectional streams (local)
    pub max_streams_uni_local: u64,
    
    /// Maximum concurrent bidirectional streams (remote)
    pub max_streams_bidi_remote: u64,
    
    /// Maximum concurrent unidirectional streams (remote)
    pub max_streams_uni_remote: u64,
    
    /// Maximum stream data (per stream, initial)
    pub max_stream_data_bidi_local: u64,
    pub max_stream_data_bidi_remote: u64,
    pub max_stream_data_uni: u64,
}

impl Default for StreamLimits {
    fn default() -> Self {
        Self {
            max_streams_bidi_local: DEFAULT_MAX_STREAMS_BIDI,
            max_streams_uni_local: DEFAULT_MAX_STREAMS_UNI,
            max_streams_bidi_remote: DEFAULT_MAX_STREAMS_BIDI,
            max_streams_uni_remote: DEFAULT_MAX_STREAMS_UNI,
            max_stream_data_bidi_local: DEFAULT_INITIAL_MAX_STREAM_DATA_BIDI,
            max_stream_data_bidi_remote: DEFAULT_INITIAL_MAX_STREAM_DATA_BIDI,
            max_stream_data_uni: DEFAULT_INITIAL_MAX_STREAM_DATA_UNI,
        }
    }
}
