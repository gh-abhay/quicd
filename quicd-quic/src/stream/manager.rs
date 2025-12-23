//! # Stream State Machine and Manager (RFC 9000 Section 3)
//!
//! Manages stream lifecycles and state transitions.

#![forbid(unsafe_code)]

use crate::error::{Error, Result, TransportError};
use crate::types::{stream_id_helpers, Side, StreamDirection, StreamId, StreamInitiator, StreamOffset};
use bytes::Bytes;

/// Stream State (RFC 9000 Section 3)
///
/// Bidirectional and unidirectional streams have different state machines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    // === Bidirectional Stream States ===
    /// Idle (not yet opened)
    Idle,

    /// Open (can send and receive)
    Open,

    /// Half-closed (local) - sent FIN, can still receive
    HalfClosedLocal,

    /// Half-closed (remote) - received FIN, can still send
    HalfClosedRemote,

    /// Closed - both sides finished
    Closed,

    // === Send-Only Stream States (Unidirectional, local initiated) ===
    /// Ready to send data
    Ready,

    /// Sending data
    Send,

    /// Data sent (waiting for ACK)
    DataSent,

    /// Reset sent
    ResetSent,

    /// Reset received ACK
    ResetRecvd,

    // === Receive-Only Stream States (Unidirectional, remote initiated) ===
    /// Receiving data
    Recv,

    /// Size known (FIN received)
    SizeKnown,

    /// Data ready to be read
    DataRecvd,

    /// Data read completely
    DataRead,
}

impl StreamState {
    /// Check if stream can send data
    pub fn can_send(&self) -> bool {
        matches!(
            self,
            StreamState::Open | StreamState::HalfClosedRemote | StreamState::Ready | StreamState::Send
        )
    }

    /// Check if stream can receive data
    pub fn can_receive(&self) -> bool {
        matches!(
            self,
            StreamState::Open
                | StreamState::HalfClosedLocal
                | StreamState::Recv
                | StreamState::SizeKnown
        )
    }

    /// Check if stream is finished
    pub fn is_finished(&self) -> bool {
        matches!(
            self,
            StreamState::Closed | StreamState::ResetRecvd | StreamState::DataRead
        )
    }
}

/// Stream Event (for application notification)
#[derive(Debug, Clone)]
pub enum StreamEvent {
    /// Stream opened (new stream ID)
    Opened { stream_id: StreamId },

    /// Data available to read
    DataAvailable { stream_id: StreamId, offset: StreamOffset, length: usize },

    /// Stream finished (FIN received)
    Finished { stream_id: StreamId },

    /// Stream reset by peer
    Reset {
        stream_id: StreamId,
        error_code: u64,
        final_size: u64,
    },

    /// Stream stopped by peer (STOP_SENDING)
    Stopped { stream_id: StreamId, error_code: u64 },

    /// Send side finished (all data ACKed)
    SendFinished { stream_id: StreamId },
}

/// Stream Controller Trait
///
/// Interface for reading/writing stream data with zero-copy.
///
/// **Design Rationale**: Cursor pattern - application reads/writes
/// via slices without intermediate buffering.
pub trait StreamController: Send {
    /// Open a new stream
    ///
    /// Returns new stream ID or error if limit reached.
    fn open_stream(&mut self, direction: StreamDirection) -> Result<StreamId>;

    /// Write data to stream
    ///
    /// **Zero-copy**: Accepts Bytes (reference-counted buffer).
    fn write_stream(
        &mut self,
        stream_id: StreamId,
        data: Bytes,
        fin: bool,
    ) -> Result<usize>;

    /// Read data from stream
    ///
    /// Returns zero-copy slice of available data.
    /// Advances read cursor by returned length.
    fn read_stream(&mut self, stream_id: StreamId, max_len: usize) -> Result<Option<Bytes>>;

    /// Reset stream (send RESET_STREAM)
    fn reset_stream(&mut self, stream_id: StreamId, error_code: u64) -> Result<()>;

    /// Stop receiving on stream (send STOP_SENDING)
    fn stop_sending(&mut self, stream_id: StreamId, error_code: u64) -> Result<()>;

    /// Get stream state
    fn stream_state(&self, stream_id: StreamId) -> Option<StreamState>;

    /// Check if stream exists
    fn has_stream(&self, stream_id: StreamId) -> bool;

    /// Get list of open streams
    fn open_streams(&self) -> Vec<StreamId>;
}

/// Stream Manager (Connection-Level)
///
/// Manages all streams for a connection. Enforces stream limits.
pub struct StreamManager {
    /// Local side (Client or Server)
    side: Side,

    /// Maximum bidirectional streams (local limit)
    max_streams_bidi_local: u64,

    /// Maximum unidirectional streams (local limit)
    max_streams_uni_local: u64,

    /// Maximum bidirectional streams (peer limit)
    max_streams_bidi_remote: u64,

    /// Maximum unidirectional streams (peer limit)
    max_streams_uni_remote: u64,

    /// Next client-initiated bidirectional stream ID
    next_bidi_client: u64,

    /// Next server-initiated bidirectional stream ID
    next_bidi_server: u64,

    /// Next client-initiated unidirectional stream ID
    next_uni_client: u64,

    /// Next server-initiated unidirectional stream ID
    next_uni_server: u64,
}

impl StreamManager {
    /// Create new stream manager
    pub fn new(side: Side) -> Self {
        Self {
            side,
            max_streams_bidi_local: 0,
            max_streams_uni_local: 0,
            max_streams_bidi_remote: 0,
            max_streams_uni_remote: 0,
            next_bidi_client: 0,
            next_bidi_server: 1,
            next_uni_client: 2,
            next_uni_server: 3,
        }
    }

    /// Allocate next stream ID
    pub fn allocate_stream_id(&mut self, direction: StreamDirection) -> Result<StreamId> {
        let initiator = if self.side == Side::Client {
            StreamInitiator::Client
        } else {
            StreamInitiator::Server
        };

        let next_id = match (initiator, direction) {
            (StreamInitiator::Client, StreamDirection::Bidirectional) => {
                let id = self.next_bidi_client;
                self.next_bidi_client += 4;
                id
            }
            (StreamInitiator::Server, StreamDirection::Bidirectional) => {
                let id = self.next_bidi_server;
                self.next_bidi_server += 4;
                id
            }
            (StreamInitiator::Client, StreamDirection::Unidirectional) => {
                let id = self.next_uni_client;
                self.next_uni_client += 4;
                id
            }
            (StreamInitiator::Server, StreamDirection::Unidirectional) => {
                let id = self.next_uni_server;
                self.next_uni_server += 4;
                id
            }
        };

        Ok(stream_id_helpers::from_raw(next_id))
    }

    /// Validate stream ID (check against limits)
    pub fn validate_stream_id(&self, stream_id: StreamId) -> Result<()> {
        let raw_id = stream_id;
        let initiator = stream_id_helpers::initiator(stream_id);
        let direction = stream_id_helpers::direction(stream_id);
        let is_remote = (self.side == Side::Client && initiator == StreamInitiator::Server)
            || (self.side == Side::Server && initiator == StreamInitiator::Client);

        let max_streams = match (is_remote, direction) {
            (true, StreamDirection::Bidirectional) => self.max_streams_bidi_remote,
            (true, StreamDirection::Unidirectional) => self.max_streams_uni_remote,
            (false, StreamDirection::Bidirectional) => self.max_streams_bidi_local,
            (false, StreamDirection::Unidirectional) => self.max_streams_uni_local,
        };

        let stream_count = raw_id.value() / 4;
        if stream_count >= max_streams {
            return Err(Error::Transport(TransportError::StreamLimitError));
        }

        Ok(())
    }

    /// Update peer's stream limits (from MAX_STREAMS frames)
    pub fn update_peer_max_streams(&mut self, direction: StreamDirection, max_streams: u64) {
        match direction {
            StreamDirection::Bidirectional => {
                self.max_streams_bidi_remote = max_streams;
            }
            StreamDirection::Unidirectional => {
                self.max_streams_uni_remote = max_streams;
            }
        }
    }
}
