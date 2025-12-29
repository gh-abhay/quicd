//! # Stream State Machine and Manager (RFC 9000 Section 3)
//!
//! Manages stream lifecycles and state transitions.

#![forbid(unsafe_code)]

use crate::error::{Error, Result, TransportError};
use crate::types::{
    stream_id_helpers, Side, StreamDirection, StreamId, StreamInitiator, StreamOffset,
};
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
            StreamState::Open
                | StreamState::HalfClosedRemote
                | StreamState::Ready
                | StreamState::Send
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
    DataAvailable {
        stream_id: StreamId,
        offset: StreamOffset,
        length: usize,
    },

    /// Stream finished (FIN received)
    Finished { stream_id: StreamId },

    /// Stream reset by peer
    Reset {
        stream_id: StreamId,
        error_code: u64,
        final_size: u64,
    },

    /// Stream stopped by peer (STOP_SENDING)
    Stopped {
        stream_id: StreamId,
        error_code: u64,
    },

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
    fn write_stream(&mut self, stream_id: StreamId, data: Bytes, fin: bool) -> Result<usize>;

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

#[cfg(test)]
mod tests {
    use super::*;

    // ==========================================================================
    // StreamState Tests - RFC 9000 Section 3
    // ==========================================================================

    #[test]
    fn test_stream_state_can_send_bidirectional() {
        // Bidirectional stream send states
        assert!(StreamState::Open.can_send());
        assert!(StreamState::HalfClosedRemote.can_send());
        assert!(!StreamState::HalfClosedLocal.can_send()); // Sent FIN
        assert!(!StreamState::Closed.can_send());
    }

    #[test]
    fn test_stream_state_can_send_unidirectional() {
        // Unidirectional send-only stream states
        assert!(StreamState::Ready.can_send());
        assert!(StreamState::Send.can_send());
        assert!(!StreamState::DataSent.can_send()); // Data sent, waiting for ACK
        assert!(!StreamState::ResetSent.can_send());
    }

    #[test]
    fn test_stream_state_can_receive_bidirectional() {
        // Bidirectional stream receive states
        assert!(StreamState::Open.can_receive());
        assert!(StreamState::HalfClosedLocal.can_receive()); // Sent FIN, can still receive
        assert!(!StreamState::HalfClosedRemote.can_receive()); // Received FIN
        assert!(!StreamState::Closed.can_receive());
    }

    #[test]
    fn test_stream_state_can_receive_unidirectional() {
        // Unidirectional receive-only stream states
        assert!(StreamState::Recv.can_receive());
        assert!(StreamState::SizeKnown.can_receive()); // FIN received but data still coming
        assert!(!StreamState::DataRecvd.can_receive());
        assert!(!StreamState::DataRead.can_receive());
    }

    #[test]
    fn test_stream_state_is_finished() {
        // Terminal states
        assert!(StreamState::Closed.is_finished());
        assert!(StreamState::ResetRecvd.is_finished());
        assert!(StreamState::DataRead.is_finished());

        // Non-terminal states
        assert!(!StreamState::Open.is_finished());
        assert!(!StreamState::HalfClosedLocal.is_finished());
        assert!(!StreamState::HalfClosedRemote.is_finished());
        assert!(!StreamState::Recv.is_finished());
        assert!(!StreamState::Send.is_finished());
    }

    #[test]
    fn test_stream_state_idle() {
        // Idle state - not yet opened
        assert!(!StreamState::Idle.can_send());
        assert!(!StreamState::Idle.can_receive());
        assert!(!StreamState::Idle.is_finished());
    }

    // ==========================================================================
    // StreamManager Tests - RFC 9000 Section 2.1 (Stream IDs)
    // ==========================================================================

    #[test]
    fn test_stream_manager_new_client() {
        let mgr = StreamManager::new(Side::Client);
        assert_eq!(mgr.side, Side::Client);
        assert_eq!(mgr.next_bidi_client, 0);
        assert_eq!(mgr.next_uni_client, 2);
    }

    #[test]
    fn test_stream_manager_new_server() {
        let mgr = StreamManager::new(Side::Server);
        assert_eq!(mgr.side, Side::Server);
        assert_eq!(mgr.next_bidi_server, 1);
        assert_eq!(mgr.next_uni_server, 3);
    }

    #[test]
    fn test_stream_id_allocation_client_bidi() {
        let mut mgr = StreamManager::new(Side::Client);

        // Client-initiated bidirectional: 0, 4, 8, 12, ...
        let id1 = mgr.allocate_stream_id(StreamDirection::Bidirectional).unwrap();
        let id2 = mgr.allocate_stream_id(StreamDirection::Bidirectional).unwrap();
        let id3 = mgr.allocate_stream_id(StreamDirection::Bidirectional).unwrap();

        assert_eq!(id1.value(), 0);
        assert_eq!(id2.value(), 4);
        assert_eq!(id3.value(), 8);
    }

    #[test]
    fn test_stream_id_allocation_client_uni() {
        let mut mgr = StreamManager::new(Side::Client);

        // Client-initiated unidirectional: 2, 6, 10, ...
        let id1 = mgr.allocate_stream_id(StreamDirection::Unidirectional).unwrap();
        let id2 = mgr.allocate_stream_id(StreamDirection::Unidirectional).unwrap();

        assert_eq!(id1.value(), 2);
        assert_eq!(id2.value(), 6);
    }

    #[test]
    fn test_stream_id_allocation_server_bidi() {
        let mut mgr = StreamManager::new(Side::Server);

        // Server-initiated bidirectional: 1, 5, 9, ...
        let id1 = mgr.allocate_stream_id(StreamDirection::Bidirectional).unwrap();
        let id2 = mgr.allocate_stream_id(StreamDirection::Bidirectional).unwrap();

        assert_eq!(id1.value(), 1);
        assert_eq!(id2.value(), 5);
    }

    #[test]
    fn test_stream_id_allocation_server_uni() {
        let mut mgr = StreamManager::new(Side::Server);

        // Server-initiated unidirectional: 3, 7, 11, ...
        let id1 = mgr.allocate_stream_id(StreamDirection::Unidirectional).unwrap();
        let id2 = mgr.allocate_stream_id(StreamDirection::Unidirectional).unwrap();

        assert_eq!(id1.value(), 3);
        assert_eq!(id2.value(), 7);
    }

    #[test]
    fn test_stream_id_types_from_rfc() {
        // RFC 9000 Section 2.1:
        // 0x00 = Client-Initiated, Bidirectional
        // 0x01 = Server-Initiated, Bidirectional
        // 0x02 = Client-Initiated, Unidirectional
        // 0x03 = Server-Initiated, Unidirectional

        let id0 = stream_id_helpers::from_raw(0);
        assert_eq!(stream_id_helpers::initiator(id0), StreamInitiator::Client);
        assert_eq!(
            stream_id_helpers::direction(id0),
            StreamDirection::Bidirectional
        );

        let id1 = stream_id_helpers::from_raw(1);
        assert_eq!(stream_id_helpers::initiator(id1), StreamInitiator::Server);
        assert_eq!(
            stream_id_helpers::direction(id1),
            StreamDirection::Bidirectional
        );

        let id2 = stream_id_helpers::from_raw(2);
        assert_eq!(stream_id_helpers::initiator(id2), StreamInitiator::Client);
        assert_eq!(
            stream_id_helpers::direction(id2),
            StreamDirection::Unidirectional
        );

        let id3 = stream_id_helpers::from_raw(3);
        assert_eq!(stream_id_helpers::initiator(id3), StreamInitiator::Server);
        assert_eq!(
            stream_id_helpers::direction(id3),
            StreamDirection::Unidirectional
        );
    }

    #[test]
    fn test_validate_stream_id_within_limit() {
        let mut mgr = StreamManager::new(Side::Client);
        mgr.max_streams_bidi_local = 10;
        mgr.max_streams_uni_local = 5;
        mgr.max_streams_bidi_remote = 10;
        mgr.max_streams_uni_remote = 5;

        // Client validates server-initiated stream (remote)
        // Server bidi stream 1 (stream count = 1/4 = 0)
        let id = stream_id_helpers::from_raw(1);
        assert!(mgr.validate_stream_id(id).is_ok());

        // Server bidi stream 5 (stream count = 5/4 = 1)
        let id = stream_id_helpers::from_raw(5);
        assert!(mgr.validate_stream_id(id).is_ok());
    }

    #[test]
    fn test_validate_stream_id_exceeds_limit() {
        let mut mgr = StreamManager::new(Side::Client);
        mgr.max_streams_bidi_remote = 1; // Only allow stream 1

        // Stream ID 5 would be stream count 5/4 = 1 >= limit 1
        let id = stream_id_helpers::from_raw(5);
        let result = mgr.validate_stream_id(id);
        assert!(result.is_err());

        match result.unwrap_err() {
            Error::Transport(TransportError::StreamLimitError) => {}
            other => panic!("Expected StreamLimitError, got {:?}", other),
        }
    }

    #[test]
    fn test_update_peer_max_streams_bidi() {
        let mut mgr = StreamManager::new(Side::Client);
        assert_eq!(mgr.max_streams_bidi_remote, 0);

        mgr.update_peer_max_streams(StreamDirection::Bidirectional, 100);
        assert_eq!(mgr.max_streams_bidi_remote, 100);
    }

    #[test]
    fn test_update_peer_max_streams_uni() {
        let mut mgr = StreamManager::new(Side::Server);
        assert_eq!(mgr.max_streams_uni_remote, 0);

        mgr.update_peer_max_streams(StreamDirection::Unidirectional, 50);
        assert_eq!(mgr.max_streams_uni_remote, 50);
    }

    // ==========================================================================
    // StreamEvent Tests
    // ==========================================================================

    #[test]
    fn test_stream_event_opened() {
        let event = StreamEvent::Opened { stream_id: stream_id_helpers::from_raw(0) };
        match event {
            StreamEvent::Opened { stream_id } => {
                assert_eq!(stream_id.value(), 0);
            }
            _ => panic!("Wrong event variant"),
        }
    }

    #[test]
    fn test_stream_event_data_available() {
        let event = StreamEvent::DataAvailable {
            stream_id: stream_id_helpers::from_raw(4),
            offset: 100,
            length: 256,
        };
        match event {
            StreamEvent::DataAvailable {
                stream_id,
                offset,
                length,
            } => {
                assert_eq!(stream_id.value(), 4);
                assert_eq!(offset, 100);
                assert_eq!(length, 256);
            }
            _ => panic!("Wrong event variant"),
        }
    }

    #[test]
    fn test_stream_event_reset() {
        let event = StreamEvent::Reset {
            stream_id: stream_id_helpers::from_raw(8),
            error_code: 0x0A,
            final_size: 1000,
        };
        match event {
            StreamEvent::Reset {
                stream_id,
                error_code,
                final_size,
            } => {
                assert_eq!(stream_id.value(), 8);
                assert_eq!(error_code, 0x0A);
                assert_eq!(final_size, 1000);
            }
            _ => panic!("Wrong event variant"),
        }
    }

    #[test]
    fn test_stream_event_stopped() {
        let event = StreamEvent::Stopped {
            stream_id: stream_id_helpers::from_raw(12),
            error_code: 0x0B,
        };
        match event {
            StreamEvent::Stopped {
                stream_id,
                error_code,
            } => {
                assert_eq!(stream_id.value(), 12);
                assert_eq!(error_code, 0x0B);
            }
            _ => panic!("Wrong event variant"),
        }
    }
}
