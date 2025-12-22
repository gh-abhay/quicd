//! # Flow Control (RFC 9000 Section 4)
//!
//! QUIC uses credit-based flow control at two levels:
//! - **Connection-level**: Total bytes across all streams
//! - **Stream-level**: Bytes per individual stream
//!
//! ## RFC 9000 Section 4.1:
//! Flow control prevents a fast sender from overwhelming a slow receiver.
//! Receivers advertise credit via MAX_DATA and MAX_STREAM_DATA frames.

#![forbid(unsafe_code)]

use crate::error::{Error, Result};
use crate::types::{StreamId, VarInt};

/// Flow Control Limit (bytes)
pub type FlowControlLimit = u64;

/// Connection Flow Controller
///
/// Manages connection-level flow control (total bytes across all streams).
///
/// ## RFC 9000 Section 4.1:
/// MAX_DATA frame advertises the maximum total bytes the peer can send.
pub trait ConnectionFlowController {
    /// Get the current connection-level send limit (bytes peer can send)
    fn send_limit(&self) -> FlowControlLimit;

    /// Get the current connection-level receive limit (bytes we can send)
    fn recv_limit(&self) -> FlowControlLimit;

    /// Update the send limit (from MAX_DATA frame)
    fn update_send_limit(&mut self, limit: FlowControlLimit);

    /// Check if we can send `bytes` without exceeding flow control
    fn can_send(&self, bytes: usize) -> bool;

    /// Consume send credit (called when sending data)
    ///
    /// # Errors
    /// Returns Error::FlowControlError if insufficient credit
    fn consume_send_credit(&mut self, bytes: usize) -> Result<()>;

    /// Consume receive credit (called when receiving data)
    ///
    /// # Errors
    /// Returns Error::FlowControlError if limit exceeded
    fn consume_recv_credit(&mut self, bytes: usize) -> Result<()>;

    /// Check if we should send MAX_DATA update to peer
    ///
    /// Called to determine if receive window needs to be extended
    fn should_send_max_data(&self) -> bool;

    /// Get the new MAX_DATA value to send
    fn new_max_data(&mut self) -> FlowControlLimit;

    /// Get total bytes sent
    fn bytes_sent(&self) -> u64;

    /// Get total bytes received
    fn bytes_received(&self) -> u64;
}

/// Stream Flow Controller
///
/// Manages flow control for a single stream.
///
/// ## RFC 9000 Section 4.1:
/// MAX_STREAM_DATA frame advertises the maximum bytes the peer can send on a stream.
pub trait StreamFlowController {
    /// Get the stream ID
    fn stream_id(&self) -> StreamId;

    /// Get the current stream-level send limit (bytes peer can send)
    fn send_limit(&self) -> FlowControlLimit;

    /// Get the current stream-level receive limit (bytes we can send)
    fn recv_limit(&self) -> FlowControlLimit;

    /// Update the send limit (from MAX_STREAM_DATA frame)
    fn update_send_limit(&mut self, limit: FlowControlLimit);

    /// Check if we can send `bytes` without exceeding flow control
    fn can_send(&self, bytes: usize) -> bool;

    /// Consume send credit
    ///
    /// # Errors
    /// Returns Error::FlowControlError if insufficient credit
    fn consume_send_credit(&mut self, bytes: usize) -> Result<()>;

    /// Consume receive credit
    ///
    /// # Errors
    /// Returns Error::FlowControlError if limit exceeded
    fn consume_recv_credit(&mut self, bytes: usize) -> Result<()>;

    /// Check if we should send MAX_STREAM_DATA update
    fn should_send_max_stream_data(&self) -> bool;

    /// Get the new MAX_STREAM_DATA value to send
    fn new_max_stream_data(&mut self) -> FlowControlLimit;

    /// Get bytes sent on this stream
    fn bytes_sent(&self) -> u64;

    /// Get bytes received on this stream
    fn bytes_received(&self) -> u64;
}

/// Flow Control Manager
///
/// Coordinates connection-level and stream-level flow control.
pub trait FlowControlManager {
    /// Get connection flow controller
    fn connection(&self) -> &dyn ConnectionFlowController;

    /// Get mutable connection flow controller
    fn connection_mut(&mut self) -> &mut dyn ConnectionFlowController;

    /// Get stream flow controller
    ///
    /// Returns None if stream doesn't exist
    fn stream(&self, stream_id: StreamId) -> Option<&dyn StreamFlowController>;

    /// Get mutable stream flow controller
    fn stream_mut(&mut self, stream_id: StreamId) -> Option<&mut dyn StreamFlowController>;

    /// Create flow controller for a new stream
    fn create_stream(&mut self, stream_id: StreamId, initial_limit: FlowControlLimit);

    /// Remove flow controller for a closed stream
    fn remove_stream(&mut self, stream_id: StreamId);

    /// Check if we can send data (both connection and stream level)
    fn can_send(&self, stream_id: StreamId, bytes: usize) -> bool;

    /// Consume send credit at both levels
    ///
    /// # Errors
    /// Returns Error::FlowControlError if either limit exceeded
    fn consume_send_credit(&mut self, stream_id: StreamId, bytes: usize) -> Result<()>;

    /// Consume receive credit at both levels
    fn consume_recv_credit(&mut self, stream_id: StreamId, bytes: usize) -> Result<()>;

    /// Get all streams that need MAX_STREAM_DATA updates
    fn streams_needing_max_stream_data(&self) -> Vec<StreamId>;

    /// Check if connection needs MAX_DATA update
    fn needs_max_data_update(&self) -> bool;
}

/// Flow Control Configuration
///
/// Initial flow control limits.
#[derive(Debug, Clone, Copy)]
pub struct FlowControlConfig {
    /// Initial connection-level receive window (bytes)
    pub initial_max_data: u64,

    /// Initial stream-level receive window for bidirectional streams (local-initiated)
    pub initial_max_stream_data_bidi_local: u64,

    /// Initial stream-level receive window for bidirectional streams (remote-initiated)
    pub initial_max_stream_data_bidi_remote: u64,

    /// Initial stream-level receive window for unidirectional streams
    pub initial_max_stream_data_uni: u64,

    /// Threshold for sending MAX_DATA updates (as fraction of window, e.g., 0.5)
    pub max_data_update_threshold: f64,

    /// Threshold for sending MAX_STREAM_DATA updates (as fraction of window)
    pub max_stream_data_update_threshold: f64,
}

impl Default for FlowControlConfig {
    fn default() -> Self {
        Self {
            initial_max_data: 10 * 1024 * 1024,           // 10 MB
            initial_max_stream_data_bidi_local: 1024 * 1024,  // 1 MB
            initial_max_stream_data_bidi_remote: 1024 * 1024, // 1 MB
            initial_max_stream_data_uni: 1024 * 1024,         // 1 MB
            max_data_update_threshold: 0.5,
            max_stream_data_update_threshold: 0.5,
        }
    }
}
