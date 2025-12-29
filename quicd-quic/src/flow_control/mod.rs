//! # Flow Control (RFC 9000 Section 4)
//!
//! Connection and stream-level flow control with credit tracking.

#![forbid(unsafe_code)]

use crate::error::{Error, Result, TransportError};
use crate::types::{StreamId, StreamOffset, VarInt};

/// Flow Controller (Connection or Stream Level)
///
/// Tracks data limits and consumption for flow control.
///
/// **RFC 9000 Section 4**: Flow control prevents sender from overwhelming
/// receiver. Limits are communicated via transport parameters and MAX_DATA/
/// MAX_STREAM_DATA frames.
#[derive(Debug, Clone)]
pub struct FlowController {
    /// Maximum data that can be received (limit set by peer)
    max_data: u64,

    /// Data consumed (bytes received and processed)
    consumed: u64,

    /// Data available for reading (not yet consumed)
    available: u64,

    /// Maximum data we allow peer to send (our limit)
    local_max_data: u64,

    /// Auto-tuning enabled (dynamically adjust window)
    auto_tune: bool,
}

impl FlowController {
    /// Create new flow controller
    pub fn new(initial_max_data: u64, local_max_data: u64) -> Self {
        Self {
            max_data: initial_max_data,
            consumed: 0,
            available: 0,
            local_max_data,
            auto_tune: true,
        }
    }

    /// Check if can receive data
    pub fn can_receive(&self, bytes: u64) -> Result<()> {
        if self.consumed + self.available + bytes > self.max_data {
            Err(Error::Transport(TransportError::FlowControlError))
        } else {
            Ok(())
        }
    }

    /// Record data received (but not yet consumed)
    pub fn on_data_received(&mut self, bytes: u64) -> Result<()> {
        self.can_receive(bytes)?;
        self.available += bytes;
        Ok(())
    }

    /// Consume data (mark as read by application)
    pub fn consume(&mut self, bytes: u64) {
        self.consumed += bytes;
        self.available = self.available.saturating_sub(bytes);
    }

    /// Update maximum data limit (from MAX_DATA frame)
    pub fn update_max_data(&mut self, max_data: u64) {
        if max_data > self.max_data {
            self.max_data = max_data;
        }
    }

    /// Check if should send MAX_DATA update
    ///
    /// Send when consumed passes threshold (50% of window).
    pub fn should_send_max_data_update(&self) -> bool {
        let threshold = self.local_max_data / 2;
        self.consumed >= threshold
    }

    /// Get updated MAX_DATA value to send
    pub fn new_max_data(&mut self) -> u64 {
        // Increase window by consumed amount
        let new_max = self.local_max_data + self.consumed;
        self.local_max_data = new_max;
        self.consumed = 0;
        new_max
    }

    /// Get available credit (bytes that can still be received)
    pub fn available_credit(&self) -> u64 {
        self.max_data.saturating_sub(self.consumed + self.available)
    }
}

/// Connection-Level Flow Control
///
/// Manages flow control for entire connection.
pub struct ConnectionFlowControl {
    /// Send flow controller (data we send)
    pub send: FlowController,

    /// Receive flow controller (data we receive)
    pub recv: FlowController,
}

impl ConnectionFlowControl {
    /// Create new connection flow control
    pub fn new(
        initial_max_data_send: u64,
        initial_max_data_recv: u64,
        local_max_data: u64,
    ) -> Self {
        Self {
            send: FlowController::new(initial_max_data_send, 0), // Send side doesn't have local limit
            recv: FlowController::new(initial_max_data_recv, local_max_data),
        }
    }
}

/// Stream-Level Flow Control
///
/// Manages flow control for a single stream.
pub struct StreamFlowControl {
    /// Stream ID
    pub stream_id: StreamId,

    /// Send flow controller
    pub send: FlowController,

    /// Receive flow controller
    pub recv: FlowController,
}

impl StreamFlowControl {
    /// Create new stream flow control
    pub fn new(
        stream_id: StreamId,
        initial_max_stream_data_send: u64,
        initial_max_stream_data_recv: u64,
        local_max_stream_data: u64,
    ) -> Self {
        Self {
            stream_id,
            send: FlowController::new(initial_max_stream_data_send, 0),
            recv: FlowController::new(initial_max_stream_data_recv, local_max_stream_data),
        }
    }
}
// ============================================================================
// Unit Tests
// ============================================================================

