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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_controller_initial_state() {
        let fc = FlowController::new(1000, 2000);
        
        assert_eq!(fc.max_data, 1000);
        assert_eq!(fc.consumed, 0);
        assert_eq!(fc.available, 0);
        assert_eq!(fc.available_credit(), 1000);
    }

    #[test]
    fn test_flow_controller_can_receive() {
        let fc = FlowController::new(1000, 2000);
        
        assert!(fc.can_receive(500).is_ok());
        assert!(fc.can_receive(1000).is_ok());
        assert!(fc.can_receive(1001).is_err());
    }

    #[test]
    fn test_flow_controller_on_data_received() {
        let mut fc = FlowController::new(1000, 2000);
        
        fc.on_data_received(300).unwrap();
        assert_eq!(fc.available, 300);
        assert_eq!(fc.consumed, 0);
        assert_eq!(fc.available_credit(), 700);
        
        fc.on_data_received(400).unwrap();
        assert_eq!(fc.available, 700);
        assert_eq!(fc.available_credit(), 300);
    }

    #[test]
    fn test_flow_controller_exceed_limit() {
        let mut fc = FlowController::new(1000, 2000);
        
        fc.on_data_received(900).unwrap();
        // Exceeding limit should fail
        assert!(fc.on_data_received(101).is_err());
    }

    #[test]
    fn test_flow_controller_consume() {
        let mut fc = FlowController::new(1000, 2000);
        
        fc.on_data_received(500).unwrap();
        assert_eq!(fc.available, 500);
        
        fc.consume(200);
        assert_eq!(fc.consumed, 200);
        assert_eq!(fc.available, 300);
        
        fc.consume(300);
        assert_eq!(fc.consumed, 500);
        assert_eq!(fc.available, 0);
    }

    #[test]
    fn test_flow_controller_consume_beyond_available() {
        let mut fc = FlowController::new(1000, 2000);
        
        fc.on_data_received(500).unwrap();
        fc.consume(1000); // Consume more than available
        
        // Should saturate at 0
        assert_eq!(fc.available, 0);
        assert_eq!(fc.consumed, 1000);
    }

    #[test]
    fn test_flow_controller_update_max_data() {
        let mut fc = FlowController::new(1000, 2000);
        
        fc.update_max_data(1500);
        assert_eq!(fc.max_data, 1500);
        assert_eq!(fc.available_credit(), 1500);
        
        // Should not decrease
        fc.update_max_data(1200);
        assert_eq!(fc.max_data, 1500);
    }

    #[test]
    fn test_flow_controller_should_send_max_data_update() {
        let mut fc = FlowController::new(5000, 2000);
        
        // Initially should not send update
        assert!(!fc.should_send_max_data_update());
        
        // Consume past threshold (50% of local_max_data = 1000 bytes)
        fc.on_data_received(600).unwrap();
        fc.consume(600);
        
        // Still not past threshold
        assert!(!fc.should_send_max_data_update());
        
        fc.on_data_received(500).unwrap();
        fc.consume(500);
        
        // Now past threshold (consumed = 1100)
        assert!(fc.should_send_max_data_update());
    }

    #[test]
    fn test_flow_controller_new_max_data() {
        let mut fc = FlowController::new(1000, 2000);
        
        fc.on_data_received(800).unwrap();
        fc.consume(800);
        
        // Get new MAX_DATA value
        let new_max = fc.new_max_data();
        
        // Should be local_max_data + consumed = 2000 + 800 = 2800
        assert_eq!(new_max, 2800);
        
        // Consumed should be reset
        assert_eq!(fc.consumed, 0);
        
        // Local max should be updated
        assert_eq!(fc.local_max_data, 2800);
    }

    #[test]
    fn test_flow_controller_available_credit() {
        let mut fc = FlowController::new(1000, 2000);
        
        assert_eq!(fc.available_credit(), 1000);
        
        fc.on_data_received(300).unwrap();
        assert_eq!(fc.available_credit(), 700);
        
        fc.consume(100);
        // After consuming, credit should remain the same since consumed doesn't increase max_data
        assert_eq!(fc.available_credit(), 700);
    }

    #[test]
    fn test_connection_flow_control() {
        let conn_fc = ConnectionFlowControl::new(10000, 20000, 30000);
        
        assert_eq!(conn_fc.send.max_data, 10000);
        assert_eq!(conn_fc.recv.max_data, 20000);
        assert_eq!(conn_fc.recv.local_max_data, 30000);
    }

    #[test]
    fn test_stream_flow_control() {
        let stream_fc = StreamFlowControl::new(StreamId::new(4), 5000, 6000, 7000);
        
        assert_eq!(stream_fc.stream_id, StreamId::new(4));
        assert_eq!(stream_fc.send.max_data, 5000);
        assert_eq!(stream_fc.recv.max_data, 6000);
        assert_eq!(stream_fc.recv.local_max_data, 7000);
    }

    #[test]
    fn test_flow_controller_window_exhaustion_and_recovery() {
        let mut fc = FlowController::new(1000, 2000);
        
        // Fill the window
        fc.on_data_received(1000).unwrap();
        assert_eq!(fc.available_credit(), 0);
        
        // Cannot receive more
        assert!(fc.on_data_received(1).is_err());
        
        // Consume some data
        fc.consume(500);
        
        // Still cannot receive (consumed doesn't free credit)
        assert!(fc.on_data_received(1).is_err());
        
        // Update max_data to provide more credit
        fc.update_max_data(2000);
        
        // Now can receive again
        assert!(fc.on_data_received(500).is_ok());
    }

    #[test]
    fn test_flow_controller_progressive_consumption() {
        let mut fc = FlowController::new(1000, 2000);
        
        // Receive and consume in chunks
        for _ in 0..5 {
            fc.on_data_received(100).unwrap();
            fc.consume(100);
        }
        
        assert_eq!(fc.consumed, 500);
        assert_eq!(fc.available, 0);
        assert_eq!(fc.available_credit(), 500);
    }

    #[test]
    fn test_flow_controller_multiple_updates() {
        let mut fc = FlowController::new(1000, 2000);
        
        fc.on_data_received(500).unwrap();
        fc.consume(500);
        
        let max1 = fc.new_max_data();
        assert_eq!(max1, 2500);
        
        fc.on_data_received(600).unwrap();
        fc.consume(600);
        
        let max2 = fc.new_max_data();
        assert_eq!(max2, 3100);
    }
}