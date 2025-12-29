//! # Flow Control (RFC 9000 Section 4)
//!
//! Connection and stream-level flow control with credit tracking.

#![forbid(unsafe_code)]

use crate::error::{Error, Result, TransportError};
use crate::types::StreamId;

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
    ///
    /// TODO: Implement auto-tuning based on RTT and throughput
    #[allow(dead_code)]
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
    use crate::types::stream_id_helpers;

    // ==========================================================================
    // FlowController Tests - RFC 9000 Section 4
    // ==========================================================================

    #[test]
    fn test_flow_controller_new() {
        let fc = FlowController::new(10000, 10000);
        assert_eq!(fc.max_data, 10000);
        assert_eq!(fc.consumed, 0);
        assert_eq!(fc.available, 0);
        assert_eq!(fc.local_max_data, 10000);
    }

    #[test]
    fn test_flow_controller_can_receive_within_limit() {
        let fc = FlowController::new(10000, 10000);
        assert!(fc.can_receive(5000).is_ok());
    }

    #[test]
    fn test_flow_controller_can_receive_at_limit() {
        let fc = FlowController::new(10000, 10000);
        assert!(fc.can_receive(10000).is_ok());
    }

    #[test]
    fn test_flow_controller_can_receive_exceeds_limit() {
        let fc = FlowController::new(10000, 10000);
        let result = fc.can_receive(10001);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Transport(TransportError::FlowControlError) => {}
            other => panic!("Expected FlowControlError, got {:?}", other),
        }
    }

    #[test]
    fn test_flow_controller_on_data_received() {
        let mut fc = FlowController::new(10000, 10000);
        
        fc.on_data_received(1000).unwrap();
        assert_eq!(fc.available, 1000);
        
        fc.on_data_received(500).unwrap();
        assert_eq!(fc.available, 1500);
    }

    #[test]
    fn test_flow_controller_on_data_received_exceeds_limit() {
        let mut fc = FlowController::new(1000, 1000);
        
        fc.on_data_received(500).unwrap();
        let result = fc.on_data_received(600);
        assert!(result.is_err());
    }

    #[test]
    fn test_flow_controller_consume() {
        let mut fc = FlowController::new(10000, 10000);
        
        fc.on_data_received(1000).unwrap();
        fc.consume(400);
        
        assert_eq!(fc.consumed, 400);
        assert_eq!(fc.available, 600);
    }

    #[test]
    fn test_flow_controller_consume_more_than_available() {
        let mut fc = FlowController::new(10000, 10000);
        
        fc.on_data_received(100).unwrap();
        fc.consume(200); // Uses saturating_sub
        
        assert_eq!(fc.consumed, 200);
        assert_eq!(fc.available, 0); // Saturated to 0
    }

    #[test]
    fn test_flow_controller_update_max_data_increase() {
        let mut fc = FlowController::new(10000, 10000);
        
        fc.update_max_data(20000);
        assert_eq!(fc.max_data, 20000);
    }

    #[test]
    fn test_flow_controller_update_max_data_decrease_ignored() {
        let mut fc = FlowController::new(10000, 10000);
        
        fc.update_max_data(5000);
        // Should NOT decrease
        assert_eq!(fc.max_data, 10000);
    }

    #[test]
    fn test_flow_controller_should_send_max_data_update() {
        let mut fc = FlowController::new(10000, 10000);
        
        // Initially no update needed
        assert!(!fc.should_send_max_data_update());
        
        // Consume 40% - still no update
        fc.on_data_received(4000).unwrap();
        fc.consume(4000);
        assert!(!fc.should_send_max_data_update());
        
        // Consume 60% - now need update
        fc.on_data_received(2000).unwrap();
        fc.consume(2000);
        // consumed = 6000 >= threshold = 5000
        assert!(fc.should_send_max_data_update());
    }

    #[test]
    fn test_flow_controller_new_max_data() {
        let mut fc = FlowController::new(10000, 10000);
        
        fc.on_data_received(5000).unwrap();
        fc.consume(5000);
        
        let new_max = fc.new_max_data();
        
        // new_max = local_max_data + consumed = 10000 + 5000 = 15000
        assert_eq!(new_max, 15000);
        assert_eq!(fc.local_max_data, 15000);
        assert_eq!(fc.consumed, 0); // Reset after new_max_data
    }

    #[test]
    fn test_flow_controller_available_credit() {
        let mut fc = FlowController::new(10000, 10000);
        
        // Initially, all credit available
        assert_eq!(fc.available_credit(), 10000);
        
        fc.on_data_received(3000).unwrap();
        assert_eq!(fc.available_credit(), 7000);
        
        fc.consume(1000);
        // credit = max_data - (consumed + available) = 10000 - (1000 + 2000) = 7000
        assert_eq!(fc.available_credit(), 7000);
    }

    // ==========================================================================
    // ConnectionFlowControl Tests
    // ==========================================================================

    #[test]
    fn test_connection_flow_control_new() {
        let cfc = ConnectionFlowControl::new(100000, 100000, 50000);
        
        assert_eq!(cfc.send.max_data, 100000);
        assert_eq!(cfc.recv.max_data, 100000);
        assert_eq!(cfc.recv.local_max_data, 50000);
    }

    #[test]
    fn test_connection_flow_control_send() {
        let mut cfc = ConnectionFlowControl::new(100000, 100000, 50000);
        
        // Record some data sent
        cfc.send.on_data_received(5000).unwrap();
        assert_eq!(cfc.send.available, 5000);
    }

    #[test]
    fn test_connection_flow_control_recv() {
        let mut cfc = ConnectionFlowControl::new(100000, 100000, 50000);
        
        cfc.recv.on_data_received(3000).unwrap();
        cfc.recv.consume(1500);
        
        assert_eq!(cfc.recv.consumed, 1500);
        assert_eq!(cfc.recv.available, 1500);
    }

    // ==========================================================================
    // StreamFlowControl Tests
    // ==========================================================================

    #[test]
    fn test_stream_flow_control_new() {
        let stream_id = stream_id_helpers::from_raw(0);
        let sfc = StreamFlowControl::new(stream_id, 50000, 50000, 25000);
        
        assert_eq!(sfc.stream_id, stream_id);
        assert_eq!(sfc.send.max_data, 50000);
        assert_eq!(sfc.recv.max_data, 50000);
        assert_eq!(sfc.recv.local_max_data, 25000);
    }

    #[test]
    fn test_stream_flow_control_send() {
        let stream_id = stream_id_helpers::from_raw(4);
        let mut sfc = StreamFlowControl::new(stream_id, 50000, 50000, 25000);
        
        sfc.send.on_data_received(10000).unwrap();
        sfc.send.consume(5000);
        
        assert_eq!(sfc.send.consumed, 5000);
    }

    #[test]
    fn test_stream_flow_control_recv() {
        let stream_id = stream_id_helpers::from_raw(8);
        let mut sfc = StreamFlowControl::new(stream_id, 50000, 50000, 25000);
        
        sfc.recv.on_data_received(20000).unwrap();
        assert!(sfc.recv.can_receive(30000).is_ok());
        
        let result = sfc.recv.can_receive(30001);
        assert!(result.is_err());
    }

    // ==========================================================================
    // Edge Cases
    // ==========================================================================

    #[test]
    fn test_flow_controller_zero_limit() {
        let fc = FlowController::new(0, 0);
        
        assert_eq!(fc.available_credit(), 0);
        assert!(fc.can_receive(1).is_err());
    }

    #[test]
    fn test_flow_controller_large_values() {
        let max = u64::MAX / 2; // Avoid overflow
        let mut fc = FlowController::new(max, max);
        
        fc.on_data_received(1_000_000_000).unwrap();
        assert!(fc.available_credit() > 0);
    }

    #[test]
    fn test_flow_controller_exact_limit() {
        let mut fc = FlowController::new(100, 100);
        
        fc.on_data_received(100).unwrap();
        assert_eq!(fc.available_credit(), 0);
        assert!(fc.can_receive(1).is_err());
    }
}