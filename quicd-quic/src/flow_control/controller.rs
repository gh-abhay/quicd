//! # Flow Control (RFC 9000 Section 4)
//!
//! QUIC implements two levels of flow control:
//! - **Connection-level**: Limits total bytes across all streams
//! - **Stream-level**: Limits bytes per individual stream
//!
//! Both use credit-based flow control where the receiver advertises
//! the maximum offset it's willing to receive.

extern crate alloc;

use crate::types::*;
use crate::error::*;

/// Flow Controller Trait
///
/// Manages flow control for a single entity (connection or stream).
pub trait FlowController: Send {
    /// Get the current send limit (maximum offset we can send)
    fn send_limit(&self) -> u64;
    
    /// Get the current receive limit (maximum offset we can receive)
    fn receive_limit(&self) -> u64;
    
    /// Get the current send offset (highest offset sent)
    fn send_offset(&self) -> u64;
    
    /// Get the current receive offset (highest offset received)
    fn receive_offset(&self) -> u64;
    
    /// Get available send capacity
    ///
    /// Returns send_limit - send_offset
    fn send_capacity(&self) -> u64 {
        self.send_limit().saturating_sub(self.send_offset())
    }
    
    /// Get available receive capacity
    ///
    /// Returns receive_limit - receive_offset
    fn receive_capacity(&self) -> u64 {
        self.receive_limit().saturating_sub(self.receive_offset())
    }
    
    /// Update the send limit (peer sent MAX_DATA or MAX_STREAM_DATA)
    fn update_send_limit(&mut self, new_limit: u64) -> Result<()>;
    
    /// Update the receive limit (we sent MAX_DATA or MAX_STREAM_DATA)
    fn update_receive_limit(&mut self, new_limit: u64) -> Result<()>;
    
    /// Record bytes sent
    ///
    /// Updates send_offset. Returns error if exceeds send_limit.
    fn record_sent(&mut self, offset: u64, length: usize) -> Result<()>;
    
    /// Record bytes received
    ///
    /// Updates receive_offset. Returns error if exceeds receive_limit.
    fn record_received(&mut self, offset: u64, length: usize) -> Result<()>;
    
    /// Check if we should send a flow control update
    ///
    /// Returns true if the receiver should advertise a new limit.
    /// Typically when consumed capacity exceeds a threshold.
    fn should_send_update(&self) -> bool;
    
    /// Check if blocked (send_offset >= send_limit)
    fn is_send_blocked(&self) -> bool {
        self.send_offset() >= self.send_limit()
    }
    
    /// Check if receive is blocked
    fn is_receive_blocked(&self) -> bool {
        self.receive_offset() >= self.receive_limit()
    }
}

/// Connection Flow Controller
///
/// Manages connection-level flow control across all streams.
#[derive(Debug, Clone)]
pub struct ConnectionFlowController {
    /// Maximum data we can send (peer's limit)
    send_limit: u64,
    
    /// Maximum data we can receive (our limit)
    receive_limit: u64,
    
    /// Highest offset sent across all streams
    send_offset: u64,
    
    /// Highest offset received across all streams
    receive_offset: u64,
    
    /// Highest offset consumed by application
    consumed_offset: u64,
    
    /// Threshold for sending MAX_DATA updates (fraction of window)
    update_threshold: f64,
}

impl ConnectionFlowController {
    /// Create a new connection flow controller
    ///
    /// # Arguments
    ///
    /// - `initial_max_data_local`: Our initial receive limit
    /// - `initial_max_data_remote`: Peer's initial send limit (from transport params)
    pub fn new(initial_max_data_local: u64, initial_max_data_remote: u64) -> Self {
        Self {
            send_limit: initial_max_data_remote,
            receive_limit: initial_max_data_local,
            send_offset: 0,
            receive_offset: 0,
            consumed_offset: 0,
            update_threshold: 0.5, // Send update when 50% consumed
        }
    }
    
    /// Record bytes consumed by application
    ///
    /// Called when application reads data. This is used to determine
    /// when to send MAX_DATA updates.
    pub fn record_consumed(&mut self, bytes: u64) {
        self.consumed_offset = self.consumed_offset.saturating_add(bytes);
    }
    
    /// Get the suggested new receive limit for MAX_DATA frame
    pub fn new_receive_limit(&self) -> u64 {
        // Increase limit to allow another window of data
        let window_size = self.receive_limit;
        self.consumed_offset.saturating_add(window_size)
    }
}

impl FlowController for ConnectionFlowController {
    fn send_limit(&self) -> u64 {
        self.send_limit
    }
    
    fn receive_limit(&self) -> u64 {
        self.receive_limit
    }
    
    fn send_offset(&self) -> u64 {
        self.send_offset
    }
    
    fn receive_offset(&self) -> u64 {
        self.receive_offset
    }
    
    fn update_send_limit(&mut self, new_limit: u64) -> Result<()> {
        if new_limit < self.send_limit {
            // Peer decreased limit - protocol violation
            return Err(Error::Transport(TransportError::FlowControlError));
        }
        self.send_limit = new_limit;
        Ok(())
    }
    
    fn update_receive_limit(&mut self, new_limit: u64) -> Result<()> {
        self.receive_limit = new_limit;
        Ok(())
    }
    
    fn record_sent(&mut self, offset: u64, length: usize) -> Result<()> {
        let new_offset = offset.saturating_add(length as u64);
        if new_offset > self.send_limit {
            return Err(Error::Transport(TransportError::FlowControlError));
        }
        self.send_offset = self.send_offset.max(new_offset);
        Ok(())
    }
    
    fn record_received(&mut self, offset: u64, length: usize) -> Result<()> {
        let new_offset = offset.saturating_add(length as u64);
        if new_offset > self.receive_limit {
            return Err(Error::Transport(TransportError::FlowControlError));
        }
        self.receive_offset = self.receive_offset.max(new_offset);
        Ok(())
    }
    
    fn should_send_update(&self) -> bool {
        let consumed = self.consumed_offset;
        let limit = self.receive_limit;
        let remaining = limit.saturating_sub(consumed);
        let window = limit.saturating_sub(0);
        
        // Send update if consumed more than threshold of window
        (consumed as f64) > (window as f64 * self.update_threshold)
            && remaining < (window as f64 * (1.0 - self.update_threshold)) as u64
    }
}

/// Stream Flow Controller
///
/// Manages flow control for a single stream.
#[derive(Debug, Clone)]
pub struct StreamFlowController {
    /// Stream ID
    stream_id: StreamId,
    
    /// Maximum data we can send (peer's limit)
    send_limit: u64,
    
    /// Maximum data we can receive (our limit)
    receive_limit: u64,
    
    /// Highest offset sent
    send_offset: u64,
    
    /// Highest offset received
    receive_offset: u64,
    
    /// Highest offset read by application
    read_offset: u64,
    
    /// Threshold for sending MAX_STREAM_DATA updates
    update_threshold: f64,
}

impl StreamFlowController {
    /// Create a new stream flow controller
    pub fn new(
        stream_id: StreamId,
        initial_max_stream_data_local: u64,
        initial_max_stream_data_remote: u64,
    ) -> Self {
        Self {
            stream_id,
            send_limit: initial_max_stream_data_remote,
            receive_limit: initial_max_stream_data_local,
            send_offset: 0,
            receive_offset: 0,
            read_offset: 0,
            update_threshold: 0.5,
        }
    }
    
    /// Record bytes read by application
    pub fn record_read(&mut self, bytes: u64) {
        self.read_offset = self.read_offset.saturating_add(bytes);
    }
    
    /// Get the suggested new receive limit for MAX_STREAM_DATA frame
    pub fn new_receive_limit(&self) -> u64 {
        let window_size = self.receive_limit;
        self.read_offset.saturating_add(window_size)
    }
    
    /// Get stream ID
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }
}

impl FlowController for StreamFlowController {
    fn send_limit(&self) -> u64 {
        self.send_limit
    }
    
    fn receive_limit(&self) -> u64 {
        self.receive_limit
    }
    
    fn send_offset(&self) -> u64 {
        self.send_offset
    }
    
    fn receive_offset(&self) -> u64 {
        self.receive_offset
    }
    
    fn update_send_limit(&mut self, new_limit: u64) -> Result<()> {
        if new_limit < self.send_limit {
            return Err(Error::Transport(TransportError::FlowControlError));
        }
        self.send_limit = new_limit;
        Ok(())
    }
    
    fn update_receive_limit(&mut self, new_limit: u64) -> Result<()> {
        self.receive_limit = new_limit;
        Ok(())
    }
    
    fn record_sent(&mut self, offset: u64, length: usize) -> Result<()> {
        let new_offset = offset.saturating_add(length as u64);
        if new_offset > self.send_limit {
            return Err(Error::Transport(TransportError::FlowControlError));
        }
        self.send_offset = self.send_offset.max(new_offset);
        Ok(())
    }
    
    fn record_received(&mut self, offset: u64, length: usize) -> Result<()> {
        let new_offset = offset.saturating_add(length as u64);
        if new_offset > self.receive_limit {
            return Err(Error::Transport(TransportError::FlowControlError));
        }
        self.receive_offset = self.receive_offset.max(new_offset);
        Ok(())
    }
    
    fn should_send_update(&self) -> bool {
        let read = self.read_offset;
        let limit = self.receive_limit;
        let remaining = limit.saturating_sub(read);
        let window = limit;
        
        (read as f64) > (window as f64 * self.update_threshold)
            && remaining < (window as f64 * (1.0 - self.update_threshold)) as u64
    }
}

/// Flow Control Manager
///
/// Coordinates connection and stream-level flow control.
pub trait FlowControlManager: Send {
    /// Get the connection flow controller
    fn connection_flow_controller(&mut self) -> &mut dyn FlowController;
    
    /// Get a stream flow controller (or create if needed)
    fn stream_flow_controller(&mut self, stream_id: StreamId) -> &mut dyn FlowController;
    
    /// Check if we can send data on a stream
    ///
    /// Verifies both stream and connection limits.
    fn can_send_on_stream(&self, stream_id: StreamId, length: usize) -> bool;
    
    /// Get all streams that need MAX_STREAM_DATA updates
    fn streams_needing_updates(&self) -> alloc::vec::Vec<StreamId>;
    
    /// Check if connection needs MAX_DATA update
    fn connection_needs_update(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::stream_id_helpers;

    // ==========================================================================
    // FlowController Trait Default Implementation Tests
    // ==========================================================================

    #[test]
    fn test_send_capacity_calculation() {
        let ctrl = ConnectionFlowController::new(10000, 5000);
        assert_eq!(ctrl.send_capacity(), 5000); // send_limit - send_offset
    }

    #[test]
    fn test_receive_capacity_calculation() {
        let ctrl = ConnectionFlowController::new(10000, 5000);
        assert_eq!(ctrl.receive_capacity(), 10000); // receive_limit - receive_offset
    }

    #[test]
    fn test_is_send_blocked_when_equal() {
        let mut ctrl = ConnectionFlowController::new(10000, 100);
        ctrl.record_sent(0, 100).unwrap();
        assert!(ctrl.is_send_blocked());
    }

    #[test]
    fn test_is_send_blocked_when_less() {
        let mut ctrl = ConnectionFlowController::new(10000, 100);
        ctrl.record_sent(0, 50).unwrap();
        assert!(!ctrl.is_send_blocked());
    }

    // ==========================================================================
    // ConnectionFlowController Tests - RFC 9000 Section 4
    // ==========================================================================

    #[test]
    fn test_connection_fc_new() {
        let ctrl = ConnectionFlowController::new(10000, 5000);
        assert_eq!(ctrl.send_limit(), 5000); // Peer's limit
        assert_eq!(ctrl.receive_limit(), 10000); // Our limit
        assert_eq!(ctrl.send_offset(), 0);
        assert_eq!(ctrl.receive_offset(), 0);
    }

    #[test]
    fn test_connection_fc_record_sent() {
        let mut ctrl = ConnectionFlowController::new(10000, 5000);
        
        ctrl.record_sent(0, 100).unwrap();
        assert_eq!(ctrl.send_offset(), 100);
        
        ctrl.record_sent(100, 200).unwrap();
        assert_eq!(ctrl.send_offset(), 300);
    }

    #[test]
    fn test_connection_fc_record_sent_exceeds_limit() {
        let mut ctrl = ConnectionFlowController::new(10000, 100);
        
        let result = ctrl.record_sent(0, 200);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Transport(TransportError::FlowControlError) => {}
            other => panic!("Expected FlowControlError, got {:?}", other),
        }
    }

    #[test]
    fn test_connection_fc_record_received() {
        let mut ctrl = ConnectionFlowController::new(10000, 5000);
        
        ctrl.record_received(0, 100).unwrap();
        assert_eq!(ctrl.receive_offset(), 100);
        
        ctrl.record_received(100, 200).unwrap();
        assert_eq!(ctrl.receive_offset(), 300);
    }

    #[test]
    fn test_connection_fc_record_received_exceeds_limit() {
        let mut ctrl = ConnectionFlowController::new(100, 5000);
        
        let result = ctrl.record_received(0, 200);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Transport(TransportError::FlowControlError) => {}
            other => panic!("Expected FlowControlError, got {:?}", other),
        }
    }

    #[test]
    fn test_connection_fc_update_send_limit_increase() {
        let mut ctrl = ConnectionFlowController::new(10000, 5000);
        
        ctrl.update_send_limit(10000).unwrap();
        assert_eq!(ctrl.send_limit(), 10000);
    }

    #[test]
    fn test_connection_fc_update_send_limit_decrease_error() {
        let mut ctrl = ConnectionFlowController::new(10000, 5000);
        
        let result = ctrl.update_send_limit(1000);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Transport(TransportError::FlowControlError) => {}
            other => panic!("Expected FlowControlError, got {:?}", other),
        }
    }

    #[test]
    fn test_connection_fc_update_receive_limit() {
        let mut ctrl = ConnectionFlowController::new(10000, 5000);
        
        ctrl.update_receive_limit(20000).unwrap();
        assert_eq!(ctrl.receive_limit(), 20000);
    }

    #[test]
    fn test_connection_fc_record_consumed() {
        let mut ctrl = ConnectionFlowController::new(10000, 5000);
        
        ctrl.record_consumed(500);
        assert_eq!(ctrl.consumed_offset, 500);
        
        ctrl.record_consumed(300);
        assert_eq!(ctrl.consumed_offset, 800);
    }

    #[test]
    fn test_connection_fc_new_receive_limit() {
        let mut ctrl = ConnectionFlowController::new(10000, 5000);
        
        ctrl.record_consumed(5000);
        let new_limit = ctrl.new_receive_limit();
        
        // Should be consumed + window = 5000 + 10000 = 15000
        assert_eq!(new_limit, 15000);
    }

    #[test]
    fn test_connection_fc_should_send_update() {
        let mut ctrl = ConnectionFlowController::new(10000, 5000);
        
        // Initially no update needed
        assert!(!ctrl.should_send_update());
        
        // After consuming more than threshold
        ctrl.record_consumed(6000);
        // Now should need update (consumed > 50% of window)
        assert!(ctrl.should_send_update());
    }

    // ==========================================================================
    // StreamFlowController Tests - RFC 9000 Section 4
    // ==========================================================================

    #[test]
    fn test_stream_fc_new() {
        let stream_id = stream_id_helpers::from_raw(0);
        let ctrl = StreamFlowController::new(stream_id, 10000, 5000);
        
        assert_eq!(ctrl.stream_id(), stream_id);
        assert_eq!(ctrl.send_limit(), 5000);
        assert_eq!(ctrl.receive_limit(), 10000);
    }

    #[test]
    fn test_stream_fc_record_sent() {
        let stream_id = stream_id_helpers::from_raw(4);
        let mut ctrl = StreamFlowController::new(stream_id, 10000, 5000);
        
        ctrl.record_sent(0, 100).unwrap();
        assert_eq!(ctrl.send_offset(), 100);
    }

    #[test]
    fn test_stream_fc_record_sent_exceeds_limit() {
        let stream_id = stream_id_helpers::from_raw(8);
        let mut ctrl = StreamFlowController::new(stream_id, 10000, 100);
        
        let result = ctrl.record_sent(0, 200);
        assert!(result.is_err());
    }

    #[test]
    fn test_stream_fc_record_received() {
        let stream_id = stream_id_helpers::from_raw(12);
        let mut ctrl = StreamFlowController::new(stream_id, 10000, 5000);
        
        ctrl.record_received(0, 500).unwrap();
        assert_eq!(ctrl.receive_offset(), 500);
    }

    #[test]
    fn test_stream_fc_record_received_exceeds_limit() {
        let stream_id = stream_id_helpers::from_raw(16);
        let mut ctrl = StreamFlowController::new(stream_id, 100, 5000);
        
        let result = ctrl.record_received(0, 200);
        assert!(result.is_err());
    }

    #[test]
    fn test_stream_fc_update_send_limit() {
        let stream_id = stream_id_helpers::from_raw(20);
        let mut ctrl = StreamFlowController::new(stream_id, 10000, 5000);
        
        ctrl.update_send_limit(10000).unwrap();
        assert_eq!(ctrl.send_limit(), 10000);
    }

    #[test]
    fn test_stream_fc_update_send_limit_decrease_error() {
        let stream_id = stream_id_helpers::from_raw(24);
        let mut ctrl = StreamFlowController::new(stream_id, 10000, 5000);
        
        let result = ctrl.update_send_limit(1000);
        assert!(result.is_err());
    }

    #[test]
    fn test_stream_fc_record_read() {
        let stream_id = stream_id_helpers::from_raw(28);
        let mut ctrl = StreamFlowController::new(stream_id, 10000, 5000);
        
        ctrl.record_read(1000);
        assert_eq!(ctrl.read_offset, 1000);
    }

    #[test]
    fn test_stream_fc_new_receive_limit() {
        let stream_id = stream_id_helpers::from_raw(32);
        let mut ctrl = StreamFlowController::new(stream_id, 10000, 5000);
        
        ctrl.record_read(5000);
        let new_limit = ctrl.new_receive_limit();
        
        // read + window = 5000 + 10000 = 15000
        assert_eq!(new_limit, 15000);
    }

    #[test]
    fn test_stream_fc_should_send_update() {
        let stream_id = stream_id_helpers::from_raw(36);
        let mut ctrl = StreamFlowController::new(stream_id, 10000, 5000);
        
        assert!(!ctrl.should_send_update());
        
        ctrl.record_read(6000);
        // Now should need update
        assert!(ctrl.should_send_update());
    }

    // ==========================================================================
    // Out-of-Order Data Tests
    // ==========================================================================

    #[test]
    fn test_connection_fc_out_of_order_data() {
        let mut ctrl = ConnectionFlowController::new(10000, 5000);
        
        // Receive data at offset 100 first
        ctrl.record_received(100, 50).unwrap();
        assert_eq!(ctrl.receive_offset(), 150);
        
        // Then receive earlier data at offset 0
        ctrl.record_received(0, 100).unwrap();
        // receive_offset should be max of all offsets
        assert_eq!(ctrl.receive_offset(), 150);
    }

    #[test]
    fn test_stream_fc_out_of_order_data() {
        let stream_id = stream_id_helpers::from_raw(40);
        let mut ctrl = StreamFlowController::new(stream_id, 10000, 5000);
        
        // Send later chunk first
        ctrl.record_sent(500, 100).unwrap();
        assert_eq!(ctrl.send_offset(), 600);
        
        // Send earlier chunk
        ctrl.record_sent(0, 100).unwrap();
        // send_offset should be max
        assert_eq!(ctrl.send_offset(), 600);
    }

    // ==========================================================================
    // Edge Cases
    // ==========================================================================

    #[test]
    fn test_connection_fc_exactly_at_limit() {
        let mut ctrl = ConnectionFlowController::new(10000, 100);
        
        // Send exactly at limit should succeed
        ctrl.record_sent(0, 100).unwrap();
        assert_eq!(ctrl.send_offset(), 100);
        assert!(ctrl.is_send_blocked());
    }

    #[test]
    fn test_stream_fc_zero_length() {
        let stream_id = stream_id_helpers::from_raw(44);
        let mut ctrl = StreamFlowController::new(stream_id, 10000, 5000);
        
        // Zero-length send should succeed
        ctrl.record_sent(0, 0).unwrap();
        assert_eq!(ctrl.send_offset(), 0);
    }

    #[test]
    fn test_send_capacity_after_sending() {
        let mut ctrl = ConnectionFlowController::new(10000, 1000);
        
        assert_eq!(ctrl.send_capacity(), 1000);
        
        ctrl.record_sent(0, 400).unwrap();
        assert_eq!(ctrl.send_capacity(), 600);
        
        ctrl.record_sent(400, 600).unwrap();
        assert_eq!(ctrl.send_capacity(), 0);
    }

    #[test]
    fn test_receive_capacity_after_receiving() {
        let mut ctrl = ConnectionFlowController::new(1000, 10000);
        
        assert_eq!(ctrl.receive_capacity(), 1000);
        
        ctrl.record_received(0, 400).unwrap();
        assert_eq!(ctrl.receive_capacity(), 600);
    }
}
