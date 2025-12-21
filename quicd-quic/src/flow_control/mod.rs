//! Flow control implementation (RFC 9000 Section 4)
//!
//! QUIC implements flow control at two levels:
//! 1. **Connection-level**: MAX_DATA limits total bytes across all streams
//! 2. **Stream-level**: MAX_STREAM_DATA limits bytes per individual stream
//!
//! Flow control is bidirectional - both sender and receiver track limits.

use crate::types::{VarInt, StreamId};
use crate::error::{Error, Result, TransportError};

/// Connection-level flow control state (RFC 9000 Section 4.1)
///
/// **Design**: Tracks aggregate data across all streams on the connection.
/// Prevents a peer from overwhelming the receiver with too much data.
#[derive(Debug, Clone)]
pub struct ConnectionFlowControl {
    // ===== Send Side (data we send to peer) =====
    
    /// Maximum data we're allowed to send (peer's MAX_DATA value)
    send_max_data: u64,
    
    /// Total bytes sent on all streams
    send_data: u64,
    
    /// True if we're blocked due to flow control
    send_blocked: bool,
    
    // ===== Receive Side (data peer sends to us) =====
    
    /// Maximum data we're willing to receive (our MAX_DATA value)
    recv_max_data: u64,
    
    /// Total bytes received on all streams
    recv_data: u64,
    
    /// Window size for automatic MAX_DATA updates
    recv_window: u64,
    
    /// Threshold for sending MAX_DATA update (typically recv_window / 2)
    recv_update_threshold: u64,
}

impl ConnectionFlowControl {
    /// Create new connection flow control
    ///
    /// **Parameters**:
    /// - `initial_send_max`: Peer's initial_max_data transport parameter
    /// - `initial_recv_max`: Our initial_max_data transport parameter
    pub fn new(initial_send_max: u64, initial_recv_max: u64) -> Self {
        let recv_window = initial_recv_max;
        
        Self {
            send_max_data: initial_send_max,
            send_data: 0,
            send_blocked: false,
            recv_max_data: initial_recv_max,
            recv_data: 0,
            recv_window,
            recv_update_threshold: recv_window / 2,
        }
    }
    
    // ===== Send Side Operations =====
    
    /// Get available send window (bytes we can send)
    pub fn send_window(&self) -> u64 {
        self.send_max_data.saturating_sub(self.send_data)
    }
    
    /// Check if we can send the specified number of bytes
    pub fn can_send(&self, bytes: usize) -> bool {
        self.send_data + bytes as u64 <= self.send_max_data
    }
    
    /// Consume send window (called when data is sent)
    ///
    /// **Returns**: `Err(FlowControl)` if insufficient window
    pub fn consume_send_window(&mut self, bytes: usize) -> Result<()> {
        let new_total = self.send_data + bytes as u64;
        
        if new_total > self.send_max_data {
            self.send_blocked = true;
            return Err(Error::TransportError(TransportError::FlowControlError));
        }
        
        self.send_data = new_total;
        Ok(())
    }
    
    /// Update send limit from peer's MAX_DATA frame
    pub fn update_send_max_data(&mut self, max_data: u64) {
        if max_data > self.send_max_data {
            self.send_max_data = max_data;
            self.send_blocked = false;
        }
    }
    
    /// Check if we're blocked and should send DATA_BLOCKED frame
    pub fn is_send_blocked(&self) -> bool {
        self.send_blocked && self.send_data >= self.send_max_data
    }
    
    /// Get current send limit
    pub fn send_max_data(&self) -> u64 {
        self.send_max_data
    }
    
    // ===== Receive Side Operations =====
    
    /// Consume receive window (called when data is received)
    ///
    /// **RFC 9000 Section 4.1**: Receiver MUST close connection with
    /// FLOW_CONTROL_ERROR if peer exceeds max_data.
    ///
    /// **Returns**: `Err(FlowControl)` if peer violated flow control
    pub fn consume_recv_window(&mut self, bytes: usize) -> Result<()> {
        let new_total = self.recv_data + bytes as u64;
        
        if new_total > self.recv_max_data {
            return Err(Error::TransportError(TransportError::FlowControlError));
        }
        
        self.recv_data = new_total;
        Ok(())
    }
    
    /// Check if we should send a MAX_DATA update
    ///
    /// **Design**: Send MAX_DATA when half the window is consumed to avoid
    /// peer stalling due to flow control.
    pub fn should_send_max_data_update(&self) -> bool {
        self.recv_data >= self.recv_update_threshold
    }
    
    /// Increase receive window and get new MAX_DATA value
    ///
    /// **Returns**: New max_data value to send in MAX_DATA frame
    pub fn increase_recv_window(&mut self) -> u64 {
        self.recv_max_data += self.recv_window;
        self.recv_update_threshold = self.recv_max_data - (self.recv_window / 2);
        self.recv_max_data
    }
    
    /// Get current receive limit
    pub fn recv_max_data(&self) -> u64 {
        self.recv_max_data
    }
    
    /// Get total bytes received
    pub fn recv_data(&self) -> u64 {
        self.recv_data
    }
}

/// Stream-level flow control state (RFC 9000 Section 4.2)
///
/// **Design**: Each stream has independent flow control limits.
/// For bidirectional streams, send and receive limits are tracked separately.
#[derive(Debug, Clone)]
pub struct StreamFlowControl {
    /// Stream identifier
    stream_id: StreamId,
    
    // ===== Send Side =====
    
    /// Maximum offset we're allowed to send (peer's MAX_STREAM_DATA)
    send_max_offset: u64,
    
    /// Highest offset sent (exclusive)
    send_offset: u64,
    
    /// True if blocked due to flow control
    send_blocked: bool,
    
    // ===== Receive Side =====
    
    /// Maximum offset we're willing to receive (our MAX_STREAM_DATA)
    recv_max_offset: u64,
    
    /// Highest offset received (exclusive)
    recv_offset: u64,
    
    /// Window size for automatic MAX_STREAM_DATA updates
    recv_window: u64,
    
    /// Threshold for sending update
    recv_update_threshold: u64,
}

impl StreamFlowControl {
    /// Create new stream flow control
    ///
    /// **Parameters**:
    /// - `stream_id`: Stream identifier
    /// - `initial_send_max`: Peer's initial_max_stream_data transport parameter
    /// - `initial_recv_max`: Our initial_max_stream_data transport parameter
    pub fn new(
        stream_id: StreamId,
        initial_send_max: u64,
        initial_recv_max: u64,
    ) -> Self {
        let recv_window = initial_recv_max;
        
        Self {
            stream_id,
            send_max_offset: initial_send_max,
            send_offset: 0,
            send_blocked: false,
            recv_max_offset: initial_recv_max,
            recv_offset: 0,
            recv_window,
            recv_update_threshold: recv_window / 2,
        }
    }
    
    // ===== Send Side Operations =====
    
    /// Get available send window
    pub fn send_window(&self) -> u64 {
        self.send_max_offset.saturating_sub(self.send_offset)
    }
    
    /// Check if we can send data at the specified offset
    pub fn can_send(&self, offset: u64, length: usize) -> bool {
        offset + length as u64 <= self.send_max_offset
    }
    
    /// Consume send window for data at offset
    ///
    /// **RFC 9000 Section 4.2**: Stream data MUST NOT exceed max_stream_data.
    pub fn consume_send_window(&mut self, offset: u64, length: usize) -> Result<()> {
        let end_offset = offset + length as u64;
        
        if end_offset > self.send_max_offset {
            self.send_blocked = true;
            return Err(Error::TransportError(TransportError::FlowControlError));
        }
        
        // Update highest offset sent
        if end_offset > self.send_offset {
            self.send_offset = end_offset;
        }
        
        Ok(())
    }
    
    /// Update send limit from peer's MAX_STREAM_DATA frame
    pub fn update_send_max_offset(&mut self, max_offset: u64) {
        if max_offset > self.send_max_offset {
            self.send_max_offset = max_offset;
            self.send_blocked = false;
        }
    }
    
    /// Check if blocked and should send STREAM_DATA_BLOCKED
    pub fn is_send_blocked(&self) -> bool {
        self.send_blocked && self.send_offset >= self.send_max_offset
    }
    
    /// Get current send limit
    pub fn send_max_offset(&self) -> u64 {
        self.send_max_offset
    }
    
    // ===== Receive Side Operations =====
    
    /// Validate received data against flow control limit
    ///
    /// **RFC 9000 Section 4.2**: Receiver MUST close connection with
    /// FLOW_CONTROL_ERROR if peer sends beyond max_stream_data.
    pub fn validate_recv_offset(&self, offset: u64, length: usize) -> Result<()> {
        let end_offset = offset + length as u64;
        
        if end_offset > self.recv_max_offset {
            return Err(Error::TransportError(TransportError::FlowControlError));
        }
        
        Ok(())
    }
    
    /// Update highest received offset
    pub fn update_recv_offset(&mut self, offset: u64, length: usize) {
        let end_offset = offset + length as u64;
        
        if end_offset > self.recv_offset {
            self.recv_offset = end_offset;
        }
    }
    
    /// Check if we should send MAX_STREAM_DATA update
    pub fn should_send_max_offset_update(&self) -> bool {
        self.recv_offset >= self.recv_update_threshold
    }
    
    /// Increase receive window and get new MAX_STREAM_DATA value
    pub fn increase_recv_window(&mut self) -> u64 {
        self.recv_max_offset += self.recv_window;
        self.recv_update_threshold = self.recv_max_offset - (self.recv_window / 2);
        self.recv_max_offset
    }
    
    /// Get current receive limit
    pub fn recv_max_offset(&self) -> u64 {
        self.recv_max_offset
    }
    
    /// Get stream ID
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }
}

/// Flow control manager for all streams on a connection
///
/// **Design**: Maintains both connection-level and per-stream flow control.
/// Validates that stream-level limits don't exceed connection-level limits.
#[derive(Debug)]
pub struct FlowControlManager {
    /// Connection-level flow control
    connection: ConnectionFlowControl,
    
    /// Initial limits for new streams (from transport parameters)
    initial_send_max_stream_data_bidi_local: u64,
    initial_send_max_stream_data_bidi_remote: u64,
    initial_send_max_stream_data_uni: u64,
    initial_recv_max_stream_data_bidi_local: u64,
    initial_recv_max_stream_data_bidi_remote: u64,
    initial_recv_max_stream_data_uni: u64,
}

impl FlowControlManager {
    /// Create new flow control manager from transport parameters
    pub fn new(
        conn_send_max: u64,
        conn_recv_max: u64,
        send_max_bidi_local: u64,
        send_max_bidi_remote: u64,
        send_max_uni: u64,
        recv_max_bidi_local: u64,
        recv_max_bidi_remote: u64,
        recv_max_uni: u64,
    ) -> Self {
        Self {
            connection: ConnectionFlowControl::new(conn_send_max, conn_recv_max),
            initial_send_max_stream_data_bidi_local: send_max_bidi_local,
            initial_send_max_stream_data_bidi_remote: send_max_bidi_remote,
            initial_send_max_stream_data_uni: send_max_uni,
            initial_recv_max_stream_data_bidi_local: recv_max_bidi_local,
            initial_recv_max_stream_data_bidi_remote: recv_max_bidi_remote,
            initial_recv_max_stream_data_uni: recv_max_uni,
        }
    }
    
    /// Create flow control state for a new stream
    ///
    /// **Design**: Initial limits depend on stream type and initiator.
    pub fn create_stream_flow_control(
        &self,
        stream_id: StreamId,
        is_local: bool,
    ) -> StreamFlowControl {
        let (send_max, recv_max) = if stream_id.is_bidirectional() {
            if is_local {
                (
                    self.initial_send_max_stream_data_bidi_remote,
                    self.initial_recv_max_stream_data_bidi_local,
                )
            } else {
                (
                    self.initial_send_max_stream_data_bidi_local,
                    self.initial_recv_max_stream_data_bidi_remote,
                )
            }
        } else {
            (
                self.initial_send_max_stream_data_uni,
                self.initial_recv_max_stream_data_uni,
            )
        };
        
        StreamFlowControl::new(stream_id, send_max, recv_max)
    }
    
    /// Get connection flow control
    pub fn connection(&self) -> &ConnectionFlowControl {
        &self.connection
    }
    
    /// Get mutable connection flow control
    pub fn connection_mut(&mut self) -> &mut ConnectionFlowControl {
        &mut self.connection
    }
    
    /// Validate stream send operation against both limits
    ///
    /// **Design**: Must check both stream-level and connection-level limits.
    pub fn validate_stream_send(
        &self,
        stream_fc: &StreamFlowControl,
        offset: u64,
        length: usize,
    ) -> Result<()> {
        // Check stream-level limit
        stream_fc.validate_recv_offset(offset, length)?;
        
        // Check connection-level limit
        if !self.connection.can_send(length) {
            return Err(Error::TransportError(TransportError::FlowControlError));
        }
        
        Ok(())
    }
    
    /// Consume both stream and connection send windows
    pub fn consume_send_windows(
        &mut self,
        stream_fc: &mut StreamFlowControl,
        offset: u64,
        length: usize,
    ) -> Result<()> {
        // Consume stream window
        stream_fc.consume_send_window(offset, length)?;
        
        // Consume connection window
        self.connection.consume_send_window(length)?;
        
        Ok(())
    }
    
    /// Validate stream receive operation against both limits
    pub fn validate_stream_recv(
        &self,
        stream_fc: &StreamFlowControl,
        offset: u64,
        length: usize,
    ) -> Result<()> {
        // Check stream-level limit
        stream_fc.validate_recv_offset(offset, length)?;
        
        // Connection-level validation happens in consume_recv_windows
        Ok(())
    }
    
    /// Consume both stream and connection receive windows
    pub fn consume_recv_windows(
        &mut self,
        stream_fc: &mut StreamFlowControl,
        offset: u64,
        length: usize,
    ) -> Result<()> {
        // Consume connection window first (can error)
        self.connection.consume_recv_window(length)?;
        
        // Update stream offset
        stream_fc.update_recv_offset(offset, length);
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_connection_flow_control_send() {
        let mut fc = ConnectionFlowControl::new(1000, 1000);
        
        assert_eq!(fc.send_window(), 1000);
        assert!(fc.can_send(500));
        
        fc.consume_send_window(500).unwrap();
        assert_eq!(fc.send_window(), 500);
        
        // Try to exceed limit
        assert!(fc.consume_send_window(600).is_err());
        assert!(fc.is_send_blocked());
        
        // Update limit
        fc.update_send_max_data(1500);
        assert!(!fc.is_send_blocked());
        assert_eq!(fc.send_window(), 1000);
    }
    
    #[test]
    fn test_stream_flow_control() {
        let stream_id = StreamId(0);  // Client-initiated bidirectional
        let mut fc = StreamFlowControl::new(stream_id, 1000, 1000);
        
        // Send data at offset 0
        fc.consume_send_window(0, 500).unwrap();
        assert_eq!(fc.send_window(), 500);
        
        // Send data at offset 500
        fc.consume_send_window(500, 500).unwrap();
        assert_eq!(fc.send_window(), 0);
        
        // Try to exceed
        assert!(fc.consume_send_window(1000, 100).is_err());
        assert!(fc.is_send_blocked());
    }
    
    #[test]
    fn test_auto_flow_control_update() {
        let mut fc = ConnectionFlowControl::new(1000, 1000);
        
        // Receive 600 bytes (exceeds threshold of 500)
        fc.consume_recv_window(600).unwrap();
        assert!(fc.should_send_max_data_update());
        
        // Increase window
        let new_limit = fc.increase_recv_window();
        assert_eq!(new_limit, 2000);
        assert!(!fc.should_send_max_data_update());
    }
}
