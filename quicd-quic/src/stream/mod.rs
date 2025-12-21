//! # QUIC Stream Management (RFC 9000 Section 2)
//!
//! This module defines the stream state machine and data management for QUIC streams.
//!
//! ## Stream Lifecycle
//!
//! QUIC streams are bidirectional or unidirectional byte streams with independent
//! flow control. Each stream has a unique 62-bit identifier.
//!
//! ### Bidirectional Stream States (RFC 9000 Section 3.4)
//!
//! ```text
//! Sending Side:
//!   Ready → Send → Data Sent → Reset Sent
//!                     ↓
//!                 Data Recvd
//!
//! Receiving Side:
//!   Recv → Size Known → Data Recvd → Reset Recvd
//! ```
//!
//! ### Unidirectional Stream States (RFC 9000 Section 3.3)
//!
//! Unidirectional streams have only one direction (send or receive), so they
//! follow a simplified version of the bidirectional state machine.
//!
//! ## Flow Control (RFC 9000 Section 4)
//!
//! Each stream has independent flow control managed by MAX_STREAM_DATA frames:
//! - **Send-side limit**: How much data we can send (peer's advertised limit)
//! - **Receive-side limit**: How much data we allow the peer to send
//!
//! ## Zero-Copy Data Management
//!
//! Stream data is managed using references to packet buffers. The reassembly
//! buffer handles out-of-order data delivery without copying.

#![forbid(unsafe_code)]

use crate::error::{Error, Result, TransportError};
use crate::frames::StreamId;
use core::fmt;

pub mod buffer;

// ============================================================================
// Stream State Machine (RFC 9000 Section 3)
// ============================================================================

/// Stream Send State (RFC 9000 Section 3.1)
///
/// Tracks the state of the sending half of a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendState {
    /// Ready: Stream is ready to send data
    ///
    /// Transitions:
    /// - To `Send` when data is queued or STREAM frame sent
    /// - To `ResetSent` if RESET_STREAM frame sent
    Ready,
    
    /// Send: Stream is actively sending data
    ///
    /// Transitions:
    /// - To `DataSent` when all data is sent and FIN is sent
    /// - To `ResetSent` if RESET_STREAM frame sent
    Send,
    
    /// DataSent: All data including FIN has been sent
    ///
    /// Transitions:
    /// - To `DataRecvd` when all sent data is acknowledged
    /// - To `ResetSent` if RESET_STREAM frame sent (error during ack wait)
    DataSent,
    
    /// DataRecvd: All sent data has been acknowledged
    ///
    /// This is a terminal state. The stream sending half is complete.
    DataRecvd,
    
    /// ResetSent: RESET_STREAM frame has been sent
    ///
    /// Transitions:
    /// - To `ResetRecvd` when peer acknowledges the reset
    ResetSent,
    
    /// ResetRecvd: Peer has acknowledged the reset
    ///
    /// This is a terminal state.
    ResetRecvd,
}

/// Stream Receive State (RFC 9000 Section 3.2)
///
/// Tracks the state of the receiving half of a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvState {
    /// Recv: Stream is receiving data
    ///
    /// Transitions:
    /// - To `SizeKnown` when STREAM frame with FIN is received
    /// - To `ResetRecvd` if RESET_STREAM frame received
    Recv,
    
    /// SizeKnown: Final size of stream is known (FIN received)
    ///
    /// Transitions:
    /// - To `DataRecvd` when all data up to final size is received
    /// - To `ResetRecvd` if RESET_STREAM frame received
    SizeKnown,
    
    /// DataRecvd: All data has been received and delivered to application
    ///
    /// This is a terminal state. The stream receiving half is complete.
    DataRecvd,
    
    /// ResetRecvd: RESET_STREAM frame has been received
    ///
    /// This is a terminal state. The stream was aborted by the peer.
    ResetRecvd,
}

/// Combined Stream State for Bidirectional Streams
///
/// Bidirectional streams have independent send and receive state machines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BidirectionalStreamState {
    pub send: SendState,
    pub recv: RecvState,
}

impl BidirectionalStreamState {
    /// Check if the stream is fully closed (both halves complete)
    pub fn is_closed(&self) -> bool {
        matches!(
            (self.send, self.recv),
            (SendState::DataRecvd | SendState::ResetRecvd, RecvState::DataRecvd | RecvState::ResetRecvd)
        )
    }
}

// ============================================================================
// Stream Flow Control (RFC 9000 Section 4)
// ============================================================================

/// Stream-Level Flow Control State
///
/// Tracks send and receive limits for a single stream.
#[derive(Debug, Clone, Copy)]
pub struct StreamFlowControl {
    /// Maximum data we can send (advertised by peer via MAX_STREAM_DATA)
    pub max_send_data: u64,
    
    /// Total data sent on this stream
    pub sent_data: u64,
    
    /// Maximum data we allow peer to send (our advertised limit)
    pub max_recv_data: u64,
    
    /// Total data received on this stream
    pub recv_data: u64,
}

impl StreamFlowControl {
    /// Create new flow control state with initial limits
    pub const fn new(initial_max_send: u64, initial_max_recv: u64) -> Self {
        Self {
            max_send_data: initial_max_send,
            sent_data: 0,
            max_recv_data: initial_max_recv,
            recv_data: 0,
        }
    }
    
    /// Check if we can send more data (have send credit)
    pub fn can_send(&self) -> bool {
        self.sent_data < self.max_send_data
    }
    
    /// Get available send credit (how much more we can send)
    pub fn send_credit(&self) -> u64 {
        self.max_send_data.saturating_sub(self.sent_data)
    }
    
    /// Check if peer is blocked (exceeded receive limit)
    pub fn is_peer_blocked(&self) -> bool {
        self.recv_data >= self.max_recv_data
    }
    
    /// Update max send data (from MAX_STREAM_DATA frame)
    pub fn update_max_send(&mut self, new_max: u64) -> Result<()> {
        if new_max < self.max_send_data {
            // RFC 9000 Section 4.1: Reducing the limit is a protocol violation
            return Err(Error::Transport(TransportError::FlowControlError));
        }
        self.max_send_data = new_max;
        Ok(())
    }
    
    /// Record sent data (updates sent_data counter)
    pub fn record_sent(&mut self, amount: u64) -> Result<()> {
        self.sent_data += amount;
        if self.sent_data > self.max_send_data {
            return Err(Error::Transport(TransportError::FlowControlError));
        }
        Ok(())
    }
    
    /// Record received data (updates recv_data counter)
    pub fn record_recv(&mut self, amount: u64) -> Result<()> {
        self.recv_data += amount;
        if self.recv_data > self.max_recv_data {
            return Err(Error::Transport(TransportError::FlowControlError));
        }
        Ok(())
    }
}

// ============================================================================
// Stream Metadata
// ============================================================================

/// Stream Metadata and State
///
/// This struct represents the control state for a QUIC stream, excluding
/// the actual data buffers (which are managed separately by the reassembly buffer).
#[derive(Debug, Clone)]
pub struct StreamMeta {
    /// Stream identifier
    pub id: StreamId,
    
    /// Send state (None for receive-only unidirectional streams)
    pub send_state: Option<SendState>,
    
    /// Receive state (None for send-only unidirectional streams)
    pub recv_state: Option<RecvState>,
    
    /// Flow control state
    pub flow_control: StreamFlowControl,
    
    /// Final size of the stream (set when FIN received or sent)
    pub final_size: Option<u64>,
    
    /// Application error code if stream was reset
    pub reset_error_code: Option<u64>,
}

impl StreamMeta {
    /// Create metadata for a new bidirectional stream
    pub fn new_bidirectional(
        id: StreamId,
        initial_max_send: u64,
        initial_max_recv: u64,
    ) -> Self {
        Self {
            id,
            send_state: Some(SendState::Ready),
            recv_state: Some(RecvState::Recv),
            flow_control: StreamFlowControl::new(initial_max_send, initial_max_recv),
            final_size: None,
            reset_error_code: None,
        }
    }
    
    /// Create metadata for a send-only unidirectional stream
    pub fn new_send_only(id: StreamId, initial_max_send: u64) -> Self {
        Self {
            id,
            send_state: Some(SendState::Ready),
            recv_state: None,
            flow_control: StreamFlowControl::new(initial_max_send, 0),
            final_size: None,
            reset_error_code: None,
        }
    }
    
    /// Create metadata for a receive-only unidirectional stream
    pub fn new_recv_only(id: StreamId, initial_max_recv: u64) -> Self {
        Self {
            id,
            send_state: None,
            recv_state: Some(RecvState::Recv),
            flow_control: StreamFlowControl::new(0, initial_max_recv),
            final_size: None,
            reset_error_code: None,
        }
    }
    
    /// Check if stream is bidirectional
    pub fn is_bidirectional(&self) -> bool {
        self.send_state.is_some() && self.recv_state.is_some()
    }
    
    /// Check if stream is fully closed (both halves complete)
    pub fn is_closed(&self) -> bool {
        let send_closed = self.send_state
            .map(|s| matches!(s, SendState::DataRecvd | SendState::ResetRecvd))
            .unwrap_or(true);
        
        let recv_closed = self.recv_state
            .map(|r| matches!(r, RecvState::DataRecvd | RecvState::ResetRecvd))
            .unwrap_or(true);
        
        send_closed && recv_closed
    }
    
    /// Transition send state
    pub fn transition_send(&mut self, new_state: SendState) -> Result<()> {
        if let Some(ref mut send_state) = self.send_state {
            *send_state = new_state;
            Ok(())
        } else {
            Err(Error::Transport(TransportError::StreamStateError))
        }
    }
    
    /// Transition receive state
    pub fn transition_recv(&mut self, new_state: RecvState) -> Result<()> {
        if let Some(ref mut recv_state) = self.recv_state {
            *recv_state = new_state;
            Ok(())
        } else {
            Err(Error::Transport(TransportError::StreamStateError))
        }
    }
}

// ============================================================================
// Stream Manager Trait
// ============================================================================

/// Stream Manager Interface
///
/// Defines the operations for managing multiple streams within a connection.
/// Implementations handle stream lifecycle, flow control, and data buffering.
pub trait StreamManager {
    /// Open a new bidirectional stream
    ///
    /// Returns the stream ID of the newly created stream.
    ///
    /// **Errors**:
    /// - `StreamLimitError` if the stream limit has been reached
    fn open_bidirectional_stream(&mut self) -> Result<StreamId>;
    
    /// Open a new unidirectional stream
    ///
    /// Returns the stream ID of the newly created stream.
    fn open_unidirectional_stream(&mut self) -> Result<StreamId>;
    
    /// Get mutable reference to stream metadata
    ///
    /// Returns `None` if the stream does not exist.
    fn get_stream_mut(&mut self, stream_id: StreamId) -> Option<&mut StreamMeta>;
    
    /// Check if a stream exists
    fn has_stream(&self, stream_id: StreamId) -> bool;
    
    /// Remove a closed stream from the manager
    ///
    /// This should be called when a stream reaches a terminal state to
    /// free resources.
    fn remove_stream(&mut self, stream_id: StreamId) -> Result<()>;
    
    /// Get the maximum number of concurrent streams allowed
    ///
    /// - `bidirectional`: If true, return limit for bidirectional streams,
    ///   otherwise return limit for unidirectional streams
    fn max_streams(&self, bidirectional: bool) -> u64;
    
    /// Update the maximum number of concurrent streams
    ///
    /// Called when a MAX_STREAMS frame is received.
    fn update_max_streams(&mut self, maximum_streams: u64, bidirectional: bool) -> Result<()>;
}

// ============================================================================
// Display Implementations
// ============================================================================

impl fmt::Display for SendState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SendState::Ready => write!(f, "Ready"),
            SendState::Send => write!(f, "Send"),
            SendState::DataSent => write!(f, "DataSent"),
            SendState::DataRecvd => write!(f, "DataRecvd"),
            SendState::ResetSent => write!(f, "ResetSent"),
            SendState::ResetRecvd => write!(f, "ResetRecvd"),
        }
    }
}

impl fmt::Display for RecvState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecvState::Recv => write!(f, "Recv"),
            RecvState::SizeKnown => write!(f, "SizeKnown"),
            RecvState::DataRecvd => write!(f, "DataRecvd"),
            RecvState::ResetRecvd => write!(f, "ResetRecvd"),
        }
    }
}
