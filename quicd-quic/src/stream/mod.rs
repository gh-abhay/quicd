//! # Stream State Machine (RFC 9000 Section 2, 3)
//!
//! Stream states, reassembly buffers, and zero-copy data access.

pub mod manager;
pub mod buffer;

pub use manager::{StreamController, StreamEvent, StreamManager, StreamState};
pub use buffer::{ReceiveBuffer, SendBuffer, StreamData};

// Re-export StreamId from types module
pub use crate::types::StreamId;

// Stub Stream type for main binary compatibility
#[derive(Debug)]
pub struct Stream;
