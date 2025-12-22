//! # QUIC Connection State Machine (RFC 9000 Section 5)
//!
//! Top-level connection management with event-driven interface.

pub mod state;

pub use state::{Connection, ConnectionConfig, ConnectionEvent, ConnectionState, DatagramInput, DatagramOutput};
