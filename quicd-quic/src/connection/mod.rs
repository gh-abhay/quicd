//! # QUIC Connection State Machine (RFC 9000 Section 5)
//!
//! Top-level connection management with event-driven interface.

pub mod cid_manager;
pub mod state;

#[cfg(test)]
mod tests;

pub use cid_manager::{
    ConnectionIdGenerator, ConnectionIdManager, NewConnectionIdData, RandomConnectionIdGenerator,
};
pub use state::{
    Connection, ConnectionConfig, ConnectionEvent, ConnectionState, DatagramInput, DatagramOutput,
};
