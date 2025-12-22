//! # QUIC Connection State Machine (RFC 9000 Section 5)
//!
//! Top-level connection management with event-driven interface.

pub mod cid_manager;
// TODO: facade module is incomplete design doc, not yet functional
// pub mod facade;
pub mod state;

pub use cid_manager::{ConnectionIdGenerator, ConnectionIdManager, NewConnectionIdData, RandomConnectionIdGenerator};
pub use state::{Connection, ConnectionConfig, ConnectionEvent, ConnectionState, DatagramInput, DatagramOutput};
