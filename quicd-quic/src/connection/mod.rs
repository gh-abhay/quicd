//! # QUIC Connection State Machine (RFC 9000)
//!
//! This module defines the **top-level connection state machine** that orchestrates
//! all QUIC subsystems: crypto, streams, recovery, flow control, and packet processing.
//!
//! ## Pure State Machine Design
//!
//! The connection is a **pure state machine** with **no I/O dependencies**:
//! - **Input**: Accepts incoming datagrams (`&[u8]`) and time (`Instant`)
//! - **Output**: Produces outgoing datagrams via caller-provided buffers (`&mut [u8]`)
//! - **Deterministic**: State transitions depend only on inputs and time
//!
//! ## Architecture
//!
//! ```text
//! ┌────────────────────────────────────────────────────────┐
//! │               QuicConnection (Main State Machine)       │
//! ├────────────────────────────────────────────────────────┤
//! │ • Connection State (Handshaking, Active, Closing, etc.) │
//! │ • Connection ID Management                              │
//! │ • Timer Management (Idle, PTO, Close, etc.)             │
//! │ • Orchestrates all subsystems                           │

pub mod state;

pub use state::{
    Connection, ConnectionBuilder, ConnectionConfig, ConnectionEvent, ConnectionIdManager,
    ConnectionState, ConnectionStats, Datagram, PacketSpaceManager,
};
