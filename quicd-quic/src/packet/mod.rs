//! # QUIC Packet Parsing (RFC 9000 Section 12, 17)
//!
//! This module handles packet headers, packet numbers, and packet number spaces.
//!
//! ## Packet Number Spaces (RFC 9000 Section 12.3)
//!
//! QUIC uses three separate packet number spaces, each with independent packet numbering:
//! - **Initial**: For Initial packets during handshake
//! - **Handshake**: For Handshake packets during handshake  
//! - **ApplicationData**: For 0-RTT and 1-RTT packets (application data)
//!
//! ## Packet Numbers (RFC 9000 Section 12.3, 17.1)
//!
//! Packet numbers are 62-bit integers that increase monotonically within a packet number space.
//! They are encoded using variable-length encoding (1-4 bytes) in packet headers.

pub mod header;
pub mod number;
pub mod space;

// Re-export core types from crate::types
pub use crate::types::{PacketNumber, PacketNumberSpace};

