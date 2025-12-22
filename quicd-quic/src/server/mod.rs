//! # QUIC Server State Machine
//!
//! RFC 9000 Section 7

#![forbid(unsafe_code)]

pub mod session;
pub mod accept;

pub use accept::{
    AcceptResult, ConnectionIdGenerator, InitialPacketInfo, Server, ServerBuilder, ServerConfig,
    TokenGenerator,
};
