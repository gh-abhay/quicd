//! # quicd-hq-interop: HTTP/0.9 over QUIC Implementation
//!
//! This crate provides the `hq-interop` protocol implementation for interoperability
//! testing. The protocol is a simplified HTTP/0.9-style interface over QUIC:
//!
//! - Client sends plain text GET request: `GET /path\r\n`
//! - Server responds with raw file content (no headers)
//! - Used by QUIC interop test suite for basic connectivity testing
//!
//! ## Architecture
//!
//! Like `quicd-h3`, this follows strict separation of concerns:
//! - **Protocol Layer** (`HqInteropApplication`): Handles request parsing and response framing
//! - **Handler Layer** (`FileHandler` trait): Business logic abstraction
//! - **Default Handler** (`StaticFileHandler`): Serves files from www directory

pub mod config;
pub mod error;
pub mod handler;

mod connection;

pub use config::{HandlerConfig, HqInteropConfig};
pub use connection::HqInteropApplication;
pub use error::{Error, Result};
pub use handler::StaticFileHandler;

// Re-export QuicdApplication trait for convenience
pub use quicd_x::QuicdApplication;
