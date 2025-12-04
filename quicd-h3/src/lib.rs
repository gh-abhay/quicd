//! HTTP/3 implementation for quicd.
//!
//! This crate provides HTTP/3 protocol support on top of the quicd QUIC server.
//! It implements the HTTP/3 session management, QPACK header compression,
//! frame parsing/encoding, and provides a clean API for applications to handle
//! HTTP requests and send responses.

pub mod config;
pub mod connect;
pub mod error;
pub mod frames;
pub mod h3_session;
pub mod metrics;
pub mod priority;
pub mod push;
pub mod session;
pub mod settings;
pub mod settings_storage;
pub mod stream_state;
pub mod stream_validation;
pub mod validation;

pub use config::{H3Config, H3ConfigBuilder, H3ConfigPreset};
pub use error::{H3Error, H3ErrorCode};
pub use frames::H3Frame;
pub use h3_session::{H3Factory, H3Session};
pub use metrics::{H3Metrics, MetricsSnapshot};
pub use session::{DefaultH3Handler, H3Handler, H3Request, H3ResponseSender};
