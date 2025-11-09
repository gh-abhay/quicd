//! HTTP/3 implementation for quicd.
//!
//! This crate provides HTTP/3 protocol support on top of the quicd QUIC server.
//! It implements the HTTP/3 session management, QPACK header compression,
//! frame parsing/encoding, and provides a clean API for applications to handle
//! HTTP requests and send responses.

pub mod error;
pub mod frames;
pub mod qpack;
pub mod session;
pub mod h3_session;

pub use error::{H3Error, H3ErrorCode};
pub use frames::H3Frame;
pub use qpack::QpackCodec;
pub use session::{DefaultH3Handler, H3Handler, H3Request, H3ResponseSender};
pub use h3_session::{H3Factory, H3Session};