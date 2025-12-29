//! # QUIC Frame Parsing and Types (RFC 9000 Section 12.4, 19)
//!
//! All 22+ frame types defined in RFC 9000 with zero-copy parsing.
//! Frame payloads reference original packet buffer via lifetimes.

pub mod parse;
pub mod types;

pub use parse::{FrameIterator, FrameParser};
pub use types::*;
