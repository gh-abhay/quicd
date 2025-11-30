//! QPACK: Header Compression for HTTP/3 (RFC 9204)
//! 
//! This crate provides a production-grade, lock-free, zero-copy implementation
//! of QPACK header compression for HTTP/3.
//! 
//! # Features
//! 
//! - **100% RFC 9204 compliant**: Full support for static table, dynamic table,
//!   encoder/decoder streams, and all instruction types.
//! - **Lock-free**: Concurrent readers, single writer with atomic operations.
//! - **Zero-copy**: Bytes-based storage and parsing minimizes allocations.
//! - **High performance**: Optimized for >10M header block ops/sec.
//! 
//! # Example
//! 
//! ```rust
//! use quicd_qpack::{Encoder, Decoder};
//! 
//! // Create encoder and decoder
//! let mut encoder = Encoder::new(4096, 100);
//! let mut decoder = Decoder::new(4096, 100);
//! 
//! // Encode headers
//! let headers = vec![
//!     (b":method".as_slice(), b"GET".as_slice()),
//!     (b":path".as_slice(), b"/".as_slice()),
//! ];
//! let encoded = encoder.encode(0, &headers).unwrap();
//! 
//! // Decode headers
//! let decoded = decoder.decode(0, encoded).unwrap();
//! ```

pub mod error;
pub mod config;
pub mod prefix_int;
pub mod static_table;
pub mod table;
pub mod instructions;
pub mod header_block;
pub mod encoder;
pub mod decoder;
pub mod huffman;

#[cfg(feature = "async")]
pub mod async_io;

// Re-export main types
pub use config::QpackConfig;
pub use encoder::{Encoder, should_never_index};
pub use decoder::{Decoder, HeaderField};
pub use error::{QpackError, Result};
pub use table::DynamicTable;

#[cfg(feature = "async")]
pub use async_io::{AsyncEncoder, AsyncDecoder};

// Re-export utilities for benchmarking and testing
pub use prefix_int::{encode_int, decode_int};
pub use huffman::{encode, decode as huffman_decode, encoded_size};