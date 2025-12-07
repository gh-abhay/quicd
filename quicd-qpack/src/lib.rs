//! QPACK: Header Compression for HTTP/3 (RFC 9204)
//!
//! This crate provides a production-grade, lock-free, zero-copy implementation
//! of QPACK header compression for HTTP/3.
//!
//! # Features
//!
//! - **100% RFC 9204 compliant**: Full support for static table, dynamic table,
//!   encoder/decoder streams, and all instruction types.
//! - **Safe**: 100% Safe Rust implementation with no `unsafe` blocks.
//! - **Zero-copy**: Bytes-based storage and parsing minimizes allocations.
//! - **High performance**: Optimized for >10M header block ops/sec.
//! - **no_std compatible**: Works in embedded environments with `alloc`.
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

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod config;
pub mod decoder;
pub mod encoder;
pub mod error;
pub mod tables;
pub mod wire;

#[cfg(feature = "async")]
pub mod async_io;

// Re-export main types
pub use config::QpackConfig;
pub use decoder::{Decoder, HeaderField};
pub use encoder::{should_never_index, Encoder};
pub use error::{QpackError, Result};
pub use tables::DynamicTable;

#[cfg(feature = "async")]
pub use async_io::{AsyncDecoder, AsyncEncoder};

// Re-export utilities for benchmarking and testing
pub use wire::huffman::{decode as huffman_decode, decode_into as huffman_decode_into, 
                   encode, encode_into as huffman_encode_into, encoded_size};
pub use wire::prefix_int::{decode_int, encode_int};
