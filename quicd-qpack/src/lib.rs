//! # quicd-qpack: High-Performance QPACK Implementation for HTTP/3
//!
//! This crate provides a production-ready, zero-copy implementation of
//! **RFC 9204: QPACK - Field Compression for HTTP/3**.
//!
//! QPACK is a compression format for efficiently representing HTTP header and trailer fields
//! (collectively called "fields") for use with HTTP/3. It builds upon HPACK (RFC 7541) but
//! is redesigned to allow correct operation in the presence of out-of-order delivery,
//! which is inherent to HTTP/3's use of QUIC streams.
//!
//! ## Features
//!
//! - **RFC 9204 Compliant**: Implements the complete QPACK specification
//! - **Zero-Copy Design**: Uses `bytes::Bytes` for minimal allocations
//! - **High Performance**: Optimized for throughput exceeding 1M headers/sec
//! - **Safe & Correct**: Defensive parsing with comprehensive error handling
//! - **Static & Dynamic Tables**: Full support for both compression tables
//! - **Huffman Encoding**: Efficient canonical Huffman implementation
//! - **Stream Blocking**: Correct handling of blocked streams per RFC requirements
//!
//! ## Three-Stream Model
//!
//! QPACK operates using three types of streams:
//!
//! 1. **Encoder Stream** (unidirectional, 0x02): Carries encoder instructions to modify
//!    the dynamic table (insertions, duplications, capacity changes)
//! 2. **Decoder Stream** (unidirectional, 0x03): Carries decoder instructions for
//!    synchronization (acknowledgments, cancellations, insert count increments)
//! 3. **Request/Response Streams** (HTTP/3 streams): Carry encoded field sections
//!
//! ## Basic Usage
//!
//! ```rust,no_run
//! use quicd_qpack::{Encoder, Decoder, FieldLine};
//! use bytes::Bytes;
//!
//! // Create encoder with 4096-byte dynamic table capacity
//! let mut encoder = Encoder::new(4096, 0);
//!
//! // Create decoder with same capacity and allowing 100 blocked streams
//! let mut decoder = Decoder::new(4096, 100);
//!
//! // Encode a list of header fields
//! let headers = vec![
//!     FieldLine::new(":method", "GET"),
//!     FieldLine::new(":path", "/"),
//!     FieldLine::new(":scheme", "https"),
//!     FieldLine::new(":authority", "example.com"),
//! ];
//!
//! let stream_id = 0;
//! let (encoded_section, encoder_instructions) = encoder.encode_field_section(stream_id, &headers).unwrap();
//!
//! // Decode the field section
//! let decoded_headers = decoder.decode_field_section(stream_id, &encoded_section).unwrap();
//! ```
//!
//! ## Module Organization
//!
//! - [`error`]: Error types for all QPACK operations
//! - [`integer`]: Prefix integer encoding/decoding (RFC 7541 Section 5.1)
//! - [`huffman`]: Huffman encoding/decoding (RFC 7541 Appendix B)
//! - [`static_table`]: QPACK static table (RFC 9204 Appendix A)
//! - [`dynamic_table`]: Dynamic table with circular buffer
//! - [`instructions`]: Encoder and decoder stream instructions
//! - [`field_line`]: Field line representations
//! - [`encoder`]: QPACK encoder implementation
//! - [`decoder`]: QPACK decoder implementation

pub mod decoder;
pub mod dynamic_table;
pub mod encoder;
pub mod error;
pub mod field_line;
pub mod huffman;
pub mod instructions;
pub mod integer;
pub mod static_table;

// Re-export main types for convenience
pub use decoder::Decoder;
pub use encoder::Encoder;
pub use error::{Error, Result};
pub use field_line::FieldLine;
pub use instructions::{DecoderInstruction, EncoderInstruction};
