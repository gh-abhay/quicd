# quicd-qpack

A production-ready, high-performance, zero-copy implementation of **RFC 9204: QPACK: Field Compression for HTTP/3**.

## Features

- **100% RFC 9204 Compliant**: Full implementation of QPACK field compression for HTTP/3
- **Zero-Copy Design**: Uses `bytes::Bytes` throughout for minimal allocations
- **High Performance**: 
  - Tree-based Huffman decoder for O(1) average-case decoding
  - LIFO buffer pool strategy for cache efficiency
  - Optimized for minimal memory allocations
- **Complete API**: 
  - Static table (99 predefined entries)
  - Dynamic table with circular buffer and eviction
  - Huffman encoding/decoding
  - All encoder and decoder stream instructions
  - Blocking stream handling

## Compliance

Implements the following RFCs:
- **RFC 9204**: QPACK: Field Compression for HTTP/3
- **RFC 7541**: HPACK (Huffman coding table reused from Section 5.2)

## Usage

```rust
use quicd_qpack::{Encoder, Decoder, FieldLine};
use bytes::Bytes;

// Create encoder and decoder
let mut encoder = Encoder::new(4096, 100);
let mut decoder = Decoder::new(4096, 100);

// Encode HTTP headers
let headers = vec![
    FieldLine::new(Bytes::from(":method"), Bytes::from("GET")),
    FieldLine::new(Bytes::from(":scheme"), Bytes::from("https")),
    FieldLine::new(Bytes::from(":path"), Bytes::from("/")),
    FieldLine::new(Bytes::from(":authority"), Bytes::from("example.com")),
];

let (encoded, encoder_instructions) = encoder.encode_field_section(0, &headers)?;

// Process encoder instructions on decoder
for instruction in encoder_instructions {
    decoder.process_encoder_instruction(&instruction)?;
}

// Decode field section
let decoded = decoder.decode_field_section(0, &encoded)?;

assert_eq!(decoded.len(), headers.len());
```

## Architecture

### Encoder
- Encodes HTTP header field sections using static and dynamic table compression
- Generates encoder stream instructions for dynamic table updates
- Tracks blocked streams waiting for table synchronization
- Supports both Huffman and literal string encoding

### Decoder
- Decodes field sections with support for all representation types
- Processes encoder stream instructions to maintain dynamic table
- Handles blocked streams and automatic retry
- Generates decoder stream instructions (acknowledgments, cancellations)

### Components

- **Static Table**: 99 predefined HTTP header entries (RFC 9204 Appendix A)
- **Dynamic Table**: Circular buffer with FIFO eviction and multiple indexing modes
- **Huffman Coding**: Canonical Huffman table from RFC 7541 with tree-based decoder
- **Instructions**: Full support for all 7 instruction types across encoder/decoder streams
- **Integer Encoding**: Prefix integer encoding with 1-8 bit prefixes

## Testing

The crate includes comprehensive tests:
- 45 unit tests covering all components
- 9 integration tests for end-to-end scenarios
- 3 documentation tests
- Property-based tests with `proptest`

Run tests:
```bash
cargo test -p quicd-qpack
```

## Performance

Designed for high-performance HTTP/3 implementations:
- Zero-copy buffer management
- Minimal allocations during encode/decode
- Tree-based Huffman decoder (vs linear search)
- Efficient dynamic table with O(1) insertion and lookup

## License

Same as the parent `quicd` project.
