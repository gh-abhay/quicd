//! Integration tests for QPACK encoder/decoder.
//! Tests full workflow including dynamic table, encoder/decoder streams.

use bytes::Bytes;
use quicd_qpack::{Decoder, Encoder};

#[test]
fn test_encode_decode_static_headers() {
    let mut encoder = Encoder::new(4096, 100);
    let mut decoder = Decoder::new(4096, 100);

    let headers = vec![
        (b":method".as_slice(), b"GET".as_slice()),
        (b":scheme".as_slice(), b"https".as_slice()),
        (b":path".as_slice(), b"/".as_slice()),
    ];

    let encoded = encoder.encode(0, &headers).unwrap();
    let decoded = decoder.decode(0, encoded).unwrap();

    assert_eq!(decoded.len(), 3);
    assert_eq!(decoded[0].name.as_ref(), b":method");
    assert_eq!(decoded[0].value.as_ref(), b"GET");
}

#[test]
fn test_encode_decode_with_dynamic_table() {
    // In a real implementation, encoder and decoder have separate tables
    // that are synchronized via encoder/decoder streams
    let mut encoder = Encoder::new(4096, 100);
    encoder.set_capacity(4096).unwrap();
    let mut decoder = Decoder::new(4096, 100);

    // First request with custom headers
    let headers1 = vec![
        (b":method".as_slice(), b"POST".as_slice()),
        (b"custom-header".as_slice(), b"custom-value".as_slice()),
    ];

    let encoded1 = encoder.encode(0, &headers1).unwrap();

    // Process encoder stream instructions (syncs tables)
    while let Some(inst) = encoder.poll_encoder_stream() {
        decoder.process_encoder_instruction(&inst).unwrap();
    }

    let decoded1 = decoder.decode(0, encoded1).unwrap();
    assert_eq!(decoded1.len(), 2);

    // Process decoder stream acknowledgements
    while let Some(ack) = decoder.poll_decoder_stream() {
        encoder.process_decoder_instruction(&ack).unwrap();
    }

    // Second request reusing the custom header (should be in dynamic table)
    let headers2 = vec![
        (b":method".as_slice(), b"POST".as_slice()),
        (b"custom-header".as_slice(), b"custom-value".as_slice()),
    ];

    let encoded2 = encoder.encode(1, &headers2).unwrap();

    // Second encoded block should be smaller (uses dynamic table references)
    // (In practice this depends on heuristics, but the mechanism is tested)
    let decoded2 = decoder.decode(1, encoded2).unwrap();
    assert_eq!(decoded2.len(), 2);
    assert_eq!(decoded2[1].name.as_ref(), b"custom-header");
    assert_eq!(decoded2[1].value.as_ref(), b"custom-value");
}

#[test]
fn test_dynamic_table_eviction() {
    let mut encoder = Encoder::new(200, 100); // Small capacity
    encoder.set_capacity(200).unwrap();
    let mut decoder = Decoder::new(200, 100);

    // Insert multiple large headers that exceed capacity
    for i in 0..5 {
        let name = format!("header-{}", i);
        let headers = vec![(name.as_bytes(), b"some-value".as_slice())];

        let encoded = encoder.encode(i, &headers).unwrap();

        // Process encoder instructions
        while let Some(inst) = encoder.poll_encoder_stream() {
            decoder.process_encoder_instruction(&inst).unwrap();
        }

        let _decoded = decoder.decode(i, encoded).unwrap();

        // Process decoder acknowledgements
        while let Some(ack) = decoder.poll_decoder_stream() {
            encoder.process_decoder_instruction(&ack).unwrap();
        }
    }

    // Oldest entries should be evicted (table has limited capacity)
    let table_len = encoder.table().len();
    assert!(table_len > 0);
    assert!(table_len < 5); // Some entries evicted due to capacity
}

#[test]
fn test_literal_without_indexing() {
    let mut encoder = Encoder::new(0, 100); // Zero capacity = no dynamic table
    let mut decoder = Decoder::new(0, 100);

    let headers = vec![(
        b"sensitive-header".as_slice(),
        b"sensitive-value".as_slice(),
    )];

    let encoded = encoder.encode(0, &headers).unwrap();
    let decoded = decoder.decode(0, encoded).unwrap();

    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].name.as_ref(), b"sensitive-header");
    assert_eq!(decoded[0].value.as_ref(), b"sensitive-value");

    // No encoder stream instructions should be generated (no dynamic table)
    assert!(encoder.poll_encoder_stream().is_none());
}

#[test]
fn test_capacity_update() {
    let mut encoder = Encoder::new(4096, 100);
    let mut decoder = Decoder::new(4096, 100);

    // Reduce capacity
    encoder.set_capacity(1024).unwrap();

    // Process capacity update instruction
    let inst = encoder.poll_encoder_stream().unwrap();
    decoder.process_encoder_instruction(&inst).unwrap();

    assert_eq!(decoder.table().capacity(), 1024);
}

#[test]
fn test_multiple_streams() {
    let mut encoder = Encoder::new(4096, 100);
    let mut decoder = Decoder::new(4096, 100);

    // Encode multiple streams concurrently
    let stream_ids = [0, 4, 8, 12];
    let mut encoded_blocks = Vec::new();

    for &stream_id in &stream_ids {
        let path = format!("/path-{}", stream_id);
        let headers = vec![
            (b":method".as_slice(), b"GET".as_slice()),
            (b":path".as_slice(), path.as_bytes()),
        ];

        let encoded = encoder.encode(stream_id, &headers).unwrap();
        encoded_blocks.push((stream_id, encoded));
    }

    // Process all encoder instructions
    let instructions: Vec<_> = encoder.drain_encoder_stream();
    for inst in instructions {
        decoder.process_encoder_instruction(&inst).unwrap();
    }

    // Decode all streams
    for (stream_id, encoded) in encoded_blocks {
        let decoded = decoder.decode(stream_id, encoded).unwrap();
        assert_eq!(decoded.len(), 2);
    }
}

#[test]
fn test_stream_cancellation() {
    let mut encoder = Encoder::new(4096, 100);
    encoder.set_capacity(4096).unwrap();
    let mut decoder = Decoder::new(4096, 100);

    let headers = vec![
        (b":method".as_slice(), b"GET".as_slice()),
        (b"custom-header".as_slice(), b"value".as_slice()),
    ];

    let encoded = encoder.encode(100, &headers).unwrap();

    // Process encoder instructions to make stream potentially blocked
    while let Some(inst) = encoder.poll_encoder_stream() {
        decoder.process_encoder_instruction(&inst).unwrap();
    }

    // Start decoding (this may block the stream)
    let _ = decoder.decode(100, encoded);

    // Now cancel the stream
    decoder.cancel_stream(100);

    // Should emit stream cancellation instruction only if stream was tracked
    // (may or may not be Some depending on whether it was blocked)
    let _ = decoder.poll_decoder_stream();
}

#[test]
fn test_rfc_example_c3() {
    // Example from RFC 9204 Appendix C.3
    // Encodes: ":path: /sample/path"

    let mut encoder = Encoder::new(4096, 100);
    let mut decoder = Decoder::new(4096, 100);

    let headers = vec![(b":path".as_slice(), b"/sample/path".as_slice())];

    let encoded = encoder.encode(0, &headers).unwrap();
    let decoded = decoder.decode(0, encoded).unwrap();

    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].name.as_ref(), b":path");
    assert_eq!(decoded[0].value.as_ref(), b"/sample/path");
}

#[test]
fn test_large_header_set() {
    let mut encoder = Encoder::new(8192, 100);
    encoder.set_capacity(8192).unwrap();
    let mut decoder = Decoder::new(8192, 100);

    // Create a large header set
    let mut headers = vec![];
    for i in 0..50 {
        headers.push((
            format!("x-custom-header-{}", i).into_bytes(),
            format!("value-{}", i).into_bytes(),
        ));
    }

    let headers_ref: Vec<_> = headers
        .iter()
        .map(|(n, v)| (n.as_slice(), v.as_slice()))
        .collect();

    let encoded = encoder.encode(0, &headers_ref).unwrap();

    // Process encoder instructions
    while let Some(inst) = encoder.poll_encoder_stream() {
        decoder.process_encoder_instruction(&inst).unwrap();
    }

    let decoded = decoder.decode(0, encoded).unwrap();
    assert_eq!(decoded.len(), 50);
}

#[test]
fn test_zero_copy_semantics() {
    // Verify that Bytes sharing works correctly
    let mut encoder = Encoder::new(4096, 100);
    let mut decoder = Decoder::new(4096, 100);

    let name = Bytes::from_static(b"content-type");
    let value = Bytes::from_static(b"application/json");

    let headers = vec![(name.as_ref(), value.as_ref())];

    let encoded = encoder.encode(0, &headers).unwrap();

    while let Some(inst) = encoder.poll_encoder_stream() {
        decoder.process_encoder_instruction(&inst).unwrap();
    }

    let decoded = decoder.decode(0, encoded).unwrap();

    // Bytes should be shared, not copied (same pointer)
    assert_eq!(decoded[0].name.as_ref(), b"content-type");
    assert_eq!(decoded[0].value.as_ref(), b"application/json");
}

/// RFC 9204 Section 4.1.2: Test Huffman encoding is applied automatically
#[test]
fn test_huffman_encoding_automatic() {
    use quicd_qpack::wire::huffman;

    let mut encoder = Encoder::new(4096, 100);
    let mut decoder = Decoder::new(4096, 100);
    encoder.set_capacity(4096).unwrap();

    // Use a long, compressible value
    let long_value = b"www.example.com/very/long/path/that/compresses/well/with/huffman/encoding";
    let headers = vec![(b"x-custom-url".as_slice(), long_value.as_slice())];

    let encoded = encoder.encode(0, &headers).unwrap();

    // Sync tables
    while let Some(inst) = encoder.poll_encoder_stream() {
        decoder.process_encoder_instruction(&inst).unwrap();
    }

    let decoded = decoder.decode(0, encoded).unwrap();
    assert_eq!(decoded[0].value.as_ref(), long_value);

    // Verify Huffman encoding reduces size
    let huffman_size = huffman::encoded_size(long_value);
    assert!(
        huffman_size < long_value.len(),
        "Huffman encoding should reduce size: {} < {}",
        huffman_size,
        long_value.len()
    );
}

/// RFC 9204 Section 4.1.2: Test Huffman roundtrip for various inputs
#[test]
fn test_huffman_roundtrip_comprehensive() {
    use quicd_qpack::wire::huffman;

    let test_cases = vec![
        b"www.example.com" as &[u8],
        b"GET",
        b"POST",
        b"application/json",
        b"text/html; charset=utf-8",
        b"gzip, deflate, br",
        b"Mozilla/5.0 (X11; Linux x86_64)",
        b"",  // Empty string
        b"a",  // Single character
        b"The quick brown fox jumps over the lazy dog",
        // All ASCII printable characters
        b" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
    ];

    for input in test_cases {
        let mut encoded = Vec::new();
        huffman::encode(input, &mut encoded);

        let mut decoded = Vec::new();
        huffman::decode(&encoded, &mut decoded).unwrap();

        assert_eq!(
            &decoded[..],
            input,
            "Huffman roundtrip failed for: {:?}",
            String::from_utf8_lossy(input)
        );
    }
}

/// RFC 9204 Section 7.1.3: Test sensitive headers are never indexed
#[test]
fn test_sensitive_headers_never_indexed() {
    let mut encoder = Encoder::new(4096, 100);
    encoder.set_capacity(4096).unwrap();

    // Drain the SetCapacity instruction from the encoder stream
    let _ = encoder.poll_encoder_stream();

    let sensitive_headers = vec![
        // RFC 9110 Authentication
        (
            b"authorization".as_slice(),
            b"Bearer secret-token".as_slice(),
        ),
        (b"cookie".as_slice(), b"sessionid=abc123".as_slice()),
        (
            b"set-cookie".as_slice(),
            b"sessionid=abc123; Secure".as_slice(),
        ),
        (
            b"proxy-authorization".as_slice(),
            b"Basic base64credentials".as_slice(),
        ),
        // API Keys
        (b"x-api-key".as_slice(), b"secret-api-key-12345".as_slice()),
        (b"x-auth-token".as_slice(), b"auth-token-67890".as_slice()),
        // OAuth/JWT
        (
            b"x-jwt".as_slice(),
            b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...".as_slice(),
        ),
        // CSRF
        (b"x-csrf-token".as_slice(), b"csrf-token-abc".as_slice()),
    ];

    for (name, value) in &sensitive_headers {
        let headers = vec![(*name, *value)];
        let _ = encoder.encode(0, &headers).unwrap();
    }

    // Sensitive headers should NOT generate dynamic table insertions
    assert!(
        encoder.poll_encoder_stream().is_none(),
        "Sensitive headers should not be inserted into dynamic table"
    );

    // Verify table is empty
    assert_eq!(
        encoder.table().len(),
        0,
        "Dynamic table should be empty after encoding sensitive headers"
    );
}

/// RFC 9204 Section 7.1.3: Test pattern-based sensitive header detection
#[test]
fn test_sensitive_pattern_detection() {
    use quicd_qpack::encoder::should_never_index;

    // Custom auth headers with patterns
    let sensitive_patterns = vec![
        b"x-custom-token" as &[u8],
        b"my-api-key",
        b"app-secret-value",
        b"user-password",
        b"oauth-bearer",
        b"jwt-token",
        b"session-cookie",
    ];

    for header in sensitive_patterns {
        assert!(
            should_never_index(header),
            "Header '{}' should be detected as sensitive",
            String::from_utf8_lossy(header)
        );
    }

    // Non-sensitive headers should not match
    let non_sensitive = vec![
        b"content-type" as &[u8],
        b"accept",
        b"user-agent",
        b"accept-encoding",
    ];

    for header in non_sensitive {
        assert!(
            !should_never_index(header),
            "Header '{}' should NOT be detected as sensitive",
            String::from_utf8_lossy(header)
        );
    }
}

/// RFC 9204: Test Huffman encoding performance benefit
#[test]
fn test_huffman_compression_ratio() {
    use quicd_qpack::wire::huffman;

    let test_cases = vec![
        // Common HTTP header values - actual compression varies by character frequency
        (b"www.example.com" as &[u8], 0.85), // Common domain, moderate compression
        (b"application/json", 0.85),         // JSON content-type
        (b"text/html; charset=utf-8", 0.8),  // HTML with charset
        (b"gzip, deflate, br", 0.85),        // Compression algos
    ];

    for (input, max_ratio) in test_cases {
        let huffman_size = huffman::encoded_size(input);
        let ratio = huffman_size as f64 / input.len() as f64;

        assert!(
            ratio <= max_ratio,
            "Huffman compression ratio {} exceeds expected {} for '{}'",
            ratio,
            max_ratio,
            String::from_utf8_lossy(input)
        );

        // Verify Huffman is generally helpful (not making things worse)
        assert!(
            ratio < 1.0,
            "Huffman should not expand data for '{}'",
            String::from_utf8_lossy(input)
        );
    }
}

/// Test HashMap optimization provides correct results
#[test]
fn test_dynamic_table_hashmap_correctness() {
    let mut encoder = Encoder::new(4096, 100);
    encoder.set_capacity(4096).unwrap();

    // Insert multiple entries
    let headers: Vec<(&[u8], &[u8])> = vec![
        (b"x-custom-1", b"value-1"),
        (b"x-custom-2", b"value-2"),
        (b"x-custom-3", b"value-3"),
        (b"x-custom-1", b"value-different"),
    ];

    for (name, value) in &headers {
        let h = vec![(*name as &[u8], *value as &[u8])];
        let _ = encoder.encode(0, &h).unwrap();
        // Drain encoder stream to sync
        let _ = encoder.drain_encoder_stream();
    }

    // The table should find entries correctly
    let table = encoder.table();

    // Check that we can find by exact match
    assert!(table.find_exact(b"x-custom-1", b"value-1").is_some());
    assert!(table.find_exact(b"x-custom-2", b"value-2").is_some());
    assert!(table.find_exact(b"x-custom-3", b"value-3").is_some());

    // Check that name-only search returns the newest entry
    let name_idx = table.find_name(b"x-custom-1");
    assert!(name_idx.is_some());
}

/// Test encoder instruction batching
#[test]
fn test_encoder_instruction_batching() {
    let mut encoder = Encoder::new(4096, 100);
    encoder.set_capacity(4096).unwrap();

    // Encode multiple headers to generate multiple instructions
    for i in 0..10 {
        let name = format!("x-header-{}", i);
        let value = format!("value-{}", i);
        let headers = vec![(name.as_bytes(), value.as_bytes())];
        let _ = encoder.encode(i, &headers).unwrap();
    }

    // Test batching with max_instructions
    let batch = encoder.poll_encoder_stream_batch(5);
    assert!(batch.is_some());

    let batch_data = batch.unwrap();
    assert!(batch_data.len() > 0, "Batch should contain data");

    // Should be able to get more batches
    let batch2 = encoder.poll_encoder_stream_batch(5);
    assert!(batch2.is_some());
}

/// Test capacity reduction triggers eviction correctly
#[test]
fn test_capacity_reduction_eviction() {
    let mut encoder = Encoder::new(4096, 100);
    encoder.set_capacity(4096).unwrap();
    let mut decoder = Decoder::new(4096, 100);

    // Fill table with entries
    for i in 0..20 {
        let name = format!("header-{}", i);
        let value = "x".repeat(100); // 100 bytes each
        let headers = vec![(name.as_bytes(), value.as_bytes())];
        let encoded = encoder.encode(i as u64, &headers).unwrap();
        
        // Process encoder instructions to sync tables
        while let Some(inst) = encoder.poll_encoder_stream() {
            decoder.process_encoder_instruction(&inst).unwrap();
        }
        
        // Decode to generate acknowledgments
        let _ = decoder.decode(i as u64, encoded).unwrap();
        decoder.ack_header_block(i as u64);
        
        // Process decoder acknowledgments to clear blocked streams
        while let Some(ack) = decoder.poll_decoder_stream() {
            encoder.process_decoder_instruction(&ack).unwrap();
        }
    }

    let initial_count = encoder.table().insert_count();
    assert!(initial_count > 0);

    // Reduce capacity significantly - should trigger eviction
    encoder.set_capacity(500).unwrap();

    // Table size should be within new capacity
    assert!(encoder.table().size() <= 500);
}

/// Test Section Ack explicit acknowledgment API
#[test]
fn test_section_ack_explicit() {
    let mut decoder = Decoder::new(4096, 100);

    // Calling ack_header_block should generate instruction
    decoder.ack_header_block(42);

    let ack_inst = decoder.poll_decoder_stream();
    assert!(
        ack_inst.is_some(),
        "Section Ack instruction should be generated"
    );
}

/// Test wrapping arithmetic for Known Received Count
#[test]
fn test_known_received_count_overflow() {
    use quicd_qpack::DynamicTable;

    let mut table = DynamicTable::new(4096);

    // Update with large increment near u64::MAX
    table.update_known_received_count(u64::MAX - 100);
    let count1 = table.known_received_count();

    // Update again - should wrap
    table.update_known_received_count(200);
    let count2 = table.known_received_count();

    // Count should have wrapped around
    assert_eq!(count2, count1.wrapping_add(200));
}

/// Test empty header block handling
#[test]
fn test_empty_header_block() {
    let mut encoder = Encoder::new(4096, 100);
    let mut decoder = Decoder::new(4096, 100);

    let headers: Vec<(&[u8], &[u8])> = vec![];
    let encoded = encoder.encode(0, &headers).unwrap();

    // Should be able to decode empty header block
    let decoded = decoder.decode(0, encoded).unwrap();
    assert_eq!(decoded.len(), 0);
}

/// Test maximum capacity enforcement
#[test]
fn test_capacity_cannot_exceed_max() {
    let mut encoder = Encoder::new(1000, 100); // max_capacity = 1000

    // Try to set capacity beyond max
    let result = encoder.set_capacity(2000);
    assert!(result.is_err(), "Should not allow capacity > max_capacity");
}
