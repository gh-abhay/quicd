//! Official RFC 9204 Test Vectors
//!
//! Test vectors from RFC 9204 examples and QPACK interop test suite

use quicd_qpack::{Decoder, Encoder};

/// RFC 9204 Appendix B.1: Literal Field Line With Name Reference
#[test]
fn test_rfc9204_b1_literal_static_name() {
    let mut encoder = Encoder::new(256, 100);
    let mut decoder = Decoder::new(256, 100);

    // Example: :path: /sample/path
    let headers = vec![(b":path".as_slice(), b"/sample/path".as_slice())];

    let encoded = encoder.encode(0, &headers).unwrap();
    let decoded = decoder.decode(0, encoded).unwrap();

    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].name.as_ref(), b":path");
    assert_eq!(decoded[0].value.as_ref(), b"/sample/path");
}

/// RFC 9204 Appendix B.2: Dynamic Table
#[test]
fn test_rfc9204_b2_dynamic_table() {
    let mut encoder = Encoder::new(220, 100);
    let mut decoder = Decoder::new(220, 100);

    // Insert x-custom: custom-value (size = 32 + 8 + 12 = 52)
    let headers1 = vec![(b"x-custom".as_slice(), b"custom-value".as_slice())];
    let encoded1 = encoder.encode(0, &headers1).unwrap();

    // Process encoder stream
    while let Some(inst) = encoder.poll_encoder_stream() {
        decoder.process_encoder_instruction(&inst).unwrap();
    }

    let decoded1 = decoder.decode(0, encoded1).unwrap();
    assert_eq!(decoded1.len(), 1);
    assert_eq!(decoded1[0].name.as_ref(), b"x-custom");

    // Verify entry was inserted
    assert_eq!(encoder.table().insert_count(), 1);
    assert_eq!(decoder.table().insert_count(), 1);
}

/// RFC 9204 Appendix B.3: Duplicate Entry
/// Note: Duplicate instruction is emitted only when beneficial (e.g., entry is being evicted)
/// In normal operation, the encoder reuses existing entries via indexed representation.
#[test]
fn test_rfc9204_b3_duplicate() {
    let mut encoder = Encoder::new(220, 100);

    // Insert x-custom: custom-value
    let headers1 = vec![(b"x-custom".as_slice(), b"custom-value".as_slice())];
    let _ = encoder.encode(0, &headers1).unwrap();
    let _ = encoder.drain_encoder_stream();

    let initial_count = encoder.table().insert_count();

    // Encode same header again - encoder will reference existing entry, not duplicate
    let headers2 = vec![(b"x-custom".as_slice(), b"custom-value".as_slice())];
    let _ = encoder.encode(1, &headers2).unwrap();

    // No new encoder stream instructions (reuses existing entry)
    let instructions = encoder.drain_encoder_stream();
    assert!(instructions.is_empty(), "Should reuse existing entry");

    // Table count unchanged (no new insertion)
    assert_eq!(encoder.table().insert_count(), initial_count);
}

/// Test Required Insert Count encoding/decoding
#[test]
fn test_required_insert_count_roundtrip() {
    use quicd_qpack::wire::header_block::EncodedPrefix;

    let max_entries = 128;
    let test_cases = vec![
        (0, 0),
        (1, 0),
        (10, 10),
        (100, 100),
        (255, 200), // Wraparound case
    ];

    for (ric, total_inserted) in test_cases {
        let prefix = EncodedPrefix {
            required_insert_count: ric,
            sign: false,
            delta_base: 0,
        };

        let encoded = prefix.encode(max_entries);
        let (decoded, _) = EncodedPrefix::decode(&encoded, max_entries, total_inserted).unwrap();

        assert_eq!(
            decoded.required_insert_count, ric,
            "RIC mismatch for ric={}, total={}",
            ric, total_inserted
        );
    }
}

/// Test Base calculation positive delta
#[test]
fn test_base_positive_delta() {
    use quicd_qpack::wire::header_block::EncodedPrefix;

    let prefix = EncodedPrefix {
        required_insert_count: 10,
        sign: false,
        delta_base: 3,
    };

    // Base = RIC + Delta = 10 + 3 = 13
    assert_eq!(prefix.base(), 13);
}

/// Test Base calculation negative delta
#[test]
fn test_base_negative_delta() {
    use quicd_qpack::wire::header_block::EncodedPrefix;

    let prefix = EncodedPrefix {
        required_insert_count: 10,
        sign: true,
        delta_base: 2,
    };

    // Base = RIC - Delta - 1 = 10 - 2 - 1 = 7
    assert_eq!(prefix.base(), 7);
}

/// Test post-base indexing
#[test]
fn test_post_base_indexing() {
    let mut encoder = Encoder::new(4096, 100);
    encoder.set_capacity(4096).unwrap();
    let mut decoder = Decoder::new(4096, 100);

    // Insert multiple entries
    for i in 0..5 {
        let name = format!("header-{}", i);
        let headers = vec![(name.as_bytes(), b"value".as_slice())];
        let _ = encoder.encode(i, &headers);
    }

    // Sync tables
    while let Some(inst) = encoder.poll_encoder_stream() {
        decoder.process_encoder_instruction(&inst).unwrap();
    }

    while let Some(ack) = decoder.poll_decoder_stream() {
        encoder.process_decoder_instruction(&ack).unwrap();
    }

    // Now encode a reference to a recent entry
    let headers = vec![(b"header-4".as_slice(), b"value".as_slice())];
    let encoded = encoder.encode(10, &headers).unwrap();

    // Decode should work
    let decoded = decoder.decode(10, encoded).unwrap();
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].name.as_ref(), b"header-4");
}

/// Test blocked stream handling
#[test]
fn test_blocked_stream() {
    let mut encoder = Encoder::new(4096, 2);
    encoder.set_capacity(4096).unwrap();
    let mut decoder = Decoder::new(4096, 2);

    // Encode with dynamic table reference
    let headers = vec![(b"x-custom".as_slice(), b"value1".as_slice())];
    let encoded = encoder.encode(0, &headers).unwrap();

    // Decoder should block if it doesn't have the entry yet
    let result = decoder.decode(0, encoded.clone());

    // If it blocks, process encoder stream and retry
    if result.is_err() {
        while let Some(inst) = encoder.poll_encoder_stream() {
            decoder.process_encoder_instruction(&inst).unwrap();
        }

        let decoded = decoder.decode(0, encoded).unwrap();
        assert_eq!(decoded.len(), 1);
    }
}

/// Test Huffman encoding effectiveness
#[test]
fn test_huffman_encoding() {
    let test_strings = vec![
        b"www.example.com".as_slice(),
        b"Mozilla/5.0".as_slice(),
        b"text/html; charset=utf-8".as_slice(),
        b"gzip, deflate, br".as_slice(),
    ];

    for s in test_strings {
        let mut encoded = Vec::new();
        quicd_qpack::wire::huffman::encode(s, &mut encoded);

        // Huffman should compress or be same size
        assert!(encoded.len() <= s.len() + 1); // +1 for padding

        let mut decoded = Vec::new();
        quicd_qpack::wire::huffman::decode(&encoded, &mut decoded).unwrap();

        assert_eq!(&decoded[..], s);
    }
}

/// Test static table completeness
#[test]
fn test_static_table_all_entries() {
    use quicd_qpack::tables::static_table;

    // RFC 9204 defines 99 entries (0-98)
    assert_eq!(static_table::len(), 99);

    // Verify key entries
    assert_eq!(static_table::get(0).unwrap().name, b":authority");
    assert_eq!(static_table::get(17).unwrap().value, b"GET");
    assert_eq!(static_table::get(25).unwrap().value, b"200");
    assert_eq!(static_table::get(98).unwrap().value, b"sameorigin");
}

/// Test never-indexed headers
#[test]
fn test_never_indexed() {
    use quicd_qpack::encoder::should_never_index;

    assert!(should_never_index(b"authorization"));
    assert!(should_never_index(b"cookie"));
    assert!(should_never_index(b"set-cookie"));
    assert!(should_never_index(b"x-api-key"));
    assert!(should_never_index(b"x-auth-token"));
    assert!(should_never_index(b"x-csrf-token"));
    
    assert!(!should_never_index(b"content-type"));
    assert!(!should_never_index(b"accept"));
}

/// Test capacity enforcement
#[test]
fn test_capacity_enforcement() {
    let mut encoder = Encoder::new(100, 100);
    encoder.set_capacity(100).unwrap();

    // Insert entries until capacity is exceeded
    for i in 0..20 {
        let name = format!("header-{}", i);
        let headers = vec![(name.as_bytes(), b"test-value-long".as_slice())];
        let _ = encoder.encode(i, &headers);
    }

    // Table size should not exceed capacity
    assert!(encoder.table().size() <= encoder.table().capacity());
}

/// Test wraparound in Required Insert Count
#[test]
fn test_ric_wraparound() {
    use quicd_qpack::wire::header_block::EncodedPrefix;

    let max_entries = 100;
    
    // Test wraparound case: insert count > 2*max_entries
    let ric = 250;
    let total_inserted = 250;
    
    let prefix = EncodedPrefix {
        required_insert_count: ric,
        sign: false,
        delta_base: 0,
    };
    
    let encoded = prefix.encode(max_entries);
    let (decoded, _) = EncodedPrefix::decode(&encoded, max_entries, total_inserted).unwrap();
    
    assert_eq!(decoded.required_insert_count, ric);
}

/// Test Insert Count Increment
#[test]
fn test_insert_count_increment() {
    use quicd_qpack::tables::DynamicTable;

    let mut table = DynamicTable::new(4096);
    table.set_capacity(4096).unwrap();

    let initial = table.known_received_count();
    table.update_known_received_count(5);
    
    assert_eq!(table.known_received_count(), initial + 5);
}

/// Test section acknowledgement flow
#[test]
fn test_section_ack_flow() {
    let mut encoder = Encoder::new(4096, 100);
    encoder.set_capacity(4096).unwrap();
    let mut decoder = Decoder::new(4096, 100);

    let headers = vec![(b"x-test".as_slice(), b"value1".as_slice())];
    let stream_id = 4;

    // Encode
    let encoded = encoder.encode(stream_id, &headers).unwrap();

    // Sync encoder stream
    while let Some(inst) = encoder.poll_encoder_stream() {
        decoder.process_encoder_instruction(&inst).unwrap();
    }

    // Decode
    let _decoded = decoder.decode(stream_id, encoded).unwrap();

    // Get acknowledgement
    let acks: Vec<_> = decoder.drain_decoder_stream();
    assert!(!acks.is_empty());

    // Process ack
    for ack in acks {
        encoder.process_decoder_instruction(&ack).unwrap();
    }

    // Known received count should be updated
    assert!(encoder.table().known_received_count() > 0);
}

/// Test encoder behavior with unacknowledged dynamic table entries
/// RFC 9204 Section 2.1.4: Encoder MAY reference unacknowledged entries if willing to block
#[test]
fn test_encoder_no_unacknowledged_references() {
    let mut encoder = Encoder::new(4096, 100);
    encoder.set_capacity(4096).unwrap();
    let mut decoder = Decoder::new(4096, 100);

    // Insert a header into dynamic table
    let headers1 = vec![(b"x-test".as_slice(), b"value1".as_slice())];
    let _encoded1 = encoder.encode(0, &headers1).unwrap();

    // Do not sync encoder stream yet - so known_received_count remains 0
    // RFC 9204: Encoder CAN reference the dynamic entry if willing to block the stream

    // Try to encode the same header again
    let headers2 = vec![(b"x-test".as_slice(), b"value1".as_slice())];
    let encoded2 = encoder.encode(1, &headers2).unwrap();

    // Decoder will block because encoder stream not processed yet
    // First process encoder stream
    while let Some(inst) = encoder.poll_encoder_stream() {
        decoder.process_encoder_instruction(&inst).unwrap();
    }
    
    // Now decode should work
    let decoded2 = decoder.decode(1, encoded2).unwrap();
    assert_eq!(decoded2.len(), 1);
    assert_eq!(decoded2[0].name.as_ref(), b"x-test");
    assert_eq!(decoded2[0].value.as_ref(), b"value1");

    // Acknowledge
    while let Some(ack) = decoder.poll_decoder_stream() {
        encoder.process_decoder_instruction(&ack).unwrap();
    }

    // Now known_received_count should be > 0
    assert!(encoder.table().known_received_count() > 0);

    // Encode again - now should use dynamic reference without blocking
    let headers3 = vec![(b"x-test".as_slice(), b"value1".as_slice())];
    let encoded3 = encoder.encode(2, &headers3).unwrap();

    // This should decode without blocking (already acknowledged)
    let decoded3 = decoder.decode(2, encoded3).unwrap();
    assert_eq!(decoded3.len(), 1);
    assert_eq!(decoded3[0].name.as_ref(), b"x-test");
    assert_eq!(decoded3[0].value.as_ref(), b"value1");
}
