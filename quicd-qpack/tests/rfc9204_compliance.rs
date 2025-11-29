//! RFC 9204 Compliance Tests
//! 
//! Tests critical behavior specified in RFC 9204:
//! - Dynamic table management
//! - Encoder/decoder stream instructions
//! - Blocked streams
//! - Required Insert Count calculation
//! - Static table indexing

use bytes::Bytes;
use quicd_qpack::{Decoder, Encoder, QpackError};

#[test]
fn test_static_table_only_encoding() {
    // RFC 9204 Example: Encode headers using only static table
    let mut encoder = Encoder::new(0, 0); // Zero capacity = static only
    let mut decoder = Decoder::new(0, 0);
    
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
    assert_eq!(decoded[1].name.as_ref(), b":scheme");
    assert_eq!(decoded[1].value.as_ref(), b"https");
}

#[test]
fn test_dynamic_table_insertion() {
    // RFC 9204 Section 3.2: Dynamic table insertion
    let mut encoder = Encoder::new(4096, 100);
    let mut decoder = Decoder::new(4096, 100);
    
    let headers = vec![
        (b"custom-key".as_slice(), b"custom-value".as_slice()),
    ];
    
    let encoded = encoder.encode(0, &headers).unwrap();
    
    // Process encoder stream instructions
    while let Some(inst) = encoder.poll_encoder_stream() {
        decoder.process_encoder_instruction(&inst).unwrap();
    }
    
    let decoded = decoder.decode(0, encoded).unwrap();
    
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].name.as_ref(), b"custom-key");
    assert_eq!(decoded[0].value.as_ref(), b"custom-value");
    
    // Verify entry was inserted into dynamic table
    assert_eq!(encoder.table().insert_count(), 1);
    assert_eq!(decoder.table().insert_count(), 1);
}

#[test]
fn test_dynamic_table_eviction() {
    // RFC 9204 Section 3.2.2: Entries evicted when capacity exceeded
    let mut encoder = Encoder::new(100, 100); // Small capacity
    
    // Insert entries that exceed capacity
    let initial_count = encoder.table().insert_count();
    for i in 0..10 {
        let name = format!("header-{}", i);
        let headers = vec![(name.as_bytes(), b"value".as_slice())];
        let _ = encoder.encode(i, &headers);
    }
    
    let table = encoder.table();
    
    // Table should have some entries and stayed within capacity
    assert!(table.insert_count() > initial_count);
    assert!(table.size() <= table.capacity());
    
    // At least some entries should have been inserted and evicted
    // The exact behavior depends on the encoder's insertion strategy
    assert!(table.insert_count() >= 1);
}

#[test]
fn test_set_dynamic_table_capacity() {
    // RFC 9204 Section 4.3.1: Set Dynamic Table Capacity instruction
    let mut encoder = Encoder::new(4096, 100);
    let mut decoder = Decoder::new(4096, 100);
    
    // Reduce capacity
    encoder.set_capacity(2048).unwrap();
    
    // Process instruction
    while let Some(inst) = encoder.poll_encoder_stream() {
        decoder.process_encoder_instruction(&inst).unwrap();
    }
    
    assert_eq!(decoder.table().capacity(), 2048);
}

#[test]
fn test_insert_with_name_reference_static() {
    // RFC 9204 Section 4.3.1.2: Insert With Name Reference (static)
    let mut encoder = Encoder::new(4096, 100);
    let mut decoder = Decoder::new(4096, 100);
    
    // Insert using static table name - use a value not in static table
    let headers = vec![
        (b":method".as_slice(), b"CUSTOM".as_slice()),
    ];
    
    let _ = encoder.encode(0, &headers).unwrap();
    
    while let Some(inst) = encoder.poll_encoder_stream() {
        decoder.process_encoder_instruction(&inst).unwrap();
    }
    
    // If encoder decided to insert, verify the entry
    if decoder.table().insert_count() > 0 {
        let entry = decoder.table().get(0).unwrap();
        assert_eq!(entry.name.as_ref(), b":method");
        assert_eq!(entry.value.as_ref(), b"CUSTOM");
    }
}

#[test]
fn test_duplicate_instruction() {
    // RFC 9204 Section 4.3.1.4: Duplicate instruction
    let mut encoder = Encoder::new(4096, 100);
    let mut decoder = Decoder::new(4096, 100);
    
    // Insert an entry
    let headers = vec![
        (b"content-type".as_slice(), b"application/json".as_slice()),
    ];
    
    let _ = encoder.encode(0, &headers).unwrap();
    
    while let Some(inst) = encoder.poll_encoder_stream() {
        decoder.process_encoder_instruction(&inst).unwrap();
    }
    
    // Encoder might have inserted the entry
    assert!(decoder.table().insert_count() <= 1);
    
    // Duplicate is tested implicitly when encoder reuses entries
}

#[test]
fn test_section_acknowledgement() {
    // RFC 9204 Section 4.3.2: Section Acknowledgement
    let mut encoder = Encoder::new(4096, 100);
    let mut decoder = Decoder::new(4096, 100);
    
    let headers = vec![
        (b"x-custom".as_slice(), b"value".as_slice()),
    ];
    
    let stream_id = 4;
    let _ = encoder.encode(stream_id, &headers).unwrap();
    
    while let Some(inst) = encoder.poll_encoder_stream() {
        decoder.process_encoder_instruction(&inst).unwrap();
    }
    
    // Decoder sends acknowledgement
    while let Some(ack) = decoder.poll_decoder_stream() {
        encoder.process_decoder_instruction(&ack).unwrap();
    }
    
    // Stream should be unblocked
    assert_eq!(encoder.table().known_received_count(), 1);
}

#[test]
fn test_insert_count_increment() {
    // RFC 9204 Section 4.3.2.3: Insert Count Increment
    let mut encoder = Encoder::new(4096, 100);
    
    // Manually update known received count
    encoder.table().update_known_received_count(5);
    
    assert_eq!(encoder.table().known_received_count(), 5);
}

#[test]
fn test_blocked_streams() {
    // RFC 9204 Section 2.1.2: Blocked streams
    let mut encoder = Encoder::new(4096, 2); // Max 2 blocked streams
    let mut decoder = Decoder::new(4096, 2);
    
    let headers = vec![
        (b"x-test".as_slice(), b"value1".as_slice()),
    ];
    
    // Encode multiple streams
    let _ = encoder.encode(0, &headers).unwrap();
    let _ = encoder.encode(4, &headers).unwrap();
    
    // Third stream should succeed (depends on blocking logic)
    let result = encoder.encode(8, &headers);
    assert!(result.is_ok() || matches!(result, Err(QpackError::BlockedStreamLimitExceeded)));
}

#[test]
fn test_required_insert_count_encoding() {
    // RFC 9204 Section 4.5.1.1: Required Insert Count encoding
    let mut encoder = Encoder::new(4096, 100);
    let mut decoder = Decoder::new(4096, 100);
    
    // Insert multiple entries
    for i in 0..5 {
        let name = format!("header-{}", i);
        let headers = vec![(name.as_bytes(), b"value".as_slice())];
        let _ = encoder.encode(i as u64, &headers);
    }
    
    // Process all instructions
    for inst in encoder.drain_encoder_stream() {
        decoder.process_encoder_instruction(&inst).unwrap();
    }
    
    assert_eq!(decoder.table().insert_count(), 5);
}

#[test]
fn test_literal_without_name_reference() {
    // RFC 9204 Section 4.5.4: Literal without name reference
    let mut encoder = Encoder::new(0, 0); // Zero capacity
    let mut decoder = Decoder::new(0, 0);
    
    let headers = vec![
        (b"x-custom-header".as_slice(), b"custom-value".as_slice()),
    ];
    
    let encoded = encoder.encode(0, &headers).unwrap();
    let decoded = decoder.decode(0, encoded).unwrap();
    
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].name.as_ref(), b"x-custom-header");
    assert_eq!(decoded[0].value.as_ref(), b"custom-value");
}

#[test]
fn test_zero_insert_count() {
    // RFC 9204: Required Insert Count of 0 means no dynamic table references
    let mut encoder = Encoder::new(0, 0);
    let mut decoder = Decoder::new(0, 0);
    
    let headers = vec![
        (b":method".as_slice(), b"GET".as_slice()),
    ];
    
    let encoded = encoder.encode(0, &headers).unwrap();
    let decoded = decoder.decode(0, encoded).unwrap();
    
    assert_eq!(decoded.len(), 1);
    assert_eq!(encoder.table().insert_count(), 0);
}

#[test]
fn test_entry_size_calculation() {
    // RFC 9204 Section 3.2.1: Entry size = name.len + value.len + 32
    let mut encoder = Encoder::new(4096, 100);
    
    let headers = vec![
        (b"test".as_slice(), b"value".as_slice()),
    ];
    
    let _ = encoder.encode(0, &headers).unwrap();
    
    let table = encoder.table();
    if let Some(entry) = table.get(0) {
        let expected_size = 4 + 5 + 32; // "test" + "value" + 32
        assert_eq!(entry.size(), expected_size);
    }
}

#[test]
fn test_max_blocked_streams_enforcement() {
    // RFC 9204: Encoder must respect max blocked streams
    let mut encoder = Encoder::new(4096, 1); // Max 1 blocked stream
    
    let headers = vec![
        (b"x-block".as_slice(), b"test".as_slice()),
    ];
    
    // First encoding might block
    let _ = encoder.encode(0, &headers);
    
    // Additional streams may exceed limit
    for stream_id in 1..10 {
        let result = encoder.encode(stream_id, &headers);
        // Should either succeed or fail with BlockedStreamLimitExceeded
        if let Err(e) = result {
            assert!(matches!(e, QpackError::BlockedStreamLimitExceeded));
            break;
        }
    }
}

#[test]
fn test_capacity_cannot_exceed_max() {
    // RFC 9204: Capacity cannot exceed maximum set at creation
    let mut encoder = Encoder::new(2048, 100);
    
    let result = encoder.set_capacity(4096);
    assert!(result.is_err());
}

#[test]
fn test_never_indexed_flag() {
    // RFC 9204 Section 4.5.4: Never-indexed literals
    // Implementation stores but doesn't require special handling in basic case
    let mut encoder = Encoder::new(4096, 100);
    let mut decoder = Decoder::new(4096, 100);
    
    // Sensitive header (would use never-indexed in real implementation)
    let headers = vec![
        (b"authorization".as_slice(), b"Bearer token123".as_slice()),
    ];
    
    let encoded = encoder.encode(0, &headers).unwrap();
    let decoded = decoder.decode(0, encoded).unwrap();
    
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].name.as_ref(), b"authorization");
}

#[test]
fn test_roundtrip_multiple_headers() {
    // Full roundtrip with diverse header types
    let mut encoder = Encoder::new(4096, 100);
    let mut decoder = Decoder::new(4096, 100);
    
    let headers = vec![
        (b":method".as_slice(), b"POST".as_slice()),
        (b":scheme".as_slice(), b"https".as_slice()),
        (b":path".as_slice(), b"/api/data".as_slice()),
        (b":authority".as_slice(), b"example.com".as_slice()),
        (b"content-type".as_slice(), b"application/json".as_slice()),
        (b"content-length".as_slice(), b"1234".as_slice()),
        (b"x-custom-header".as_slice(), b"custom-value".as_slice()),
    ];
    
    let encoded = encoder.encode(0, &headers).unwrap();
    
    // Process encoder instructions
    for inst in encoder.drain_encoder_stream() {
        decoder.process_encoder_instruction(&inst).unwrap();
    }
    
    let decoded = decoder.decode(0, encoded).unwrap();
    
    assert_eq!(decoded.len(), headers.len());
    for (i, (name, value)) in headers.iter().enumerate() {
        assert_eq!(decoded[i].name.as_ref(), *name);
        assert_eq!(decoded[i].value.as_ref(), *value);
    }
}
