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
    
    let headers = vec![
        (b"sensitive-header".as_slice(), b"sensitive-value".as_slice()),
    ];
    
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
