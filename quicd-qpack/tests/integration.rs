// Integration tests for end-to-end QPACK encoding/decoding

use bytes::Bytes;
use quicd_qpack::{Decoder, Encoder, FieldLine};

#[test]
fn test_simple_request_headers() {
    // Encode a simple HTTP/3 GET request
    let mut encoder = Encoder::new(4096, 100);
    let mut decoder = Decoder::new(4096, 100);

    let headers = vec![
        FieldLine::new(Bytes::from(":method"), Bytes::from("GET")),
        FieldLine::new(Bytes::from(":scheme"), Bytes::from("https")),
        FieldLine::new(Bytes::from(":path"), Bytes::from("/")),
        FieldLine::new(Bytes::from(":authority"), Bytes::from("example.com")),
    ];

    // Encode field section
    let (encoded, encoder_instructions) = encoder.encode_field_section(0, &headers).unwrap();

    // Process encoder instructions on decoder
    for instruction in encoder_instructions {
        decoder.process_encoder_instruction(&instruction).unwrap();
    }

    // Decode field section
    let decoded = decoder.decode_field_section(0, &encoded).unwrap();

    // Verify round-trip
    assert_eq!(decoded.len(), headers.len());
    for (original, decoded) in headers.iter().zip(decoded.iter()) {
        assert_eq!(original.name, decoded.name);
        assert_eq!(original.value, decoded.value);
    }
}

#[test]
fn test_multiple_requests_with_dynamic_table() {
    let mut encoder = Encoder::new(4096, 100);
    let mut decoder = Decoder::new(4096, 100);

    // First request
    let headers1 = vec![
        FieldLine::new(Bytes::from(":method"), Bytes::from("GET")),
        FieldLine::new(Bytes::from(":scheme"), Bytes::from("https")),
        FieldLine::new(Bytes::from(":path"), Bytes::from("/index.html")),
        FieldLine::new(Bytes::from(":authority"), Bytes::from("example.com")),
        FieldLine::new(Bytes::from("user-agent"), Bytes::from("quicd/1.0")),
    ];

    let (encoded1, enc_instr1) = encoder.encode_field_section(0, &headers1).unwrap();
    for instruction in enc_instr1 {
        decoder.process_encoder_instruction(&instruction).unwrap();
    }
    let decoded1 = decoder.decode_field_section(0, &encoded1).unwrap();
    assert_eq!(decoded1.len(), headers1.len());

    // Second request (reuses :authority and user-agent from dynamic table)
    let headers2 = vec![
        FieldLine::new(Bytes::from(":method"), Bytes::from("GET")),
        FieldLine::new(Bytes::from(":scheme"), Bytes::from("https")),
        FieldLine::new(Bytes::from(":path"), Bytes::from("/style.css")),
        FieldLine::new(Bytes::from(":authority"), Bytes::from("example.com")),
        FieldLine::new(Bytes::from("user-agent"), Bytes::from("quicd/1.0")),
    ];

    let (encoded2, enc_instr2) = encoder.encode_field_section(1, &headers2).unwrap();
    for instruction in enc_instr2 {
        decoder.process_encoder_instruction(&instruction).unwrap();
    }

    // Second encoding should be smaller due to dynamic table reuse
    // (This is a heuristic - exact sizes depend on encoding strategy)
    println!("First request: {} bytes", encoded1.len());
    println!("Second request: {} bytes", encoded2.len());

    let decoded2 = decoder.decode_field_section(1, &encoded2).unwrap();
    assert_eq!(decoded2.len(), headers2.len());
}

#[test]
fn test_capacity_change() {
    let mut encoder = Encoder::new(4096, 100);
    let mut decoder = Decoder::new(4096, 100);

    // Add some entries
    let headers = vec![
        FieldLine::new(Bytes::from("custom-header-1"), Bytes::from("value1")),
        FieldLine::new(Bytes::from("custom-header-2"), Bytes::from("value2")),
    ];

    let (encoded, enc_instr) = encoder.encode_field_section(0, &headers).unwrap();
    for instruction in enc_instr {
        decoder.process_encoder_instruction(&instruction).unwrap();
    }
    let _ = decoder.decode_field_section(0, &encoded).unwrap();

    // Change capacity to smaller value (causes eviction)
    let cap_instruction = encoder.set_capacity(512).unwrap();
    decoder
        .process_encoder_instruction(&cap_instruction)
        .unwrap();

    // Send more headers after capacity change
    let headers2 = vec![FieldLine::new(
        Bytes::from("another-header"),
        Bytes::from("another-value"),
    )];

    let (encoded2, enc_instr2) = encoder.encode_field_section(1, &headers2).unwrap();
    for instruction in enc_instr2 {
        decoder.process_encoder_instruction(&instruction).unwrap();
    }
    let decoded2 = decoder.decode_field_section(1, &encoded2).unwrap();
    assert_eq!(decoded2.len(), headers2.len());
}

#[test]
fn test_large_header_values() {
    let mut encoder = Encoder::new(8192, 100);
    let mut decoder = Decoder::new(8192, 100);

    // Create headers with large values
    let large_value = Bytes::from("x".repeat(4000));
    let headers = vec![
        FieldLine::new(Bytes::from(":method"), Bytes::from("POST")),
        FieldLine::new(Bytes::from(":scheme"), Bytes::from("https")),
        FieldLine::new(Bytes::from(":path"), Bytes::from("/upload")),
        FieldLine::new(Bytes::from("content-length"), Bytes::from("4000")),
        FieldLine::new(Bytes::from("x-large-header"), large_value.clone()),
    ];

    let (encoded, enc_instr) = encoder.encode_field_section(0, &headers).unwrap();
    for instruction in enc_instr {
        decoder.process_encoder_instruction(&instruction).unwrap();
    }
    let decoded = decoder.decode_field_section(0, &encoded).unwrap();

    assert_eq!(decoded.len(), headers.len());
    assert_eq!(decoded[4].value, headers[4].value);
}

#[test]
fn test_huffman_encoding_benefit() {
    let mut encoder = Encoder::new(4096, 100);

    // Common ASCII text compresses well with Huffman
    let headers = vec![
        FieldLine::new(
            Bytes::from("content-type"),
            Bytes::from("text/html; charset=utf-8"),
        ),
        FieldLine::new(
            Bytes::from("cache-control"),
            Bytes::from("max-age=3600, public"),
        ),
    ];

    let (encoded, _) = encoder.encode_field_section(0, &headers).unwrap();

    // Calculate uncompressed size (names + values)
    let uncompressed: usize = headers.iter().map(|h| h.name.len() + h.value.len()).sum();

    println!("Uncompressed: {} bytes", uncompressed);
    println!("Encoded: {} bytes", encoded.len());

    // Huffman + indexing should provide some compression
    assert!(encoded.len() < uncompressed);
}

#[test]
fn test_empty_field_section() {
    let mut encoder = Encoder::new(4096, 100);
    let mut decoder = Decoder::new(4096, 100);

    let headers: Vec<FieldLine> = vec![];
    let (encoded, _) = encoder.encode_field_section(0, &headers).unwrap();
    let decoded = decoder.decode_field_section(0, &encoded).unwrap();

    assert_eq!(decoded.len(), 0);
}

#[test]
fn test_special_characters_in_values() {
    let mut encoder = Encoder::new(4096, 100);
    let mut decoder = Decoder::new(4096, 100);

    // Test various special characters
    let headers = vec![
        FieldLine::new(Bytes::from("x-test-1"), Bytes::from("value with spaces")),
        FieldLine::new(Bytes::from("x-test-2"), Bytes::from("value,with,commas")),
        FieldLine::new(
            Bytes::from("x-test-3"),
            Bytes::from("value;with;semicolons"),
        ),
        FieldLine::new(Bytes::from("x-test-4"), Bytes::from("value=with=equals")),
        FieldLine::new(Bytes::from("x-test-5"), Bytes::from("value\"with\"quotes")),
    ];

    let (encoded, enc_instr) = encoder.encode_field_section(0, &headers).unwrap();
    for instruction in enc_instr {
        decoder.process_encoder_instruction(&instruction).unwrap();
    }
    let decoded = decoder.decode_field_section(0, &encoded).unwrap();

    assert_eq!(decoded.len(), headers.len());
    for (original, decoded) in headers.iter().zip(decoded.iter()) {
        assert_eq!(original.name, decoded.name);
        assert_eq!(original.value, decoded.value);
    }
}

#[test]
fn test_stream_cancellation() {
    let mut decoder = Decoder::new(4096, 100);

    // Acknowledge and cancel stream
    decoder.cancel_stream(5);

    // Should not panic or error - cancellation is just cleanup
}

#[test]
fn test_concurrent_stream_encoding() {
    let mut encoder = Encoder::new(4096, 100);
    let mut decoder = Decoder::new(4096, 100);

    // Encode multiple streams
    let headers1 = vec![FieldLine::new(
        Bytes::from(":path"),
        Bytes::from("/stream1"),
    )];
    let headers2 = vec![FieldLine::new(
        Bytes::from(":path"),
        Bytes::from("/stream2"),
    )];
    let headers3 = vec![FieldLine::new(
        Bytes::from(":path"),
        Bytes::from("/stream3"),
    )];

    let (encoded1, enc_instr1) = encoder.encode_field_section(0, &headers1).unwrap();
    let (encoded2, enc_instr2) = encoder.encode_field_section(4, &headers2).unwrap();
    let (encoded3, enc_instr3) = encoder.encode_field_section(8, &headers3).unwrap();

    // Process encoder instructions
    for instruction in enc_instr1.iter().chain(&enc_instr2).chain(&enc_instr3) {
        decoder.process_encoder_instruction(instruction).unwrap();
    }

    // Decode out of order
    let decoded2 = decoder.decode_field_section(4, &encoded2).unwrap();
    let decoded1 = decoder.decode_field_section(0, &encoded1).unwrap();
    let decoded3 = decoder.decode_field_section(8, &encoded3).unwrap();

    assert_eq!(decoded1[0].value, headers1[0].value);
    assert_eq!(decoded2[0].value, headers2[0].value);
    assert_eq!(decoded3[0].value, headers3[0].value);
}
