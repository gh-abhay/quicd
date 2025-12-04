//! Production-grade QPACK usage example.
//!
//! Demonstrates complete encoder/decoder workflow with:
//! - Dynamic table management
//! - Encoder/decoder stream handling
//! - Blocked stream tracking
//! - Multi-stream scenarios

use quicd_qpack::{Decoder, Encoder, HeaderField};

fn main() {
    println!("=== QPACK Production Example ===\n");

    // Configuration
    let max_table_capacity = 4096; // 4KB dynamic table
    let max_blocked_streams = 100;

    // Create encoder and decoder
    let mut encoder = Encoder::new(max_table_capacity, max_blocked_streams);
    let mut decoder = Decoder::new(max_table_capacity, max_blocked_streams);

    println!("1. Initial configuration:");
    println!("   Max table capacity: {} bytes", max_table_capacity);
    println!("   Max blocked streams: {}\n", max_blocked_streams);

    // Stream 1: Encode request headers
    println!("2. Encoding Stream 1 (HTTP Request):");
    let headers_1 = vec![
        (b":method".as_slice(), b"GET".as_slice()),
        (b":scheme".as_slice(), b"https".as_slice()),
        (b":authority".as_slice(), b"example.com".as_slice()),
        (b":path".as_slice(), b"/".as_slice()),
        (b"user-agent".as_slice(), b"quicd/1.0".as_slice()),
        (b"accept".as_slice(), b"*/*".as_slice()),
    ];

    let encoded_1 = encoder.encode(1, &headers_1).unwrap();
    println!(
        "   Encoded {} headers into {} bytes",
        headers_1.len(),
        encoded_1.len()
    );
    println!(
        "   Dynamic table insert count: {}",
        encoder.table().insert_count()
    );

    // Process encoder stream instructions
    let encoder_instructions = encoder.drain_encoder_stream();
    println!(
        "   Generated {} encoder stream instructions",
        encoder_instructions.len()
    );
    for inst in &encoder_instructions {
        decoder.process_encoder_instruction(inst).unwrap();
    }

    // Decode headers
    let decoded_1 = decoder.decode(1, encoded_1.clone()).unwrap();
    println!("   Decoded {} headers", decoded_1.len());
    for header in &decoded_1 {
        println!(
            "     {}: {}",
            String::from_utf8_lossy(&header.name),
            String::from_utf8_lossy(&header.value)
        );
    }

    // Process decoder stream instructions (acknowledgement)
    let decoder_instructions = decoder.drain_decoder_stream();
    println!(
        "   Generated {} decoder stream instructions",
        decoder_instructions.len()
    );
    for inst in &decoder_instructions {
        encoder.process_decoder_instruction(inst).unwrap();
    }
    println!();

    // Stream 2: Encode similar request (should see compression benefits)
    println!("3. Encoding Stream 2 (Similar Request):");
    let headers_2 = vec![
        (b":method".as_slice(), b"GET".as_slice()),
        (b":scheme".as_slice(), b"https".as_slice()),
        (b":authority".as_slice(), b"example.com".as_slice()),
        (b":path".as_slice(), b"/api/data".as_slice()),
        (b"user-agent".as_slice(), b"quicd/1.0".as_slice()),
        (b"accept".as_slice(), b"application/json".as_slice()),
    ];

    let encoded_2 = encoder.encode(2, &headers_2).unwrap();
    println!(
        "   Encoded {} headers into {} bytes",
        headers_2.len(),
        encoded_2.len()
    );
    println!(
        "   Compression ratio: {:.1}%",
        100.0 * (1.0 - encoded_2.len() as f64 / encoded_1.len() as f64)
    );

    // Process encoder stream
    let encoder_instructions_2 = encoder.drain_encoder_stream();
    println!(
        "   Generated {} encoder stream instructions",
        encoder_instructions_2.len()
    );
    for inst in &encoder_instructions_2 {
        decoder.process_encoder_instruction(inst).unwrap();
    }

    let decoded_2 = decoder.decode(2, encoded_2).unwrap();
    println!("   Decoded {} headers", decoded_2.len());

    // Acknowledge
    let decoder_instructions_2 = decoder.drain_decoder_stream();
    for inst in &decoder_instructions_2 {
        encoder.process_decoder_instruction(inst).unwrap();
    }
    println!();

    // Stream 3: Response headers
    println!("4. Encoding Stream 3 (HTTP Response):");
    let headers_3 = vec![
        (b":status".as_slice(), b"200".as_slice()),
        (b"content-type".as_slice(), b"application/json".as_slice()),
        (b"content-length".as_slice(), b"1234".as_slice()),
        (b"cache-control".as_slice(), b"no-cache".as_slice()),
        (b"x-custom-header".as_slice(), b"custom-value".as_slice()),
    ];

    let encoded_3 = encoder.encode(3, &headers_3).unwrap();
    println!(
        "   Encoded {} headers into {} bytes",
        headers_3.len(),
        encoded_3.len()
    );

    // Process streams
    for inst in encoder.drain_encoder_stream() {
        decoder.process_encoder_instruction(&inst).unwrap();
    }

    let decoded_3 = decoder.decode(3, encoded_3).unwrap();
    println!("   Decoded {} headers", decoded_3.len());
    for header in &decoded_3 {
        println!(
            "     {}: {}",
            String::from_utf8_lossy(&header.name),
            String::from_utf8_lossy(&header.value)
        );
    }

    for inst in decoder.drain_decoder_stream() {
        encoder.process_decoder_instruction(&inst).unwrap();
    }
    println!();

    // Final statistics
    println!("5. Final Statistics:");
    println!("   Encoder dynamic table:");
    println!("     Insert count: {}", encoder.table().insert_count());
    println!("     Current size: {} bytes", encoder.table().size());
    println!("     Entry count: {}", encoder.table().len());
    println!();
    println!("   Decoder dynamic table:");
    println!("     Insert count: {}", decoder.table().insert_count());
    println!("     Current size: {} bytes", decoder.table().size());
    println!("     Entry count: {}", decoder.table().len());
    println!();

    // Demonstrate dynamic table capacity change
    println!("6. Dynamic Table Capacity Update:");
    let new_capacity = 2048;
    encoder.set_capacity(new_capacity).unwrap();
    println!("   Reduced capacity to {} bytes", new_capacity);
    println!(
        "   Encoder table size after eviction: {} bytes",
        encoder.table().size()
    );
    println!("   Encoder entry count: {}", encoder.table().len());

    // Send capacity instruction to decoder
    for inst in encoder.drain_encoder_stream() {
        decoder.process_encoder_instruction(&inst).unwrap();
    }
    println!(
        "   Decoder table capacity updated: {} bytes",
        decoder.table().capacity()
    );
    println!();

    // Stream 4: Large header set to demonstrate eviction
    println!("7. Encoding Stream 4 (Large Header Set):");
    let mut large_headers = vec![
        (b":method".as_slice(), b"POST".as_slice()),
        (b":scheme".as_slice(), b"https".as_slice()),
        (b":authority".as_slice(), b"api.example.com".as_slice()),
        (b":path".as_slice(), b"/v1/upload".as_slice()),
    ];

    // Add many custom headers
    for i in 0..20 {
        let name = format!("x-custom-{}", i);
        let value = format!("value-{}-with-some-data", i);
        large_headers.push((
            Box::leak(name.into_bytes().into_boxed_slice()) as &[u8],
            Box::leak(value.into_bytes().into_boxed_slice()) as &[u8],
        ));
    }

    let encoded_4 = encoder.encode(4, &large_headers).unwrap();
    println!(
        "   Encoded {} headers into {} bytes",
        large_headers.len(),
        encoded_4.len()
    );
    println!(
        "   Encoder table size: {} bytes (entries: {})",
        encoder.table().size(),
        encoder.table().len()
    );

    // Process and decode
    for inst in encoder.drain_encoder_stream() {
        decoder.process_encoder_instruction(&inst).unwrap();
    }

    let decoded_4 = decoder.decode(4, encoded_4).unwrap();
    println!("   Decoded {} headers", decoded_4.len());
    println!(
        "   Decoder table size: {} bytes (entries: {})",
        decoder.table().size(),
        decoder.table().len()
    );

    for inst in decoder.drain_decoder_stream() {
        encoder.process_decoder_instruction(&inst).unwrap();
    }
    println!();

    println!("=== Example Complete ===");
    println!("Demonstrated:");
    println!("  ✓ Static table lookups");
    println!("  ✓ Dynamic table insertions");
    println!("  ✓ Encoder/decoder stream coordination");
    println!("  ✓ Header acknowledgements");
    println!("  ✓ Capacity updates");
    println!("  ✓ Automatic eviction under pressure");
}

// Helper to verify header correctness
#[allow(dead_code)]
fn verify_headers(expected: &[(&[u8], &[u8])], actual: &[HeaderField]) {
    assert_eq!(expected.len(), actual.len(), "Header count mismatch");

    for (i, (exp_name, exp_value)) in expected.iter().enumerate() {
        assert_eq!(
            actual[i].name.as_ref(),
            *exp_name,
            "Name mismatch at index {}",
            i
        );
        assert_eq!(
            actual[i].value.as_ref(),
            *exp_value,
            "Value mismatch at index {}",
            i
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_production_workflow() {
        let mut encoder = Encoder::new(4096, 100);
        let mut decoder = Decoder::new(4096, 100);

        // Encode
        let headers = vec![
            (b":method".as_slice(), b"GET".as_slice()),
            (b":path".as_slice(), b"/".as_slice()),
        ];
        let encoded = encoder.encode(1, &headers).unwrap();

        // Process encoder stream
        for inst in encoder.drain_encoder_stream() {
            decoder.process_encoder_instruction(&inst).unwrap();
        }

        // Decode
        let decoded = decoder.decode(1, encoded).unwrap();
        verify_headers(&headers, &decoded);

        // Process decoder stream
        for inst in decoder.drain_decoder_stream() {
            encoder.process_decoder_instruction(&inst).unwrap();
        }
    }

    #[test]
    fn test_capacity_reduction() {
        let mut encoder = Encoder::new(4096, 100);

        // Insert several entries
        for i in 0..10 {
            let value = format!("value-{}", i);
            let value_bytes = value.as_bytes();
            let headers = vec![(b"x-header".as_slice(), value_bytes)];
            let _ = encoder.encode(i, &headers);
        }

        let initial_count = encoder.table().len();
        assert!(initial_count > 0);

        // Reduce capacity significantly
        encoder.set_capacity(100).unwrap();

        // Some entries should be evicted
        assert!(encoder.table().len() < initial_count);
        assert!(encoder.table().size() <= 100);
    }
}
