//! Example: Basic QPACK encoder/decoder usage
//!
//! Run with: cargo run --example basic

use quicd_qpack::{Decoder, Encoder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("QPACK Example - Basic Encoding/Decoding\n");

    // Create encoder and decoder with 4KB dynamic table capacity
    // and max 100 blocked streams
    let mut encoder = Encoder::new(4096, 100);
    let mut decoder = Decoder::new(4096, 100);

    // Example 1: Encode static table headers (common HTTP/3 headers)
    println!("=== Example 1: Static Table Headers ===");
    let headers1 = vec![
        (b":method".as_slice(), b"GET".as_slice()),
        (b":scheme".as_slice(), b"https".as_slice()),
        (b":path".as_slice(), b"/".as_slice()),
        (b":authority".as_slice(), b"example.com".as_slice()),
    ];

    let stream_id = 0;
    let encoded1 = encoder.encode(stream_id, &headers1)?;
    println!(
        "Encoded {} headers into {} bytes",
        headers1.len(),
        encoded1.len()
    );

    // Check for encoder stream instructions (none expected for static-only)
    let encoder_insts = encoder.drain_encoder_stream();
    println!("Encoder instructions: {}", encoder_insts.len());

    // Decode headers
    let decoded1 = decoder.decode(stream_id, encoded1)?;
    println!("Decoded {} headers:", decoded1.len());
    for header in &decoded1 {
        println!(
            "  {}: {}",
            String::from_utf8_lossy(&header.name),
            String::from_utf8_lossy(&header.value)
        );
    }

    // Process decoder acknowledgements
    let decoder_insts = decoder.drain_decoder_stream();
    for inst in decoder_insts {
        encoder.process_decoder_instruction(&inst)?;
    }

    println!();

    // Example 2: Custom headers (will use dynamic table)
    println!("=== Example 2: Custom Headers (Dynamic Table) ===");
    let headers2 = vec![
        (b":method".as_slice(), b"POST".as_slice()),
        (b":path".as_slice(), b"/api/users".as_slice()),
        (b"content-type".as_slice(), b"application/json".as_slice()),
        (b"x-request-id".as_slice(), b"abc123".as_slice()),
        (b"x-custom-header".as_slice(), b"custom-value".as_slice()),
    ];

    let stream_id2 = 4;
    let encoded2 = encoder.encode(stream_id2, &headers2)?;
    println!(
        "Encoded {} headers into {} bytes",
        headers2.len(),
        encoded2.len()
    );

    // Process encoder instructions (dynamic table insertions)
    let encoder_insts2 = encoder.drain_encoder_stream();
    println!("Encoder instructions: {}", encoder_insts2.len());
    for inst in encoder_insts2 {
        let _ = decoder.process_encoder_instruction(&inst)?;
    }

    // Decode headers
    let decoded2 = decoder.decode(stream_id2, encoded2)?;
    println!("Decoded {} headers:", decoded2.len());
    for header in &decoded2 {
        println!(
            "  {}: {}",
            String::from_utf8_lossy(&header.name),
            String::from_utf8_lossy(&header.value)
        );
    }

    // Process decoder acknowledgements
    let decoder_insts2 = decoder.drain_decoder_stream();
    for inst in decoder_insts2 {
        encoder.process_decoder_instruction(&inst)?;
    }

    println!();

    // Example 3: Reuse dynamic table entries
    println!("=== Example 3: Reusing Dynamic Table ===");
    let headers3 = vec![
        (b":method".as_slice(), b"POST".as_slice()),
        (b":path".as_slice(), b"/api/posts".as_slice()),
        (b"x-custom-header".as_slice(), b"custom-value".as_slice()), // Already in table
    ];

    let stream_id3 = 8;
    let encoded3 = encoder.encode(stream_id3, &headers3)?;
    println!(
        "Encoded {} headers into {} bytes (using dynamic table)",
        headers3.len(),
        encoded3.len()
    );

    // Should have fewer/no new instructions since entries are already in table
    let encoder_insts3 = encoder.drain_encoder_stream();
    println!("New encoder instructions: {}", encoder_insts3.len());

    for inst in encoder_insts3 {
        let _ = decoder.process_encoder_instruction(&inst)?;
    }

    let decoded3 = decoder.decode(stream_id3, encoded3)?;
    println!("Decoded {} headers:", decoded3.len());
    for header in &decoded3 {
        println!(
            "  {}: {}",
            String::from_utf8_lossy(&header.name),
            String::from_utf8_lossy(&header.value)
        );
    }

    println!();

    // Display dynamic table stats
    println!("=== Dynamic Table Statistics ===");
    println!("Encoder table size: {} bytes", encoder.table().size());
    println!(
        "Encoder table capacity: {} bytes",
        encoder.table().capacity()
    );
    println!("Encoder table entries: {}", encoder.table().len());
    println!("Encoder insert count: {}", encoder.table().insert_count());

    Ok(())
}
