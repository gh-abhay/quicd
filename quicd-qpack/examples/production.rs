//! Production Example: HTTP/3 Request/Response Cycle
//!
//! Demonstrates realistic usage of QPACK encoder/decoder in an HTTP/3 context.

use quicd_qpack::{Decoder, Encoder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== QPACK Production Example ===\n");

    // Initialize encoder and decoder (one per HTTP/3 connection)
    // 4KB dynamic table, 100 max blocked streams
    let mut encoder = Encoder::new(4096, 100);
    let mut decoder = Decoder::new(4096, 100);

    println!("Created encoder and decoder with 4KB dynamic table capacity\n");

    // Simulate multiple HTTP/3 requests on different streams
    simulate_request_response_cycle(&mut encoder, &mut decoder, 0)?;
    simulate_request_response_cycle(&mut encoder, &mut decoder, 4)?;
    simulate_request_response_cycle(&mut encoder, &mut decoder, 8)?;

    // Show dynamic table statistics
    print_table_stats(&encoder, &decoder);

    Ok(())
}

fn simulate_request_response_cycle(
    encoder: &mut Encoder,
    decoder: &mut Decoder,
    stream_id: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("--- Stream {} ---", stream_id);

    // CLIENT: Encode request headers
    let request_headers = vec![
        (b":method".as_slice(), b"POST".as_slice()),
        (b":scheme".as_slice(), b"https".as_slice()),
        (b":authority".as_slice(), b"api.example.com".as_slice()),
        (b":path".as_slice(), b"/v1/data".as_slice()),
        (b"content-type".as_slice(), b"application/json".as_slice()),
        (b"content-length".as_slice(), b"1234".as_slice()),
        (b"user-agent".as_slice(), b"quicd/1.0".as_slice()),
        (b"authorization".as_slice(), b"Bearer token123".as_slice()),
    ];

    let encoded_request = encoder.encode(stream_id, &request_headers)?;
    println!(
        "Encoded {} request headers → {} bytes",
        request_headers.len(),
        encoded_request.len()
    );

    // Transfer encoder stream instructions (would be sent over QUIC encoder stream)
    let mut encoder_instructions = Vec::new();
    while let Some(inst) = encoder.poll_encoder_stream() {
        encoder_instructions.push(inst);
    }
    if !encoder_instructions.is_empty() {
        println!(
            "Generated {} encoder stream instruction(s)",
            encoder_instructions.len()
        );
    }

    // SERVER: Process encoder instructions
    for inst in encoder_instructions {
        let _ = decoder.process_encoder_instruction(&inst)?;
    }

    // SERVER: Decode request headers
    let decoded_request = decoder.decode(stream_id, encoded_request)?;
    println!("Decoded {} request headers:", decoded_request.len());
    for (i, field) in decoded_request.iter().enumerate() {
        let name = std::str::from_utf8(&field.name).unwrap_or("<invalid>");
        let value = std::str::from_utf8(&field.value).unwrap_or("<invalid>");
        println!("  {}. {} = {}", i + 1, name, value);
    }

    // SERVER: Send decoder acknowledgements (would be sent over QUIC decoder stream)
    let mut decoder_instructions = Vec::new();
    while let Some(ack) = decoder.poll_decoder_stream() {
        decoder_instructions.push(ack);
    }
    if !decoder_instructions.is_empty() {
        println!(
            "Generated {} decoder stream instruction(s)",
            decoder_instructions.len()
        );
    }

    // CLIENT: Process decoder acknowledgements
    for ack in decoder_instructions {
        encoder.process_decoder_instruction(&ack)?;
    }

    // SERVER: Encode response headers
    let response_headers = vec![
        (b":status".as_slice(), b"200".as_slice()),
        (b"content-type".as_slice(), b"application/json".as_slice()),
        (b"content-length".as_slice(), b"5678".as_slice()),
        (b"cache-control".as_slice(), b"max-age=3600".as_slice()),
        (b"x-request-id".as_slice(), b"abc123".as_slice()),
    ];

    let encoded_response = encoder.encode(stream_id + 1, &response_headers)?;
    println!(
        "\nEncoded {} response headers → {} bytes",
        response_headers.len(),
        encoded_response.len()
    );

    // Transfer encoder instructions again
    while let Some(inst) = encoder.poll_encoder_stream() {
        decoder.process_encoder_instruction(&inst)?;
    }

    // CLIENT: Decode response
    let decoded_response = decoder.decode(stream_id + 1, encoded_response)?;
    println!("Decoded {} response headers:", decoded_response.len());
    for (i, field) in decoded_response.iter().enumerate() {
        let name = std::str::from_utf8(&field.name).unwrap_or("<invalid>");
        let value = std::str::from_utf8(&field.value).unwrap_or("<invalid>");
        println!("  {}. {} = {}", i + 1, name, value);
    }

    // Process decoder acks
    while let Some(ack) = decoder.poll_decoder_stream() {
        encoder.process_decoder_instruction(&ack)?;
    }

    println!();
    Ok(())
}

fn print_table_stats(encoder: &Encoder, decoder: &Decoder) {
    println!("=== Dynamic Table Statistics ===");
    println!("Encoder table:");
    println!("  Insert count: {}", encoder.table().insert_count());
    println!("  Current size: {} bytes", encoder.table().size());
    println!("  Capacity: {} bytes", encoder.table().capacity());
    println!("  Entries: {}", encoder.table().len());
    println!(
        "  Known received: {}",
        encoder.table().known_received_count()
    );

    println!("\nDecoder table:");
    println!("  Insert count: {}", decoder.table().insert_count());
    println!("  Current size: {} bytes", decoder.table().size());
    println!("  Capacity: {} bytes", decoder.table().capacity());
    println!("  Entries: {}", decoder.table().len());

    println!("\n=== Compression Efficiency ===");
    let total_original = estimate_header_size();
    let total_compressed = estimate_compressed_size(encoder.table().insert_count());
    let compression_ratio = total_original as f64 / total_compressed as f64;
    println!("Original header size: ~{} bytes", total_original);
    println!("Compressed size: ~{} bytes", total_compressed);
    println!("Compression ratio: {:.2}x", compression_ratio);
}

fn estimate_header_size() -> usize {
    // Rough estimate: 3 requests × 8 headers × 40 bytes average
    3 * 8 * 40 + 3 * 5 * 30 // requests + responses
}

fn estimate_compressed_size(insert_count: u64) -> usize {
    // Very rough estimate based on typical QPACK compression
    // Static table refs: ~2 bytes, dynamic refs: ~2 bytes, literals: full size
    // After dynamic table is populated, most headers become 1-2 byte references
    if insert_count > 5 {
        // Good compression with dynamic table
        300
    } else {
        // Mostly static table
        450
    }
}
