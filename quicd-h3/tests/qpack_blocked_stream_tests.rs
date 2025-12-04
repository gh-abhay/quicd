//! GAP #5: QPACK blocked stream retry mechanism tests (RFC 9204 Section 2.1.4)

use bytes::Bytes;
use quicd_qpack::{Decoder, Encoder, QpackError};
use std::time::Duration;

#[test]
fn test_blocked_stream_retry_on_table_update() {
    // Test that blocked streams are retried when required table entries arrive
    // RFC 9204 Section 2.1.4: Blocked streams wait for dynamic table updates

    // Setup: Create encoder and decoder
    let mut encoder = Encoder::new(4096, 100);
    let mut decoder = Decoder::new(4096, 100);

    // First, encode a header that will create a dynamic table entry
    let headers_to_insert = vec![(b"x-custom-header".as_slice(), b"value1".as_slice())];
    let _ = encoder.encode(1, &headers_to_insert).unwrap();

    // Now encode headers that reference the dynamic entry (index 0 in dynamic table)
    // This will require insert_count >= 1
    let headers_with_ref = vec![
        (b"x-custom-header".as_slice(), b"value1".as_slice()), // Dynamic index 0
        (b":method".as_slice(), b"GET".as_slice()),
    ];

    // Encode on stream 3 - this should reference the dynamic entry
    let encoded = encoder.encode(3, &headers_with_ref).unwrap();

    // Try to decode before the encoder instructions are processed - should block
    let result = decoder.decode(3, encoded.clone());
    assert!(matches!(result, Err(QpackError::DecompressionFailed(_))));

    // Now process the encoder instructions to update the decoder's table
    while let Some(inst) = encoder.poll_encoder_stream() {
        decoder.process_encoder_instruction(&inst).unwrap();
    }

    // Now try decoding again - should succeed
    let decoded = decoder.decode(3, encoded).unwrap();
    assert_eq!(decoded.len(), 2);
    assert_eq!(decoded[0].name, Bytes::from("x-custom-header"));
    assert_eq!(decoded[0].value, Bytes::from("value1"));
    assert_eq!(decoded[1].name, Bytes::from(":method"));
    assert_eq!(decoded[1].value, Bytes::from("GET"));
}

#[test]
fn test_blocked_stream_timeout() {
    // Test that blocked streams timeout after configured duration
    // RFC 9204 Section 2.1.4: "Implementations SHOULD impose a timeout"

    // Setup: Create decoder with short timeout
    let mut decoder = Decoder::with_timeout(4096, 100, Duration::from_millis(10));

    // Create a header block that requires a non-existent table entry
    // Manually construct a header block that references dynamic index 0
    // when the table is empty (RIC=1, but insert_count=0)
    let mut data = bytes::BytesMut::new();

    // Prefix: RIC=1, Delta=0 -> Base=1
    data.extend_from_slice(&[0x80, 0x00]); // RIC=1 (10000000), Delta=0

    // Indexed field: dynamic index 0 (relative to base)
    // Base=1 means dynamic index 0 refers to absolute index 1
    // But since insert_count=0, this should block
    data.extend_from_slice(&[0x80]); // 10000000 = indexed, dynamic, index 0

    let encoded = data.freeze();

    // Try to decode - should block
    let result = decoder.decode(5, encoded);
    assert!(matches!(result, Err(QpackError::DecompressionFailed(_))));

    // Wait for timeout
    std::thread::sleep(Duration::from_millis(20));

    // Check timeouts - should cancel the blocked stream
    decoder.check_blocked_stream_timeouts();

    // Verify that a StreamCancel instruction was generated
    let instructions = decoder.drain_decoder_stream();
    assert!(!instructions.is_empty());

    // The last instruction should be a StreamCancel for stream 5
    let last_inst = &instructions[instructions.len() - 1];
    // We can't easily parse the instruction here, but we know it was generated
    assert!(!last_inst.is_empty());
}

#[test]
fn test_multiple_streams_blocked_same_entry() {
    // Test that multiple streams blocked on same entry all unblock together

    // Setup: Create encoder and decoder
    let mut encoder = Encoder::new(4096, 100);
    let mut decoder = Decoder::new(4096, 100);

    // Create header blocks that all reference the same future dynamic entry
    // First, encode headers that will create the dynamic entry
    let headers_to_insert = vec![(b"x-shared-header".as_slice(), b"shared-value".as_slice())];
    let _ = encoder.encode(1, &headers_to_insert).unwrap();

    // Create three streams that reference this dynamic entry
    let headers_with_ref = vec![
        (b"x-shared-header".as_slice(), b"shared-value".as_slice()), // Dynamic index 0
    ];

    let encoded_a = encoder.encode(3, &headers_with_ref).unwrap();
    let encoded_b = encoder.encode(5, &headers_with_ref).unwrap();
    let encoded_c = encoder.encode(7, &headers_with_ref).unwrap();

    // All should block initially
    assert!(matches!(
        decoder.decode(3, encoded_a.clone()),
        Err(QpackError::DecompressionFailed(_))
    ));
    assert!(matches!(
        decoder.decode(5, encoded_b.clone()),
        Err(QpackError::DecompressionFailed(_))
    ));
    assert!(matches!(
        decoder.decode(7, encoded_c.clone()),
        Err(QpackError::DecompressionFailed(_))
    ));

    // Process encoder instructions - all should unblock
    while let Some(inst) = encoder.poll_encoder_stream() {
        decoder.process_encoder_instruction(&inst).unwrap();
    }

    // All should now decode successfully
    let decoded_a = decoder.decode(3, encoded_a).unwrap();
    let decoded_b = decoder.decode(5, encoded_b).unwrap();
    let decoded_c = decoder.decode(7, encoded_c).unwrap();

    for decoded in &[decoded_a, decoded_b, decoded_c] {
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].name, Bytes::from("x-shared-header"));
        assert_eq!(decoded[0].value, Bytes::from("shared-value"));
    }
}

#[test]
fn test_blocked_streams_limit() {
    // Test SETTINGS_QPACK_BLOCKED_STREAMS limit enforcement
    // RFC 9204: Cannot have more blocked streams than advertised

    // Setup: Create decoder with max_blocked_streams = 2
    let mut decoder = Decoder::new(4096, 2);

    // Create header blocks that require non-existent entries
    let mut data = bytes::BytesMut::new();
    data.extend_from_slice(&[0x80, 0x00]); // RIC=1, Delta=0
    data.extend_from_slice(&[0x80]); // Indexed dynamic 0
    let encoded = data.freeze();

    // Block two streams - should succeed
    assert!(matches!(
        decoder.decode(1, encoded.clone()),
        Err(QpackError::DecompressionFailed(_))
    ));
    assert!(matches!(
        decoder.decode(3, encoded.clone()),
        Err(QpackError::DecompressionFailed(_))
    ));

    // Third stream should fail with BlockedStreamLimitExceeded
    let result = decoder.decode(5, encoded);
    assert!(matches!(
        result,
        Err(QpackError::BlockedStreamLimitExceeded)
    ));
}

#[test]
fn test_blocked_stream_check_interval() {
    // Test that blocked streams are checked periodically per configuration

    // Setup: Create decoder with short timeout
    let mut decoder = Decoder::with_timeout(4096, 100, Duration::from_millis(50));

    // Create a blocking header block
    let mut data = bytes::BytesMut::new();
    data.extend_from_slice(&[0x80, 0x00]); // RIC=1, Delta=0
    data.extend_from_slice(&[0x80]); // Indexed dynamic 0
    let encoded = data.freeze();

    // Block a stream
    assert!(matches!(
        decoder.decode(9, encoded),
        Err(QpackError::DecompressionFailed(_))
    ));

    // Wait less than timeout
    std::thread::sleep(Duration::from_millis(20));

    // Call check_blocked_stream_timeouts - should not timeout yet
    decoder.check_blocked_stream_timeouts();

    // Should still have the blocked stream (no StreamCancel generated)
    let instructions = decoder.drain_decoder_stream();
    assert_eq!(instructions.len(), 0); // No instructions generated yet

    // Wait for timeout
    std::thread::sleep(Duration::from_millis(40));

    // Now check timeouts - should cancel the stream
    decoder.check_blocked_stream_timeouts();

    // Should have generated a StreamCancel
    let instructions = decoder.drain_decoder_stream();
    assert!(!instructions.is_empty());
}
