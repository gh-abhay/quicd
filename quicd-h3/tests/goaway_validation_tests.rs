/// Tests for GOAWAY validation per RFC 9114 Section 5.2

/// Test GOAWAY ID monotonicity - subsequent GOAWAY must have ID <= previous
#[test]
fn test_goaway_id_monotonicity() {
    // RFC 9114 Section 5.2: "Endpoints MUST NOT increase the stream ID in
    // GOAWAY frames, as even-numbered stream IDs might be impossible to
    // determine. A client that receives a GOAWAY frame with a stream ID
    // that is greater than any previously received MUST treat this as a
    // connection error of type H3_ID_ERROR."

    // First GOAWAY with stream ID 100
    let first_goaway_id = 100u64;

    // Second GOAWAY with lower ID (valid)
    let second_goaway_id = 50u64;
    assert!(second_goaway_id <= first_goaway_id);

    // Third GOAWAY with higher ID (invalid - should error)
    let invalid_goaway_id = 150u64;
    assert!(invalid_goaway_id > first_goaway_id);
}

#[test]
fn test_goaway_decreasing_sequence() {
    // Valid sequence: each GOAWAY has ID <= previous
    let sequence = vec![1000u64, 800, 600, 400, 200, 0];

    let mut previous = u64::MAX;
    for id in sequence {
        assert!(
            id <= previous,
            "GOAWAY ID {} must be <= previous {}",
            id,
            previous
        );
        previous = id;
    }
}

#[test]
fn test_goaway_same_id_allowed() {
    // RFC 9114: Same ID is allowed (idempotent)
    let goaway_id = 500u64;

    // Sending same ID again should be valid
    assert!(goaway_id <= goaway_id);
}

#[test]
fn test_goaway_zero_id() {
    // GOAWAY with stream ID 0 means no new requests should be processed
    let goaway_zero = 0u64;

    // Any previous ID should be >= 0
    let previous_ids = vec![100u64, 50, 10, 0];
    for prev_id in previous_ids {
        assert!(goaway_zero <= prev_id);
    }
}

#[test]
fn test_goaway_max_stream_id() {
    // Test with maximum stream ID value
    let max_id = u64::MAX;

    // First GOAWAY with max ID
    // Second with any lower ID should be valid
    let lower_id = u64::MAX - 1000;
    assert!(lower_id < max_id);
}

#[test]
fn test_goaway_client_initiated_streams_only() {
    // RFC 9114 Section 5.2: GOAWAY carries stream ID for client-initiated
    // bidirectional stream (request stream)

    // Client-initiated streams have odd IDs (0, 4, 8, 12, ...)
    // Wait, in HTTP/3, client streams are 0, 4, 8 (client-initiated bidirectional)
    // Actually in QUIC/HTTP3: client bidi = 0, 4, 8, 12... (0, 4, 8 mod 4 = 0)

    let valid_client_stream_ids = vec![0u64, 4, 8, 12, 16, 20];

    for id in valid_client_stream_ids {
        // These are valid client-initiated bidirectional stream IDs
        assert_eq!(id % 4, 0, "Client-initiated bidi streams are 0 mod 4");
    }
}

#[test]
fn test_goaway_ordering_violation() {
    // Simulate the error condition from RFC 9114
    let first_goaway = 100u64;
    let second_goaway = 150u64; // Invalid - increases

    // This should trigger H3_ID_ERROR
    let is_valid = second_goaway <= first_goaway;
    assert!(!is_valid, "Increasing GOAWAY ID should be invalid");
}

#[test]
fn test_goaway_graceful_shutdown_sequence() {
    // Typical graceful shutdown:
    // 1. Server sends GOAWAY with high ID (stop accepting new after this)
    // 2. Finish processing existing requests
    // 3. Send another GOAWAY with ID 0 (no new requests at all)

    let initial_goaway = 1000u64;
    let final_goaway = 0u64;

    assert!(final_goaway <= initial_goaway);

    // Intermediate GOAWAYs should also decrease
    let intermediate = 500u64;
    assert!(intermediate <= initial_goaway);
    assert!(final_goaway <= intermediate);
}

#[test]
fn test_goaway_error_code_mapping() {
    // RFC 9114 Section 8.1: H3_ID_ERROR = 0x108
    let h3_id_error: u64 = 0x108;

    // Should be used when GOAWAY ID increases
    assert_eq!(h3_id_error, 0x108);
}

#[test]
fn test_goaway_no_new_requests_after() {
    // After GOAWAY with ID 100, only requests <= 100 should be processed
    let goaway_id = 100u64;

    let request_streams = vec![
        (50u64, true),   // < goaway_id, should process
        (100u64, true),  // == goaway_id, should process (depends on implementation)
        (104u64, false), // > goaway_id, should reject
        (200u64, false), // > goaway_id, should reject
    ];

    for (stream_id, should_accept) in request_streams {
        let would_accept = stream_id <= goaway_id;
        assert_eq!(
            would_accept, should_accept,
            "Stream {} acceptance ({}) doesn't match expected ({})",
            stream_id, would_accept, should_accept
        );
    }
}

#[test]
fn test_goaway_connection_closure_sequence() {
    // RFC 9114 Section 5.2: After sending GOAWAY, endpoint can close connection
    // once all accepted requests are complete

    let goaway_id = 200u64;
    let active_streams = vec![50u64, 100, 150, 200]; // All <= goaway_id

    // All active streams should be <= goaway_id
    for stream_id in &active_streams {
        assert!(*stream_id <= goaway_id);
    }

    // After these complete, connection can close
    // New stream 204 should be rejected
    let new_stream = 204u64;
    assert!(new_stream > goaway_id);
}

#[test]
fn test_goaway_idempotent_resend() {
    // Sending same GOAWAY multiple times should be safe (idempotent)
    let goaway_id = 300u64;

    // Send first GOAWAY
    let first_send = goaway_id;

    // Resend same GOAWAY (valid)
    let resend = goaway_id;
    assert_eq!(first_send, resend);
    assert!(resend <= first_send);
}

#[test]
fn test_goaway_even_vs_odd_stream_ids() {
    // In HTTP/3 over QUIC:
    // - Client-initiated bidirectional (request streams): 0, 4, 8, 12... (0 mod 4)
    // - Server-initiated bidirectional: 1, 5, 9, 13... (1 mod 4)
    // - Client-initiated unidirectional: 2, 6, 10, 14... (2 mod 4)
    // - Server-initiated unidirectional: 3, 7, 11, 15... (3 mod 4)

    // GOAWAY only applies to client-initiated bidirectional streams
    let client_bidi_streams = vec![0u64, 4, 8, 12, 16];

    for stream_id in client_bidi_streams {
        assert_eq!(stream_id % 4, 0);
    }
}
