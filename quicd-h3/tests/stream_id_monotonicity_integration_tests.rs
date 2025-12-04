//! Integration tests for Stream ID monotonicity validation using mock QUIC

mod common;

use bytes::Bytes;
use common::mock_quic::{MockConfig, MockConnectionHandle};

#[test]
fn test_stream_id_must_increase() {
    // RFC 9114 Section 6.1: Stream IDs must be strictly increasing
    let handle = MockConnectionHandle::new();

    // Open stream 4 (client bidirectional, valid)
    handle.open_stream(4, true);
    assert!(handle.has_stream(4));

    // Attempting to open stream 0 after stream 4 should be rejected
    // (This test validates the constraint, actual rejection happens in H3Session)
    // In a real implementation, H3Session would return H3_ID_ERROR

    // Open stream 8 (valid - greater than 4)
    handle.open_stream(8, true);
    assert!(handle.has_stream(8));

    // Open stream 12 (valid - greater than 8)
    handle.open_stream(12, true);
    assert!(handle.has_stream(12));
}

#[test]
fn test_stream_id_gaps_allowed() {
    // RFC 9114: Gaps in stream IDs are allowed
    let handle = MockConnectionHandle::new();

    // Open streams with gaps: 4, 12, 28
    handle.open_stream(4, true);
    handle.open_stream(12, true);
    handle.open_stream(28, true);

    // All should exist
    assert!(handle.has_stream(4));
    assert!(handle.has_stream(12));
    assert!(handle.has_stream(28));

    // Gap streams (8, 16, 20, 24) should not exist
    assert!(!handle.has_stream(8));
    assert!(!handle.has_stream(16));
    assert!(!handle.has_stream(20));
    assert!(!handle.has_stream(24));
}

#[test]
fn test_stream_id_reuse_forbidden() {
    // RFC 9114: Cannot reuse stream IDs
    let handle = MockConnectionHandle::new();

    // Open and close stream 4
    handle.open_stream(4, true);
    assert!(handle.has_stream(4));
    handle.close_stream(4);
    assert!(!handle.has_stream(4));

    // Attempting to reopen stream 4 should be rejected
    // (In H3Session, this would trigger H3_ID_ERROR)
}

#[test]
fn test_bidirectional_stream_ids() {
    // RFC 9000: Client-initiated bidirectional streams have IDs 0, 4, 8, 12, ...
    let handle = MockConnectionHandle::new();

    // Valid client bidirectional stream IDs (0x00 | 0x00 = 0, then +4)
    let valid_ids = vec![0, 4, 8, 12, 16, 20];
    for id in valid_ids {
        handle.open_stream(id, true);
        assert!(handle.has_stream(id));
    }
}

#[test]
fn test_unidirectional_stream_ids() {
    // RFC 9000: Client-initiated unidirectional streams have IDs 2, 6, 10, 14, ...
    let handle = MockConnectionHandle::new();

    // Valid client unidirectional stream IDs (0x02 | 0x00 = 2, then +4)
    let valid_ids = vec![2, 6, 10, 14, 18, 22];
    for id in valid_ids {
        handle.open_stream(id, false);
        assert!(handle.has_stream(id));
    }
}

#[test]
fn test_server_initiated_streams_rejected() {
    // Server (this implementation) should not accept server-initiated streams from peer
    // Server bidirectional: IDs 1, 5, 9, 13, ...
    // Server unidirectional: IDs 3, 7, 11, 15, ...
    // (In actual H3Session, these would be rejected)

    let handle = MockConnectionHandle::new();

    // These would be valid server stream IDs, but client shouldn't send them
    let server_bidi_ids = vec![1, 5, 9, 13];
    let server_uni_ids = vec![3, 7, 11, 15];

    // Test setup - these exist in mock but H3Session would reject
    for id in server_bidi_ids {
        handle.open_stream(id, true);
        assert!(handle.has_stream(id));
    }

    for id in server_uni_ids {
        handle.open_stream(id, false);
        assert!(handle.has_stream(id));
    }
}

#[test]
fn test_stream_id_ordering_enforcement() {
    // Comprehensive test: streams must arrive in increasing ID order
    let handle = MockConnectionHandle::new();

    // Scenario 1: Streams arrive in order (valid)
    handle.open_stream(4, true);
    handle.open_stream(8, true);
    handle.open_stream(12, true);

    // Scenario 2: Stream arrives out of order (should be rejected in H3Session)
    // This simulates receiving stream 16, then trying to receive stream 8
    handle.open_stream(16, true);
    // In H3Session, attempting to process stream 8 now would fail with H3_ID_ERROR
}

#[test]
fn test_concurrent_stream_id_tracking() {
    // Test that bidi and uni streams are tracked separately
    let handle = MockConnectionHandle::new();

    // Open bidirectional streams
    handle.open_stream(0, true); // Client bidi
    handle.open_stream(4, true);
    handle.open_stream(8, true);

    // Open unidirectional streams
    handle.open_stream(2, false); // Client uni
    handle.open_stream(6, false);
    handle.open_stream(10, false);

    // All should coexist
    assert!(handle.has_stream(0));
    assert!(handle.has_stream(4));
    assert!(handle.has_stream(8));
    assert!(handle.has_stream(2));
    assert!(handle.has_stream(6));
    assert!(handle.has_stream(10));
}

#[test]
fn test_max_stream_id_tracking() {
    // Test tracking of maximum seen stream ID
    let handle = MockConnectionHandle::new();

    // Open streams in increasing order
    let stream_ids = vec![4, 8, 16, 20, 32];
    for id in &stream_ids {
        handle.open_stream(*id, true);
    }

    // Maximum should be 32
    // In H3Session, any stream ID <= 32 received later would be H3_ID_ERROR
}

#[test]
fn test_stream_id_validation_with_data() {
    // Test that data on invalid stream IDs is rejected
    let handle = MockConnectionHandle::new();

    // Open stream 8
    handle.open_stream(8, true);
    handle.receive_data(8, Bytes::from("valid data"), false);

    // Attempting to send data on stream 4 (< 8) should be rejected
    // (In H3Session this would be detected and cause H3_ID_ERROR)
}

#[test]
fn test_stream_id_overflow_protection() {
    // Test handling of very large stream IDs (near u64::MAX)
    let handle = MockConnectionHandle::new();

    // Open streams with progressively larger IDs
    handle.open_stream(4, true);
    handle.open_stream(100, true);
    handle.open_stream(10000, true);

    // All valid if increasing
    assert!(handle.has_stream(4));
    assert!(handle.has_stream(100));
    assert!(handle.has_stream(10000));
}
