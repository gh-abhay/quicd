//! GAP #3: Stream ID monotonicity validation tests (RFC 9114 Section 6.1)

use bytes::Bytes;

#[test]
fn test_stream_id_monotonicity_bidirectional() {
    // Test that bidirectional stream IDs must be strictly increasing
    // RFC 9114 Section 6.1: "An endpoint that receives an unexpected stream ID
    // MUST respond with a connection error of type H3_ID_ERROR."
    
    // This would require mocking the QUIC layer to inject stream open events
    // For now, this is a placeholder for integration testing
    // TODO: Implement with mock ConnectionHandle
}

#[test]
fn test_stream_id_monotonicity_unidirectional() {
    // Test that unidirectional stream IDs must be strictly increasing
    // Similar to bidirectional test but for uni streams
    
    // TODO: Implement with mock ConnectionHandle
}

#[test]
fn test_stream_id_even_client_rejected() {
    // Test that even-numbered streams from client are rejected
    // RFC 9000: Client-initiated streams have odd IDs
    
    // TODO: Implement with mock ConnectionHandle
}

#[test]
fn test_stream_id_gap_allowed() {
    // Test that gaps in stream IDs are allowed
    // RFC 9114: Stream IDs can have gaps (e.g., 1, 5, 9 is valid)
    
    // TODO: Implement with mock ConnectionHandle
}

#[test]
fn test_stream_id_reuse_rejected() {
    // Test that reusing a stream ID is rejected
    // Once ID N is used, no stream with ID <= N can be opened
    
    // TODO: Implement with mock ConnectionHandle
}
