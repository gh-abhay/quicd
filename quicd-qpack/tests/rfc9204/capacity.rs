//! P0 Critical Test: RFC 9204 Section 3.2.2 Maximum Table Capacity Validation
//!
//! Tests that table capacity cannot exceed 2^30 bytes (1,073,741,824).

use quicd_qpack::{Decoder, Encoder};

/// RFC 9204 Section 3.2.2: Capacity MUST NOT exceed 2^30
const MAX_ALLOWED_CAPACITY: usize = 1 << 30; // 1,073,741,824 bytes

#[test]
fn test_max_capacity_limit_enforced() {
    // Should succeed at the limit
    let encoder = Encoder::new(MAX_ALLOWED_CAPACITY, 100);
    assert_eq!(encoder.table().max_capacity(), MAX_ALLOWED_CAPACITY);

    let decoder = Decoder::new(MAX_ALLOWED_CAPACITY, 100);
    assert_eq!(decoder.table().max_capacity(), MAX_ALLOWED_CAPACITY);
}

#[test]
#[should_panic(expected = "exceeds RFC 9204 limit")]
fn test_max_capacity_overflow_rejected_encoder() {
    // Should panic when exceeding 2^30
    let _encoder = Encoder::new(MAX_ALLOWED_CAPACITY + 1, 100);
}

#[test]
#[should_panic(expected = "exceeds RFC 9204 limit")]
fn test_max_capacity_overflow_rejected_decoder() {
    // Should panic when exceeding 2^30
    let _decoder = Decoder::new(MAX_ALLOWED_CAPACITY + 1, 100);
}

#[test]
#[should_panic(expected = "exceeds RFC 9204 limit")]
fn test_max_capacity_way_over_limit() {
    // Test with obviously invalid value (2^31)
    let _encoder = Encoder::new(1usize << 31, 100);
}

#[test]
fn test_set_capacity_respects_limit() {
    let mut encoder = Encoder::new(MAX_ALLOWED_CAPACITY, 100);
    
    // Setting capacity to max should succeed
    assert!(encoder.set_capacity(MAX_ALLOWED_CAPACITY).is_ok());
    
    // Setting capacity above max should fail
    assert!(encoder.set_capacity(MAX_ALLOWED_CAPACITY + 1).is_err());
}

#[test]
fn test_boundary_values() {
    // Test values around the boundary
    let valid_capacities = vec![
        MAX_ALLOWED_CAPACITY - 1,
        MAX_ALLOWED_CAPACITY,
    ];
    
    for capacity in valid_capacities {
        let encoder = Encoder::new(capacity, 100);
        assert_eq!(encoder.table().max_capacity(), capacity);
    }
}

#[test]
fn test_typical_values_still_work() {
    // Ensure common values still work
    let typical_capacities = vec![
        4096,       // 4 KB
        65536,      // 64 KB
        1048576,    // 1 MB
        16777216,   // 16 MB
    ];
    
    for capacity in typical_capacities {
        let encoder = Encoder::new(capacity, 100);
        assert_eq!(encoder.table().max_capacity(), capacity);
        
        let mut encoder_mut = encoder;
        assert!(encoder_mut.set_capacity(capacity).is_ok());
    }
}
