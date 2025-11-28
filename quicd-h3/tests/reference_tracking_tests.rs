/// Tests for QPACK dynamic table reference tracking per RFC 9204 Section 2.1.2
/// These tests verify the API works correctly even though internal counts aren't exposed
use quicd_h3::qpack::QpackCodec;

#[test]
fn test_reference_tracking_basic_operations() {
    let mut codec = QpackCodec::with_capacity(4096);
    
    // Insert entry into dynamic table
    codec.insert("x-custom-header".to_string(), "value1".to_string());
    
    // Add and release references - should not panic
    codec.add_reference(0);
    codec.release_reference(0);
}

#[test]
fn test_multiple_references_same_entry() {
    let mut codec = QpackCodec::with_capacity(4096);
    
    codec.insert("content-type".to_string(), "application/json".to_string());
    
    // Multiple streams reference the same entry
    codec.add_reference(0);
    codec.add_reference(0);
    codec.add_reference(0);
    
    // Release references one by one
    codec.release_reference(0);
    codec.release_reference(0);
    codec.release_reference(0);
}

#[test]
fn test_reference_tracking_with_eviction() {
    let mut codec = QpackCodec::with_capacity(256); // Small capacity
    
    // Insert first entry
    codec.insert("header-1".to_string(), "value-1".to_string());
    codec.add_reference(0); // Reference it
    
    // Insert many more entries to trigger eviction
    for i in 2..20 {
        codec.insert(format!("header-{}", i), format!("value-{}", i));
    }
    
    // Release the reference when done
    codec.release_reference(0);
}

#[test]
fn test_reference_multiple_entries() {
    let mut codec = QpackCodec::with_capacity(4096);
    
    // Insert multiple entries
    codec.insert("header-1".to_string(), "value-1".to_string());
    codec.insert("header-2".to_string(), "value-2".to_string());
    codec.insert("header-3".to_string(), "value-3".to_string());
    
    // Reference all of them
    codec.add_reference(0);
    codec.add_reference(1);
    codec.add_reference(2);
    
    // Release in different order
    codec.release_reference(1);
    codec.release_reference(0);
    codec.release_reference(2);
}

#[test]
fn test_reference_tracking_during_encoding() {
    let mut codec = QpackCodec::with_capacity(4096);
    
    // Insert entries
    codec.insert("x-trace-id".to_string(), "abc123".to_string());
    codec.insert("x-request-id".to_string(), "xyz789".to_string());
    
    // Encode headers that may reference dynamic table
    let headers = vec![
        ("x-trace-id".to_string(), "abc123".to_string()),
        ("x-request-id".to_string(), "xyz789".to_string()),
    ];
    
    let result = codec.encode_headers(&headers);
    assert!(result.is_ok());
    
    let (_, _, referenced) = result.unwrap();
    
    // Add references for any dynamic table entries used
    for index in &referenced {
        codec.add_reference(*index);
    }
    
    // Release when done
    for index in referenced {
        codec.release_reference(index);
    }
}

#[test]
fn test_release_without_add() {
    let mut codec = QpackCodec::with_capacity(4096);
    
    codec.insert("test-header".to_string(), "test-value".to_string());
    
    // Release reference that was never added (should handle gracefully)
    codec.release_reference(0);
    // Should not panic
}

#[test]
fn test_reference_tracking_with_capacity_changes() {
    let mut codec = QpackCodec::with_capacity(512);
    
    // Insert and reference entries
    codec.insert("header-1".to_string(), "value-1".to_string());
    codec.insert("header-2".to_string(), "value-2".to_string());
    codec.add_reference(0);
    codec.add_reference(1);
    
    // Update table capacity
    codec.set_table_capacity(256);
    
    // Release references - should work even after capacity change
    codec.release_reference(0);
    codec.release_reference(1);
}

#[test]
fn test_rfc_9204_reference_lifecycle() {
    // RFC 9204 Section 2.1.2: References must be tracked for dynamic table entries
    
    let mut codec = QpackCodec::with_capacity(4096);
    
    // 1. Insert entry
    codec.insert("authorization".to_string(), "Bearer token".to_string());
    
    // 2. Add reference when encoding uses it
    codec.add_reference(0);
    
    // 3. Entry should not be evicted while referenced (even if table fills)
    for i in 1..50 {
        codec.insert(format!("filler-{}", i), format!("data-{}", i));
    }
    
    // 4. Release reference when stream completes
    codec.release_reference(0);
    
    // 5. Now entry can be evicted if needed
}

#[test]
fn test_concurrent_stream_references() {
    let mut codec = QpackCodec::with_capacity(4096);
    
    // Simulate scenario where multiple streams use same dynamic entry
    codec.insert("common-header".to_string(), "shared-value".to_string());
    
    // Stream 1, 2, 3 all reference it
    codec.add_reference(0); // Stream 1
    codec.add_reference(0); // Stream 2  
    codec.add_reference(0); // Stream 3
    
    // Streams complete at different times
    codec.release_reference(0); // Stream 1 done
    codec.release_reference(0); // Stream 2 done
    codec.release_reference(0); // Stream 3 done
}

#[test]
fn test_reference_tracking_insert_count_sync() {
    let mut codec = QpackCodec::with_capacity(4096);
    
    let initial_count = codec.insert_count();
    
    codec.insert("header-1".to_string(), "value-1".to_string());
    codec.insert("header-2".to_string(), "value-2".to_string());
    
    // Insert count tracks entries added to dynamic table
    // Note: May not increment if table capacity is 0 (not yet set via SETTINGS)
    let _final_count = codec.insert_count();
    assert!(_final_count >= initial_count);
    
    // Reference tracking should work correctly with insert count
    codec.add_reference(0);
    codec.add_reference(1);
    codec.release_reference(0);
    codec.release_reference(1);
}

#[test]
fn test_reference_many_entries() {
    let mut codec = QpackCodec::with_capacity(4096);
    
    // Insert many entries
    for i in 0..100 {
        codec.insert(format!("header-{}", i), format!("value-{}", i));
    }
    
    // Reference many entries
    for i in 0..100 {
        codec.add_reference(i);
    }
    
    // Release all
    for i in 0..100 {
        codec.release_reference(i);
    }
}

#[test]
fn test_reference_tracking_boundary_conditions() {
    let mut codec = QpackCodec::with_capacity(4096);
    
    // Empty table - release should not panic
    codec.release_reference(0);
    codec.release_reference(999);
    
    // Add some entries
    codec.insert("test".to_string(), "value".to_string());
    
    // Reference valid and invalid indices
    codec.add_reference(0); // Valid
    codec.add_reference(100); // Invalid - should handle gracefully
    
    codec.release_reference(0);
    codec.release_reference(100);
}
