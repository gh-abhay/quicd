//! Performance optimization tests for QPACK and frame parsing

use bytes::Bytes;
use quicd_h3::{H3Frame, QpackCodec};
use quicd_h3::frames::Setting;

#[test]
fn test_qpack_with_capacity_preallocates() {
    // Create codec with 4KB capacity
    let codec = QpackCodec::with_capacity(4096);
    
    // Verify it was created successfully
    assert_eq!(codec.table_capacity(), 0); // Not set until set_max_table_capacity called
    
    // The internal Vec should be pre-allocated (can't directly test, but no panic is good)
}

#[test]
fn test_qpack_preallocates_on_set_max_capacity() {
    let mut codec = QpackCodec::new();
    
    // Set a large capacity
    codec.set_max_table_capacity(8192); // 8KB = ~256 entries
    
    // Should not panic and capacity should be set
    assert_eq!(codec.table_capacity(), 8192);
}

#[test]
fn test_frame_batch_parsing_single_frame() {
    // Encode a SETTINGS frame
    let settings = vec![
        Setting { identifier: 0x1, value: 4096 },
        Setting { identifier: 0x6, value: 16384 },
    ];
    let frame = H3Frame::Settings { settings: settings.clone() };
    let encoded = frame.encode();
    
    // Parse using batch parser
    let (frames, consumed) = H3Frame::parse_multiple(&encoded).unwrap();
    
    assert_eq!(frames.len(), 1);
    assert_eq!(consumed, encoded.len());
    
    match &frames[0] {
        H3Frame::Settings { settings: parsed } => {
            assert_eq!(parsed.len(), 2);
            assert_eq!(parsed[0].identifier, 0x1);
            assert_eq!(parsed[0].value, 4096);
        }
        _ => panic!("Expected SETTINGS frame"),
    }
}

#[test]
fn test_frame_batch_parsing_multiple_frames() {
    // Create multiple frames
    let frame1 = H3Frame::MaxPushId { push_id: 100 };
    let frame2 = H3Frame::GoAway { stream_id: 42 };
    let frame3 = H3Frame::CancelPush { push_id: 10 };
    
    // Encode them
    let encoded1 = frame1.encode();
    let encoded2 = frame2.encode();
    let encoded3 = frame3.encode();
    
    // Concatenate into single buffer
    let mut combined = Vec::new();
    combined.extend_from_slice(&encoded1);
    combined.extend_from_slice(&encoded2);
    combined.extend_from_slice(&encoded3);
    let combined_bytes = Bytes::from(combined);
    
    // Parse all at once
    let (frames, consumed) = H3Frame::parse_multiple(&combined_bytes).unwrap();
    
    assert_eq!(frames.len(), 3);
    assert_eq!(consumed, combined_bytes.len());
    
    assert!(matches!(frames[0], H3Frame::MaxPushId { push_id: 100 }));
    assert!(matches!(frames[1], H3Frame::GoAway { stream_id: 42 }));
    assert!(matches!(frames[2], H3Frame::CancelPush { push_id: 10 }));
}

#[test]
fn test_frame_batch_parsing_partial_frame() {
    // Create a frame and only include partial data
    let frame = H3Frame::MaxPushId { push_id: 999 };
    let encoded = frame.encode();
    
    // Take only first 3 bytes (incomplete)
    let partial = encoded.slice(0..3);
    
    // Should return empty Vec, not error
    let (frames, consumed) = H3Frame::parse_multiple(&partial).unwrap();
    
    assert_eq!(frames.len(), 0);
    assert_eq!(consumed, 0);
}

#[test]
fn test_qpack_decode_with_preallocated_headers() {
    let mut codec = QpackCodec::new();
    
    // Encode some headers
    let headers = vec![
        (":method".to_string(), "GET".to_string()),
        (":path".to_string(), "/".to_string()),
        (":scheme".to_string(), "https".to_string()),
        (":authority".to_string(), "example.com".to_string()),
    ];
    
    let (encoded, _instructions, _refs) = codec.encode_headers(&headers).unwrap();
    
    // Decode - should use pre-allocated Vec
    let (decoded, _refs) = codec.decode_headers(&encoded).unwrap();
    
    assert_eq!(decoded.len(), 4);
    assert_eq!(decoded[0], (":method".to_string(), "GET".to_string()));
}

#[test]
fn test_qpack_encode_with_improved_estimation() {
    let mut codec = QpackCodec::new();
    codec.set_max_table_capacity(4096);
    
    // Encode many headers to test buffer estimation
    let headers = vec![
        (":method".to_string(), "POST".to_string()),
        (":path".to_string(), "/api/v1/users".to_string()),
        (":scheme".to_string(), "https".to_string()),
        (":authority".to_string(), "api.example.com".to_string()),
        ("content-type".to_string(), "application/json".to_string()),
        ("authorization".to_string(), "Bearer token123456789".to_string()),
        ("user-agent".to_string(), "test-client/1.0".to_string()),
        ("accept".to_string(), "application/json".to_string()),
    ];
    
    // Should not panic with improved estimation
    let result = codec.encode_headers(&headers);
    assert!(result.is_ok());
    
    let (encoded, _instructions, _refs) = result.unwrap();
    assert!(encoded.len() > 0);
}
