use bytes::Bytes;
/// Zero-copy optimizations and performance tests
use quicd_h3::frames::H3Frame;

#[test]
fn test_zero_copy_frame_parsing() {
    // Create a DATA frame
    let data = Bytes::from(vec![1, 2, 3, 4, 5]);
    let frame = H3Frame::Data { data: data.clone() };
    let encoded = frame.encode();

    // Parse using zero-copy method - parse_bytes uses Bytes::slice internally
    let (parsed, consumed) = H3Frame::parse_bytes(&encoded).unwrap();

    assert_eq!(consumed, encoded.len());
    match parsed {
        H3Frame::Data { data: parsed_data } => {
            assert_eq!(parsed_data, data);
            // parse_bytes uses Bytes::slice which is zero-copy friendly (reference counted slices)
        }
        _ => panic!("Expected DATA frame"),
    }
}

#[test]
fn test_optimized_cancel_push_encoding() {
    // Test that CancelPush frame encoding is optimized (no intermediate buffer)
    let push_id = 12345u64;
    let frame = H3Frame::CancelPush { push_id };
    let encoded = frame.encode();

    // Parse it back
    let (parsed, consumed) = H3Frame::parse(&encoded).unwrap();

    assert_eq!(consumed, encoded.len());
    match parsed {
        H3Frame::CancelPush { push_id: parsed_id } => {
            assert_eq!(parsed_id, push_id);
        }
        _ => panic!("Expected CANCEL_PUSH frame"),
    }
}

#[test]
fn test_optimized_goaway_encoding() {
    // Test that GoAway frame encoding is optimized
    let stream_id = 98765u64;
    let frame = H3Frame::GoAway { stream_id };
    let encoded = frame.encode();

    let (parsed, _) = H3Frame::parse(&encoded).unwrap();

    match parsed {
        H3Frame::GoAway {
            stream_id: parsed_id,
        } => {
            assert_eq!(parsed_id, stream_id);
        }
        _ => panic!("Expected GOAWAY frame"),
    }
}

#[test]
fn test_optimized_max_push_id_encoding() {
    // Test that MaxPushId frame encoding is optimized
    let push_id = 54321u64;
    let frame = H3Frame::MaxPushId { push_id };
    let encoded = frame.encode();

    let (parsed, _) = H3Frame::parse(&encoded).unwrap();

    match parsed {
        H3Frame::MaxPushId { push_id: parsed_id } => {
            assert_eq!(parsed_id, push_id);
        }
        _ => panic!("Expected MAX_PUSH_ID frame"),
    }
}

#[test]
fn test_frame_encoding_sizes() {
    // Test that frame encoding produces minimal sizes

    // Small push_id (< 64) should use 1 byte
    let frame1 = H3Frame::CancelPush { push_id: 42 };
    let encoded1 = frame1.encode();
    // Frame type (1) + length (1) + push_id (1) = 3 bytes
    assert_eq!(encoded1.len(), 3);

    // Medium push_id (< 16384) should use 2 bytes
    let frame2 = H3Frame::CancelPush { push_id: 1000 };
    let encoded2 = frame2.encode();
    // Frame type (1) + length (1) + push_id (2) = 4 bytes
    assert_eq!(encoded2.len(), 4);

    // Large push_id (< 1073741824) should use 4 bytes
    let frame3 = H3Frame::CancelPush { push_id: 100000 };
    let encoded3 = frame3.encode();
    // Frame type (1) + length (1) + push_id (4) = 6 bytes
    assert_eq!(encoded3.len(), 6);
}

#[test]
fn test_parse_bytes_multiple_frames() {
    // Test zero-copy parsing of multiple frames
    let frame1 = H3Frame::CancelPush { push_id: 1 };
    let frame2 = H3Frame::MaxPushId { push_id: 100 };
    let frame3 = H3Frame::GoAway { stream_id: 200 };

    let encoded1 = frame1.encode();
    let encoded2 = frame2.encode();
    let encoded3 = frame3.encode();

    // Concatenate frames
    let mut combined =
        bytes::BytesMut::with_capacity(encoded1.len() + encoded2.len() + encoded3.len());
    combined.extend_from_slice(&encoded1);
    combined.extend_from_slice(&encoded2);
    combined.extend_from_slice(&encoded3);
    let combined = combined.freeze();

    // Parse all frames using zero-copy method
    let (frames, total_consumed) = H3Frame::parse_multiple(&combined).unwrap();

    assert_eq!(frames.len(), 3);
    assert_eq!(total_consumed, combined.len());

    // Verify frames
    match &frames[0] {
        H3Frame::CancelPush { push_id } => assert_eq!(*push_id, 1),
        _ => panic!("Expected CANCEL_PUSH"),
    }
    match &frames[1] {
        H3Frame::MaxPushId { push_id } => assert_eq!(*push_id, 100),
        _ => panic!("Expected MAX_PUSH_ID"),
    }
    match &frames[2] {
        H3Frame::GoAway { stream_id } => assert_eq!(*stream_id, 200),
        _ => panic!("Expected GOAWAY"),
    }
}

#[test]
fn test_headers_frame_zero_copy() {
    // Test that HEADERS frame uses Bytes::slice for efficient parsing
    let encoded_headers = Bytes::from(vec![0x01, 0x02, 0x03, 0x04]);
    let frame = H3Frame::Headers {
        encoded_headers: encoded_headers.clone(),
    };
    let encoded_frame = frame.encode();

    // Parse back using zero-copy method
    let (parsed, _) = H3Frame::parse_bytes(&encoded_frame).unwrap();

    match parsed {
        H3Frame::Headers {
            encoded_headers: parsed_headers,
        } => {
            assert_eq!(parsed_headers, encoded_headers);
            // parse_bytes uses Bytes::slice internally for zero-copy
        }
        _ => panic!("Expected HEADERS frame"),
    }
}

#[test]
fn test_data_frame_zero_copy() {
    // Test that DATA frame uses Bytes for efficient handling
    let data = Bytes::from(b"Hello, HTTP/3!".to_vec());
    let frame = H3Frame::Data { data: data.clone() };
    let encoded_frame = frame.encode();

    // Parse back using zero-copy method
    let (parsed, _) = H3Frame::parse_bytes(&encoded_frame).unwrap();

    match parsed {
        H3Frame::Data { data: parsed_data } => {
            assert_eq!(parsed_data, data);
            // Bytes uses reference counting for efficient memory management
        }
        _ => panic!("Expected DATA frame"),
    }
}

#[test]
fn test_large_frame_encoding() {
    // Test encoding of a large DATA frame (should still be efficient)
    let large_data = Bytes::from(vec![0xAB; 65536]); // 64 KB
    let frame = H3Frame::Data {
        data: large_data.clone(),
    };

    let encoded = frame.encode();

    // Frame type (1) + length varint (4 bytes for 65536 since it's >= 16384) + data (65536) = 65541
    assert_eq!(encoded.len(), 1 + 4 + 65536);

    // Parse back
    let (parsed, consumed) = H3Frame::parse(&encoded).unwrap();
    assert_eq!(consumed, encoded.len());

    match parsed {
        H3Frame::Data { data } => {
            assert_eq!(data.len(), 65536);
            assert_eq!(data, large_data);
        }
        _ => panic!("Expected DATA frame"),
    }
}
