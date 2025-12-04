/// Tests for GOAWAY and other frame varint encoding (RFC 9114 Section 7.2.6)
use quicd_h3::frames::H3Frame;

#[test]
fn test_goaway_frame_encoding() {
    let goaway = H3Frame::GoAway { stream_id: 1234567 };
    let encoded = goaway.encode();

    // Verify it's not using fixed 8-byte encoding
    assert!(encoded.len() < 12); // Type (1-2 bytes) + Length (1-2 bytes) + Value (< 8 bytes)

    // Decode and verify
    let (decoded, _) = H3Frame::parse(&encoded).unwrap();
    match decoded {
        H3Frame::GoAway { stream_id } => {
            assert_eq!(stream_id, 1234567);
        }
        _ => panic!("Expected GoAway frame"),
    }
}

#[test]
fn test_cancel_push_frame_encoding() {
    let cancel = H3Frame::CancelPush { push_id: 42 };
    let encoded = cancel.encode();

    // Verify varint encoding (not fixed 8 bytes)
    assert!(encoded.len() < 12);

    let (decoded, _) = H3Frame::parse(&encoded).unwrap();
    match decoded {
        H3Frame::CancelPush { push_id } => {
            assert_eq!(push_id, 42);
        }
        _ => panic!("Expected CancelPush frame"),
    }
}

#[test]
fn test_max_push_id_frame_encoding() {
    let max_push = H3Frame::MaxPushId { push_id: 1000 };
    let encoded = max_push.encode();

    // Verify varint encoding
    assert!(encoded.len() < 12);

    let (decoded, _) = H3Frame::parse(&encoded).unwrap();
    match decoded {
        H3Frame::MaxPushId { push_id } => {
            assert_eq!(push_id, 1000);
        }
        _ => panic!("Expected MaxPushId frame"),
    }
}

#[test]
fn test_push_promise_frame_encoding() {
    use bytes::Bytes;
    let headers = Bytes::from(vec![0x00, 0x01, 0x02, 0x03]); // Dummy encoded headers
    let push_promise = H3Frame::PushPromise {
        push_id: 99,
        encoded_headers: headers.clone(),
    };
    let encoded = push_promise.encode();

    let (decoded, _) = H3Frame::parse(&encoded).unwrap();
    match decoded {
        H3Frame::PushPromise {
            push_id,
            encoded_headers,
        } => {
            assert_eq!(push_id, 99);
            assert_eq!(encoded_headers, headers);
        }
        _ => panic!("Expected PushPromise frame"),
    }
}

#[test]
fn test_large_id_varint_encoding() {
    // Test with large IDs to ensure varint encoding works correctly
    let large_id = 16383; // Requires 2-byte varint
    let goaway = H3Frame::GoAway {
        stream_id: large_id,
    };
    let encoded = goaway.encode();

    let (decoded, _) = H3Frame::parse(&encoded).unwrap();
    match decoded {
        H3Frame::GoAway { stream_id } => {
            assert_eq!(stream_id, large_id);
        }
        _ => panic!("Expected GoAway frame"),
    }

    // Test very large ID
    let very_large_id = 1_073_741_823; // Requires 4-byte varint
    let goaway = H3Frame::GoAway {
        stream_id: very_large_id,
    };
    let encoded = goaway.encode();

    let (decoded, _) = H3Frame::parse(&encoded).unwrap();
    match decoded {
        H3Frame::GoAway { stream_id } => {
            assert_eq!(stream_id, very_large_id);
        }
        _ => panic!("Expected GoAway frame"),
    }
}
