use bytes::Bytes;
use quicd_h3::frames::{H3Frame, Priority, Setting};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_frame_encoding_decoding() {
        // Test PRIORITY frame with request stream
        let priority = Priority {
            prioritized_element_type: 0x00, // request stream
            element_id: 1,
            priority_element_type: 0x00, // request stream
            priority_id: 0,
        };

        let frame = H3Frame::Priority { priority };
        let encoded = frame.encode();

        // Parse it back
        let (decoded_frame, consumed) = H3Frame::parse(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());

        match decoded_frame {
            H3Frame::Priority { priority: decoded_priority } => {
                assert_eq!(decoded_priority.prioritized_element_type, 0x00);
                assert_eq!(decoded_priority.element_id, 1);
                assert_eq!(decoded_priority.priority_element_type, 0x00);
                assert_eq!(decoded_priority.priority_id, 0);
            }
            _ => panic!("Expected PRIORITY frame"),
        }
    }

    #[test]
    fn test_push_promise_frame_encoding_decoding() {
        let push_id = 42;
        let headers_data = b"encoded headers data";

        let frame = H3Frame::PushPromise {
            push_id,
            encoded_headers: Bytes::from(headers_data.as_ref()),
        };
        let encoded = frame.encode();

        // Parse it back
        let (decoded_frame, consumed) = H3Frame::parse(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());

        match decoded_frame {
            H3Frame::PushPromise { push_id: decoded_push_id, encoded_headers } => {
                assert_eq!(decoded_push_id, push_id);
                assert_eq!(encoded_headers.as_ref(), headers_data);
            }
            _ => panic!("Expected PUSH_PROMISE frame"),
        }
    }

    #[test]
    fn test_max_push_id_frame_encoding_decoding() {
        let push_id = 100;

        let frame = H3Frame::MaxPushId { push_id };
        let encoded = frame.encode();

        // Parse it back
        let (decoded_frame, consumed) = H3Frame::parse(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());

        match decoded_frame {
            H3Frame::MaxPushId { push_id: decoded_push_id } => {
                assert_eq!(decoded_push_id, push_id);
            }
            _ => panic!("Expected MAX_PUSH_ID frame"),
        }
    }

    #[test]
    fn test_cancel_push_frame_encoding_decoding() {
        let push_id = 123;

        let frame = H3Frame::CancelPush { push_id };
        let encoded = frame.encode();

        // Parse it back
        let (decoded_frame, consumed) = H3Frame::parse(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());

        match decoded_frame {
            H3Frame::CancelPush { push_id: decoded_push_id } => {
                assert_eq!(decoded_push_id, push_id);
            }
            _ => panic!("Expected CANCEL_PUSH frame"),
        }
    }

    #[test]
    fn test_settings_frame_encoding_decoding() {
        let settings = vec![
            Setting { identifier: 0x1, value: 4096 }, // QPACK max table capacity
            Setting { identifier: 0x6, value: 0 },    // Max field section size
            Setting { identifier: 0x7, value: 100 },  // QPACK blocked streams
        ];

        let frame = H3Frame::Settings { settings };
        let encoded = frame.encode();

        // Parse it back
        let (decoded_frame, consumed) = H3Frame::parse(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());

        match decoded_frame {
            H3Frame::Settings { settings: decoded_settings } => {
                assert_eq!(decoded_settings.len(), 3);
                assert_eq!(decoded_settings[0].identifier, 0x1);
                assert_eq!(decoded_settings[0].value, 4096);
                assert_eq!(decoded_settings[1].identifier, 0x6);
                assert_eq!(decoded_settings[1].value, 0);
                assert_eq!(decoded_settings[2].identifier, 0x7);
                assert_eq!(decoded_settings[2].value, 100);
            }
            _ => panic!("Expected SETTINGS frame"),
        }
    }

    #[test]
    fn test_headers_frame_encoding_decoding() {
        let headers_data = b"encoded qpack headers";

        let frame = H3Frame::Headers {
            encoded_headers: Bytes::from(headers_data.as_ref()),
        };
        let encoded = frame.encode();

        // Parse it back
        let (decoded_frame, consumed) = H3Frame::parse(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());

        match decoded_frame {
            H3Frame::Headers { encoded_headers } => {
                assert_eq!(encoded_headers.as_ref(), headers_data);
            }
            _ => panic!("Expected HEADERS frame"),
        }
    }

    #[test]
    fn test_data_frame_encoding_decoding() {
        let data = b"Hello, HTTP/3 world!";

        let frame = H3Frame::Data {
            data: Bytes::from(data.as_ref()),
        };
        let encoded = frame.encode();

        // Parse it back
        let (decoded_frame, consumed) = H3Frame::parse(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());

        match decoded_frame {
            H3Frame::Data { data: decoded_data } => {
                assert_eq!(decoded_data.as_ref(), data);
            }
            _ => panic!("Expected DATA frame"),
        }
    }

    #[test]
    fn test_goaway_frame_encoding_decoding() {
        let stream_id = 42;

        let frame = H3Frame::GoAway { stream_id };
        let encoded = frame.encode();

        // Parse it back
        let (decoded_frame, consumed) = H3Frame::parse(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());

        match decoded_frame {
            H3Frame::GoAway { stream_id: decoded_stream_id } => {
                assert_eq!(decoded_stream_id, stream_id);
            }
            _ => panic!("Expected GOAWAY frame"),
        }
    }

    #[test]
    fn test_duplicate_push_frame_encoding_decoding() {
        let push_id = 99;

        let frame = H3Frame::DuplicatePush { push_id };
        let encoded = frame.encode();

        // Parse it back
        let (decoded_frame, consumed) = H3Frame::parse(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());

        match decoded_frame {
            H3Frame::DuplicatePush { push_id: decoded_push_id } => {
                assert_eq!(decoded_push_id, push_id);
            }
            _ => panic!("Expected DUPLICATE_PUSH frame"),
        }
    }

    #[test]
    fn test_multiple_frames_parsing() {
        let mut combined_data = Vec::new();

        // Create multiple frames
        let frame1 = H3Frame::Data { data: Bytes::from("frame1") };
        let frame2 = H3Frame::Headers { encoded_headers: Bytes::from("headers") };
        let frame3 = H3Frame::MaxPushId { push_id: 123 };

        combined_data.extend_from_slice(&frame1.encode());
        combined_data.extend_from_slice(&frame2.encode());
        combined_data.extend_from_slice(&frame3.encode());

        // Parse all frames
        let mut offset = 0;
        let mut frame_count = 0;

        while offset < combined_data.len() {
            let (frame, consumed) = H3Frame::parse(&combined_data[offset..]).unwrap();
            offset += consumed;
            frame_count += 1;

            match frame_count {
                1 => assert!(matches!(frame, H3Frame::Data { .. })),
                2 => assert!(matches!(frame, H3Frame::Headers { .. })),
                3 => assert!(matches!(frame, H3Frame::MaxPushId { .. })),
                _ => panic!("Unexpected frame count"),
            }
        }

        assert_eq!(frame_count, 3);
        assert_eq!(offset, combined_data.len());
    }
}