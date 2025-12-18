//! Comprehensive unit tests for HTTP/3 frame parsing and serialization.

use bytes::{Bytes, BytesMut};
use quicd_h3::frame::*;
use quicd_h3::varint;

#[test]
fn test_all_frame_types_roundtrip() {
    let test_frames = vec![
        Frame::Data(DataFrame {
            payload: Bytes::from_static(b"Hello, HTTP/3!"),
        }),
        Frame::Headers(HeadersFrame {
            encoded_field_section: Bytes::from_static(b"\x00\x00\xd1\xd7"),
        }),
        Frame::CancelPush(CancelPushFrame { push_id: 42 }),
        Frame::Settings(SettingsFrame {
            settings: vec![
                Setting {
                    identifier: SettingId::QpackMaxTableCapacity,
                    value: 4096,
                },
                Setting {
                    identifier: SettingId::MaxFieldSectionSize,
                    value: 16384,
                },
            ],
        }),
        Frame::PushPromise(PushPromiseFrame {
            push_id: 100,
            encoded_field_section: Bytes::from_static(b"\x00\x00\xd1"),
        }),
        Frame::Goaway(GoawayFrame { id: 1000 }),
        Frame::MaxPushId(MaxPushIdFrame { push_id: 500 }),
        Frame::Unknown {
            frame_type: 0x21,
            payload: Bytes::from_static(b"unknown frame data"),
        },
    ];

    for frame in test_frames {
        let mut buf = BytesMut::new();
        write_frame(&frame, &mut buf).unwrap();

        let mut parser = FrameParser::new();
        let parsed_frames = parser.parse(buf.freeze()).unwrap();

        assert_eq!(parsed_frames.len(), 1);
        assert_eq!(parsed_frames[0], frame);
    }
}

#[test]
fn test_partial_frame_buffering() {
    let frame = Frame::Data(DataFrame {
        payload: Bytes::from_static(b"This is a longer payload that will be split"),
    });

    let mut buf = BytesMut::new();
    write_frame(&frame, &mut buf).unwrap();
    let serialized = buf.freeze();

    // Split at various points
    for split_point in 1..serialized.len() {
        let mut parser = FrameParser::new();

        // Parse first part - should return no frames
        let part1 = parser.parse(serialized.slice(..split_point)).unwrap();
        assert_eq!(part1.len(), 0, "Partial frame should not be parsed");

        // Parse second part - should return complete frame
        let part2 = parser.parse(serialized.slice(split_point..)).unwrap();
        assert_eq!(part2.len(), 1);
        assert_eq!(part2[0], frame);
    }
}

#[test]
fn test_multiple_frames_in_buffer() {
    let frames = vec![
        Frame::Settings(SettingsFrame {
            settings: vec![Setting {
                identifier: SettingId::QpackMaxTableCapacity,
                value: 4096,
            }],
        }),
        Frame::Headers(HeadersFrame {
            encoded_field_section: Bytes::from_static(b"\x00\x00"),
        }),
        Frame::Data(DataFrame {
            payload: Bytes::from_static(b"body content"),
        }),
        Frame::Data(DataFrame {
            payload: Bytes::from_static(b"more body"),
        }),
    ];

    let mut buf = BytesMut::new();
    for frame in &frames {
        write_frame(frame, &mut buf).unwrap();
    }

    let mut parser = FrameParser::new();
    let parsed = parser.parse(buf.freeze()).unwrap();

    assert_eq!(parsed.len(), frames.len());
    for (original, parsed) in frames.iter().zip(parsed.iter()) {
        assert_eq!(original, parsed);
    }
}

#[test]
fn test_settings_frame_validation() {
    // Valid settings
    let valid = SettingsFrame {
        settings: vec![
            Setting {
                identifier: SettingId::QpackMaxTableCapacity,
                value: 4096,
            },
            Setting {
                identifier: SettingId::MaxFieldSectionSize,
                value: 16384,
            },
            Setting {
                identifier: SettingId::QpackBlockedStreams,
                value: 100,
            },
        ],
    };

    let mut buf = BytesMut::new();
    write_frame(&Frame::Settings(valid), &mut buf).unwrap();

    let mut parser = FrameParser::new();
    let frames = parser.parse(buf.freeze()).unwrap();
    assert_eq!(frames.len(), 1);
}

#[test]
fn test_empty_data_frame() {
    let frame = Frame::Data(DataFrame {
        payload: Bytes::new(),
    });

    let mut buf = BytesMut::new();
    write_frame(&frame, &mut buf).unwrap();

    let mut parser = FrameParser::new();
    let frames = parser.parse(buf.freeze()).unwrap();

    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0], frame);
}

#[test]
fn test_large_data_frame() {
    let large_payload = vec![b'A'; 1_000_000]; // 1 MB
    let frame = Frame::Data(DataFrame {
        payload: Bytes::from(large_payload.clone()),
    });

    let mut buf = BytesMut::new();
    write_frame(&frame, &mut buf).unwrap();

    let mut parser = FrameParser::new();
    let frames = parser.parse(buf.freeze()).unwrap();

    assert_eq!(frames.len(), 1);
    if let Frame::Data(df) = &frames[0] {
        assert_eq!(df.payload.len(), 1_000_000);
    } else {
        panic!("Expected DATA frame");
    }
}

#[test]
fn test_frame_type_validation_on_streams() {
    // DATA frame is valid on request streams
    let data_frame = Frame::Data(DataFrame {
        payload: Bytes::new(),
    });
    assert!(data_frame.is_valid_on_request_stream());
    assert!(!data_frame.is_valid_on_control_stream());

    // SETTINGS frame is valid on control streams only
    let settings_frame = Frame::Settings(SettingsFrame {
        settings: vec![],
    });
    assert!(!settings_frame.is_valid_on_request_stream());
    assert!(settings_frame.is_valid_on_control_stream());

    // PUSH_PROMISE is valid on request streams
    let push_frame = Frame::PushPromise(PushPromiseFrame {
        push_id: 1,
        encoded_field_section: Bytes::new(),
    });
    assert!(push_frame.is_valid_on_request_stream());
    assert!(!push_frame.is_valid_on_control_stream());
}

#[test]
fn test_varint_encoding_in_frames() {
    // Test various varint sizes in frame encoding
    let test_cases = vec![
        (0u64, 1),       // 6-bit
        (63, 1),         // 6-bit max
        (64, 2),         // 14-bit
        (16383, 2),      // 14-bit max
        (16384, 4),      // 30-bit
        (1073741823, 4), // 30-bit max
        (1073741824, 8), // 62-bit
    ];

    for (push_id, expected_varint_len) in test_cases {
        let frame = Frame::MaxPushId(MaxPushIdFrame { push_id });

        let mut buf = BytesMut::new();
        write_frame(&frame, &mut buf).unwrap();

        // Frame structure: type (varint) + length (varint) + payload (varint)
        // Minimum: 1 + 1 + expected_varint_len
        assert!(buf.len() >= expected_varint_len);

        let mut parser = FrameParser::new();
        let frames = parser.parse(buf.freeze()).unwrap();

        assert_eq!(frames.len(), 1);
        if let Frame::MaxPushId(mpf) = &frames[0] {
            assert_eq!(mpf.push_id, push_id);
        } else {
            panic!("Expected MAX_PUSH_ID frame");
        }
    }
}

#[test]
fn test_reserved_frame_types() {
    // Reserved frame types should be parsed as Unknown
    let reserved_type = 0x21; // Reserved per RFC 9114
    let frame = Frame::Unknown {
        frame_type: reserved_type,
        payload: Bytes::from_static(b"reserved payload"),
    };

    let mut buf = BytesMut::new();
    write_frame(&frame, &mut buf).unwrap();

    let mut parser = FrameParser::new();
    let frames = parser.parse(buf.freeze()).unwrap();

    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].frame_type(), reserved_type);
}
