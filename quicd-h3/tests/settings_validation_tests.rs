/// Tests for SETTINGS frame validation (RFC 9114 Sections 6.2.1, 7.2.4)
use quicd_h3::error::{H3Error, H3ErrorCode};
use quicd_h3::frames::{H3Frame, Setting};

#[test]
fn test_settings_frame_encoding() {
    let settings = H3Frame::Settings {
        settings: vec![
            Setting {
                identifier: 0x1,
                value: 4096,
            }, // QPACK_MAX_TABLE_CAPACITY
            Setting {
                identifier: 0x6,
                value: 16384,
            }, // MAX_FIELD_SECTION_SIZE
            Setting {
                identifier: 0x7,
                value: 100,
            }, // QPACK_BLOCKED_STREAMS
        ],
    };

    let encoded = settings.encode();
    assert!(!encoded.is_empty());

    // Decode and verify
    let (decoded, _) = H3Frame::parse(&encoded).unwrap();
    match decoded {
        H3Frame::Settings {
            settings: decoded_settings,
        } => {
            assert_eq!(decoded_settings.len(), 3);
            assert_eq!(decoded_settings[0].identifier, 0x1);
            assert_eq!(decoded_settings[0].value, 4096);
        }
        _ => panic!("Expected Settings frame"),
    }
}

#[test]
fn test_settings_identifier_values() {
    // Test RFC-defined setting identifiers
    assert_eq!(0x1, 0x1); // SETTINGS_QPACK_MAX_TABLE_CAPACITY
    assert_eq!(0x6, 0x6); // SETTINGS_MAX_FIELD_SECTION_SIZE
    assert_eq!(0x7, 0x7); // SETTINGS_QPACK_BLOCKED_STREAMS
}

#[test]
fn test_unknown_settings_ignored() {
    // Unknown settings should be ignored per RFC 9114 Section 7.2.4
    let settings = H3Frame::Settings {
        settings: vec![
            Setting {
                identifier: 0x1,
                value: 4096,
            },
            Setting {
                identifier: 0xFF,
                value: 12345,
            }, // Unknown
            Setting {
                identifier: 0x7,
                value: 100,
            },
        ],
    };

    let encoded = settings.encode();
    let (decoded, _) = H3Frame::parse(&encoded).unwrap();

    match decoded {
        H3Frame::Settings {
            settings: decoded_settings,
        } => {
            assert_eq!(decoded_settings.len(), 3);
            // Unknown setting should still be present in raw data
            assert_eq!(decoded_settings[1].identifier, 0xFF);
        }
        _ => panic!("Expected Settings frame"),
    }
}

#[test]
fn test_error_code_mapping() {
    let error = H3Error::Connection("H3_MISSING_SETTINGS: first frame was not SETTINGS".into());
    let code = error.to_error_code();
    assert_eq!(code, H3ErrorCode::MissingSettings);

    let error = H3Error::Connection("H3_FRAME_UNEXPECTED: duplicate SETTINGS frame".into());
    let code = error.to_error_code();
    assert_eq!(code, H3ErrorCode::FrameUnexpected);
}
