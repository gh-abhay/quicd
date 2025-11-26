//! Integration tests for HTTP/3 RFC compliance modules.
//!
//! Tests the interaction between stream_state, validation, qpack_streams,
//! connect, and settings modules to ensure RFC 9114 and RFC 9204 compliance.

use quicd_h3::error::H3Error;
use quicd_h3::stream_state::{StreamFrameParser, StreamState};
use quicd_h3::validation::{validate_request_headers, validate_response_headers};
use quicd_h3::qpack_streams::QpackStreamManager;
use quicd_h3::settings::{SettingsValidator, SettingsBuilder};
use std::collections::HashMap;

#[test]
fn test_settings_validation_workflow() {
    // Test RFC 9114 Section 7.2.4 compliance
    let mut validator = SettingsValidator::new();
    
    // Should reject non-SETTINGS frame as first frame
    assert!(validator.validate_first_frame().is_err());
    
    // Valid SETTINGS frame
    let settings = SettingsBuilder::new()
        .qpack_max_table_capacity(4096)
        .max_field_section_size(8192)
        .enable_connect_protocol()
        .build();
    
    assert!(validator.validate_settings(settings).is_ok());
    
    // Now first frame check should pass
    assert!(validator.validate_first_frame().is_ok());
    
    // Duplicate SETTINGS should fail
    let settings2 = HashMap::new();
    assert!(validator.validate_settings(settings2).is_err());
    
    // Verify settings values
    assert_eq!(validator.qpack_max_table_capacity(), 4096);
    assert_eq!(validator.max_field_section_size(), Some(8192));
    assert!(validator.enable_connect_protocol());
}

#[test]
fn test_reserved_settings_rejection() {
    let mut validator = SettingsValidator::new();
    
    // Reserved settings should be rejected
    use quicd_h3::settings::known::*;
    let mut settings = HashMap::new();
    settings.insert(RESERVED_0X02, 100);
    
    let result = validator.validate_settings(settings);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), H3Error::SettingsError));
}

#[test]
fn test_request_validation_workflow() {
    // Test RFC 9114 Section 4.3 pseudo-header validation
    
    // Valid GET request
    let headers = vec![
        (":method".to_string(), "GET".to_string()),
        (":scheme".to_string(), "https".to_string()),
        (":authority".to_string(), "example.com".to_string()),
        (":path".to_string(), "/".to_string()),
        ("content-type".to_string(), "text/html".to_string()),
    ];
    
    assert!(validate_request_headers(&headers).is_ok());
    
    // Invalid: uppercase field name
    let bad_headers = vec![
        (":method".to_string(), "GET".to_string()),
        (":scheme".to_string(), "https".to_string()),
        (":authority".to_string(), "example.com".to_string()),
        (":path".to_string(), "/".to_string()),
        ("Content-Type".to_string(), "text/html".to_string()),
    ];
    assert!(validate_request_headers(&bad_headers).is_err());
    
    // Invalid: connection-specific header
    let conn_headers = vec![
        (":method".to_string(), "GET".to_string()),
        (":scheme".to_string(), "https".to_string()),
        (":authority".to_string(), "example.com".to_string()),
        (":path".to_string(), "/".to_string()),
        ("connection".to_string(), "keep-alive".to_string()),
    ];
    assert!(validate_request_headers(&conn_headers).is_err());
}

#[test]
fn test_connect_request_validation() {
    // Standard CONNECT (RFC 9114 Section 4.4)
    let standard_connect = vec![
        (":method".to_string(), "CONNECT".to_string()),
        (":authority".to_string(), "example.com:443".to_string()),
    ];
    
    let result = validate_request_headers(&standard_connect);
    assert!(result.is_ok());
    let pseudo = result.unwrap();
    assert!(pseudo.is_connect());
    assert!(!pseudo.is_extended_connect());
    
    // Extended CONNECT with :protocol
    let extended_connect = vec![
        (":method".to_string(), "CONNECT".to_string()),
        (":scheme".to_string(), "https".to_string()),
        (":authority".to_string(), "example.com".to_string()),
        (":path".to_string(), "/websocket".to_string()),
        (":protocol".to_string(), "websocket".to_string()),
    ];
    
    let result = validate_request_headers(&extended_connect);
    assert!(result.is_ok());
    let pseudo = result.unwrap();
    assert!(pseudo.is_connect());
    assert!(pseudo.is_extended_connect());
    
    // Invalid: standard CONNECT with :scheme
    let invalid_connect = vec![
        (":method".to_string(), "CONNECT".to_string()),
        (":scheme".to_string(), "https".to_string()),
        (":authority".to_string(), "example.com:443".to_string()),
    ];
    
    assert!(validate_request_headers(&invalid_connect).is_err());
}

#[test]
fn test_stream_state_transitions() {
    let parser = StreamFrameParser::new(4);
    
    // Initial state should be Idle
    assert_eq!(parser.state(), StreamState::Idle);
}

#[test]
fn test_qpack_stream_manager() {
    let mut manager = QpackStreamManager::new();
    
    // Initially no streams
    assert!(!manager.has_encoder_stream());
    assert!(!manager.has_decoder_stream());
    
    // Set encoder and decoder streams
    manager.set_encoder_stream(2);
    manager.set_decoder_stream(3);
    
    assert!(manager.has_encoder_stream());
    assert!(manager.has_decoder_stream());
    
    // Test blocked stream tracking
    manager.mark_blocked(4);
    assert!(manager.is_blocked(4));
    
    manager.cancel_stream(4);
    assert!(!manager.is_blocked(4));
}

#[test]
fn test_response_validation() {
    // Valid response
    let headers = vec![
        (":status".to_string(), "200".to_string()),
        ("content-type".to_string(), "text/html".to_string()),
    ];
    
    assert!(validate_response_headers(&headers).is_ok());
    
    // Missing :status
    let bad_headers = vec![
        ("content-type".to_string(), "text/html".to_string()),
    ];
    
    assert!(validate_response_headers(&bad_headers).is_err());
    
    // Duplicate :status
    let dup_headers = vec![
        (":status".to_string(), "200".to_string()),
        (":status".to_string(), "404".to_string()),
    ];
    
    assert!(validate_response_headers(&dup_headers).is_err());
}

#[test]
fn test_integration_settings_and_validation() {
    // Simulate H3 session initialization flow
    
    // 1. Create settings validator
    let mut settings_validator = SettingsValidator::new();
    
    // 2. Receive SETTINGS frame
    let settings = SettingsBuilder::new()
        .qpack_max_table_capacity(4096)
        .max_field_section_size(16384)
        .qpack_blocked_streams(100)
        .enable_connect_protocol()
        .build();
    
    assert!(settings_validator.validate_settings(settings).is_ok());
    
    // 3. Validate request
    let headers = vec![
        (":method".to_string(), "GET".to_string()),
        (":scheme".to_string(), "https".to_string()),
        (":authority".to_string(), "example.com".to_string()),
        (":path".to_string(), "/".to_string()),
        ("user-agent".to_string(), "test".to_string()),
    ];
    
    assert!(validate_request_headers(&headers).is_ok());
    
    // 4. Validate extended CONNECT (should be allowed)
    let connect_headers = vec![
        (":method".to_string(), "CONNECT".to_string()),
        (":scheme".to_string(), "https".to_string()),
        (":authority".to_string(), "example.com".to_string()),
        (":path".to_string(), "/ws".to_string()),
        (":protocol".to_string(), "websocket".to_string()),
    ];
    
    if settings_validator.enable_connect_protocol() {
        assert!(validate_request_headers(&connect_headers).is_ok());
    }
}

#[test]
fn test_integration_qpack_and_streams() {
    // Simulate QPACK stream coordination
    
    let mut manager = QpackStreamManager::new();
    
    // Peer opens encoder stream (type 0x02)
    manager.set_encoder_stream(2);
    
    // Peer opens decoder stream (type 0x03)
    manager.set_decoder_stream(3);
    
    // Mark stream as blocked waiting for dynamic table
    manager.mark_blocked(8);
    assert!(manager.is_blocked(8));
    
    // Simulate section acknowledgment received
    use quicd_h3::qpack::QpackInstruction;
    let ack = QpackInstruction::SectionAcknowledgment { stream_id: 8 };
    
    let result = manager.process_decoder_instruction(ack);
    assert!(result.is_ok());
    
    // Stream should no longer be blocked
    assert!(!manager.is_blocked(8));
}

#[test]
fn test_error_code_mapping() {
    use quicd_h3::error::H3ErrorCode;
    
    // Test proper error code mapping
    let settings_error = H3Error::SettingsError;
    assert_eq!(settings_error.to_error_code() as u64, H3ErrorCode::SettingsError as u64);
    
    let missing_settings = H3Error::MissingSettings;
    assert_eq!(missing_settings.to_error_code() as u64, H3ErrorCode::MissingSettings as u64);
    
    let frame_unexpected = H3Error::FrameUnexpected;
    assert_eq!(frame_unexpected.to_error_code() as u64, H3ErrorCode::FrameUnexpected as u64);
    
    let message_error = H3Error::MessageError;
    assert_eq!(message_error.to_error_code() as u64, H3ErrorCode::MessageError as u64);
}

#[test]
fn test_missing_pseudo_headers() {
    // Missing :method
    let headers = vec![
        (":scheme".to_string(), "https".to_string()),
        (":authority".to_string(), "example.com".to_string()),
        (":path".to_string(), "/".to_string()),
    ];
    assert!(validate_request_headers(&headers).is_err());
    
    // Missing :scheme
    let headers = vec![
        (":method".to_string(), "GET".to_string()),
        (":authority".to_string(), "example.com".to_string()),
        (":path".to_string(), "/".to_string()),
    ];
    assert!(validate_request_headers(&headers).is_err());
    
    // Missing :authority
    let headers = vec![
        (":method".to_string(), "GET".to_string()),
        (":scheme".to_string(), "https".to_string()),
        (":path".to_string(), "/".to_string()),
    ];
    assert!(validate_request_headers(&headers).is_err());
}

#[test]
fn test_pseudo_header_order() {
    // Pseudo-header after regular header should fail
    let headers = vec![
        (":method".to_string(), "GET".to_string()),
        (":scheme".to_string(), "https".to_string()),
        ("user-agent".to_string(), "test".to_string()), // Regular header
        (":authority".to_string(), "example.com".to_string()), // Pseudo after regular
        (":path".to_string(), "/".to_string()),
    ];
    assert!(validate_request_headers(&headers).is_err());
}
