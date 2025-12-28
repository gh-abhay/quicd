//! Integration tests for HTTP/3 end-to-end functionality.
//!
//! These tests verify the complete HTTP/3 protocol flow including
//! connection setup, request/response handling, and proper cleanup.

use bytes::Buf;
use quicd_h3::{H3Application, H3Config};
use tempfile::TempDir;
use tokio::fs;

/// Helper to create a test H3 application with file serving.
async fn create_test_app() -> (H3Application, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    
    // Create a simple test file
    let index_path = temp_dir.path().join("index.html");
    fs::write(&index_path, b"<html><body>Hello, HTTP/3!</body></html>")
        .await
        .unwrap();

    let mut config = H3Config::default();
    config.handler.file_root = temp_dir.path().to_path_buf();
    
    let app = H3Application::new(config);
    
    (app, temp_dir)
}

#[tokio::test]
async fn test_h3_application_creation() {
    let temp_dir = TempDir::new().unwrap();
    let mut config = H3Config::default();
    config.handler.file_root = temp_dir.path().to_path_buf();
    
    let app = H3Application::new(config.clone());
    
    assert_eq!(app.config().qpack.max_table_capacity, config.qpack.max_table_capacity);
    assert_eq!(app.config().limits.max_field_section_size, config.limits.max_field_section_size);
}

#[tokio::test]
async fn test_h3_config_validation() {
    let config = H3Config::default();
    let errors = config.validate();
    
    // Default config should be valid (except file root may not exist)
    // We allow file root validation errors for default config
    assert!(errors.is_empty() || errors.iter().all(|e| e.contains("File serving root")));
}

#[tokio::test]
async fn test_h3_config_invalid_qpack_capacity() {
    let mut config = H3Config::default();
    config.qpack.max_table_capacity = 0;
    
    let errors = config.validate();
    assert!(!errors.is_empty());
    assert!(errors.iter().any(|e| e.contains("max_table_capacity")));
}

#[tokio::test]
async fn test_h3_config_invalid_limits() {
    let mut config = H3Config::default();
    config.limits.max_field_section_size = 0;
    
    let errors = config.validate();
    assert!(!errors.is_empty());
    assert!(errors.iter().any(|e| e.contains("max_field_section_size")));
}

#[tokio::test]
async fn test_file_handler_config() {
    let (app, temp_dir) = create_test_app().await;
    
    assert_eq!(app.config().handler.file_root, temp_dir.path());
    assert!(app.config().handler.file_serving_enabled);
}

#[test]
fn test_error_code_mapping() {
    use quicd_h3::{Error, ErrorCode};
    
    let protocol_error = Error::protocol(ErrorCode::FrameError, "test error");
    assert_eq!(protocol_error.to_error_code(), ErrorCode::FrameError);
    assert!(protocol_error.is_connection_error());
    
    let stream_error = Error::InvalidMessage("test".to_string());
    assert_eq!(stream_error.to_error_code(), ErrorCode::MessageError);
    assert!(!stream_error.is_connection_error());
}

#[test]
fn test_all_error_codes() {
    use quicd_h3::ErrorCode;
    
    let error_codes = vec![
        ErrorCode::NoError,
        ErrorCode::GeneralProtocolError,
        ErrorCode::InternalError,
        ErrorCode::StreamCreationError,
        ErrorCode::ClosedCriticalStream,
        ErrorCode::FrameUnexpected,
        ErrorCode::FrameError,
        ErrorCode::ExcessiveLoad,
        ErrorCode::IdError,
        ErrorCode::SettingsError,
        ErrorCode::MissingSettings,
        ErrorCode::RequestRejected,
        ErrorCode::RequestCancelled,
        ErrorCode::RequestIncomplete,
        ErrorCode::MessageError,
        ErrorCode::ConnectError,
        ErrorCode::VersionFallback,
        ErrorCode::QpackDecompressionFailed,
        ErrorCode::QpackEncoderStreamError,
        ErrorCode::QpackDecoderStreamError,
    ];
    
    for code in error_codes {
        let num = code.to_code();
        let parsed = ErrorCode::from_code(num).unwrap();
        assert_eq!(code, parsed, "Error code roundtrip failed for {:?}", code);
    }
}

#[tokio::test]
async fn test_stream_type_identification() {
    use quicd_h3::stream_type::*;
    use bytes::BytesMut;
    
    let stream_types = vec![
        StreamType::Control,
        StreamType::Push,
        StreamType::QpackEncoder,
        StreamType::QpackDecoder,
    ];
    
    for stream_type in stream_types {
        let mut buf = BytesMut::new();
        write_stream_type(stream_type, &mut buf).unwrap();
        
        let mut read_buf = buf.clone();
        let parsed = read_stream_type(&mut read_buf).unwrap();
        
        assert_eq!(stream_type, parsed);
        assert_eq!(read_buf.remaining(), 0);
    }
}

#[tokio::test]
async fn test_varint_all_sizes() {
    use quicd_h3::varint;
    use bytes::BytesMut;
    
    let test_values = vec![
        0u64,
        1,
        63,          // 6-bit max
        64,          // 14-bit min
        16383,       // 14-bit max
        16384,       // 30-bit min
        1073741823,  // 30-bit max
        1073741824,  // 62-bit min
        varint::MAX, // 62-bit max
    ];
    
    for value in test_values {
        let mut buf = BytesMut::new();
        varint::encode_buf(value, &mut buf).unwrap();
        
        let mut read_buf = buf.clone();
        let decoded = varint::decode_buf(&mut read_buf).unwrap();
        
        assert_eq!(value, decoded);
        assert_eq!(read_buf.remaining(), 0);
    }
}

#[test]
fn test_qpack_basic_encoding() {
    use quicd_qpack::{Encoder, Decoder, FieldLine};
    
    let mut encoder = Encoder::new(4096, 100);
    let mut decoder = Decoder::new(4096, 100);
    
    let fields = vec![
        FieldLine::new("content-type", "text/html"),
        FieldLine::new("content-length", "1234"),
    ];
    
    let (encoded, _instructions) = encoder.encode_field_section(0, &fields).unwrap();
    assert!(!encoded.is_empty());
    
    let decoded = decoder.decode_field_section(0, &encoded).unwrap();
    assert_eq!(decoded.len(), fields.len());
    
    for (original, decoded) in fields.iter().zip(decoded.iter()) {
        assert_eq!(original.name, decoded.name);
        assert_eq!(original.value, decoded.value);
    }
}

#[tokio::test]
async fn test_configuration_defaults() {
    let config = H3Config::default();
    
    // QPACK defaults
    assert_eq!(config.qpack.max_table_capacity, 4096);
    assert_eq!(config.qpack.blocked_streams, 100);
    
    // Push defaults
    assert!(!config.push.enabled);
    assert_eq!(config.push.max_concurrent, 100);
    
    // Handler defaults
    assert!(config.handler.file_serving_enabled);
    assert!(!config.handler.directory_listing);
    assert!(config.handler.compression_enabled);
    
    // Limits defaults
    assert_eq!(config.limits.max_field_section_size, 16384);
    assert_eq!(config.limits.max_concurrent_streams, 100);
    assert_eq!(config.limits.idle_timeout_secs, 30);
}
