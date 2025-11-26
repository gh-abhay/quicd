/// Tests for QPACK field section prefix (RFC 9204 Section 4.5.1)
use quicd_h3::qpack::QpackCodec;

#[test]
fn test_encode_headers_with_prefix() {
    let mut codec = QpackCodec::new();
    let headers = vec![
        (":method".to_string(), "GET".to_string()),
        (":path".to_string(), "/".to_string()),
        (":scheme".to_string(), "https".to_string()),
        (":authority".to_string(), "example.com".to_string()),
    ];
    
    let (encoded, _instructions, _refs) = codec.encode_headers(&headers).unwrap();
    
    // Verify encoded data has prefix (at least 2 bytes for Required Insert Count and Base)
    assert!(encoded.len() >= 2);
    
    // First byte should be Required Insert Count (8-bit prefix)
    // For static table only, this should be 0
    let first_byte = encoded[0];
    assert_eq!(first_byte, 0); // No dynamic table entries required
}

#[test]
fn test_decode_headers_with_prefix() {
    let mut codec = QpackCodec::new();
    let headers = vec![
        (":method".to_string(), "POST".to_string()),
        (":path".to_string(), "/api".to_string()),
    ];
    
    let (encoded, _instructions, _refs) = codec.encode_headers(&headers).unwrap();
    let (decoded, _dec_refs) = codec.decode_headers(&encoded).unwrap();
    
    // Verify round-trip
    assert_eq!(decoded.len(), headers.len());
    for (original, decoded_item) in headers.iter().zip(decoded.iter()) {
        assert_eq!(original, decoded_item);
    }
}

#[test]
fn test_required_insert_count_encoding() {
    let codec = QpackCodec::new();
    
    // With no dynamic table, required insert count should be 0
    let ric = codec.encode_required_insert_count();
    assert_eq!(ric, 0);
}

#[test]
fn test_qpack_varint_encoding() {
    let codec = QpackCodec::new();
    let mut buf = bytes::BytesMut::new();
    
    // Test small value (fits in prefix)
    codec.encode_qpack_varint(&mut buf, 10, 8);
    assert_eq!(buf[0], 10);
    
    // Test value that needs continuation
    buf.clear();
    codec.encode_qpack_varint(&mut buf, 255, 8);
    assert!(buf.len() > 1); // Should use continuation bytes
}

#[test]
fn test_static_table_references() {
    let mut codec = QpackCodec::new();
    
    // Common headers should use static table
    let headers = vec![
        (":method".to_string(), "GET".to_string()),
    ];
    
    let (encoded, _instructions, _refs) = codec.encode_headers(&headers).unwrap();
    
    // Encoded size should be small (using indexed representation)
    // Prefix (2 bytes) + indexed field (1-2 bytes)
    assert!(encoded.len() < 10);
}
