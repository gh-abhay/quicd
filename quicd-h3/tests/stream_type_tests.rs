/// Tests for stream type identification (RFC 9114 Section 6.2)
use quicd_h3::frames::H3Frame;

#[test]
fn test_stream_type_encoding() {
    // Control stream type = 0x00
    let control_type = H3Frame::encode_varint_to_bytes(0x00);
    assert_eq!(control_type[0] & 0xC0, 0x00); // Single byte varint
    
    // Push stream type = 0x01
    let push_type = H3Frame::encode_varint_to_bytes(0x01);
    assert_eq!(push_type[0], 0x01);
    
    // QPACK encoder stream type = 0x02
    let encoder_type = H3Frame::encode_varint_to_bytes(0x02);
    assert_eq!(encoder_type[0], 0x02);
    
    // QPACK decoder stream type = 0x03
    let decoder_type = H3Frame::encode_varint_to_bytes(0x03);
    assert_eq!(decoder_type[0], 0x03);
}

#[test]
fn test_varint_decoding() {
    // Test single-byte varint
    let data = vec![0x25]; // 37 in decimal
    let (value, consumed) = H3Frame::decode_varint(&data).unwrap();
    assert_eq!(value, 37);
    assert_eq!(consumed, 1);
    
    // Test two-byte varint
    let data = vec![0x7F, 0x01]; // 128 encoded
    let (value, consumed) = H3Frame::decode_varint(&data).unwrap();
    assert_eq!(value, 128);
    assert_eq!(consumed, 2);
    
    // Test four-byte varint
    let data = vec![0x9D, 0x7F, 0x00, 0x00]; // 16383 encoded
    let (value, consumed) = H3Frame::decode_varint(&data).unwrap();
    assert_eq!(value, 16383);
    assert_eq!(consumed, 4);
}

#[test]
fn test_reserved_stream_types() {
    // Reserved stream types follow pattern: 0x21 + k * 0x1F
    let reserved_types = vec![0x21, 0x40, 0x5F, 0x7E];
    
    for stream_type in reserved_types {
        // Verify the pattern
        assert!((stream_type >= 0x21) && ((stream_type - 0x21) % 0x1F == 0));
    }
}
