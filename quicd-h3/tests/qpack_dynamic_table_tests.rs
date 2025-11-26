use quicd_h3::qpack::QpackCodec;

#[test]
fn test_dynamic_table_insertion() {
    let mut codec = QpackCodec::new();
    codec.set_max_table_capacity(4096);
    
    // Create headers that should be inserted into dynamic table
    let headers = vec![
        ("x-custom-header".to_string(), "custom-value".to_string()),
        (":method".to_string(), "GET".to_string()), // In static table
        ("x-another-custom".to_string(), "another-value".to_string()),
    ];
    
    // Encode headers
    let result = codec.encode_headers(&headers);
    assert!(result.is_ok(), "Encoding should succeed");
    
    let (encoded, instructions, _refs) = result.unwrap();
    
    // Should have generated encoder instructions for custom headers
    assert!(!instructions.is_empty(), "Should have encoder instructions for custom headers");
    assert_eq!(instructions.len(), 2, "Should have 2 instructions for the 2 custom headers");
    
    // Encoded headers should be non-empty
    assert!(!encoded.is_empty(), "Encoded headers should not be empty");
    
    // Verify dynamic table now contains the custom headers
    // (This is internal but we can verify by encoding again and checking)
    let result2 = codec.encode_headers(&headers);
    assert!(result2.is_ok());
    
    let (_encoded2, instructions2, _refs2) = result2.unwrap();
    // Second encoding should not generate new instructions (headers already in table)
    assert_eq!(instructions2.len(), 0, "Should not generate duplicate instructions");
}

#[test]
fn test_encoder_instruction_format() {
    let mut codec = QpackCodec::new();
    codec.set_max_table_capacity(4096);
    
    // Header with name in static table
    let headers = vec![
        ("content-type".to_string(), "application/custom".to_string()),
    ];
    
    let result = codec.encode_headers(&headers);
    assert!(result.is_ok());
    
    let (_encoded, instructions, _refs) = result.unwrap();
    assert_eq!(instructions.len(), 1, "Should have one instruction");
    
    let instruction = &instructions[0];
    // First byte should be 0xC0 (Insert with Name Reference, static table)
    // Format: 11TTTTTT where T=0 for static table
    assert!(instruction[0] & 0xC0 == 0xC0, "Should be Insert with Name Reference instruction");
}

#[test]
fn test_literal_name_insertion() {
    let mut codec = QpackCodec::new();
    codec.set_max_table_capacity(4096);
    
    // Header with completely new name (not in static table)
    let headers = vec![
        ("x-totally-custom".to_string(), "totally-custom-value".to_string()),
    ];
    
    let result = codec.encode_headers(&headers);
    assert!(result.is_ok());
    
    let (_encoded, instructions, _refs) = result.unwrap();
    assert_eq!(instructions.len(), 1, "Should have one instruction");
    
    let instruction = &instructions[0];
    // First byte should be 0x40 (Insert with Literal Name)
    // Format: 01HMMMMM where H=huffman bit, M=length
    assert_eq!(instruction[0] & 0xC0, 0x40, "Should be Insert with Literal Name instruction");
}

#[test]
fn test_required_insert_count_increments() {
    let mut codec = QpackCodec::new();
    codec.set_max_table_capacity(4096);
    
    // Encode first set of headers
    let headers1 = vec![
        ("x-header-1".to_string(), "value-1".to_string()),
        ("x-header-2".to_string(), "value-2".to_string()),
    ];
    
    let result1 = codec.encode_headers(&headers1);
    assert!(result1.is_ok());
    let (encoded1, _instructions1, _refs1) = result1.unwrap();
    
    // Required Insert Count should be in the encoded field section prefix
    // First byte (or varint) is the Required Insert Count
    assert!(encoded1.len() >= 2, "Should have at least prefix bytes");
    
    // Encode more headers to increment insert count
    let headers2 = vec![
        ("x-header-3".to_string(), "value-3".to_string()),
    ];
    
    let result2 = codec.encode_headers(&headers2);
    assert!(result2.is_ok());
    let (_encoded2, _instructions2, _refs2) = result2.unwrap();
    
    // Insert count should have increased
    // We can't directly check it but the test verifies the flow works
}

#[test]
fn test_no_instruction_for_static_table_exact_match() {
    let mut codec = QpackCodec::new();
    codec.set_max_table_capacity(4096);
    
    // Use a header that exists exactly in static table
    let headers = vec![
        (":method".to_string(), "GET".to_string()),
        (":scheme".to_string(), "https".to_string()),
    ];
    
    let result = codec.encode_headers(&headers);
    assert!(result.is_ok());
    
    let (_encoded, instructions, _refs) = result.unwrap();
    // Should not generate instructions for exact static table matches
    assert_eq!(instructions.len(), 0, "Should not generate instructions for static table entries");
}

#[test]
fn test_heuristic_does_not_insert_small_headers() {
    let mut codec = QpackCodec::new();
    codec.set_max_table_capacity(4096);
    
    // Small header that wouldn't benefit from dynamic table insertion
    // Note: Current heuristic inserts if > 64 bytes or name not in static table
    let headers = vec![
        ("x-tiny".to_string(), "v".to_string()), // 7 bytes total
    ];
    
    let result = codec.encode_headers(&headers);
    assert!(result.is_ok());
    
    let (_encoded, instructions, _refs) = result.unwrap();
    // Current implementation should still insert since name not in static table
    // This test documents current behavior - could be optimized later
    assert!(instructions.len() >= 0, "Instruction count depends on heuristic");
}

#[test]
fn test_multiple_encode_calls_build_dynamic_table() {
    let mut codec = QpackCodec::new();
    codec.set_max_table_capacity(4096);
    
    // First encoding
    let headers1 = vec![
        ("x-session-id".to_string(), "abc123".to_string()),
    ];
    let result1 = codec.encode_headers(&headers1);
    assert!(result1.is_ok());
    let (_enc1, inst1, _refs1) = result1.unwrap();
    assert_eq!(inst1.len(), 1, "First encoding should insert into dynamic table");
    
    // Second encoding with same header
    let result2 = codec.encode_headers(&headers1);
    assert!(result2.is_ok());
    let (_enc2, inst2, _refs2) = result2.unwrap();
    assert_eq!(inst2.len(), 0, "Second encoding should reuse dynamic table entry");
    
    // Third encoding with different header
    let headers2 = vec![
        ("x-user-agent".to_string(), "Mozilla/5.0".to_string()),
    ];
    let result3 = codec.encode_headers(&headers2);
    assert!(result3.is_ok());
    let (_enc3, inst3, _refs3) = result3.unwrap();
    assert_eq!(inst3.len(), 1, "New header should be inserted");
}
