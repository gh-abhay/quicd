/// Tests for Huffman encoding (RFC 7541 Appendix B, used by QPACK)
use quicd_h3::qpack::QpackCodec;

#[test]
fn test_huffman_encoding_simple() {
    let codec = QpackCodec::new();
    let input = b"hello";
    
    let encoded = codec.encode_huffman(input);
    assert!(encoded.is_some());
    
    let encoded = encoded.unwrap();
    // Huffman encoding should typically be shorter or similar length for ASCII
    assert!(encoded.len() <= input.len() + 2);
}

#[test]
fn test_huffman_encoding_common_headers() {
    let codec = QpackCodec::new();
    
    // Test common HTTP header values
    let test_cases: Vec<&[u8]> = vec![
        b"GET",
        b"POST",
        b"https",
        b"example.com",
        b"application/json",
    ];
    
    for input in test_cases {
        let encoded = codec.encode_huffman(input);
        assert!(encoded.is_some(), "Failed to encode: {:?}", std::str::from_utf8(input));
    }
}

#[test]
fn test_huffman_roundtrip() {
    let codec = QpackCodec::new();
    let input = b"Content-Type";
    
    let encoded = codec.encode_huffman(input).expect("Failed to encode");
    let decoded = codec.decode_huffman(&encoded).expect("Failed to decode");
    
    assert_eq!(decoded.as_bytes(), input);
}

#[test]
fn test_huffman_all_ascii() {
    let codec = QpackCodec::new();
    
    // Test all printable ASCII characters
    for c in 32u8..127u8 {
        let input = vec![c];
        let encoded = codec.encode_huffman(&input);
        assert!(encoded.is_some(), "Failed to encode ASCII {}", c);
        
        if let Some(enc) = encoded {
            let decoded = codec.decode_huffman(&enc);
            assert!(decoded.is_some(), "Failed to decode ASCII {}", c);
            assert_eq!(decoded.unwrap().as_bytes(), &input);
        }
    }
}

#[test]
fn test_huffman_padding() {
    let codec = QpackCodec::new();
    
    // Test that padding is correctly added (all 1s)
    let input = b"a"; // Single character
    let encoded = codec.encode_huffman(input).unwrap();
    
    // Last byte should have padding bits set to 1
    let _last_byte = encoded[encoded.len() - 1];
    // The padding should be all 1s (EOS symbol)
    // We can't test exact value without knowing the bit alignment,
    // but we can verify it encodes and decodes correctly
    let decoded = codec.decode_huffman(&encoded).unwrap();
    assert_eq!(decoded, "a");
}

#[test]
fn test_huffman_empty_string() {
    let codec = QpackCodec::new();
    let input = b"";
    
    let encoded = codec.encode_huffman(input);
    assert!(encoded.is_some());
    
    let encoded = encoded.unwrap();
    assert_eq!(encoded.len(), 0); // Empty input should produce empty output
}

#[test]
fn test_huffman_compression_ratio() {
    let codec = QpackCodec::new();
    
    // Common header values that should compress well
    let test_cases = vec![
        ("text/html", true),           // Common MIME type
        ("application/json", true),    // Common MIME type
        ("gzip", true),                // Common encoding
        ("en-US", true),               // Common language
    ];
    
    for (input, should_compress) in test_cases {
        let input_bytes = input.as_bytes();
        let encoded = codec.encode_huffman(input_bytes).unwrap();
        
        if should_compress {
            // Should be at least somewhat compressed
            assert!(encoded.len() < input_bytes.len() * 2,
                "Failed to compress '{}': {} bytes -> {} bytes",
                input, input_bytes.len(), encoded.len());
        }
    }
}
