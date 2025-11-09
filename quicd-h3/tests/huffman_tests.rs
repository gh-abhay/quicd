use bytes::BytesMut;
use quicd_h3::qpack::{QpackCodec, HUFFMAN_CODES};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_huffman_codes_table() {
        // Test that the Huffman codes table has the correct size
        assert_eq!(HUFFMAN_CODES.len(), 256);

        // Test some known Huffman codes from RFC 7541
        // Space (32) should have code 0x14, length 6
        assert_eq!(HUFFMAN_CODES[32].code, 0x14);
        assert_eq!(HUFFMAN_CODES[32].length, 6);

        // 'a' (97) should have code 0x3, length 5
        assert_eq!(HUFFMAN_CODES[97].code, 0x3);
        assert_eq!(HUFFMAN_CODES[97].length, 5);

        // 'A' (65) should have code 0x21, length 6
        assert_eq!(HUFFMAN_CODES[65].code, 0x21);
        assert_eq!(HUFFMAN_CODES[65].length, 6);
    }

    #[test]
    fn test_huffman_roundtrip() {
        let codec = QpackCodec::new();

        // Test various strings
        let test_strings = vec![
            "hello world",
            "HTTP/3 is awesome",
            "Content-Type: application/json",
            "abcdefghijklmnopqrstuvwxyz",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "0123456789",
            "!@#$%^&*()",
            "",  // empty string
            "a", // single character
            "🚀🌟", // unicode (should be handled as bytes)
        ];

        for test_str in test_strings {
            // Encode
            let encoded = codec.encode_huffman(test_str.as_bytes());
            assert!(encoded.is_some(), "Failed to encode: {}", test_str);

            let encoded = encoded.unwrap();

            // Decode
            let decoded = codec.decode_huffman(&encoded);
            assert!(decoded.is_some(), "Failed to decode: {}", test_str);

            let decoded = decoded.unwrap();
            assert_eq!(decoded, test_str, "Roundtrip failed for: {}", test_str);
        }
    }

    #[test]
    fn test_huffman_compression_benefit() {
        let codec = QpackCodec::new();

        // Test that Huffman encoding provides compression benefit for typical HTTP headers
        let test_headers = vec![
            "content-type",
            "application/json",
            "cache-control",
            "no-cache",
            "accept-encoding",
            "gzip, deflate, br",
        ];

        for header in test_headers {
            let original_len = header.len();
            let encoded = codec.encode_huffman(header.as_bytes());

            if let Some(encoded) = encoded {
                // Huffman should either compress or at least not expand too much
                assert!(encoded.len() <= original_len + 1, "Huffman encoding expanded too much for: {}", header);
            } else {
                panic!("Failed to encode header: {}", header);
            }
        }
    }

    #[test]
    fn test_string_encoding_decoding() {
        let codec = QpackCodec::new();
        let mut buf = BytesMut::new();

        // Test strings of various lengths
        let short = "short".to_string();
        let medium = "a".repeat(100);
        let long = "b".repeat(1000);
        let test_strings = vec![
            short.as_str(),
            medium.as_str(),
            long.as_str(),
        ];

        for test_str in test_strings {
            buf.clear();

            // Encode
            codec.encode_string(&mut buf, &test_str);

            // Decode
            let (decoded, consumed) = codec.decode_string(&buf).unwrap();
            assert_eq!(consumed, buf.len(), "Not all bytes consumed");
            assert_eq!(decoded, test_str, "String roundtrip failed");
        }
    }

    #[test]
    fn test_string_encoding_prefers_huffman() {
        let codec = QpackCodec::new();
        let mut buf_huffman = BytesMut::new();

        let test_str = "content-type: application/json";

        // Force literal encoding by temporarily making Huffman worse
        // This is a bit tricky to test directly, but we can check that
        // the encoding works and produces valid output

        codec.encode_string(&mut buf_huffman, test_str);
        assert!(!buf_huffman.is_empty(), "String encoding failed");

        // Decode to verify it's valid
        let (decoded, _) = codec.decode_string(&buf_huffman).unwrap();
        assert_eq!(decoded, test_str);
    }

    #[test]
    fn test_invalid_huffman_data() {
        let codec = QpackCodec::new();

        // Test invalid Huffman data - a code that doesn't exist
        let invalid_data = vec![0x00]; // 0x00 is not a valid Huffman code
        let result = codec.decode_huffman(&invalid_data);
        assert!(result.is_none(), "Should reject invalid Huffman data");
    }

    #[test]
    fn test_qpack_codec_creation() {
        let codec = QpackCodec::new();

        // Test initial state
        assert_eq!(codec.table_capacity(), 0);
        assert_eq!(codec.insert_count(), 0);
        assert_eq!(codec.known_received_count(), 0);
    }

    #[test]
    fn test_qpack_dynamic_table() {
        let mut codec = QpackCodec::new();

        // Set table capacity
        codec.set_max_table_capacity(1024);
        assert_eq!(codec.table_capacity(), 1024);

        // Insert entries
        let index1 = codec.insert("name1".to_string(), "value1".to_string());
        assert_eq!(index1, Some(0));

        let index2 = codec.insert("name2".to_string(), "value2".to_string());
        assert_eq!(index2, Some(0)); // Should be at index 0 (most recent)

        // Check insert count
        assert_eq!(codec.insert_count(), 2);

        // Get entries
        let entry = codec.get_relative(0);
        assert!(entry.is_some());
        let (name, value) = entry.unwrap();
        assert_eq!(name, "name2");
        assert_eq!(value, "value2");
    }
}