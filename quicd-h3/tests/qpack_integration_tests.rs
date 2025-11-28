use quicd_h3::qpack::QpackCodec;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qpack_header_compression() {
        let mut codec = QpackCodec::new();

        // Set up dynamic table
        codec.set_max_table_capacity(1024);

        // Test headers that should benefit from compression
        let headers = vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("cache-control".to_string(), "no-cache".to_string()),
            ("accept-encoding".to_string(), "gzip, deflate, br".to_string()),
        ];

        // Encode headers
        let (encoded, _instructions, _refs) = codec.encode_headers(&headers).unwrap();

        // Decode headers
        let (decoded, _dec_refs) = codec.decode_headers(&encoded).unwrap();

        // Verify roundtrip
        assert_eq!(decoded.len(), headers.len());
        for (i, (name, value)) in headers.iter().enumerate() {
            assert_eq!(decoded[i].0, *name);
            assert_eq!(decoded[i].1, *value);
        }
    }

    #[test]
    fn test_qpack_dynamic_table_usage() {
        let mut codec = QpackCodec::new();
        codec.set_max_table_capacity(1024);

        // Insert some headers into dynamic table
        let name1 = "x-custom-header".to_string();
        let value1 = "custom-value-1".to_string();
        codec.insert(name1.clone(), value1.clone());

        let name2 = "x-custom-header".to_string();
        let value2 = "custom-value-2".to_string();
        codec.insert(name2.clone(), value2.clone());

        // Create headers that reference the dynamic table
        let headers = vec![
            (name1.clone(), value1.clone()), // Should use dynamic table
            (name2.clone(), value2.clone()), // Should use dynamic table
            ("content-type".to_string(), "text/plain".to_string()), // Static table
        ];

        let (encoded, _instructions, _refs) = codec.encode_headers(&headers).unwrap();
        let (decoded, _dec_refs) = codec.decode_headers(&encoded).unwrap();

        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0], (name1, value1));
        assert_eq!(decoded[1], (name2, value2));
        assert_eq!(decoded[2], ("content-type".to_string(), "text/plain".to_string()));
    }

    #[test]
    fn test_qpack_static_table() {
        let mut codec = QpackCodec::new();

        // Test some known static table entries by index
        assert_eq!(codec.get_static_entry(0), Some(&(":authority".to_string(), "".to_string())));
        assert_eq!(codec.get_static_entry(1), Some(&(":path".to_string(), "/".to_string())));
        assert_eq!(codec.get_static_entry(17), Some(&(":method".to_string(), "GET".to_string())));
        assert_eq!(codec.get_static_entry(20), Some(&(":method".to_string(), "POST".to_string())));
        assert_eq!(codec.get_static_entry(23), Some(&(":scheme".to_string(), "https".to_string())));
        assert_eq!(codec.get_static_entry(24), Some(&(":status".to_string(), "103".to_string())));
        assert_eq!(codec.get_static_entry(25), Some(&(":status".to_string(), "200".to_string())));
        assert_eq!(codec.get_static_entry(26), Some(&(":status".to_string(), "304".to_string())));

        // Test find_static_name_index returns first occurrence of name
        assert_eq!(codec.find_static_name_index(":method"), Some(15)); // First :method entry (CONNECT)
        assert_eq!(codec.find_static_name_index(":authority"), Some(0));
        assert_eq!(codec.find_static_name_index(":path"), Some(1));
        assert_eq!(codec.find_static_name_index(":status"), Some(24)); // First :status entry (103)
        assert_eq!(codec.find_static_name_index("content-type"), Some(44)); // First content-type entry
        assert_eq!(codec.find_static_name_index("nonexistent"), None);
    }

    #[test]
    fn test_qpack_instruction_encoding_decoding() {
        let mut codec = QpackCodec::new();

        use quicd_h3::qpack::QpackInstruction;

        let instructions = vec![
            QpackInstruction::SetDynamicTableCapacity { capacity: 1024 },
            QpackInstruction::InsertWithNameReference {
                static_table: true,
                name_index: 1,
                value: "test-value".to_string(),
            },
            QpackInstruction::InsertWithLiteralName {
                name: "custom-header".to_string(),
                value: "custom-value".to_string(),
            },
            QpackInstruction::Duplicate { index: 5 },
        ];

        for instruction in instructions {
            let encoded = codec.encode_instruction(&instruction).unwrap();
            let (decoded, consumed) = codec.decode_instruction(&encoded).unwrap();
            assert_eq!(consumed, encoded.len());
            assert_eq!(format!("{:?}", instruction), format!("{:?}", decoded));
        }
    }

    #[test]
    fn test_qpack_table_eviction() {
        let mut codec = QpackCodec::new();
        codec.set_max_table_capacity(100); // Small capacity

        // Insert entries that exceed capacity
        for i in 0..10 {
            let name = format!("header{}", i);
            let value = "x".repeat(20); // Each entry ~32 bytes
            codec.insert(name, value);
        }

        // Table should have evicted old entries to fit
        let capacity = codec.table_capacity();
        assert!(capacity <= 100);

        // Should be able to insert more
        codec.insert("final".to_string(), "value".to_string());
        assert!(codec.get_relative(0).is_some());
    }

    #[test]
    fn test_qpack_large_headers() {
        let mut codec = QpackCodec::new();

        // Test with very large header values
        let large_value = "x".repeat(10000);
        let headers = vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("x-large-header".to_string(), large_value.clone()),
        ];

        let (encoded, _instructions, _refs) = codec.encode_headers(&headers).unwrap();
        let (decoded, _dec_refs) = codec.decode_headers(&encoded).unwrap();

        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].1, "application/json");
        assert_eq!(decoded[1].1, large_value);
    }

    #[test]
    fn test_qpack_mixed_encoding() {
        let mut codec = QpackCodec::new();
        codec.set_max_table_capacity(1024);

        // Mix of static table and literal encoding
        let headers = vec![
            (":method".to_string(), "GET".to_string()), // Static table - exact match
            (":path".to_string(), "/".to_string()), // Static table - exact match
        ];

        let (encoded, instructions, _refs) = codec.encode_headers(&headers).unwrap();
        
        println!("Encoded bytes: {:02x?}", encoded.as_ref());
        println!("Instructions: {}", instructions.len());
        
        // These headers are in static table, so no encoder instructions needed
        assert_eq!(instructions.len(), 0);
        
        // Decode with same codec (has same dynamic table state)
        let (decoded, _dec_refs) = codec.decode_headers(&encoded).unwrap();

        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0], (":method".to_string(), "GET".to_string()));
        assert_eq!(decoded[1], (":path".to_string(), "/".to_string()));
    }

    #[test]
    fn test_cookie_header_splitting() {
        // RFC 9114 Section 4.2.1: Cookie headers should be split for better compression
        let codec = QpackCodec::new();

        // Test that split_cookie_headers works correctly
        let single_cookie = vec![
            ("cookie".to_string(), "session=abc123".to_string()),
        ];
        let split_single = QpackCodec::split_cookie_headers(&single_cookie);
        assert_eq!(split_single.len(), 1);
        assert_eq!(split_single[0].1, "session=abc123");

        // Test multiple cookies in one header - should be split
        let multi_cookie = vec![
            ("cookie".to_string(), "session=abc123; user=john; theme=dark".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
        ];
        let split_multi = QpackCodec::split_cookie_headers(&multi_cookie);
        
        // After splitting, we should have 4 headers total (3 cookies + 1 content-type)
        assert_eq!(split_multi.len(), 4, "Cookie should be split into 3 separate headers");
        
        // Verify all cookie values are present
        let cookie_headers: Vec<_> = split_multi.iter()
            .filter(|(name, _)| name == "cookie")
            .collect();
        assert_eq!(cookie_headers.len(), 3);
        
        // Verify individual cookie values (order preserved)
        assert_eq!(cookie_headers[0].1, "session=abc123");
        assert_eq!(cookie_headers[1].1, "user=john");
        assert_eq!(cookie_headers[2].1, "theme=dark");
        
        // Verify content-type is preserved
        let content_type = split_multi.iter()
            .find(|(name, _)| name == "content-type");
        assert!(content_type.is_some());
        assert_eq!(content_type.unwrap().1, "application/json");

        // Test empty cookie pairs are filtered out
        let empty_cookies = vec![
            ("cookie".to_string(), "a=b;;  ; c=d".to_string()),
        ];
        let split_empty = QpackCodec::split_cookie_headers(&empty_cookies);
        assert_eq!(split_empty.len(), 2);
        assert_eq!(split_empty[0].1, "a=b");
        assert_eq!(split_empty[1].1, "c=d");
    }
}