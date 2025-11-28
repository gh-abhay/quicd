//! Tests for QPACK instruction encoding and decoding per RFC 9204.
//!
//! These tests verify that encoder and decoder stream instructions are correctly
//! encoded and decoded according to RFC 9204 Sections 4.3 and 4.4.

use quicd_h3::qpack::{QpackCodec, QpackInstruction};

#[cfg(test)]
mod encoder_instruction_tests {
    use super::*;

    #[test]
    fn test_set_dynamic_table_capacity_roundtrip() {
        let codec = QpackCodec::new();
        let instruction = QpackInstruction::SetDynamicTableCapacity { capacity: 4096 };
        
        // Encode
        let encoded = codec.encode_instruction(&instruction).unwrap();
        
        // Decode
        let (decoded, consumed) = codec.decode_instruction_with_context(&encoded, true).unwrap();
        
        // Verify
        assert_eq!(consumed, encoded.len());
        match decoded {
            QpackInstruction::SetDynamicTableCapacity { capacity } => {
                assert_eq!(capacity, 4096);
            }
            _ => panic!("Expected SetDynamicTableCapacity"),
        }
    }

    #[test]
    fn test_insert_with_name_reference_static_roundtrip() {
        let codec = QpackCodec::new();
        let instruction = QpackInstruction::InsertWithNameReference {
            static_table: true,
            name_index: 15, // ":method"
            value: "GET".to_string(),
        };
        
        // Encode
        let encoded = codec.encode_instruction(&instruction).unwrap();
        
        // Decode
        let (decoded, consumed) = codec.decode_instruction_with_context(&encoded, true).unwrap();
        
        // Verify
        assert_eq!(consumed, encoded.len());
        match decoded {
            QpackInstruction::InsertWithNameReference { static_table, name_index, value } => {
                assert_eq!(static_table, true);
                assert_eq!(name_index, 15);
                assert_eq!(value, "GET");
            }
            _ => panic!("Expected InsertWithNameReference"),
        }
    }

    #[test]
    fn test_insert_with_name_reference_dynamic_roundtrip() {
        let codec = QpackCodec::new();
        let instruction = QpackInstruction::InsertWithNameReference {
            static_table: false,
            name_index: 5,
            value: "test-value".to_string(),
        };
        
        // Encode
        let encoded = codec.encode_instruction(&instruction).unwrap();
        
        // Decode
        let (decoded, consumed) = codec.decode_instruction_with_context(&encoded, true).unwrap();
        
        // Verify
        assert_eq!(consumed, encoded.len());
        match decoded {
            QpackInstruction::InsertWithNameReference { static_table, name_index, value } => {
                assert_eq!(static_table, false);
                assert_eq!(name_index, 5);
                assert_eq!(value, "test-value");
            }
            _ => panic!("Expected InsertWithNameReference"),
        }
    }

    #[test]
    fn test_insert_with_literal_name_roundtrip() {
        let codec = QpackCodec::new();
        let instruction = QpackInstruction::InsertWithLiteralName {
            name: "x-custom-header".to_string(),
            value: "custom-value".to_string(),
        };
        
        // Encode
        let encoded = codec.encode_instruction(&instruction).unwrap();
        
        // Decode
        let (decoded, consumed) = codec.decode_instruction_with_context(&encoded, true).unwrap();
        
        // Verify
        assert_eq!(consumed, encoded.len());
        match decoded {
            QpackInstruction::InsertWithLiteralName { name, value } => {
                assert_eq!(name, "x-custom-header");
                assert_eq!(value, "custom-value");
            }
            _ => panic!("Expected InsertWithLiteralName"),
        }
    }

    #[test]
    fn test_insert_with_literal_name_long_values() {
        let codec = QpackCodec::new();
        // Test with values that exceed the prefix (require continuation bytes)
        let long_name = "x-very-long-custom-header-name-that-exceeds-prefix";
        let long_value = "a".repeat(200);
        
        let instruction = QpackInstruction::InsertWithLiteralName {
            name: long_name.to_string(),
            value: long_value.clone(),
        };
        
        // Encode
        let encoded = codec.encode_instruction(&instruction).unwrap();
        
        // Decode
        let (decoded, consumed) = codec.decode_instruction_with_context(&encoded, true).unwrap();
        
        // Verify
        assert_eq!(consumed, encoded.len());
        match decoded {
            QpackInstruction::InsertWithLiteralName { name, value } => {
                assert_eq!(name, long_name);
                assert_eq!(value, long_value);
            }
            _ => panic!("Expected InsertWithLiteralName"),
        }
    }

    #[test]
    fn test_duplicate_roundtrip() {
        let codec = QpackCodec::new();
        let instruction = QpackInstruction::Duplicate { index: 10 };
        
        // Encode
        let encoded = codec.encode_instruction(&instruction).unwrap();
        
        // Decode
        let (decoded, consumed) = codec.decode_instruction_with_context(&encoded, true).unwrap();
        
        // Verify
        assert_eq!(consumed, encoded.len());
        match decoded {
            QpackInstruction::Duplicate { index } => {
                assert_eq!(index, 10);
            }
            _ => panic!("Expected Duplicate"),
        }
    }

    #[test]
    fn test_duplicate_large_index() {
        let codec = QpackCodec::new();
        // Test with index that exceeds 5-bit prefix (requires continuation bytes)
        let instruction = QpackInstruction::Duplicate { index: 1000 };
        
        // Encode
        let encoded = codec.encode_instruction(&instruction).unwrap();
        
        // Decode
        let (decoded, consumed) = codec.decode_instruction_with_context(&encoded, true).unwrap();
        
        // Verify
        assert_eq!(consumed, encoded.len());
        match decoded {
            QpackInstruction::Duplicate { index } => {
                assert_eq!(index, 1000);
            }
            _ => panic!("Expected Duplicate"),
        }
    }
}

#[cfg(test)]
mod decoder_instruction_tests {
    use super::*;

    #[test]
    fn test_section_acknowledgment_roundtrip() {
        let codec = QpackCodec::new();
        let instruction = QpackInstruction::SectionAcknowledgment { stream_id: 12 };
        
        // Encode
        let encoded = codec.encode_instruction(&instruction).unwrap();
        
        // Decode (decoder stream context)
        let (decoded, consumed) = codec.decode_instruction_with_context(&encoded, false).unwrap();
        
        // Verify
        assert_eq!(consumed, encoded.len());
        match decoded {
            QpackInstruction::SectionAcknowledgment { stream_id } => {
                assert_eq!(stream_id, 12);
            }
            _ => panic!("Expected SectionAcknowledgment"),
        }
    }

    #[test]
    fn test_section_acknowledgment_large_stream_id() {
        let codec = QpackCodec::new();
        // Test with stream_id that exceeds 7-bit prefix
        let instruction = QpackInstruction::SectionAcknowledgment { stream_id: 5000 };
        
        // Encode
        let encoded = codec.encode_instruction(&instruction).unwrap();
        
        // Decode
        let (decoded, consumed) = codec.decode_instruction_with_context(&encoded, false).unwrap();
        
        // Verify
        assert_eq!(consumed, encoded.len());
        match decoded {
            QpackInstruction::SectionAcknowledgment { stream_id } => {
                assert_eq!(stream_id, 5000);
            }
            _ => panic!("Expected SectionAcknowledgment"),
        }
    }

    #[test]
    fn test_stream_cancellation_roundtrip() {
        let codec = QpackCodec::new();
        let instruction = QpackInstruction::StreamCancellation { stream_id: 8 };
        
        // Encode
        let encoded = codec.encode_instruction(&instruction).unwrap();
        
        // Decode (decoder stream context)
        let (decoded, consumed) = codec.decode_instruction_with_context(&encoded, false).unwrap();
        
        // Verify
        assert_eq!(consumed, encoded.len());
        match decoded {
            QpackInstruction::StreamCancellation { stream_id } => {
                assert_eq!(stream_id, 8);
            }
            _ => panic!("Expected StreamCancellation"),
        }
    }

    #[test]
    fn test_stream_cancellation_large_stream_id() {
        let codec = QpackCodec::new();
        // Test with stream_id that exceeds 6-bit prefix
        let instruction = QpackInstruction::StreamCancellation { stream_id: 1024 };
        
        // Encode
        let encoded = codec.encode_instruction(&instruction).unwrap();
        
        // Decode
        let (decoded, consumed) = codec.decode_instruction_with_context(&encoded, false).unwrap();
        
        // Verify
        assert_eq!(consumed, encoded.len());
        match decoded {
            QpackInstruction::StreamCancellation { stream_id } => {
                assert_eq!(stream_id, 1024);
            }
            _ => panic!("Expected StreamCancellation"),
        }
    }

    #[test]
    fn test_insert_count_increment_roundtrip() {
        let codec = QpackCodec::new();
        let instruction = QpackInstruction::InsertCountIncrement { increment: 5 };
        
        // Encode
        let encoded = codec.encode_instruction(&instruction).unwrap();
        
        // Decode (decoder stream context)
        let (decoded, consumed) = codec.decode_instruction_with_context(&encoded, false).unwrap();
        
        // Verify
        assert_eq!(consumed, encoded.len());
        match decoded {
            QpackInstruction::InsertCountIncrement { increment } => {
                assert_eq!(increment, 5);
            }
            _ => panic!("Expected InsertCountIncrement"),
        }
    }

    #[test]
    fn test_insert_count_increment_large_value() {
        let codec = QpackCodec::new();
        // Test with increment that exceeds 6-bit prefix
        let instruction = QpackInstruction::InsertCountIncrement { increment: 2048 };
        
        // Encode
        let encoded = codec.encode_instruction(&instruction).unwrap();
        
        // Decode
        let (decoded, consumed) = codec.decode_instruction_with_context(&encoded, false).unwrap();
        
        // Verify
        assert_eq!(consumed, encoded.len());
        match decoded {
            QpackInstruction::InsertCountIncrement { increment } => {
                assert_eq!(increment, 2048);
            }
            _ => panic!("Expected InsertCountIncrement"),
        }
    }
}

#[cfg(test)]
mod ambiguous_instruction_tests {
    use super::*;

    /// Test that 00xxxxxx instructions are correctly disambiguated by stream context
    #[test]
    fn test_duplicate_vs_insert_count_increment() {
        let codec = QpackCodec::new();
        
        // Create Duplicate instruction (encoder stream)
        let duplicate = QpackInstruction::Duplicate { index: 42 };
        let encoded_dup = codec.encode_instruction(&duplicate).unwrap();
        
        // Create Insert Count Increment instruction (decoder stream)
        let insert_count = QpackInstruction::InsertCountIncrement { increment: 42 };
        let encoded_inc = codec.encode_instruction(&insert_count).unwrap();
        
        // Debug: print encodings
        println!("Duplicate(42) encoded as: {:02x?}", encoded_dup.as_ref());
        println!("InsertCountIncrement(42) encoded as: {:02x?}", encoded_inc.as_ref());
        
        // Both should have identical wire format since they encode the same value
        // The stream context determines which instruction it is
        
        // Decode as encoder stream instruction (should be Duplicate)
        let (decoded_dup, _) = codec.decode_instruction_with_context(&encoded_dup, true).unwrap();
        match decoded_dup {
            QpackInstruction::Duplicate { index } => {
                assert_eq!(index, 42);
            }
            _ => panic!("Expected Duplicate on encoder stream"),
        }
        
        // Decode as decoder stream instruction (should be Insert Count Increment)
        let (decoded_inc, _) = codec.decode_instruction_with_context(&encoded_inc, false).unwrap();
        match decoded_inc {
            QpackInstruction::InsertCountIncrement { increment } => {
                assert_eq!(increment, 42);
            }
            _ => panic!("Expected InsertCountIncrement on decoder stream, got: {:?}", decoded_inc),
        }
    }

    /// Test that 10xxxxxx instructions are correctly disambiguated
    #[test]
    fn test_insert_name_ref_dynamic_vs_section_ack() {
        let codec = QpackCodec::new();
        
        // These have the same first byte pattern (10xxxxxx) but different stream contexts
        
        // Section Acknowledgment on decoder stream
        let section_ack = QpackInstruction::SectionAcknowledgment { stream_id: 5 };
        let encoded_ack = codec.encode_instruction(&section_ack).unwrap();
        
        let (decoded, _) = codec.decode_instruction_with_context(&encoded_ack, false).unwrap();
        match decoded {
            QpackInstruction::SectionAcknowledgment { stream_id } => {
                assert_eq!(stream_id, 5);
            }
            _ => panic!("Expected SectionAcknowledgment on decoder stream"),
        }
        
        // Insert with Name Reference (dynamic) on encoder stream
        // Note: The wire format is the same if the value happens to match
        let insert_ref = QpackInstruction::InsertWithNameReference {
            static_table: false,
            name_index: 3,
            value: "test".to_string(),
        };
        let encoded_ref = codec.encode_instruction(&insert_ref).unwrap();
        
        let (decoded, _) = codec.decode_instruction_with_context(&encoded_ref, true).unwrap();
        match decoded {
            QpackInstruction::InsertWithNameReference { static_table, name_index, value } => {
                assert_eq!(static_table, false);
                assert_eq!(name_index, 3);
                assert_eq!(value, "test");
            }
            _ => panic!("Expected InsertWithNameReference on encoder stream"),
        }
    }
}

#[cfg(test)]
mod edge_case_tests {
    use super::*;

    #[test]
    fn test_zero_values() {
        let codec = QpackCodec::new();
        
        // Zero capacity
        let cap = QpackInstruction::SetDynamicTableCapacity { capacity: 0 };
        let encoded = codec.encode_instruction(&cap).unwrap();
        let (decoded, _) = codec.decode_instruction_with_context(&encoded, true).unwrap();
        match decoded {
            QpackInstruction::SetDynamicTableCapacity { capacity } => assert_eq!(capacity, 0),
            _ => panic!("Expected SetDynamicTableCapacity"),
        }
        
        // Zero stream_id
        let ack = QpackInstruction::SectionAcknowledgment { stream_id: 0 };
        let encoded = codec.encode_instruction(&ack).unwrap();
        let (decoded, _) = codec.decode_instruction_with_context(&encoded, false).unwrap();
        match decoded {
            QpackInstruction::SectionAcknowledgment { stream_id } => assert_eq!(stream_id, 0),
            _ => panic!("Expected SectionAcknowledgment"),
        }
    }

    #[test]
    fn test_max_prefix_values() {
        let codec = QpackCodec::new();
        
        // Test values at prefix boundaries (require continuation bytes)
        
        // 5-bit prefix max = 31, test 31 and 32
        let dup31 = QpackInstruction::Duplicate { index: 31 };
        let encoded = codec.encode_instruction(&dup31).unwrap();
        let (decoded, _) = codec.decode_instruction_with_context(&encoded, true).unwrap();
        match decoded {
            QpackInstruction::Duplicate { index } => assert_eq!(index, 31),
            _ => panic!("Expected Duplicate"),
        }
        
        let dup32 = QpackInstruction::Duplicate { index: 32 };
        let encoded = codec.encode_instruction(&dup32).unwrap();
        let (decoded, _) = codec.decode_instruction_with_context(&encoded, true).unwrap();
        match decoded {
            QpackInstruction::Duplicate { index } => assert_eq!(index, 32),
            _ => panic!("Expected Duplicate"),
        }
        
        // 6-bit prefix max = 63
        let cancel63 = QpackInstruction::StreamCancellation { stream_id: 63 };
        let encoded = codec.encode_instruction(&cancel63).unwrap();
        let (decoded, _) = codec.decode_instruction_with_context(&encoded, false).unwrap();
        match decoded {
            QpackInstruction::StreamCancellation { stream_id } => assert_eq!(stream_id, 63),
            _ => panic!("Expected StreamCancellation"),
        }
        
        let cancel64 = QpackInstruction::StreamCancellation { stream_id: 64 };
        let encoded = codec.encode_instruction(&cancel64).unwrap();
        let (decoded, _) = codec.decode_instruction_with_context(&encoded, false).unwrap();
        match decoded {
            QpackInstruction::StreamCancellation { stream_id } => assert_eq!(stream_id, 64),
            _ => panic!("Expected StreamCancellation"),
        }
        
        // 7-bit prefix max = 127
        let ack127 = QpackInstruction::SectionAcknowledgment { stream_id: 127 };
        let encoded = codec.encode_instruction(&ack127).unwrap();
        let (decoded, _) = codec.decode_instruction_with_context(&encoded, false).unwrap();
        match decoded {
            QpackInstruction::SectionAcknowledgment { stream_id } => assert_eq!(stream_id, 127),
            _ => panic!("Expected SectionAcknowledgment"),
        }
        
        let ack128 = QpackInstruction::SectionAcknowledgment { stream_id: 128 };
        let encoded = codec.encode_instruction(&ack128).unwrap();
        let (decoded, _) = codec.decode_instruction_with_context(&encoded, false).unwrap();
        match decoded {
            QpackInstruction::SectionAcknowledgment { stream_id } => assert_eq!(stream_id, 128),
            _ => panic!("Expected SectionAcknowledgment"),
        }
    }

    #[test]
    fn test_empty_strings() {
        let codec = QpackCodec::new();
        
        let instruction = QpackInstruction::InsertWithLiteralName {
            name: "".to_string(),
            value: "".to_string(),
        };
        
        let encoded = codec.encode_instruction(&instruction).unwrap();
        let (decoded, _) = codec.decode_instruction_with_context(&encoded, true).unwrap();
        
        match decoded {
            QpackInstruction::InsertWithLiteralName { name, value } => {
                assert_eq!(name, "");
                assert_eq!(value, "");
            }
            _ => panic!("Expected InsertWithLiteralName"),
        }
    }
}
