//! Tests for P0 fixes and RFC compliance gaps.

use quicd_qpack::{Decoder, Encoder, QpackError};
use bytes::Bytes;

#[test]
fn test_huffman_padding_validation() {
    // Valid padding: 7 bits of 1s (0x7F at end of byte)
    // Input: 0xFF (8 bits of 1s) -> Invalid padding (too long)
    // Input: 0xFE (11111110) -> Invalid padding (not all 1s)
    
    // Let's construct a valid Huffman sequence followed by invalid padding.
    // 'a' is 0x1c (00011100, 5 bits).
    // If we have 'a' then padding.
    // Byte: 00011 111 (0x1F).
    // 5 bits 'a', 3 bits padding (111). Valid.
    
    let input = vec![0x1F];
    let mut output = Vec::new();
    quicd_qpack::wire::huffman::decode(&input, &mut output).unwrap();
    assert_eq!(output, vec![b'a']);
    
    // Invalid padding: 00011 110 (0x1E).
    // 5 bits 'a', 3 bits padding (110). Invalid (not all 1s).
    let input = vec![0x1E];
    let mut output = Vec::new();
    let err = quicd_qpack::wire::huffman::decode(&input, &mut output).unwrap_err();
    assert!(matches!(err, QpackError::HuffmanDecodingError(_)));
    
    // Invalid padding: > 7 bits.
    // We need a sequence where we have > 7 bits of 1s at the end.
    // EOS is 30 bits of 1s.
    // If we have 0xFF (8 bits of 1s).
    // It's a prefix of EOS.
    // But it's > 7 bits of padding.
    // So it should be rejected.
    let input = vec![0xFF];
    let mut output = Vec::new();
    let err = quicd_qpack::wire::huffman::decode(&input, &mut output).unwrap_err();
    assert!(matches!(err, QpackError::HuffmanDecodingError(_)));
}

#[test]
fn test_eos_rejection() {
    // EOS is 30 bits of 1s.
    // 0xFF 0xFF 0xFF 0xFC (30 bits 1s, 2 bits 0 padding).
    // 11111111 11111111 11111111 11111100
    let input = vec![0xFF, 0xFF, 0xFF, 0xFC];
    let mut output = Vec::new();
    let err = quicd_qpack::wire::huffman::decode(&input, &mut output).unwrap_err();
    assert!(matches!(err, QpackError::HuffmanDecodingError(_)));
}

#[test]
fn test_indexed_dynamic_underflow() {
    // Test that relative index >= Base causes error.
    // Field Line: Indexed Dynamic
    // Pattern: 1T | Index (6+)
    // T=0 for dynamic.
    // Byte: 10xx xxxx
    
    // Let's say Base = 5.
    // We want Index = 5 (so Relative Index = 5).
    // Absolute Index = Base - Relative Index - 1 = 5 - 5 - 1 = -1 (Underflow).
    // This should fail.
    
    // Encode Index 5: 0x80 | 0x05 = 0x85.
    
    let data = Bytes::from_static(&[0x85]);
    let base = 5;
    
    use quicd_qpack::wire::header_block::FieldLine;
    
    let result = FieldLine::decode(data, base);
    assert!(matches!(result, Err(QpackError::DecompressionFailed(_))));
}

#[test]
fn test_ici_zero_rejection() {
    let mut encoder = Encoder::new(4096, 100);
    
    // Construct Insert Count Increment with increment=0
    // Pattern: 00xxxxxx. 00000000 = 0x00.
    let inst = vec![0x00];
    
    let err = encoder.process_decoder_instruction(&inst).unwrap_err();
    assert!(matches!(err, QpackError::DecoderStreamError(msg) if msg.contains("zero")));
}

#[test]
fn test_duplicate_emission() {
    let mut encoder = Encoder::new(100, 100); // Small capacity
    encoder.set_capacity(100).unwrap();
    
    // Insert entry 1 (size ~40)
    let headers1 = vec![(b"x-1".as_slice(), b"val1".as_slice())];
    encoder.encode(0, &headers1).unwrap();
    
    // Insert entry 2 (size ~40)
    let headers2 = vec![(b"x-2".as_slice(), b"val2".as_slice())];
    encoder.encode(1, &headers2).unwrap();
    
    // Table has 2 entries. Capacity 100. Size ~80.
    // Next insertion will evict entry 1.
    
    // Reference entry 1. It is old (index 0).
    // It should be duplicated because it's about to be evicted.
    // Wait, `should_duplicate` requires table_len > 4.
    // I need to fill the table with more small entries.
    
    let mut encoder = Encoder::new(1000, 100);
    encoder.set_capacity(1000).unwrap();
    
    // Fill table with 5 entries
    for i in 0..5 {
        let name = format!("x-{}", i);
        let headers = vec![(name.as_bytes(), b"val".as_slice())];
        encoder.encode(i, &headers).unwrap();
    }
    
    // Drain instructions
    encoder.drain_encoder_stream();
    
    // Now table has 5 entries.
    // Entry 0 is oldest.
    // Reference entry 0.
    let headers = vec![(b"x-0".as_slice(), b"val".as_slice())];
    encoder.encode(10, &headers).unwrap();
    
    // Check instructions. Should contain Duplicate.
    let insts = encoder.drain_encoder_stream();
    let has_duplicate = insts.iter().any(|bytes| {
        // Duplicate starts with 000xxxxx
        bytes[0] & 0xE0 == 0x00
    });
    
    assert!(has_duplicate, "Should emit Duplicate instruction for old entry");
}

#[test]
fn test_literal_dynamic_name_absolute_index() {
    let mut decoder = Decoder::new(4096, 100);
    let mut encoder = Encoder::new(4096, 100);

    // 1. Insert entries
    let headers = vec![
        (b"name1".as_slice(), b"value1".as_slice()), // Abs 0
        (b"name2".as_slice(), b"value2".as_slice()), // Abs 1
    ];
    let encoded = encoder.encode(0, &headers).unwrap();

    // Feed encoder instructions to decoder
    let instructions = encoder.drain_encoder_stream();
    for inst in instructions {
        let _ = decoder.process_encoder_instruction(&inst).unwrap();
    }

    // Decode the first block (optional, but good to verify sync)
    decoder.decode(0, encoded).unwrap();

    // Now table has:
    // 1: name2, value2
    // 0: name1, value1
    // Insert Count = 2.

    // 2. Create a block with LiteralDynamicName referring to Abs 1 ("name2").
    // We need Base >= 2. Let's use Base = 2.
    // Relative Index = Base - Abs - 1 = 2 - 1 - 1 = 0.
    // Instruction: LiteralDynamicName (01NT) | Index(0).
    // 0x40 | 0 = 0x40.
    // Value: "new_value".

    // Prefix: RIC=2, BaseDelta=0 (Base=2).
    // MaxEntries = 4096 / 32 = 128.
    // EncodedRIC = (2 % (2*128)) + 1 = 3.
    // Prefix bytes: 0x03 (RIC), 0x00 (BaseDelta).

    // Instruction: 0x40 (LitDyn, Index 0).
    // Value: "new_value". Length 9. 0x09. "new_value".

    let mut block = vec![];
    // Prefix
    block.push(0x03); // RIC=2
    block.push(0x00); // BaseDelta=0 -> Base=2

    // LiteralDynamicName
    block.push(0x40); // Index 0 -> Abs 1
    block.push(0x09); // Len 9
    block.extend_from_slice(b"new_value");

    let decoded = decoder.decode(1, bytes::Bytes::from(block)).unwrap();

    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].name, "name2");
    assert_eq!(decoded[0].value, "new_value");
}

#[test]
fn test_ric_decoding_edge_cases() {
    let mut decoder = Decoder::new(4096, 100);

    // Test RIC=0
    let block = vec![0x00, 0x00]; // RIC=0, BaseDelta=0
    let _ = decoder.decode(2, bytes::Bytes::from(block)).unwrap();
}

#[test]
fn test_post_base_index_with_advanced_table() {
    // Scenario: Decoder table is ahead of the header block Base.
    // 1. Encoder inserts A (Index 0).
    // 2. Encoder inserts B (Index 1).
    // 3. Encoder encodes Block referencing A using Post-Base Index relative to Base=0.
    //    (This is artificial but valid: Base=0, Post-Base Index=0 -> Absolute Index 0).
    // 4. Decoder has both A and B (Insert Count = 2).
    // 5. Decoder processes Block with Base=0.
    //    If it uses table.insert_count() (2), it calculates Absolute Index = 2 + 0 = 2 -> Error.
    //    If it uses Base (0), it calculates Absolute Index = 0 + 0 = 0 -> Success (Entry A).

    let mut decoder = Decoder::new(4096, 100);

    // Manually insert entries into decoder table to simulate state
    // We can use process_encoder_instruction
    
    // Insert A: "key", "A"
    let inst_a = quicd_qpack::wire::instructions::EncoderInstruction::InsertLiteral {
        name: Bytes::from_static(b"key"),
        value: Bytes::from_static(b"A"),
    };
    decoder.process_encoder_instruction(&inst_a.encode()).unwrap();

    // Insert B: "key", "B"
    let inst_b = quicd_qpack::wire::instructions::EncoderInstruction::InsertLiteral {
        name: Bytes::from_static(b"key"),
        value: Bytes::from_static(b"B"),
    };
    decoder.process_encoder_instruction(&inst_b.encode()).unwrap();

    assert_eq!(decoder.table().insert_count(), 2);

    // Construct Header Block
    // Prefix: Required Insert Count = 1 (Needs A), Delta Base = 0, Sign = + (Base = 0 + 0 = 0? No)
    // Base calculation:
    // RIC = 1.
    // Base = RIC + DeltaBase = 1 + 0 = 1.
    // Wait, if Base=1, then Post-Base Index 0 -> Absolute 1 (B).
    // We want Absolute 0 (A).
    // Post-Base Index is for entries with Absolute Index >= Base.
    // So if Base=1, we can only reference B (Index 1) or newer.
    // We cannot reference A (Index 0) using Post-Base Index if Base=1.
    // We must use Base=0 to reference A via Post-Base Index?
    // RFC 9204 Section 4.5.2: "Post-Base Index... used for entries with absolute indices greater than or equal to Base."
    // So yes, to reference A (0), Base must be <= 0. So Base=0.
    
    // Prefix for Base=0:
    // RIC = 1 (We need A).
    // Base = RIC + DeltaBase. 0 = 1 + DeltaBase -> DeltaBase = -1.
    // Sign = 1 (-). DeltaBase Value = 0.
    // Base = RIC - DeltaBase - 1 = 1 - 0 - 1 = 0. Correct.
    
    let prefix = quicd_qpack::wire::header_block::EncodedPrefix {
        required_insert_count: 1,
        sign: true, // Negative
        delta_base: 0,
    };
    
    // Instruction: Indexed Dynamic Post (0001 | Index)
    // Index = Absolute Index - Base = 0 - 0 = 0.
    // Byte: 0001 0000 = 0x10.
    
    use bytes::BytesMut;
    let mut block = BytesMut::new();
    prefix.encode_into(4096, &mut block);
    block.extend_from_slice(&[0x10]); // Indexed Post-Base 0
    
    let encoded = block.freeze();
    
    // Decode
    let headers = decoder.decode(1, encoded).unwrap();
    
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].value.as_ref(), b"A");
}
