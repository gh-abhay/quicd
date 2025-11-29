//! QPACK encoder and decoder stream instructions per RFC 9204.
//! 
//! Encoder stream instructions (Section 4.3.1):
//! - Set Dynamic Table Capacity
//! - Insert With Name Reference
//! - Insert Without Name Reference  
//! - Duplicate
//! 
//! Decoder stream instructions (Section 4.3.2):
//! - Section Acknowledgement
//! - Stream Cancellation
//! - Insert Count Increment

use bytes::{Bytes, BytesMut};

use crate::error::{QpackError, Result};
use crate::huffman;
use crate::prefix_int::{decode_int, encode_int_with_prefix};

/// Encoder stream instruction types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncoderInstruction {
    /// Set Dynamic Table Capacity.
    /// Pattern: 001xxxxx (capacity with 5-bit prefix)
    SetCapacity { capacity: u64 },
    
    /// Insert With Name Reference.
    /// Pattern: 1Txxxxxx (T=0 dynamic, T=1 static, name index with 6-bit prefix)
    InsertWithNameRef {
        is_static: bool,
        name_index: u64,
        value: Bytes,
    },
    
    /// Insert Without Name Reference (literal name).
    /// Pattern: 01Hxxxxx (H=Huffman flag, name length with 5-bit prefix)
    InsertLiteral { name: Bytes, value: Bytes },
    
    /// Duplicate existing dynamic table entry.
    /// Pattern: 000xxxxx (index with 5-bit prefix)
    Duplicate { index: u64 },
}

impl EncoderInstruction {
    /// Encode instruction to bytes.
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        
        match self {
            EncoderInstruction::SetCapacity { capacity } => {
                // 001 | Capacity (5+)
                buf.extend_from_slice(&encode_int_with_prefix(*capacity, 5, 0x20));
            }
            
            EncoderInstruction::InsertWithNameRef {
                is_static,
                name_index,
                value,
            } => {
                // 1T | Name Index (6+)
                let prefix = if *is_static { 0xC0 } else { 0x80 };
                buf.extend_from_slice(&encode_int_with_prefix(*name_index, 6, prefix));
                
                // H | Value Length (7+) | Value
                encode_string(value.as_ref(), false, &mut buf);
            }
            
            EncoderInstruction::InsertLiteral { name, value } => {
                // 01H | Name Length (5+) | Name
                encode_string_with_prefix(name.as_ref(), false, 5, 0x40, &mut buf);
                
                // H | Value Length (7+) | Value
                encode_string(value.as_ref(), false, &mut buf);
            }
            
            EncoderInstruction::Duplicate { index } => {
                // 000 | Index (5+)
                buf.extend_from_slice(&encode_int_with_prefix(*index, 5, 0x00));
            }
        }
        
        buf.freeze()
    }
    
    /// Decode instruction from bytes.
    /// Returns (instruction, bytes_consumed).
    pub fn decode(mut data: &[u8]) -> Result<(Self, usize)> {
        if data.is_empty() {
            return Err(QpackError::UnexpectedEof);
        }
        
        let start_len = data.len();
        let first = data[0];
        
        let inst = if first & 0x80 != 0 {
            // 1T | Name Index (6+)
            let is_static = (first & 0x40) != 0;
            let (name_index, consumed) = decode_int(data, 6)?;
            data = &data[consumed..];
            
            let (value, consumed) = decode_string(data)?;
            data = &data[consumed..];
            
            EncoderInstruction::InsertWithNameRef {
                is_static,
                name_index,
                value,
            }
        } else if first & 0xC0 == 0x40 {
            // 01H | Name Length (5+)
            let (name, name_consumed) = decode_string_with_prefix(data, 5)?;
            data = &data[name_consumed..];
            
            let (value, value_consumed) = decode_string(data)?;
            data = &data[value_consumed..];
            
            EncoderInstruction::InsertLiteral { name, value }
        } else if first & 0xE0 == 0x20 {
            // 001 | Capacity (5+)
            let (capacity, consumed) = decode_int(data, 5)?;
            data = &data[consumed..];
            
            EncoderInstruction::SetCapacity { capacity }
        } else {
            // 000 | Index (5+)
            let (index, consumed) = decode_int(data, 5)?;
            data = &data[consumed..];
            
            EncoderInstruction::Duplicate { index }
        };
        
        let consumed = start_len - data.len();
        Ok((inst, consumed))
    }
}

/// Decoder stream instruction types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecoderInstruction {
    /// Section Acknowledgement.
    /// Pattern: 1xxxxxxx (stream ID with 7-bit prefix)
    SectionAck { stream_id: u64 },
    
    /// Stream Cancellation.
    /// Pattern: 01xxxxxx (stream ID with 6-bit prefix)
    StreamCancel { stream_id: u64 },
    
    /// Insert Count Increment.
    /// Pattern: 00xxxxxx (increment with 6-bit prefix)
    InsertCountIncrement { increment: u64 },
}

impl DecoderInstruction {
    /// Encode instruction to bytes.
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();
        
        match self {
            DecoderInstruction::SectionAck { stream_id } => {
                // 1 | Stream ID (7+)
                buf.extend_from_slice(&encode_int_with_prefix(*stream_id, 7, 0x80));
            }
            
            DecoderInstruction::StreamCancel { stream_id } => {
                // 01 | Stream ID (6+)
                buf.extend_from_slice(&encode_int_with_prefix(*stream_id, 6, 0x40));
            }
            
            DecoderInstruction::InsertCountIncrement { increment } => {
                // 00 | Increment (6+)
                buf.extend_from_slice(&encode_int_with_prefix(*increment, 6, 0x00));
            }
        }
        
        buf.freeze()
    }
    
    /// Decode instruction from bytes.
    /// Returns (instruction, bytes_consumed).
    pub fn decode(mut data: &[u8]) -> Result<(Self, usize)> {
        if data.is_empty() {
            return Err(QpackError::UnexpectedEof);
        }
        
        let start_len = data.len();
        let first = data[0];
        
        let inst = if first & 0x80 != 0 {
            // 1 | Stream ID (7+)
            let (stream_id, consumed) = decode_int(data, 7)?;
            data = &data[consumed..];
            DecoderInstruction::SectionAck { stream_id }
        } else if first & 0xC0 == 0x40 {
            // 01 | Stream ID (6+)
            let (stream_id, consumed) = decode_int(data, 6)?;
            data = &data[consumed..];
            DecoderInstruction::StreamCancel { stream_id }
        } else {
            // 00 | Increment (6+)
            let (increment, consumed) = decode_int(data, 6)?;
            data = &data[consumed..];
            DecoderInstruction::InsertCountIncrement { increment }
        };
        
        let consumed = start_len - data.len();
        Ok((inst, consumed))
    }
}

/// Encode a string with optional Huffman encoding.
/// Pattern: H | Length (7+) | Data
#[inline]
fn encode_string(data: &[u8], huffman: bool, buf: &mut BytesMut) {
    if huffman {
        // Use Huffman encoding if beneficial
        let huffman_size = huffman::encoded_size(data);
        if huffman_size < data.len() {
            buf.extend_from_slice(&encode_int_with_prefix(huffman_size as u64, 7, 0x80));
            let mut encoded = Vec::new();
            huffman::encode(data, &mut encoded);
            buf.extend_from_slice(&encoded);
            return;
        }
    }
    
    // Literal encoding
    buf.extend_from_slice(&encode_int_with_prefix(data.len() as u64, 7, 0x00));
    buf.extend_from_slice(data);
}

/// Encode a string with custom prefix bits and mask.
#[inline]
fn encode_string_with_prefix(
    data: &[u8],
    huffman: bool,
    prefix_bits: u8,
    prefix_mask: u8,
    buf: &mut BytesMut,
) {
    if huffman {
        let huffman_size = huffman::encoded_size(data);
        if huffman_size < data.len() {
            let h_bit = 1u8 << prefix_bits;
            let full_prefix = prefix_mask | h_bit;
            buf.extend_from_slice(&encode_int_with_prefix(huffman_size as u64, prefix_bits, full_prefix));
            let mut encoded = Vec::new();
            huffman::encode(data, &mut encoded);
            buf.extend_from_slice(&encoded);
            return;
        }
    }
    
    // Literal encoding
    buf.extend_from_slice(&encode_int_with_prefix(data.len() as u64, prefix_bits, prefix_mask));
    buf.extend_from_slice(data);
}

/// Decode a string (with 7-bit length prefix).
/// Returns (data, bytes_consumed).
#[inline]
fn decode_string(data: &[u8]) -> Result<(Bytes, usize)> {
    if data.is_empty() {
        return Err(QpackError::UnexpectedEof);
    }
    
    let huffman = (data[0] & 0x80) != 0;
    let (len, mut offset) = decode_int(data, 7)?;
    
    if offset + len as usize > data.len() {
        return Err(QpackError::UnexpectedEof);
    }
    
    let string_data = &data[offset..offset + len as usize];
    offset += len as usize;
    
    let decoded_data = if huffman {
        let mut decoded = Vec::new();
        huffman::decode(string_data, &mut decoded)?;
        Bytes::from(decoded)
    } else {
        Bytes::copy_from_slice(string_data)
    };
    
    Ok((decoded_data, offset))
}

/// Decode a string with custom prefix bits.
/// Returns (data, bytes_consumed).
#[inline]
fn decode_string_with_prefix(data: &[u8], prefix_bits: u8) -> Result<(Bytes, usize)> {
    if data.is_empty() {
        return Err(QpackError::UnexpectedEof);
    }
    
    let huffman = (data[0] & (1u8 << prefix_bits)) != 0;
    let (len, mut offset) = decode_int(data, prefix_bits)?;
    
    if offset + len as usize > data.len() {
        return Err(QpackError::UnexpectedEof);
    }
    
    let string_data = &data[offset..offset + len as usize];
    offset += len as usize;
    
    let decoded_data = if huffman {
        let mut decoded = Vec::new();
        huffman::decode(string_data, &mut decoded)?;
        Bytes::from(decoded)
    } else {
        Bytes::copy_from_slice(string_data)
    };
    
    Ok((decoded_data, offset))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_set_capacity() {
        let inst = EncoderInstruction::SetCapacity { capacity: 4096 };
        let encoded = inst.encode();
        let (decoded, consumed) = EncoderInstruction::decode(&encoded).unwrap();
        
        assert_eq!(decoded, inst);
        assert_eq!(consumed, encoded.len());
    }
    
    #[test]
    fn test_insert_with_name_ref() {
        let inst = EncoderInstruction::InsertWithNameRef {
            is_static: true,
            name_index: 17,
            value: Bytes::from_static(b"custom-value"),
        };
        
        let encoded = inst.encode();
        let (decoded, consumed) = EncoderInstruction::decode(&encoded).unwrap();
        
        assert_eq!(decoded, inst);
        assert_eq!(consumed, encoded.len());
    }
    
    #[test]
    fn test_insert_literal() {
        let inst = EncoderInstruction::InsertLiteral {
            name: Bytes::from_static(b"custom-header"),
            value: Bytes::from_static(b"custom-value"),
        };
        
        let encoded = inst.encode();
        let (decoded, consumed) = EncoderInstruction::decode(&encoded).unwrap();
        
        assert_eq!(decoded, inst);
        assert_eq!(consumed, encoded.len());
    }
    
    #[test]
    fn test_duplicate() {
        let inst = EncoderInstruction::Duplicate { index: 5 };
        let encoded = inst.encode();
        let (decoded, consumed) = EncoderInstruction::decode(&encoded).unwrap();
        
        assert_eq!(decoded, inst);
        assert_eq!(consumed, encoded.len());
    }
    
    #[test]
    fn test_section_ack() {
        let inst = DecoderInstruction::SectionAck { stream_id: 123 };
        let encoded = inst.encode();
        let (decoded, consumed) = DecoderInstruction::decode(&encoded).unwrap();
        
        assert_eq!(decoded, inst);
        assert_eq!(consumed, encoded.len());
    }
    
    #[test]
    fn test_stream_cancel() {
        let inst = DecoderInstruction::StreamCancel { stream_id: 456 };
        let encoded = inst.encode();
        let (decoded, consumed) = DecoderInstruction::decode(&encoded).unwrap();
        
        assert_eq!(decoded, inst);
        assert_eq!(consumed, encoded.len());
    }
    
    #[test]
    fn test_insert_count_increment() {
        let inst = DecoderInstruction::InsertCountIncrement { increment: 10 };
        let encoded = inst.encode();
        let (decoded, consumed) = DecoderInstruction::decode(&encoded).unwrap();
        
        assert_eq!(decoded, inst);
        assert_eq!(consumed, encoded.len());
    }
}
