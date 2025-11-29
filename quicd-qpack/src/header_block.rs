//! Header block encoding and decoding per RFC 9204 Section 4.5.
//! 
//! Header block structure:
//! - Encoded Field Section Prefix (Required Insert Count, Delta Base, Base)
//! - Encoded Field Lines (Indexed, Literal with/without name reference)

use bytes::{Bytes, BytesMut};

use crate::error::{QpackError, Result};
use crate::prefix_int::{decode_int, encode_int_with_prefix};

/// Representation types for header fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldLine {
    /// Indexed Field Line - Static Table.
    /// Pattern: 1T | Index (6+), T=1 for static
    IndexedStatic { index: u64 },
    
    /// Indexed Field Line - Dynamic Table with Post-Base Index.
    /// Pattern: 1T | Index (6+), T=0 for dynamic (post-base)
    IndexedDynamicPost { index: u64 },
    
    /// Indexed Field Line - Dynamic Table (Base-relative).
    /// Pattern: 1xxx xxxx followed by 0xxx xxxx (dynamic with base)
    IndexedDynamic { absolute_index: u64 },
    
    /// Literal Field Line With Name Reference - Static Table.
    /// Pattern: 01NT | Index (4+), N=never-indexed, T=1 for static
    LiteralStaticName {
        name_index: u64,
        value: Bytes,
        never_indexed: bool,
    },
    
    /// Literal Field Line With Name Reference - Dynamic Table.
    /// Pattern: 01NT | Index (4+), N=never-indexed, T=0 for dynamic
    LiteralDynamicName {
        name_index: u64,
        value: Bytes,
        never_indexed: bool,
    },
    
    /// Literal Field Line Without Name Reference.
    /// Pattern: 001N H | Name Length (3+) | Name | H | Value Length (7+) | Value
    LiteralName {
        name: Bytes,
        value: Bytes,
        never_indexed: bool,
    },
    
    /// Literal Field Line With Post-Base Name Reference.
    /// Pattern: 0000 N | Index (3+)
    LiteralPostBaseName {
        name_index: u64,
        value: Bytes,
        never_indexed: bool,
    },
}

/// Encoded field section prefix per RFC 9204 Section 4.5.1.
#[derive(Debug, Clone, Copy)]
pub struct EncodedPrefix {
    /// Required Insert Count (encoded).
    pub required_insert_count: u64,
    /// Sign bit for delta base (0 = positive, 1 = negative).
    pub sign: bool,
    /// Delta Base absolute value.
    pub delta_base: u64,
}

impl EncodedPrefix {
    /// Encode the prefix.
    pub fn encode(&self, max_entries: u64) -> Bytes {
        let mut buf = BytesMut::new();
        
        // Encode Required Insert Count with wraparound
        let enc_ric = encode_required_insert_count(self.required_insert_count, max_entries);
        buf.extend_from_slice(&encode_int_with_prefix(enc_ric, 8, 0));
        
        // Encode Delta Base: S | Delta Base (7+)
        let sign_bit = if self.sign { 0x80 } else { 0x00 };
        buf.extend_from_slice(&encode_int_with_prefix(self.delta_base, 7, sign_bit));
        
        buf.freeze()
    }
    
    /// Decode the prefix.
    pub fn decode(data: &[u8], max_entries: u64, total_inserted: u64) -> Result<(Self, usize)> {
        let mut offset = 0;
        
        // Decode Required Insert Count
        let (enc_ric, consumed) = decode_int(&data[offset..], 8)?;
        offset += consumed;
        
        let required_insert_count = decode_required_insert_count(enc_ric, max_entries, total_inserted)?;
        
        // Decode Delta Base
        if offset >= data.len() {
            return Err(QpackError::UnexpectedEof);
        }
        
        let sign = (data[offset] & 0x80) != 0;
        let (delta_base, consumed) = decode_int(&data[offset..], 7)?;
        offset += consumed;
        
        Ok((
            EncodedPrefix {
                required_insert_count,
                sign,
                delta_base,
            },
            offset,
        ))
    }
    
    /// Calculate Base from Required Insert Count and Delta Base.
    pub fn base(&self) -> u64 {
        if self.sign {
            // Negative delta: Base = Required Insert Count - Delta Base - 1
            self.required_insert_count.saturating_sub(self.delta_base + 1)
        } else {
            // Positive delta: Base = Required Insert Count + Delta Base
            self.required_insert_count + self.delta_base
        }
    }
}

/// Encode Required Insert Count per RFC 9204 Section 4.5.1.1.
fn encode_required_insert_count(ric: u64, max_entries: u64) -> u64 {
    if ric == 0 {
        return 0;
    }
    
    // EncodedInsertCount = (InsertCount mod (2 * MaxEntries)) + 1
    (ric % (2 * max_entries)) + 1
}

/// Decode Required Insert Count per RFC 9204 Section 4.5.1.1.
fn decode_required_insert_count(
    encoded: u64,
    max_entries: u64,
    total_inserted: u64,
) -> Result<u64> {
    if encoded == 0 {
        return Ok(0);
    }
    
    // FullRange = 2 * MaxEntries
    let full_range = 2 * max_entries;
    
    if encoded > full_range {
        return Err(QpackError::DecompressionFailed(
            "Encoded Insert Count too large".into(),
        ));
    }
    
    // MaxValue = TotalNumberOfInserts + MaxEntries
    let max_value = total_inserted + max_entries;
    
    // MaxWrapped = (MaxValue / FullRange) * FullRange
    let max_wrapped = (max_value / full_range) * full_range;
    
    // ReqInsertCount = MaxWrapped + EncodedInsertCount - 1
    let mut ric = max_wrapped + encoded - 1;
    
    // If ReqInsertCount > MaxValue, subtract FullRange
    if ric > max_value {
        if ric <= full_range {
            return Err(QpackError::DecompressionFailed(
                "Invalid Required Insert Count".into(),
            ));
        }
        ric -= full_range;
    }
    
    Ok(ric)
}

impl FieldLine {
    /// Encode a field line to bytes.
    pub fn encode(&self, base: u64) -> Bytes {
        let mut buf = BytesMut::new();
        
        match self {
            FieldLine::IndexedStatic { index } => {
                // 1T | Index (6+), T=1
                buf.extend_from_slice(&encode_int_with_prefix(*index, 6, 0xC0));
            }
            
            FieldLine::IndexedDynamicPost { index } => {
                // 0001 | Index (4+)
                buf.extend_from_slice(&encode_int_with_prefix(*index, 4, 0x10));
            }
            
            FieldLine::IndexedDynamic { absolute_index } => {
                // 1T | Index (6+), T=0 for dynamic
                // Calculate relative index from base
                let relative_index = base.saturating_sub(*absolute_index + 1);
                buf.extend_from_slice(&encode_int_with_prefix(relative_index, 6, 0x80));
            }
            
            FieldLine::LiteralStaticName {
                name_index,
                value,
                never_indexed,
            } => {
                // 01NT | Index (4+), T=1
                let prefix = if *never_indexed { 0x70 } else { 0x50 };
                buf.extend_from_slice(&encode_int_with_prefix(*name_index, 4, prefix));
                encode_string(value.as_ref(), &mut buf);
            }
            
            FieldLine::LiteralDynamicName {
                name_index,
                value,
                never_indexed,
            } => {
                // 01NT | Index (4+), T=0
                let prefix = if *never_indexed { 0x60 } else { 0x40 };
                let relative_index = base.saturating_sub(*name_index + 1);
                buf.extend_from_slice(&encode_int_with_prefix(relative_index, 4, prefix));
                encode_string(value.as_ref(), &mut buf);
            }
            
            FieldLine::LiteralName {
                name,
                value,
                never_indexed,
            } => {
                // 001NH | Name Length (3+)
                let prefix = if *never_indexed { 0x28 } else { 0x20 };
                encode_string_with_prefix(name.as_ref(), 3, prefix, &mut buf);
                encode_string(value.as_ref(), &mut buf);
            }
            
            FieldLine::LiteralPostBaseName {
                name_index,
                value,
                never_indexed,
            } => {
                // 0000N | Index (3+)
                let prefix = if *never_indexed { 0x08 } else { 0x00 };
                buf.extend_from_slice(&encode_int_with_prefix(*name_index, 3, prefix));
                encode_string(value.as_ref(), &mut buf);
            }
        }
        
        buf.freeze()
    }
    
    /// Decode a field line from bytes.
    pub fn decode(data: &[u8], base: u64) -> Result<(Self, usize)> {
        if data.is_empty() {
            return Err(QpackError::UnexpectedEof);
        }
        
        let first = data[0];
        let mut offset;
        
        let field_line = if first & 0x80 != 0 {
            // Indexed Field Line: 1T | Index (6+)
            let is_static = (first & 0x40) != 0;
            let (index, consumed) = decode_int(data, 6)?;
            offset = consumed;
            
            if is_static {
                FieldLine::IndexedStatic { index }
            } else {
                // Dynamic table with base-relative index
                let absolute_index = base.saturating_sub(index + 1);
                FieldLine::IndexedDynamic { absolute_index }
            }
        } else if first & 0xF0 == 0x10 {
            // Indexed Post-Base: 0001 | Index (4+)
            let (index, consumed) = decode_int(data, 4)?;
            offset = consumed;
            FieldLine::IndexedDynamicPost { index }
        } else if first & 0xC0 == 0x40 {
            // Literal With Name Reference: 01NT | Index (4+)
            let never_indexed = (first & 0x20) != 0;
            let is_static = (first & 0x10) != 0;
            let (name_index, consumed) = decode_int(data, 4)?;
            offset = consumed;
            
            let (value, consumed) = decode_string(&data[offset..])?;
            offset += consumed;
            
            if is_static {
                FieldLine::LiteralStaticName {
                    name_index,
                    value,
                    never_indexed,
                }
            } else {
                FieldLine::LiteralDynamicName {
                    name_index,
                    value,
                    never_indexed,
                }
            }
        } else if first & 0xF0 == 0x00 {
            // Literal Post-Base: 0000N | Index (3+)
            let never_indexed = (first & 0x08) != 0;
            let (name_index, consumed) = decode_int(data, 3)?;
            offset = consumed;
            
            let (value, consumed) = decode_string(&data[offset..])?;
            offset += consumed;
            
            FieldLine::LiteralPostBaseName {
                name_index,
                value,
                never_indexed,
            }
        } else if first & 0xE0 == 0x20 {
            // Literal Without Name Reference: 001NH | Name Length (3+)
            let never_indexed = (first & 0x10) != 0;
            let (name, consumed) = decode_string_with_prefix(data, 3)?;
            offset = consumed;
            
            let (value, consumed) = decode_string(&data[offset..])?;
            offset += consumed;
            
            FieldLine::LiteralName {
                name,
                value,
                never_indexed,
            }
        } else {
            return Err(QpackError::DecompressionFailed(
                "Invalid field line pattern".into(),
            ));
        };
        
        Ok((field_line, offset))
    }
}

/// Encode a string (7-bit length prefix) with optional Huffman encoding.
/// 
/// RFC 9204 Section 4.1.2: Uses Huffman encoding if it reduces size.
/// RFC 9204 Section 7.1: Applies automatically for compression efficiency.
#[inline]
fn encode_string(data: &[u8], buf: &mut BytesMut) {
    // Calculate Huffman encoded size
    let huffman_size = crate::huffman::encoded_size(data);
    
    if huffman_size < data.len() {
        // Use Huffman encoding (H bit = 1)
        buf.extend_from_slice(&encode_int_with_prefix(huffman_size as u64, 7, 0x80));
        let mut encoded = Vec::with_capacity(huffman_size);
        crate::huffman::encode(data, &mut encoded);
        buf.extend_from_slice(&encoded);
    } else {
        // Use literal encoding (H bit = 0)
        buf.extend_from_slice(&encode_int_with_prefix(data.len() as u64, 7, 0x00));
        buf.extend_from_slice(data);
    }
}

/// Encode a string with custom prefix bits and optional Huffman encoding.
/// 
/// RFC 9204 Section 4.1.2: Uses Huffman encoding if it reduces size.
#[inline]
fn encode_string_with_prefix(data: &[u8], prefix_bits: u8, prefix_mask: u8, buf: &mut BytesMut) {
    let huffman_size = crate::huffman::encoded_size(data);
    
    if huffman_size < data.len() {
        // Use Huffman encoding (H bit = 1)
        let h_bit = 1u8 << prefix_bits;
        let full_prefix = prefix_mask | h_bit;
        buf.extend_from_slice(&encode_int_with_prefix(huffman_size as u64, prefix_bits, full_prefix));
        let mut encoded = Vec::with_capacity(huffman_size);
        crate::huffman::encode(data, &mut encoded);
        buf.extend_from_slice(&encoded);
    } else {
        // Use literal encoding (H bit = 0)
        buf.extend_from_slice(&encode_int_with_prefix(data.len() as u64, prefix_bits, prefix_mask));
        buf.extend_from_slice(data);
    }
}

/// Decode a string (7-bit length prefix).
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
        crate::huffman::decode(string_data, &mut decoded)
            .map_err(|e| QpackError::HuffmanDecodingError(format!("{}", e)))?;
        Bytes::from(decoded)
    } else {
        Bytes::copy_from_slice(string_data)
    };
    
    Ok((decoded_data, offset))
}

/// Decode a string with custom prefix bits.
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
        crate::huffman::decode(string_data, &mut decoded)
            .map_err(|e| QpackError::HuffmanDecodingError(format!("{}", e)))?;
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
    fn test_encode_decode_prefix() {
        let prefix = EncodedPrefix {
            required_insert_count: 10,
            sign: false,
            delta_base: 5,
        };
        
        let encoded = prefix.encode(100);
        let (decoded, _) = EncodedPrefix::decode(&encoded, 100, 50).unwrap();
        
        assert_eq!(decoded.required_insert_count, 10);
        assert_eq!(decoded.sign, false);
        assert_eq!(decoded.delta_base, 5);
    }
    
    #[test]
    fn test_indexed_static() {
        let field = FieldLine::IndexedStatic { index: 17 };
        let encoded = field.encode(0);
        let (decoded, _) = FieldLine::decode(&encoded, 0).unwrap();
        
        assert_eq!(decoded, field);
    }
    
    #[test]
    fn test_literal_static_name() {
        let field = FieldLine::LiteralStaticName {
            name_index: 5,
            value: Bytes::from_static(b"custom"),
            never_indexed: false,
        };
        
        let encoded = field.encode(0);
        let (decoded, _) = FieldLine::decode(&encoded, 0).unwrap();
        
        assert_eq!(decoded, field);
    }
}
