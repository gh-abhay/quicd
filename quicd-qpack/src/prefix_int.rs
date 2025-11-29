//! Prefix integer encoding and decoding per RFC 7541 Section 5.1.
//! Used throughout QPACK for encoding indexes, lengths, and counts.

use crate::error::{QpackError, Result};

/// Decode a prefix integer from a byte slice.
/// 
/// # Arguments
/// * `data` - Input byte slice
/// * `prefix_bits` - Number of bits in first byte used for the integer (1-8)
/// 
/// # Returns
/// Tuple of (decoded_value, bytes_consumed)
/// 
/// # Performance
/// Optimized for the common case where values fit in the prefix (single byte).
/// Uses branchless operations where possible.
#[inline(always)]
pub fn decode_int(data: &[u8], prefix_bits: u8) -> Result<(u64, usize)> {
    if data.is_empty() {
        return Err(QpackError::UnexpectedEof);
    }
    
    debug_assert!(prefix_bits > 0 && prefix_bits <= 8);
    
    let mask = if prefix_bits == 8 {
        0xFF
    } else {
        (1u8 << prefix_bits) - 1
    };
    let mut value = (data[0] & mask) as u64;
    
    // Fast path: value fits in prefix (most common case)
    if value < mask as u64 {
        return Ok((value, 1));
    }
    
    // Multi-byte encoding - unrolled first iteration for better performance
    let mut offset = 1;
    let mut m = 0u32;
    
    loop {
        if offset >= data.len() {
            return Err(QpackError::UnexpectedEof);
        }
        
        let byte = data[offset];
        offset += 1;
        
        // Check for overflow before computation
        if m >= 56 {
            return Err(QpackError::IntegerOverflow);
        }
        
        value = value
            .checked_add(((byte & 0x7F) as u64) << m)
            .ok_or(QpackError::IntegerOverflow)?;
        
        m += 7;
        
        if byte & 0x80 == 0 {
            break;
        }
        
        // Prevent infinite loops
        if offset > 10 {
            return Err(QpackError::IntegerOverflow);
        }
    }
    
    Ok((value, offset))
}

/// Encode an integer with a given prefix.
/// 
/// # Arguments
/// * `value` - Value to encode
/// * `prefix_bits` - Number of bits available in first byte
/// * `prefix_mask` - Mask for high bits of first byte (bits that are not part of the integer)
/// 
/// # Returns
/// Encoded bytes
/// 
/// # Performance
/// Optimized for single-byte encoding (most common case).
/// Preallocates buffer size for multi-byte case to avoid reallocations.
#[inline(always)]
pub fn encode_int_with_prefix(value: u64, prefix_bits: u8, prefix_mask: u8) -> Vec<u8> {
    debug_assert!(prefix_bits > 0 && prefix_bits <= 8);
    
    let max_first_byte = (1u64 << prefix_bits) - 1;
    
    // Fast path: fits in first byte (most common case)
    if value < max_first_byte {
        return vec![prefix_mask | (value as u8)];
    }
    
    // Multi-byte encoding - preallocate for typical case (2-3 bytes)
    let mut buf = Vec::with_capacity(3);
    buf.push(prefix_mask | max_first_byte as u8);
    let mut remaining = value - max_first_byte;
    
    while remaining >= 128 {
        buf.push(0x80 | (remaining & 0x7F) as u8);
        remaining >>= 7;
    }
    
    buf.push(remaining as u8);
    buf
}

/// Encode an integer with zero prefix mask (all bits available).
#[inline]
pub fn encode_int(value: u64, prefix_bits: u8) -> Vec<u8> {
    encode_int_with_prefix(value, prefix_bits, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_decode_small_value() {
        let data = [10u8];
        let (val, consumed) = decode_int(&data, 5).unwrap();
        assert_eq!(val, 10);
        assert_eq!(consumed, 1);
    }
    
    #[test]
    fn test_decode_prefix_boundary() {
        // Value = 31 with 5-bit prefix should require 2 bytes
        let data = [0x1F, 0x00]; // 31 - 31 = 0
        let (val, consumed) = decode_int(&data, 5).unwrap();
        assert_eq!(val, 31);
        assert_eq!(consumed, 2);
    }
    
    #[test]
    fn test_decode_large_value() {
        // Encoding 1337 with 5-bit prefix
        // 1337 = 31 + 1306
        // 1306 = 0x51A
        let data = [0x1F, 0x9A, 0x0A]; // 31 + (26 | 0x80) + 10
        let (val, consumed) = decode_int(&data, 5).unwrap();
        assert_eq!(val, 1337);
        assert_eq!(consumed, 3);
    }
    
    #[test]
    fn test_encode_small_value() {
        let buf = encode_int_with_prefix(10, 5, 0xE0);
        assert_eq!(buf, vec![0xEA]); // 0xE0 | 10
    }
    
    #[test]
    fn test_encode_large_value() {
        let buf = encode_int_with_prefix(1337, 5, 0xE0);
        // 1337 requires multi-byte: first byte = 0xE0 | 0x1F
        // remaining = 1337 - 31 = 1306
        assert_eq!(buf[0], 0xFF);
        let (decoded, _) = decode_int(&buf, 5).unwrap();
        assert_eq!(decoded, 1337);
    }
    
    #[test]
    fn test_roundtrip() {
        for value in [0u64, 1, 31, 127, 128, 255, 1337, 65535, 1_000_000] {
            for prefix_bits in 1..=8 {
                let buf = encode_int(value, prefix_bits);
                let (decoded, _) = decode_int(&buf, prefix_bits).unwrap();
                assert_eq!(decoded, value, "Failed for value={} prefix={}", value, prefix_bits);
            }
        }
    }
}
