//! Prefix integer encoding and decoding.
//!
//! Implements the variable-length integer encoding defined in RFC 7541 Section 5.1,
//! used heavily throughout QPACK. The format allows efficient encoding of integers
//! while sharing byte prefixes with other fields.
//!
//! ## Format
//!
//! An integer is represented in two parts:
//! - A prefix that fills the remainder of a byte (N bits, where 1 ≤ N ≤ 8)
//! - Optional continuation bytes if the value doesn't fit in the prefix
//!
//! If I < 2^N - 1, the integer is encoded in the N-bit prefix.
//! Otherwise, the prefix bits are all set to 1, and the value is encoded
//! in one or more continuation bytes.
//!
//! RFC 9204 requires support for integers up to 62 bits.

use crate::error::{Error, Result};

/// Maximum integer value that can be encoded (2^62 - 1).
const MAX_INTEGER: u64 = (1u64 << 62) - 1;

/// Encodes an integer with an N-bit prefix.
///
/// # Arguments
///
/// * `value` - The integer to encode (must be ≤ 2^62 - 1)
/// * `prefix_bits` - Number of bits available in the prefix (1-8)
/// * `prefix_mask` - Bits to preserve in the first byte (outside the N-bit prefix)
/// * `buf` - Buffer to write the encoded bytes
///
/// # Returns
///
/// Number of bytes written.
///
/// # Panics
///
/// Panics if `prefix_bits` is not in range 1..=8 or if buffer is too small.
///
/// # Example
///
/// ```
/// use quicd_qpack::integer::encode;
///
/// let mut buf = vec![0u8; 10];
/// // Encode 10 with a 5-bit prefix, preserving the top 3 bits as 001
/// let n = encode(10, 5, 0b001_00000, &mut buf);
/// assert_eq!(n, 1);
/// assert_eq!(buf[0], 0b001_01010);
/// ```
pub fn encode(value: u64, prefix_bits: u8, prefix_mask: u8, buf: &mut [u8]) -> usize {
    assert!(
        prefix_bits >= 1 && prefix_bits <= 8,
        "prefix_bits must be 1-8"
    );
    assert!(value <= MAX_INTEGER, "value exceeds maximum");
    assert!(!buf.is_empty(), "buffer is empty");

    // Calculate max_prefix safely to avoid shift overflow when prefix_bits == 8
    let max_prefix = if prefix_bits == 8 {
        255u64
    } else {
        (1u64 << prefix_bits) - 1
    };

    if value < max_prefix {
        // Value fits in the prefix
        buf[0] = prefix_mask | (value as u8);
        1
    } else {
        // Value doesn't fit in prefix - use continuation bytes
        buf[0] = prefix_mask | (max_prefix as u8);
        let mut remaining = value - max_prefix;
        let mut pos = 1;

        while remaining >= 128 {
            assert!(pos < buf.len(), "buffer too small");
            buf[pos] = ((remaining & 0x7F) | 0x80) as u8;
            remaining >>= 7;
            pos += 1;
        }

        assert!(pos < buf.len(), "buffer too small");
        buf[pos] = remaining as u8;
        pos + 1
    }
}

/// Decodes an integer with an N-bit prefix.
///
/// # Arguments
///
/// * `prefix_bits` - Number of bits available in the prefix (1-8)
/// * `data` - Buffer containing the encoded integer
///
/// # Returns
///
/// A tuple of (decoded value, number of bytes consumed), or an error.
///
/// # Example
///
/// ```
/// use quicd_qpack::integer::decode;
///
/// let data = &[0b001_01010]; // 10 with 5-bit prefix
/// let (value, consumed) = decode(5, data).unwrap();
/// assert_eq!(value, 10);
/// assert_eq!(consumed, 1);
/// ```
pub fn decode(prefix_bits: u8, data: &[u8]) -> Result<(u64, usize)> {
    if !(1..=8).contains(&prefix_bits) {
        return Err(Error::IntegerError("prefix_bits must be 1-8".into()));
    }

    if data.is_empty() {
        return Err(Error::Incomplete(1));
    }

    // Calculate mask safely to avoid shift overflow when prefix_bits == 8
    let mask = if prefix_bits == 8 {
        0xFFu8
    } else {
        (1u8 << prefix_bits) - 1
    };
    let mut value = (data[0] & mask) as u64;

    if value < (mask as u64) {
        // Value fits in prefix
        return Ok((value, 1));
    }

    // Read continuation bytes
    let mut pos = 1;
    let mut shift = 0u32;

    loop {
        if pos >= data.len() {
            return Err(Error::Incomplete(1));
        }

        let byte = data[pos];
        pos += 1;

        let byte_value = (byte & 0x7F) as u64;

        // Check for overflow
        if shift >= 56 {
            // At shift >= 56, we can only accept values that don't overflow
            let max_value = MAX_INTEGER.wrapping_sub(value);
            let shifted = byte_value.checked_shl(shift);
            if shifted.is_none() || shifted.unwrap() > max_value {
                return Err(Error::IntegerError("integer overflow".into()));
            }
        }

        value = value
            .checked_add(byte_value << shift)
            .ok_or_else(|| Error::IntegerError("integer overflow".into()))?;

        if value > MAX_INTEGER {
            return Err(Error::IntegerError(
                "value exceeds maximum (2^62 - 1)".into(),
            ));
        }

        // Check if this is the last byte
        if (byte & 0x80) == 0 {
            break;
        }

        shift += 7;

        // Prevent infinite loops on malicious input
        if shift > 63 {
            return Err(Error::IntegerError("integer encoding too long".into()));
        }
    }

    Ok((value, pos))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_small() {
        let mut buf = [0u8; 10];

        // Test values that fit in various prefix sizes
        for prefix_bits in 1..=8 {
            let max_prefix = (1u64 << prefix_bits) - 1;
            for value in 0..max_prefix {
                let n = encode(value, prefix_bits, 0, &mut buf);
                assert_eq!(n, 1);
                let (decoded, consumed) = decode(prefix_bits, &buf[..n]).unwrap();
                assert_eq!(decoded, value);
                assert_eq!(consumed, 1);
            }
        }
    }

    #[test]
    fn test_encode_decode_large() {
        let mut buf = [0u8; 20];
        let test_values = vec![
            127,
            128,
            255,
            256,
            1337,
            65535,
            65536,
            1_000_000,
            100_000_000,
            (1u64 << 32) - 1,
            1u64 << 32,
            (1u64 << 48) - 1,
            (1u64 << 62) - 1,
        ];

        for &value in &test_values {
            for prefix_bits in 1..=8 {
                let n = encode(value, prefix_bits, 0, &mut buf);
                let (decoded, consumed) = decode(prefix_bits, &buf[..n]).unwrap();
                assert_eq!(
                    decoded, value,
                    "failed for value {} with {} prefix bits",
                    value, prefix_bits
                );
                assert_eq!(consumed, n);
            }
        }
    }

    #[test]
    fn test_encode_with_prefix_mask() {
        let mut buf = [0u8; 10];

        // RFC 9204 example: 5-bit prefix with top 3 bits as 001
        let n = encode(10, 5, 0b001_00000, &mut buf);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 0b001_01010);

        let (value, _) = decode(5, &buf[..n]).unwrap();
        assert_eq!(value, 10);
    }

    #[test]
    fn test_rfc_example_10() {
        // RFC 7541 Section 5.1 Example 1: Encoding 10 with 5-bit prefix
        let mut buf = [0u8; 10];
        let n = encode(10, 5, 0, &mut buf);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 10);
    }

    #[test]
    fn test_rfc_example_1337() {
        // RFC 7541 Section 5.1 Example 2: Encoding 1337 with 5-bit prefix
        let mut buf = [0u8; 10];
        let n = encode(1337, 5, 0, &mut buf);
        assert_eq!(n, 3);
        assert_eq!(buf[0], 31); // 0x1F
        assert_eq!(buf[1], 154); // 0x9A (0x1A | 0x80)
        assert_eq!(buf[2], 10); // 0x0A

        let (value, consumed) = decode(5, &buf[..n]).unwrap();
        assert_eq!(value, 1337);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn test_rfc_example_42() {
        // RFC 7541 Section 5.1 Example 3: Encoding 42 with 8-bit prefix
        let mut buf = [0u8; 10];
        let n = encode(42, 8, 0, &mut buf);
        assert_eq!(n, 1);
        assert_eq!(buf[0], 42);
    }

    #[test]
    fn test_incomplete_data() {
        // First byte indicates continuation but no more data
        let data = &[0xFF]; // All bits set, indicating more data needed
        let result = decode(5, data);
        assert!(matches!(result, Err(Error::Incomplete(_))));
    }

    #[test]
    fn test_overflow_detection() {
        // Try to decode an integer that would overflow 62 bits
        let data = &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let result = decode(8, data);
        assert!(result.is_err());
    }

    #[test]
    fn test_round_trip_property() {
        use proptest::prelude::*;

        proptest!(|(value in 0u64..=MAX_INTEGER, prefix_bits in 1u8..=8)| {
            let mut buf = vec![0u8; 20];
            let n = encode(value, prefix_bits, 0, &mut buf);
            let (decoded, consumed) = decode(prefix_bits, &buf[..n]).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(consumed, n);
        });
    }
}
