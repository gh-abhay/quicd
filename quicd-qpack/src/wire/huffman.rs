//! Huffman coding for QPACK per RFC 7541 Appendix B.
//!
//! Zero-allocation decoder with efficient encoder using static Huffman table.

use crate::error::Result;
use spin::Once;

/// Huffman decoding tree node.
#[derive(Clone, Copy, Debug)]
struct Node {
    left: u16,  // Left child index or symbol if leaf
    right: u16, // Right child index or unused if leaf
    is_leaf: bool,
}

/// Static Huffman decoding tree (initialized safely on first use).
static DECODE_TREE: Once<[Node; 1024]> = Once::new();

/// RFC 7541 Appendix B Huffman code table (256 symbols + EOS at 256).
const HUFFMAN_CODES: [(u32, u8); 257] = [
    // Symbols 0-31
    (0x1ff8, 13),
    (0x7fffd8, 23),
    (0xfffffe2, 28),
    (0xfffffe3, 28),
    (0xfffffe4, 28),
    (0xfffffe5, 28),
    (0xfffffe6, 28),
    (0xfffffe7, 28),
    (0xfffffe8, 28),
    (0xffffea, 24),
    (0x3ffffffc, 30),
    (0xfffffe9, 28),
    (0xfffffea, 28),
    (0x3ffffffd, 30),
    (0xfffffeb, 28),
    (0xfffffec, 28),
    (0xfffffed, 28),
    (0xfffffee, 28),
    (0xfffffef, 28),
    (0xffffff0, 28),
    (0xffffff1, 28),
    (0xffffff2, 28),
    (0x3ffffffe, 30),
    (0xffffff3, 28),
    (0xffffff4, 28),
    (0xffffff5, 28),
    (0xffffff6, 28),
    (0xffffff7, 28),
    (0xffffff8, 28),
    (0xffffff9, 28),
    (0xffffffa, 28),
    (0xffffffb, 28),
    // Symbols 32-63
    (0x14, 6),
    (0x3f8, 10),
    (0x3f9, 10),
    (0xffa, 12),
    (0x1ff9, 13),
    (0x15, 6),
    (0xf8, 8),
    (0x7fa, 11),
    (0x3fa, 10),
    (0x3fb, 10),
    (0xf9, 8),
    (0x7fb, 11),
    (0xfa, 8),
    (0x16, 6),
    (0x17, 6),
    (0x18, 6),
    (0x0, 5),
    (0x1, 5),
    (0x2, 5),
    (0x19, 6),
    (0x1a, 6),
    (0x1b, 6),
    (0x1c, 6),
    (0x1d, 6),
    (0x1e, 6),
    (0x1f, 6),
    (0x5c, 7),
    (0xfb, 8),
    (0x7ffc, 15),
    (0x20, 6),
    (0xffb, 12),
    (0x3fc, 10),
    // Symbols 64-95
    (0x1ffa, 13),
    (0x21, 6),
    (0x5d, 7),
    (0x5e, 7),
    (0x5f, 7),
    (0x60, 7),
    (0x61, 7),
    (0x62, 7),
    (0x63, 7),
    (0x64, 7),
    (0x65, 7),
    (0x66, 7),
    (0x67, 7),
    (0x68, 7),
    (0x69, 7),
    (0x6a, 7),
    (0x6b, 7),
    (0x6c, 7),
    (0x6d, 7),
    (0x6e, 7),
    (0x6f, 7),
    (0x70, 7),
    (0x71, 7),
    (0x72, 7),
    (0xfc, 8),
    (0x73, 7),
    (0xfd, 8),
    (0x1ffb, 13),
    (0x7fff0, 19),
    (0x1ffc, 13),
    (0x3ffc, 14),
    (0x22, 6),
    // Symbols 96-127
    (0x7ffd, 15),
    (0x3, 5),
    (0x23, 6),
    (0x4, 5),
    (0x24, 6),
    (0x5, 5),
    (0x25, 6),
    (0x26, 6),
    (0x27, 6),
    (0x6, 5),
    (0x74, 7),
    (0x75, 7),
    (0x28, 6),
    (0x29, 6),
    (0x2a, 6),
    (0x7, 5),
    (0x2b, 6),
    (0x76, 7),
    (0x2c, 6),
    (0x8, 5),
    (0x9, 5),
    (0x2d, 6),
    (0x77, 7),
    (0x78, 7),
    (0x79, 7),
    (0x7a, 7),
    (0x7b, 7),
    (0x7ffe, 15),
    (0x7fc, 11),
    (0x3ffd, 14),
    (0x1ffd, 13),
    (0xffffffc, 28),
    // Symbols 128-159
    (0xfffe6, 20),
    (0x3fffd2, 22),
    (0xfffe7, 20),
    (0xfffe8, 20),
    (0x3fffd3, 22),
    (0x3fffd4, 22),
    (0x3fffd5, 22),
    (0x7fffd9, 23),
    (0x3fffd6, 22),
    (0x7fffda, 23),
    (0x7fffdb, 23),
    (0x7fffdc, 23),
    (0x7fffdd, 23),
    (0x7fffde, 23),
    (0xffffeb, 24),
    (0x7fffdf, 23),
    (0xffffec, 24),
    (0xffffed, 24),
    (0x3fffd7, 22),
    (0x7fffe0, 23),
    (0xffffee, 24),
    (0x7fffe1, 23),
    (0x7fffe2, 23),
    (0x7fffe3, 23),
    (0x7fffe4, 23),
    (0x1fffdc, 21),
    (0x3fffd8, 22),
    (0x7fffe5, 23),
    (0x3fffd9, 22),
    (0x7fffe6, 23),
    (0x7fffe7, 23),
    (0xffffef, 24),
    // Symbols 160-191
    (0x3fffda, 22),
    (0x1fffdd, 21),
    (0xfffe9, 20),
    (0x3fffdb, 22),
    (0x3fffdc, 22),
    (0x7fffe8, 23),
    (0x7fffe9, 23),
    (0x1fffde, 21),
    (0x7fffea, 23),
    (0x3fffdd, 22),
    (0x3fffde, 22),
    (0xfffff0, 24),
    (0x1fffdf, 21),
    (0x3fffdf, 22),
    (0x7fffeb, 23),
    (0x7fffec, 23),
    (0x1fffe0, 21),
    (0x1fffe1, 21),
    (0x3fffe0, 22),
    (0x1fffe2, 21),
    (0x7fffed, 23),
    (0x3fffe1, 22),
    (0x7fffee, 23),
    (0x7fffef, 23),
    (0xfffea, 20),
    (0x3fffe2, 22),
    (0x3fffe3, 22),
    (0x3fffe4, 22),
    (0x7ffff0, 23),
    (0x3fffe5, 22),
    (0x3fffe6, 22),
    (0x7ffff1, 23),
    // Symbols 192-223
    (0x3ffffe0, 26),
    (0x3ffffe1, 26),
    (0xfffeb, 20),
    (0x7fff1, 19),
    (0x3fffe7, 22),
    (0x7ffff2, 23),
    (0x3fffe8, 22),
    (0x1ffffec, 25),
    (0x3ffffe2, 26),
    (0x3ffffe3, 26),
    (0x3ffffe4, 26),
    (0x7ffffde, 27),
    (0x7ffffdf, 27),
    (0x3ffffe5, 26),
    (0xfffff1, 24),
    (0x1ffffed, 25),
    (0x7fff2, 19),
    (0x1fffe3, 21),
    (0x3ffffe6, 26),
    (0x7ffffe0, 27),
    (0x7ffffe1, 27),
    (0x3ffffe7, 26),
    (0x7ffffe2, 27),
    (0xfffff2, 24),
    (0x1fffe4, 21),
    (0x1fffe5, 21),
    (0x3ffffe8, 26),
    (0x3ffffe9, 26),
    (0xffffffd, 28),
    (0x7ffffe3, 27),
    (0x7ffffe4, 27),
    (0x7ffffe5, 27),
    // Symbols 224-255
    (0xfffec, 20),
    (0xfffff3, 24),
    (0xfffed, 20),
    (0x1fffe6, 21),
    (0x3fffe9, 22),
    (0x1fffe7, 21),
    (0x1fffe8, 21),
    (0x7ffff3, 23),
    (0x3fffea, 22),
    (0x3fffeb, 22),
    (0x1ffffee, 25),
    (0x1ffffef, 25),
    (0xfffff4, 24),
    (0xfffff5, 24),
    (0x3ffffea, 26),
    (0x7ffff4, 23),
    (0x3ffffeb, 26),
    (0x7ffffe6, 27),
    (0x3ffffec, 26),
    (0x3ffffed, 26),
    (0x7ffffe7, 27),
    (0x7ffffe8, 27),
    (0x7ffffe9, 27),
    (0x7ffffea, 27),
    (0x7ffffeb, 27),
    (0xffffffe, 28),
    (0x7ffffec, 27),
    (0x7ffffed, 27),
    (0x7ffffee, 27),
    (0x7ffffef, 27),
    (0x7fffff0, 27),
    (0x3ffffee, 26),
    // EOS symbol at 256
    (0x3fffffff, 30),
];

/// Create the Huffman decoding tree.
fn create_decode_tree() -> [Node; 1024] {
    let mut tree = [Node {
        left: 0,
        right: 0,
        is_leaf: false,
    }; 1024];
    
    let mut next_node = 1u16;

    // Build tree from all symbols including EOS
    for (symbol, &(code, bits)) in HUFFMAN_CODES.iter().enumerate() {
        let mut node_idx = 0u16;

        for bit_pos in (0..bits).rev() {
            let bit = ((code >> bit_pos) & 1) != 0;

            if bit_pos == 0 {
                // Leaf node
                let child_idx = next_node;
                next_node += 1;

                tree[child_idx as usize] = Node {
                    left: symbol as u16,
                    right: 0,
                    is_leaf: true,
                };

                if bit {
                    tree[node_idx as usize].right = child_idx;
                } else {
                    tree[node_idx as usize].left = child_idx;
                }
            } else {
                // Internal node - get or create child
                let child_idx = if bit {
                    let idx = tree[node_idx as usize].right;
                    if idx == 0 {
                        let new_idx = next_node;
                        next_node += 1;
                        tree[node_idx as usize].right = new_idx;
                        new_idx
                    } else {
                        idx
                    }
                } else {
                    let idx = tree[node_idx as usize].left;
                    if idx == 0 {
                        let new_idx = next_node;
                        next_node += 1;
                        tree[node_idx as usize].left = new_idx;
                        new_idx
                    } else {
                        idx
                    }
                };

                node_idx = child_idx;
            }
        }
    }
    
    tree
}

/// Decode Huffman-encoded data with zero allocations on fast path.
/// 
/// This is a convenience wrapper around `decode_into` that manages Vec growth.
/// For zero-allocation decoding, use `decode_into` with a pre-allocated buffer.
/// 
/// # Performance
/// This function pre-allocates based on estimated output size to minimize reallocations.
/// For maximum performance in hot paths, use `decode_into` directly.
pub fn decode(input: &[u8], output: &mut Vec<u8>) -> Result<usize> {
    if input.is_empty() {
        return Ok(0);
    }

    // Estimate output size: max expansion is 8/5 = 1.6.
    // Safe upper bound: input.len() * 2.
    let initial_len = output.len();
    let estimated_size = input.len() * 2;
    
    // Ensure capacity
    output.reserve(estimated_size);
    
    // Resize to include spare capacity (safe because we will overwrite or truncate)
    output.resize(initial_len + estimated_size, 0);
    
    match decode_into(input, &mut output[initial_len..]) {
        Ok(written) => {
            output.truncate(initial_len + written);
            Ok(written)
        }
        Err(e) => {
            output.truncate(initial_len); // Restore original length
            Err(e)
        }
    }
}

/// Encode data using Huffman coding into a fixed buffer.
/// Returns the number of bytes written to output.
/// 
/// # Safety
/// The output buffer must be large enough to hold the encoded data.
/// Use `encoded_size()` to calculate the required size.
pub fn encode_into(input: &[u8], output: &mut [u8]) -> Result<usize> {
    if output.len() < encoded_size(input) {
        return Err(crate::error::QpackError::HuffmanEncodingError(
            "Output buffer too small for Huffman encoding".to_string()
        ));
    }

    let mut acc = 0u64;
    let mut acc_bits = 0u8;
    let mut output_pos = 0;

    for &byte in input {
        let (code, bits) = HUFFMAN_CODES[byte as usize];

        acc = (acc << bits) | (code as u64);
        acc_bits += bits;

        while acc_bits >= 8 {
            acc_bits -= 8;
            output[output_pos] = (acc >> acc_bits) as u8;
            output_pos += 1;
            acc &= (1u64 << acc_bits) - 1;
        }
    }

    // Padding with all 1s
    if acc_bits > 0 {
        let padding = 8 - acc_bits;
        acc = (acc << padding) | ((1u64 << padding) - 1);
        output[output_pos] = acc as u8;
        output_pos += 1;
    }

    Ok(output_pos)
}

/// Encode data using Huffman coding.
pub fn encode(input: &[u8], output: &mut Vec<u8>) -> usize {
    let size = encoded_size(input);
    let start = output.len();
    output.resize(start + size, 0);
    // We can unwrap because we just resized the buffer
    encode_into(input, &mut output[start..]).unwrap()
}

/// Calculate encoded size without allocating.
#[inline]
pub fn encoded_size(input: &[u8]) -> usize {
    let total_bits: usize = input
        .iter()
        .map(|&byte| HUFFMAN_CODES[byte as usize].1 as usize)
        .sum();
    total_bits.div_ceil(8)
}

/// Decode small Huffman-encoded data with stack allocation.
/// Uses a fixed-size stack buffer.
/// 
/// Returns the decoded data as Bytes.
pub fn decode_small(input: &[u8]) -> crate::error::Result<bytes::Bytes> {
    const MAX_STACK_SIZE: usize = 4096;
    
    if input.is_empty() {
        return Ok(bytes::Bytes::new());
    }
    
    let mut buffer = [0u8; MAX_STACK_SIZE];
    let written = decode_into(input, &mut buffer)?;
    Ok(bytes::Bytes::copy_from_slice(&buffer[..written]))
}

/// Encode small data using Huffman coding with stack allocation.
/// Uses a fixed-size stack buffer for inputs up to 4096 bytes.
/// For larger inputs, falls back to heap allocation.
/// 
/// Returns the encoded data as Bytes.
pub fn encode_small(input: &[u8]) -> crate::error::Result<bytes::Bytes> {
    const MAX_STACK_SIZE: usize = 4096;
    
    if input.len() > MAX_STACK_SIZE {
        // Fall back to heap allocation for large inputs
        let mut output = Vec::new();
        encode(input, &mut output);
        return Ok(bytes::Bytes::from(output));
    }
    
    let encoded_size = encoded_size(input);
    if encoded_size <= MAX_STACK_SIZE {
        let mut buffer = [0u8; MAX_STACK_SIZE];
        let written = encode_into(input, &mut buffer[..encoded_size])?;
        Ok(bytes::Bytes::copy_from_slice(&buffer[..written]))
    } else {
        // Should not happen since encoded_size should be <= input.len() + 1
        let mut output = Vec::new();
        encode(input, &mut output);
        Ok(bytes::Bytes::from(output))
    }
}

/// Decode Huffman-encoded data into a fixed buffer (zero allocation).
/// Returns the number of bytes written.
/// 
/// # Arguments
/// * `input` - Huffman-encoded input data
/// * `output` - Pre-allocated output buffer
/// 
/// # Returns
/// Number of decoded bytes written to output buffer.
/// 
/// # Errors
/// - `QpackError::DecompressionFailed` if output buffer is too small
/// - `QpackError::HuffmanDecodingError` if input is invalid (EOS symbol, invalid padding)
/// 
/// # Performance
/// **This is the zero-allocation fast path.** The output buffer should be sized
/// using worst-case expansion factor (input.len() * 2) or known size.
/// 
/// This implementation is fully stack-based with no heap allocations, making it
/// suitable for embedded environments and high-throughput servers processing
/// millions of requests per second.
/// 
/// # RFC 7541 Compliance
/// - Section 5.2: Validates padding is less than 8 bits and consists only of 1-bits
/// - Section 5.2: Rejects EOS symbol (256) if encountered in stream
pub fn decode_into(input: &[u8], output: &mut [u8]) -> Result<usize> {
    if input.is_empty() {
        return Ok(0);
    }

    if output.is_empty() {
        return Err(crate::error::QpackError::DecompressionFailed(
            "Output buffer too small for Huffman decoding".to_string()
        ));
    }

    let tree = DECODE_TREE.call_once(create_decode_tree);

    let mut output_pos = 0;
    let mut node_idx = 0u16;
    let mut bits_since_last_symbol = 0u8;

    // Process input bytes with manually unrolled bit traversal
    // Unrolling improves branch prediction and instruction-level parallelism
    for &byte in input {
        // Process all 8 bits of the byte
        for bit_idx in (0..8).rev() {
            let bit = (byte >> bit_idx) & 1;

            // Follow tree path (branchless node selection)
            let node = &tree[node_idx as usize];
            node_idx = if bit == 0 { node.left } else { node.right };
            
            bits_since_last_symbol += 1;

            // Check if we reached a leaf node
            let current_node = &tree[node_idx as usize];
            if current_node.is_leaf {
                // RFC 7541 Section 5.2: EOS symbol (256) MUST NOT appear in stream
                if current_node.left == 256 {
                    return Err(crate::error::QpackError::HuffmanDecodingError(
                        "EOS symbol (256) encountered in stream (RFC 7541 violation)".to_string()
                    ));
                }

                // Write decoded symbol to output
                if output_pos >= output.len() {
                    return Err(crate::error::QpackError::DecompressionFailed(
                        "Output buffer too small for Huffman decoding".to_string()
                    ));
                }
                output[output_pos] = current_node.left as u8;
                output_pos += 1;
                
                // Reset to root for next symbol
                node_idx = 0;
                bits_since_last_symbol = 0;
            }
        }
    }

    // RFC 7541 Section 5.2: Validate padding after all bits processed
    // After decoding, we should be at root or have valid padding (< 8 bits, all 1s)
    if node_idx != 0 {
        // Padding MUST be less than 8 bits
        if bits_since_last_symbol > 7 {
             return Err(crate::error::QpackError::HuffmanDecodingError(
                "Padding longer than 7 bits (RFC 7541 Section 5.2 violation)".to_string()
            ));
        }
        
        // RFC 7541 Section 5.2: Padding MUST be a prefix of the EOS symbol (all 1-bits)
        // Verify by following only right (1) branches until we reach EOS
        let mut check_idx = node_idx;
        for _ in 0..7 {  // Maximum padding is 7 bits
            let node = &tree[check_idx as usize];
            if node.is_leaf {
                // Must be EOS symbol (256) for valid padding
                if node.left == 256 {
                    break; // Valid padding - prefix of EOS
                } else {
                    return Err(crate::error::QpackError::HuffmanDecodingError(
                        "Invalid padding: decodes to non-EOS symbol (RFC 7541 violation)".to_string()
                    ));
                }
            }
            
            // Move right (bit 1) - padding must consist only of 1-bits
            check_idx = node.right;
            if check_idx == 0 {
                 return Err(crate::error::QpackError::HuffmanDecodingError(
                    "Invalid padding: not all 1-bits (RFC 7541 Section 5.2 violation)".to_string()
                ));
            }
        }
    }

    Ok(output_pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_huffman_roundtrip() {
        let input = b"www.example.com";
        let mut encoded = Vec::new();
        encode(input, &mut encoded);

        let mut decoded = Vec::new();
        decode(&encoded, &mut decoded).unwrap();

        assert_eq!(&decoded[..], &input[..]);
    }

    #[test]
    fn test_huffman_size() {
        let input = b"hello world";
        assert_eq!(encoded_size(input), {
            let mut buf = Vec::new();
            encode(input, &mut buf);
            buf.len()
        });
    }

    #[test]
    fn test_huffman_empty() {
        let mut encoded = Vec::new();
        encode(b"", &mut encoded);
        assert_eq!(encoded.len(), 0);

        let mut decoded = Vec::new();
        decode(&[], &mut decoded).unwrap();
        assert_eq!(decoded.len(), 0);
    }

    #[test]
    fn test_huffman_single_char() {
        for ch in 32u8..=126 {
            let input = [ch];
            let mut encoded = Vec::new();
            encode(&input, &mut encoded);

            let mut decoded = Vec::new();
            decode(&encoded, &mut decoded).unwrap();

            assert_eq!(decoded, vec![ch]);
        }
    }

    #[test]
    fn test_encode_into() {
        let input = b"hello world";
        let mut buffer = [0u8; 32];
        let written = encode_into(input, &mut buffer).unwrap();
        
        let mut vec_encoded = Vec::new();
        encode(input, &mut vec_encoded);
        
        assert_eq!(written, vec_encoded.len());
        assert_eq!(&buffer[..written], &vec_encoded[..]);
    }

    #[test]
    fn test_decode_into() {
        let input = b"hello world";
        let mut encoded = Vec::new();
        encode(input, &mut encoded);
        
        let mut buffer = [0u8; 32];
        let written = decode_into(&encoded, &mut buffer).unwrap();
        
        assert_eq!(written, input.len());
        assert_eq!(&buffer[..written], input);
    }

    #[test]
    fn test_encode_small() {
        let input = b"hello world";
        let encoded = encode_small(input).unwrap();
        
        let mut vec_encoded = Vec::new();
        encode(input, &mut vec_encoded);
        
        assert_eq!(encoded.as_ref(), &vec_encoded[..]);
    }

    #[test]
    fn test_decode_small() {
        let input = b"hello world";
        let mut encoded = Vec::new();
        encode(input, &mut encoded);
        
        let decoded = decode_small(&encoded).unwrap();
        
        assert_eq!(decoded.as_ref(), input);
    }
}
