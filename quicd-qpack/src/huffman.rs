//! Huffman encoding and decoding for QPACK.
//!
//! Implements the static Huffman code defined in RFC 7541 Appendix B.
//! QPACK reuses HPACK's Huffman table without modification.
//!
//! The implementation uses lookup tables for efficient encoding and decoding,
//! avoiding tree traversal for performance.

use crate::error::{Error, Result};
use std::sync::OnceLock;

/// Huffman code entry: (code, code_length_in_bits)
struct HuffmanEntry {
    code: u32,
    len: u8,
}

// Huffman encoding table (RFC 7541 Appendix B)
// Each entry is (code, bit_length) for symbols 0-255, plus EOS (256)
static ENCODE_TABLE: [HuffmanEntry; 257] = include!("huffman_table.inc");

// Decode tree node
#[derive(Clone, Copy, Debug)]
struct DecodeNode {
    // If symbol < 256, this is a leaf node with the decoded byte
    // If symbol == 256, this is EOS (end of string)
    // If symbol == 257, this is not a leaf (continue decoding)
    #[allow(dead_code)]
    symbol: u16,
    // Next nodes in the tree (for non-leaf nodes)
    left: u16,  // bit 0
    right: u16, // bit 1
}

const NOT_LEAF: u16 = 257;
// Use 512+ to encode internal node indices, 0-256 for symbols
const NODE_OFFSET: u16 = 512;

// Lazily build decode tree at runtime (first use)
static DECODE_TREE: OnceLock<Vec<DecodeNode>> = OnceLock::new();

fn get_decode_tree() -> &'static [DecodeNode] {
    DECODE_TREE.get_or_init(|| {
        let mut tree = vec![
            DecodeNode {
                symbol: NOT_LEAF,
                left: 0,
                right: 0
            };
            512
        ];
        let mut next_node = 1u16;

        // Insert each symbol into the tree
        for sym in 0..257 {
            let entry = &ENCODE_TABLE[sym];
            let mut node_idx = 0usize;

            for bit_idx in 0..entry.len {
                let bit = (entry.code >> (entry.len - bit_idx - 1)) & 1;

                if bit_idx == entry.len - 1 {
                    // Last bit - create leaf (store symbol value directly: 0-256)
                    if bit == 0 {
                        tree[node_idx].left = sym as u16;
                    } else {
                        tree[node_idx].right = sym as u16;
                    }
                } else {
                    // Intermediate bit - create or follow node
                    let next_idx = if bit == 0 {
                        tree[node_idx].left
                    } else {
                        tree[node_idx].right
                    };

                    if next_idx == 0 {
                        // Create new internal node (encode as NODE_OFFSET + index)
                        let new_node_val = NODE_OFFSET + next_node;
                        tree[next_node as usize] = DecodeNode {
                            symbol: NOT_LEAF,
                            left: 0,
                            right: 0,
                        };
                        next_node += 1;

                        if bit == 0 {
                            tree[node_idx].left = new_node_val;
                        } else {
                            tree[node_idx].right = new_node_val;
                        }
                        node_idx = (new_node_val - NODE_OFFSET) as usize;
                    } else {
                        // Follow existing node
                        node_idx = (next_idx - NODE_OFFSET) as usize;
                    }
                }
            }
        }

        tree
    })
}

/// Encodes data using Huffman coding.
///
/// # Arguments
///
/// * `data` - Raw bytes to encode
/// * `output` - Buffer to write encoded data  
///
/// # Returns
///
/// Number of bytes written to output.
pub fn encode(data: &[u8], output: &mut Vec<u8>) -> usize {
    let initial_len = output.len();
    let mut acc: u64 = 0;
    let mut bits: u8 = 0;

    for &byte in data {
        let entry = &ENCODE_TABLE[byte as usize];
        acc = (acc << entry.len) | (entry.code as u64);
        bits += entry.len;

        while bits >= 8 {
            bits -= 8;
            output.push((acc >> bits) as u8);
        }
    }

    // Pad with 1s (per RFC 7541 Section 5.2)
    if bits > 0 {
        acc <<= 8 - bits;
        acc |= (1u64 << (8 - bits)) - 1;
        output.push(acc as u8);
    }

    output.len() - initial_len
}

/// Decodes Huffman-encoded data using tree traversal.
///
/// # Arguments
///
/// * `data` - Huffman-encoded bytes
/// * `output` - Buffer to write decoded bytes
///
/// # Returns
///
/// Number of bytes written to output, or an error if decoding fails.
pub fn decode(data: &[u8], output: &mut Vec<u8>) -> Result<usize> {
    if data.is_empty() {
        return Ok(0);
    }

    let tree = get_decode_tree();
    let initial_len = output.len();
    let mut node_idx = 0usize;

    for &byte in data {
        for bit_pos in (0..8).rev() {
            let bit = (byte >> bit_pos) & 1;
            let node = tree[node_idx];

            let next = if bit == 0 { node.left } else { node.right };

            if next <= 256 {
                // Leaf node - emit symbol (values 0-256)
                if next == 256 {
                    // EOS symbol
                    return Err(Error::HuffmanError("unexpected EOS symbol".into()));
                }
                output.push(next as u8);
                node_idx = 0; // Back to root
            } else if next >= NODE_OFFSET {
                // Internal node - continue traversal
                node_idx = (next - NODE_OFFSET) as usize;
            } else {
                // Invalid (should never happen)
                return Err(Error::HuffmanError("invalid huffman code".into()));
            }
        }
    }

    // After consuming all bytes, check for valid termination
    // RFC 7541 Section 5.2: Padding (< 8 bits) must be most-significant bits of EOS
    // If we're not at root, verify padding leads to EOS
    if node_idx != 0 {
        let mut test_node = node_idx;

        // Follow right (1-bit) edges until we reach a leaf
        // This represents continuing with all-1 padding bits
        loop {
            let node = tree[test_node];
            let next = node.right;

            if next == 0 {
                // Dead end - padding doesn't lead to valid symbol
                return Err(Error::HuffmanError("invalid padding".into()));
            } else if next == 256 {
                // Reached EOS - valid padding
                break;
            } else if next <= 255 {
                // Reached a different symbol - padding doesn't lead to EOS
                return Err(Error::HuffmanError("invalid padding".into()));
            } else if next >= NODE_OFFSET {
                // Continue traversal
                test_node = (next - NODE_OFFSET) as usize;
            } else {
                // Should not happen
                return Err(Error::HuffmanError("invalid padding".into()));
            }
        }
    }

    Ok(output.len() - initial_len)
}

/// Returns the encoded size for the given data.
///
/// This is useful for pre-allocating buffers and calculating
/// whether Huffman encoding reduces size.
pub fn encoded_size(data: &[u8]) -> usize {
    let mut bits = 0usize;
    for &byte in data {
        bits += ENCODE_TABLE[byte as usize].len as usize;
    }
    // Round up to byte boundary
    (bits + 7) / 8
}

