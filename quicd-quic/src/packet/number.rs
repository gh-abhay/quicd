//! # Packet Number Encoding/Decoding (RFC 9000 Section 17.1)
//!
//! Packet numbers use **truncated encoding** to minimize overhead. Instead of sending
//! the full 62-bit value, QUIC encodes only the least significant bits needed to
//! disambiguate the packet number from recently received packets.
//!
//! ## Encoding Algorithm (RFC 9000 Section A.2)
//!
//! ```text
//! Given:
//! - full_pn: The full packet number to encode
//! - largest_acked: The largest packet number acknowledged by the peer
//!
//! The encoder:
//! 1. Computes the number of bits needed to represent (full_pn - largest_acked)
//! 2. Adds 1 bit to handle potential reordering
//! 3. Rounds up to 8, 16, 24, or 32 bits (1-4 bytes)
//! 4. Encodes only those least significant bits
//! ```
//!
//! ## Decoding Algorithm (RFC 9000 Section A.3)
//!
//! ```text
//! Given:
//! - truncated_pn: The truncated packet number from the packet header
//! - pn_nbits: Number of bits in truncated_pn (8, 16, 24, or 32)
//! - expected_pn: The next expected packet number (largest_received + 1)
//!
//! The decoder:
//! 1. Finds the candidate full packet number closest to expected_pn
//! 2. Ensures the candidate is within the valid window
//! ```

#![forbid(unsafe_code)]

use super::PacketNumber;
use crate::error::{Error, Result};

/// Encode a packet number using truncated encoding (RFC 9000 Appendix A.2)
///
/// Returns the number of bytes required to encode the packet number.
///
/// # Arguments
/// * `full_pn` - The full packet number to encode
/// * `largest_acked` - The largest packet number acknowledged by the peer
///
/// # Returns
/// The minimum number of bytes needed (1, 2, 3, or 4)
pub fn encode_length(full_pn: PacketNumber, largest_acked: PacketNumber) -> usize {
    let num_unacked = full_pn.saturating_sub(largest_acked);
    
    // RFC 9000 Section A.2: Add 1 bit to account for potential reordering
    let num_bits = (64 - num_unacked.leading_zeros()) as usize + 1;
    
    // Round up to byte boundary and choose encoding length
    if num_bits <= 8 {
        1
    } else if num_bits <= 16 {
        2
    } else if num_bits <= 24 {
        3
    } else {
        4
    }
}

/// Decode a truncated packet number to its full value (RFC 9000 Appendix A.3)
///
/// # Arguments
/// * `truncated_pn` - The truncated packet number from the packet header
/// * `pn_nbits` - Number of bits in the truncated encoding (8, 16, 24, or 32)
/// * `expected_pn` - The expected next packet number (typically largest_received + 1)
///
/// # Returns
/// The reconstructed full packet number
///
/// # Errors
/// Returns an error if `pn_nbits` is not 8, 16, 24, or 32.
pub fn decode(truncated_pn: u64, pn_nbits: usize, expected_pn: PacketNumber) -> Result<PacketNumber> {
    if !matches!(pn_nbits, 8 | 16 | 24 | 32) {
        return Err(Error::InvalidInput);
    }
    
    // RFC 9000 Appendix A.3: Find candidate closest to expected_pn
    let pn_win = 1u64 << pn_nbits;
    let pn_hwin = pn_win / 2;
    
    // Mask for extracting the truncated bits
    let pn_mask = pn_win - 1;
    
    // Candidate packet number
    let candidate = (expected_pn & !pn_mask) | truncated_pn;
    
    // Adjust candidate to be closest to expected_pn
    if candidate + pn_hwin <= expected_pn {
        Ok(candidate + pn_win)
    } else if candidate > expected_pn + pn_hwin && candidate >= pn_win {
        Ok(candidate - pn_win)
    } else {
        Ok(candidate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encode_length() {
        // No packets acked yet
        assert_eq!(encode_length(0, 0), 1);
        assert_eq!(encode_length(1, 0), 1);
        
        // Small gap
        assert_eq!(encode_length(100, 99), 1);
        
        // Larger gap requiring 2 bytes
        assert_eq!(encode_length(1000, 500), 2);
    }
    
    #[test]
    fn test_decode() {
        // Expected PN = 10, received truncated PN = 11 (8 bits)
        let decoded = decode(11, 8, 10).unwrap();
        assert_eq!(decoded, 11);
        
        // Expected PN = 1000, received truncated PN with wrapping
        let truncated = 5 & 0xFF; // Low 8 bits of 1005
        let decoded = decode(truncated, 8, 1000).unwrap();
        assert_eq!(decoded, 1005);
    }
}

