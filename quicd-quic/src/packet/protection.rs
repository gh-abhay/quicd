//! # Header Protection (RFC 9001 Section 5.4)
//!
//! Header protection prevents ossification of QUIC packet headers by
//! encrypting the first byte and packet number field. This module defines
//! traits for applying and removing header protection.

use crate::types::*;
use crate::error::*;

/// Header Protection Provider Trait (RFC 9001 Section 5.4)
///
/// Provides cryptographic primitives for header protection.
/// The actual encryption is delegated to the CryptoBackend.
pub trait HeaderProtectionProvider: Send + Sync {
    /// Apply header protection mask to packet header
    ///
    /// # Arguments
    ///
    /// - `sample`: 16-byte sample from packet payload
    /// - `first_byte`: First byte of packet header (will be masked)
    /// - `pn_bytes`: Packet number bytes (1-4 bytes, will be masked)
    ///
    /// Returns (masked_first_byte, masked_pn_bytes)
    fn apply_mask(
        &self,
        sample: &[u8; 16],
        first_byte: u8,
        pn_bytes: &[u8],
    ) -> Result<(u8, alloc::vec::Vec<u8>)>;
    
    /// Remove header protection mask from packet header
    ///
    /// This is the inverse operation of apply_mask.
    fn remove_mask(
        &self,
        sample: &[u8; 16],
        first_byte: u8,
        pn_bytes: &[u8],
    ) -> Result<(u8, alloc::vec::Vec<u8>)>;
}

/// Header Protection Algorithm Type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderProtectionAlgorithm {
    /// AES-128 ECB
    Aes128,
    /// AES-256 ECB
    Aes256,
    /// ChaCha20
    ChaCha20,
}

/// In-place header protection remover
///
/// This is a stateful helper that maintains the current encryption level
/// and applies header protection removal directly to mutable buffers.
pub struct InPlaceHeaderProtectionRemover {
    /// Current header protection provider for this encryption level
    provider: alloc::boxed::Box<dyn HeaderProtectionProvider>,
}

impl InPlaceHeaderProtectionRemover {
    /// Create a new in-place header protection remover
    pub fn new(provider: alloc::boxed::Box<dyn HeaderProtectionProvider>) -> Self {
        Self { provider }
    }
    
    /// Remove header protection from buffer in-place
    ///
    /// # Arguments
    ///
    /// - `buf`: Mutable packet buffer
    /// - `pn_offset`: Offset to packet number field
    /// - `sample_offset`: Offset to 16-byte sample
    /// - `is_long_header`: Whether this is a long header packet
    ///
    /// Returns (packet_number, pn_length, key_phase_bit)
    /// The key_phase_bit is only relevant for short headers.
    pub fn remove_protection_in_place(
        &self,
        buf: &mut [u8],
        pn_offset: usize,
        sample_offset: usize,
        is_long_header: bool,
    ) -> Result<(PacketNumber, u8, Option<bool>)> {
        // Extract sample
        if sample_offset + 16 > buf.len() {
            return Err(Error::Transport(TransportError::FrameEncodingError));
        }
        
        let mut sample = [0u8; 16];
        sample.copy_from_slice(&buf[sample_offset..sample_offset + 16]);
        
        // Remove mask from first byte
        let first_byte = buf[0];
        let (unmasked_first_byte, _) = self.provider.remove_mask(&sample, first_byte, &[])?;
        
        // Extract packet number length from unmasked first byte
        let pn_length = if is_long_header {
            (unmasked_first_byte & 0x03) + 1
        } else {
            (unmasked_first_byte & 0x03) + 1
        };
        
        if pn_offset + pn_length as usize > buf.len() {
            return Err(Error::Transport(TransportError::FrameEncodingError));
        }
        
        // Remove mask from packet number bytes
        let pn_bytes = &buf[pn_offset..pn_offset + pn_length as usize];
        let (_, unmasked_pn_bytes) = self.provider.remove_mask(&sample, first_byte, pn_bytes)?;
        
        // Decode packet number
        let mut pn: u64 = 0;
        for &byte in &unmasked_pn_bytes {
            pn = (pn << 8) | (byte as u64);
        }
        
        // Write unmasked values back to buffer
        buf[0] = unmasked_first_byte;
        buf[pn_offset..pn_offset + pn_length as usize].copy_from_slice(&unmasked_pn_bytes);
        
        // Extract key phase bit for short headers
        let key_phase = if !is_long_header {
            Some((unmasked_first_byte & 0x04) != 0)
        } else {
            None
        };
        
        Ok((pn, pn_length, key_phase))
    }
}
