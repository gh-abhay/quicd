//! # QUIC Cryptography Interface (RFC 9001)
//!
//! This module defines **trait-based abstractions** for the cryptographic operations
//! required by QUIC. It does NOT implement cryptography itself - instead, it defines
//! the interface that a crypto provider (like `rustls`, `ring`, or OpenSSL) must implement.
//!
//! ## Architecture Rationale
//!
//! QUIC's crypto is tightly integrated with TLS 1.3 (RFC 9001), but the QUIC transport
//! state machine should be **decoupled** from the specific TLS implementation. This allows:
//!
//! 1. **Testability**: Mock crypto providers for unit tests without real TLS handshakes
//! 2. **Flexibility**: Swap crypto backends (rustls, OpenSSL, BoringSSL) at runtime
//! 3. **No-Std Support**: Crypto can be provided externally in `#![no_std]` environments
//!
//! ## RFC 9001 Key Concepts
//!
//! ### Packet Protection (Section 5)
//! QUIC packets are encrypted using AEAD (Authenticated Encryption with Associated Data).
//! The payload is encrypted, and the header is authenticated as additional data.

pub mod backend;

pub use backend::{
    Aead, AeadAlgorithm, CryptoBackend, CryptoKeys, EncryptionLevel, HandshakeStatus,
    HeaderProtection, HeaderProtectionAlgorithm, InitialSecretDerivation, KeyPhase,
    INITIAL_SALT_V1,
};

use crate::error::Result;
use crate::types::Instant;

/// AEAD Nonce for packet encryption
///
/// The nonce is constructed from the packet number and an IV derived
/// during key derivation (RFC 9001 Section 5.3).
pub type Nonce = [u8; 12];

/// AEAD Tag for authenticated encryption
///
/// The authentication tag is appended to the ciphertext to verify integrity.
/// For AES-128-GCM and ChaCha20-Poly1305, this is 16 bytes.
pub type Tag = [u8; 16];

// ============================================================================
// Trait: Cryptographic Context (Main Interface)
// ============================================================================

/// Cryptographic Context for a QUIC Connection
///
/// This trait represents the complete cryptographic state for a connection,
/// including keys for all encryption levels and key update state.
///
/// **Lifecycle**:
/// 1. Created with Initial keys (derived from connection ID)
/// 2. Updated with Handshake keys (from TLS handshake)
/// 3. Updated with 0-RTT keys (if early data is enabled)
/// 4. Updated with 1-RTT keys (after handshake completes)
/// 5. Periodically updates 1-RTT keys (RFC 9001 Section 6)
///
/// **Design Note**: This trait does NOT perform the TLS handshake itself.
/// It only manages the keys produced by the handshake. The TLS handshake
/// is handled externally (e.g., by `rustls`).
pub trait CryptoContext {
    /// Get the packet protector for a specific encryption level
    ///
    /// Returns `None` if keys for that level are not yet available.
    fn packet_protector(&mut self, level: EncryptionLevel) -> Option<&mut dyn PacketProtector>;
    
    /// Get the header protector for a specific encryption level
    ///
    /// Returns `None` if keys for that level are not yet available.
    fn header_protector(&mut self, level: EncryptionLevel) -> Option<&mut dyn HeaderProtector>;
    
    /// Install keys for a specific encryption level
    ///
    /// Called when the TLS handshake provides new keys.
    ///
    /// **RFC 9001 Section 4.1.4**: Keys are installed in order:
    /// Initial → Handshake → 0-RTT (optional) → 1-RTT
    fn install_keys(
        &mut self,
        level: EncryptionLevel,
        secret: &[u8],
        time_now: Instant,
    ) -> Result<()>;
    
    /// Discard keys for a specific encryption level
    ///
    /// **RFC 9001 Section 4.9**: Once keys are no longer needed, they should
    /// be discarded to reduce attack surface. For example:
    /// - Initial keys are discarded when Handshake keys are confirmed
    /// - Handshake keys are discarded when 1-RTT keys are confirmed
    fn discard_keys(&mut self, level: EncryptionLevel);
    
    /// Update 1-RTT keys (RFC 9001 Section 6)
    ///
    /// Initiates a key update by deriving new keys from the current secret.
    /// The Key Phase bit in packet headers will toggle.
    ///
    /// **Constraints**:
    /// - Can only be called for 1-RTT keys
    /// - Cannot be called again until the previous update is confirmed
    fn update_keys(&mut self) -> Result<()>;
    
    /// Get the current key phase for 1-RTT encryption
    fn key_phase(&self) -> KeyPhase;
}

// ============================================================================
// Trait: Packet Protector (AEAD Encryption/Decryption)
// ============================================================================

/// Packet Protection using AEAD (RFC 9001 Section 5)
///
/// Encrypts and decrypts QUIC packet payloads using Authenticated Encryption
/// with Associated Data (AEAD). Supported ciphers:
/// - AES-128-GCM (REQUIRED)
/// - AES-256-GCM
/// - ChaCha20-Poly1305
///
/// **Zero-Copy Design**: All operations work in-place on mutable buffers.
///
/// ## Packet Protection Process (RFC 9001 Section 5.3)
///
/// **Encryption**:
/// 1. Construct nonce from packet number and IV: `nonce = iv XOR packet_number`
/// 2. Set Associated Data (AD) to the packet header
/// 3. Encrypt payload in-place: `ciphertext = AEAD-Encrypt(key, nonce, payload, AD)`
/// 4. Append authentication tag to ciphertext
///
/// **Decryption**:
/// 1. Reconstruct nonce from packet number and IV
/// 2. Extract AD from packet header
/// 3. Decrypt payload in-place: `payload = AEAD-Decrypt(key, nonce, ciphertext, AD)`
/// 4. Verify authentication tag
pub trait PacketProtector {
    /// Encrypt a packet payload in-place (RFC 9001 Section 5.3)
    ///
    /// # Arguments
    /// * `packet_number` - The packet number (used to construct the nonce)
    /// * `header` - The packet header (used as Additional Authenticated Data)
    /// * `payload` - Mutable buffer containing plaintext; will be overwritten with ciphertext + tag
    ///
    /// # Returns
    /// The number of bytes written (ciphertext + tag length).
    ///
    /// # Layout
    /// ```text
    /// Input:  [plaintext payload] [unused space for tag]
    /// Output: [ciphertext] [tag]
    /// ```
    ///
    /// **Requirement**: The buffer must have at least `tag_len()` extra bytes
    /// after the payload for the authentication tag.
    fn encrypt_in_place(
        &mut self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<usize>;
    
    /// Decrypt a packet payload in-place (RFC 9001 Section 5.3)
    ///
    /// # Arguments
    /// * `packet_number` - The packet number (used to construct the nonce)
    /// * `header` - The packet header (used as Additional Authenticated Data)
    /// * `payload` - Mutable buffer containing ciphertext + tag; will be overwritten with plaintext
    ///
    /// # Returns
    /// The number of bytes of plaintext (excludes the tag).
    ///
    /// # Errors
    /// Returns `Error::Crypto` if authentication fails (tag mismatch).
    ///
    /// # Layout
    /// ```text
    /// Input:  [ciphertext] [tag]
    /// Output: [plaintext payload]
    /// ```
    fn decrypt_in_place(
        &mut self,
        packet_number: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<usize>;
    
    /// Get the AEAD tag length in bytes
    ///
    /// For AES-128-GCM and ChaCha20-Poly1305, this is 16 bytes.
    fn tag_len(&self) -> usize;
    
    /// Get the maximum plaintext size that can fit in the given buffer
    ///
    /// This accounts for the tag overhead: `buffer_size - tag_len()`
    fn max_plaintext_len(&self, buffer_size: usize) -> usize {
        buffer_size.saturating_sub(self.tag_len())
    }
}

// ============================================================================
// Trait: Header Protector (Header Obfuscation)
// ============================================================================

/// Header Protection (RFC 9001 Section 5.4)
///
/// Obfuscates the packet number and certain header bits to prevent passive
/// observers from tracking connections or packet loss patterns.
///
/// ## Process
///
/// **Apply Protection** (after packet encryption):
/// 1. Sample 16 bytes from the encrypted payload starting at byte 4
/// 2. Generate a 5-byte mask using the sample as AES-ECB or ChaCha20 input
/// 3. XOR the first byte of the mask with protected header bits
/// 4. XOR the remaining 4 bytes with the packet number bytes
///
/// **Remove Protection** (before packet decryption):
/// 1. Sample 16 bytes from the encrypted payload
/// 2. Generate the same mask
/// 3. XOR to reveal the original header bits and packet number
///
/// **Zero-Copy Design**: Modifies the header in-place using XOR operations.
pub trait HeaderProtector {
    /// Apply header protection to a packet (RFC 9001 Section 5.4.1)
    ///
    /// # Arguments
    /// * `header` - Mutable slice of the packet header (first byte through packet number)
    /// * `payload_sample` - 16-byte sample from the encrypted payload (starting at byte 4)
    ///
    /// # Header Layout (Short Header Example)
    /// ```text
    /// Byte 0: [0|1|S|R|R|K|P P]
    ///          ^           ^^^^
    ///          |           packet number length (protected)
    ///          fixed bit (not protected)
    ///
    /// Bytes 1-4+: Packet Number (protected)
    /// ```
    ///
    /// **Protected Bits**:
    /// - Long header: bits 0x0f of byte 0, all packet number bytes
    /// - Short header: bits 0x1f of byte 0, all packet number bytes
    fn apply_header_protection(
        &mut self,
        header: &mut [u8],
        payload_sample: &[u8; 16],
    ) -> Result<()>;
    
    /// Remove header protection from a packet (RFC 9001 Section 5.4.2)
    ///
    /// # Arguments
    /// * `header` - Mutable slice of the packet header
    /// * `payload_sample` - 16-byte sample from the encrypted payload
    ///
    /// # Returns
    /// The revealed packet number length (1-4 bytes).
    ///
    /// **Critical**: This must be called BEFORE decrypting the packet payload,
    /// because the packet number is needed to construct the decryption nonce.
    fn remove_header_protection(
        &mut self,
        header: &mut [u8],
        payload_sample: &[u8; 16],
    ) -> Result<usize>;
    
    /// Get the sample offset for header protection (RFC 9001 Section 5.4.2)
    ///
    /// The sample is taken from the encrypted payload starting at this offset.
    /// For most cases, this is 4 bytes after the packet number.
    fn sample_offset(&self) -> usize {
        4
    }
    
    /// Get the sample length (always 16 bytes for QUIC)
    fn sample_len(&self) -> usize {
        16
    }
}

// ============================================================================
// Zero-Copy Helpers
// ============================================================================

/// Construct a nonce from packet number and IV (RFC 9001 Section 5.3)
///
/// The nonce is computed as: `nonce = iv XOR packet_number` (left-padded)
///
/// # Example
/// ```text
/// iv:            [0x12, 0x34, ..., 0xab, 0xcd]  (12 bytes)
/// packet_number: 0x123456                       (u64)
/// 
/// Result:        [0x12, 0x34, ..., 0xab ^ 0x12, 0xcd ^ 0x34, 0x56]
/// ```
#[inline]
pub fn construct_nonce(iv: &[u8; 12], packet_number: u64) -> Nonce {
    let mut nonce = *iv;
    let pn_bytes = packet_number.to_be_bytes();
    
    // XOR the last 8 bytes of the nonce with the packet number
    for i in 0..8 {
        nonce[4 + i] ^= pn_bytes[i];
    }
    
    nonce
}

// Constants re-exported from backend module:
// - INITIAL_SALT_V1
// - AEAD_TAG_LEN (if needed)
// - HP_SAMPLE_LEN (if needed)
