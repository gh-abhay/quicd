//! # Cryptographic Backend Trait (RFC 9001)
//!
//! This module defines the trait interface for cryptographic operations.
//! The QUIC state machine uses this trait to encrypt/decrypt packets
//! and protect/unprotect headers without depending on a specific TLS library.
//!
//! ## RFC 9001: Using TLS to Secure QUIC
//!
//! QUIC uses TLS 1.3 for:
//! - Handshake authentication
//! - Key derivation
//! - AEAD encryption (ChaCha20-Poly1305, AES-GCM)
//! - Header protection (AES-ECB or ChaCha20)
//!
//! ## Design:
//! This trait abstracts the crypto provider (rustls, boring, ring, etc.)
//! allowing unit testing with mock crypto and algorithm swapping.

#![forbid(unsafe_code)]

use crate::error::{Error, Result};
use crate::types::{PacketNumber, PacketNumberSpace};
use bytes::{Bytes, BytesMut};

/// AEAD Algorithm Identifier (RFC 9001 Section 5.3)
///
/// QUIC supports multiple AEAD algorithms for packet protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlgorithm {
    /// AES-128-GCM
    Aes128Gcm,

    /// AES-256-GCM
    Aes256Gcm,

    /// ChaCha20-Poly1305
    ChaCha20Poly1305,
}

impl AeadAlgorithm {
    /// Returns the key length in bytes for this algorithm
    pub fn key_len(&self) -> usize {
        match self {
            AeadAlgorithm::Aes128Gcm => 16,
            AeadAlgorithm::Aes256Gcm => 32,
            AeadAlgorithm::ChaCha20Poly1305 => 32,
        }
    }

    /// Returns the IV length in bytes for this algorithm
    pub fn iv_len(&self) -> usize {
        match self {
            AeadAlgorithm::Aes128Gcm => 12,
            AeadAlgorithm::Aes256Gcm => 12,
            AeadAlgorithm::ChaCha20Poly1305 => 12,
        }
    }

    /// Returns the authentication tag length in bytes
    pub fn tag_len(&self) -> usize {
        16 // All supported algorithms use 16-byte tags
    }
}

/// Header Protection Algorithm (RFC 9001 Section 5.4)
///
/// Used to protect packet header fields (packet number, etc.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderProtectionAlgorithm {
    /// AES-128-ECB (for AES-GCM)
    Aes128,

    /// AES-256-ECB (for AES-256-GCM)
    Aes256,

    /// ChaCha20 (for ChaCha20-Poly1305)
    ChaCha20,
}

/// Key Phase (RFC 9001 Section 6)
///
/// QUIC supports in-protocol key updates. Each key phase has distinct keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPhase {
    /// Initial phase (phase 0)
    Zero,

    /// Updated phase (phase 1)
    One,
}

/// Encryption Level (RFC 9001 Section 4)
///
/// Corresponds to TLS encryption levels and packet number spaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionLevel {
    /// Initial packets (uses Initial Secret derived from DCID)
    Initial,

    /// Handshake packets (uses Handshake Secret from TLS)
    Handshake,

    /// 0-RTT packets (uses Early Data Secret from TLS)
    ZeroRtt,

    /// 1-RTT packets (uses Application Secret from TLS)
    OneRtt,
}

impl EncryptionLevel {
    /// Map encryption level to packet number space
    pub fn packet_number_space(&self) -> PacketNumberSpace {
        match self {
            EncryptionLevel::Initial => PacketNumberSpace::Initial,
            EncryptionLevel::Handshake => PacketNumberSpace::Handshake,
            EncryptionLevel::ZeroRtt | EncryptionLevel::OneRtt => {
                PacketNumberSpace::ApplicationData
            }
        }
    }
}

/// Cryptographic Keys (RFC 9001 Section 5)
///
/// Contains keys derived from TLS for a specific encryption level.
#[derive(Clone)]
pub struct CryptoKeys {
    /// Encryption level these keys are for
    pub level: EncryptionLevel,

    /// AEAD algorithm
    pub aead: AeadAlgorithm,

    /// Header protection algorithm
    pub hp_algo: HeaderProtectionAlgorithm,

    /// Packet protection key
    pub key: Bytes,

    /// Packet protection IV
    pub iv: Bytes,

    /// Header protection key
    pub hp_key: Bytes,
}

/// AEAD Trait (RFC 9001 Section 5.3)
///
/// Interface for Authenticated Encryption with Associated Data.
/// Used to encrypt/decrypt QUIC packet payloads.
pub trait Aead {
    /// Encrypt a packet payload.
    ///
    /// # Arguments
    /// - `packet_number`: Packet number (used in nonce construction)
    /// - `header`: Packet header bytes (associated data)
    /// - `plaintext`: Payload to encrypt
    /// - `output`: Buffer to write ciphertext + tag
    ///
    /// # Returns
    /// Number of bytes written (plaintext.len() + tag_len())
    ///
    /// # RFC 9001 Section 5.3
    /// The nonce is constructed by XORing the packet number with the IV.
    fn seal(
        &self,
        packet_number: PacketNumber,
        header: &[u8],
        plaintext: &[u8],
        output: &mut [u8],
    ) -> Result<usize>;

    /// Decrypt a packet payload.
    ///
    /// # Arguments
    /// - `packet_number`: Packet number (used in nonce construction)
    /// - `header`: Packet header bytes (associated data)
    /// - `ciphertext`: Encrypted payload + tag
    /// - `output`: Buffer to write plaintext
    ///
    /// # Returns
    /// Number of bytes written (ciphertext.len() - tag_len())
    ///
    /// # Errors
    /// Returns Error::Crypto if authentication fails
    fn open(
        &self,
        packet_number: PacketNumber,
        header: &[u8],
        ciphertext: &[u8],
        output: &mut [u8],
    ) -> Result<usize>;

    /// Get the authentication tag length
    fn tag_len(&self) -> usize;
}

/// Header Protection Trait (RFC 9001 Section 5.4)
///
/// Interface for protecting/unprotecting packet header fields.
/// This prevents intermediaries from observing packet numbers.
pub trait HeaderProtection {
    /// Protect packet header fields.
    ///
    /// # RFC 9001 Section 5.4.1
    /// Applies header protection to:
    /// - First byte (flags, packet number length)
    /// - Packet number bytes
    ///
    /// The sample is taken from the encrypted payload.
    ///
    /// # Arguments
    /// - `sample`: 16-byte sample from encrypted payload
    /// - `first_byte`: Mutable reference to first header byte
    /// - `packet_number_bytes`: Mutable packet number bytes (1-4 bytes)
    fn protect(&self, sample: &[u8], first_byte: &mut u8, packet_number_bytes: &mut [u8])
        -> Result<()>;

    /// Unprotect packet header fields.
    ///
    /// # RFC 9001 Section 5.4.2
    /// Removes header protection to reveal:
    /// - Original first byte flags
    /// - Original packet number bytes
    ///
    /// # Arguments
    /// - `sample`: 16-byte sample from encrypted payload
    /// - `first_byte`: Mutable reference to first header byte
    /// - `packet_number_bytes`: Mutable packet number bytes (1-4 bytes)
    fn unprotect(
        &self,
        sample: &[u8],
        first_byte: &mut u8,
        packet_number_bytes: &mut [u8],
    ) -> Result<()>;
}

/// TLS Handshake Status (RFC 9001 Section 4)
///
/// Tracks the state of the TLS handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeStatus {
    /// Handshake in progress
    InProgress,

    /// Handshake completed successfully
    Complete,

    /// Handshake failed
    Failed,
}

/// Crypto Backend Trait (RFC 9001)
///
/// Main interface between QUIC state machine and TLS provider.
/// Handles handshake processing and key derivation.
///
/// ## Implementation Notes:
/// - Typically wraps rustls, boring, or ring
/// - Maintains TLS handshake state
/// - Provides keys at appropriate encryption levels
pub trait CryptoBackend {
    /// Process incoming CRYPTO data.
    ///
    /// # Arguments
    /// - `level`: Encryption level of the CRYPTO frame
    /// - `data`: CRYPTO frame data
    ///
    /// # Returns
    /// Handshake status after processing
    ///
    /// # RFC 9001 Section 4.1
    /// CRYPTO frames are processed by TLS in order.
    fn process_crypto_data(&mut self, level: EncryptionLevel, data: &[u8]) -> Result<HandshakeStatus>;

    /// Get outgoing CRYPTO data to send.
    ///
    /// # Arguments
    /// - `level`: Encryption level to get data for
    /// - `output`: Buffer to write CRYPTO data
    ///
    /// # Returns
    /// Number of bytes written
    fn get_crypto_data(&mut self, level: EncryptionLevel, output: &mut BytesMut) -> Result<usize>;

    /// Get keys for a specific encryption level.
    ///
    /// Returns None if keys not yet available.
    ///
    /// # RFC 9001 Section 5
    /// Keys become available after TLS derives secrets.
    fn get_keys(&self, level: EncryptionLevel) -> Option<&CryptoKeys>;

    /// Get AEAD for encryption at a level.
    fn get_aead(&self, level: EncryptionLevel) -> Result<&dyn Aead>;

    /// Get header protection for a level.
    fn get_header_protection(&self, level: EncryptionLevel) -> Result<&dyn HeaderProtection>;

    /// Check if handshake is complete.
    fn is_handshake_complete(&self) -> bool;

    /// Update 1-RTT keys (RFC 9001 Section 6)
    ///
    /// Performs in-protocol key update for 1-RTT packets.
    fn update_keys(&mut self) -> Result<()>;

    /// Get peer's TLS certificate chain (for validation)
    fn peer_certificates(&self) -> Option<&[Bytes]>;

    /// Get negotiated ALPN protocol
    fn alpn(&self) -> Option<&[u8]>;

    /// Get negotiated QUIC transport parameters
    fn transport_parameters(&self) -> Option<&[u8]>;
}

/// Initial Secret Derivation (RFC 9001 Section 5.2)
///
/// QUIC derives Initial Secrets from the client's DCID.
/// This allows stateless servers to decrypt Initial packets.
///
/// # Salt for QUIC Version 1
/// ```text
/// 38762cf7f55934b34d179ae6a4c80cadccbb7f0a
/// ```
pub const INITIAL_SALT_V1: &[u8] = &[
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
    0xad, 0xcc, 0xbb, 0x7f, 0x0a,
];

/// Trait for deriving Initial Secrets
pub trait InitialSecretDerivation {
    /// Derive client Initial Secret from DCID.
    ///
    /// # RFC 9001 Section 5.2
    /// Uses HKDF-Extract with INITIAL_SALT and DCID.
    fn derive_client_initial_secret(&self, dcid: &[u8]) -> Result<Bytes>;

    /// Derive server Initial Secret from DCID.
    fn derive_server_initial_secret(&self, dcid: &[u8]) -> Result<Bytes>;

    /// Derive keys from a secret.
    fn derive_keys(&self, secret: &[u8], aead: AeadAlgorithm) -> Result<CryptoKeys>;
}
