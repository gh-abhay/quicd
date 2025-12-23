//! # Cryptography Backend Traits (RFC 9001)
//!
//! Pluggable interfaces for TLS/crypto providers.
//! Enables swapping implementations (rustls, BoringSSL, mock for testing).

#![forbid(unsafe_code)]

use crate::error::{CryptoError, Error, Result};
use crate::types::{ConnectionId, PacketNumber, PacketNumberSpace, Side};
use bytes::{Bytes, BytesMut};

// ============================================================================
// Crypto Level (RFC 9001 Section 4)
// ============================================================================

/// Encryption Level (RFC 9001 Section 4)
///
/// QUIC uses four encryption levels during connection establishment:
/// - Initial: Client's first packets (uses Initial secret derived from DCID)
/// - Early Data (0-RTT): Early application data
/// - Handshake: TLS handshake messages
/// - Application (1-RTT): Protected application data
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CryptoLevel {
    /// Initial packets (derived from Destination CID)
    Initial,

    /// 0-RTT early data packets
    EarlyData,

    /// Handshake packets (TLS handshake)
    Handshake,

    /// 1-RTT application data packets
    Application,
}

impl CryptoLevel {
    /// Get corresponding packet number space
    pub fn packet_number_space(&self) -> PacketNumberSpace {
        match self {
            CryptoLevel::Initial => PacketNumberSpace::Initial,
            CryptoLevel::Handshake => PacketNumberSpace::Handshake,
            CryptoLevel::EarlyData | CryptoLevel::Application => {
                PacketNumberSpace::ApplicationData
            }
        }
    }
}

// ============================================================================
// AEAD Provider (RFC 9001 Section 5)
// ============================================================================

/// AEAD (Authenticated Encryption with Associated Data) Provider
///
/// RFC 9001 Section 5: QUIC packets are protected using AEAD algorithms.
/// Provides encryption/decryption of packet payloads.
///
/// **Design**: Stateless trait - keys are passed as parameters.
/// Implementation handles algorithm-specific operations (AES-GCM, ChaCha20-Poly1305).
pub trait AeadProvider: Send + Sync {
    /// Encrypt packet payload
    ///
    /// **Parameters**:
    /// - `key`: Packet protection key
    /// - `iv`: Packet-specific IV (XOR of base IV and packet number)
    /// - `packet_number`: Full packet number (for IV derivation)
    /// - `header`: Packet header (used as AAD - Additional Authenticated Data)
    /// - `payload`: Plaintext payload to encrypt
    /// - `output`: Buffer to write ciphertext + auth tag
    ///
    /// **Returns**: Length of ciphertext (includes auth tag)
    fn seal(
        &self,
        key: &[u8],
        iv: &[u8],
        packet_number: PacketNumber,
        header: &[u8],
        payload: &[u8],
        output: &mut [u8],
    ) -> Result<usize>;

    /// Decrypt packet payload
    ///
    /// **Parameters**:
    /// - `key`: Packet protection key
    /// - `iv`: Packet-specific IV
    /// - `packet_number`: Full packet number
    /// - `header`: Packet header (AAD)
    /// - `ciphertext`: Encrypted payload + auth tag
    /// - `output`: Buffer to write decrypted plaintext
    ///
    /// **Returns**: Length of plaintext (excludes auth tag)
    fn open(
        &self,
        key: &[u8],
        iv: &[u8],
        packet_number: PacketNumber,
        header: &[u8],
        ciphertext: &[u8],
        output: &mut [u8],
    ) -> Result<usize>;

    /// Get AEAD algorithm tag length (typically 16 bytes)
    fn tag_len(&self) -> usize;

    /// Get key length for this AEAD algorithm
    fn key_len(&self) -> usize;

    /// Get IV length for this AEAD algorithm
    fn iv_len(&self) -> usize;
}

// ============================================================================
// Header Protection Provider (RFC 9001 Section 5.4)
// ============================================================================

/// Header Protection Provider
///
/// RFC 9001 Section 5.4: Packet numbers and certain header bits are protected
/// using a sample from the packet payload to prevent ossification.
///
/// **Algorithm**: Uses first 16 bytes of ciphertext as sample, generates
/// 5-byte mask, XORs with header bits and packet number.
pub trait HeaderProtectionProvider: Send + Sync {
    /// Generate header protection mask from sample
    ///
    /// **Parameters**:
    /// - `hp_key`: Header protection key (separate from packet key)
    /// - `sample`: 16-byte sample from encrypted payload
    ///
    /// **Returns**: 5-byte mask (byte 0 for header, bytes 1-4 for packet number)
    fn generate_mask(&self, hp_key: &[u8], sample: &[u8; 16]) -> Result<[u8; 5]>;

    /// Get header protection key length
    fn key_len(&self) -> usize;
}

// ============================================================================
// Key Schedule (RFC 9001 Section 5.1, 5.2)
// ============================================================================

/// Key Schedule (Derives keys from TLS secrets)
///
/// RFC 9001 Section 5.1: QUIC derives packet protection keys from TLS secrets.
/// Each encryption level has its own set of keys.
///
/// **Keys Derived**:
/// - Packet protection key (for AEAD)
/// - Packet protection IV (base IV, XORed with packet number)
/// - Header protection key (for header masking)
pub trait KeySchedule: Send + Sync {
    /// Derive Initial secrets (RFC 9001 Section 5.2)
    ///
    /// Initial packets use secrets derived from the Destination Connection ID
    /// using a version-specific salt.
    ///
    /// **Parameters**:
    /// - `version`: QUIC version (determines salt)
    /// - `dcid`: Destination Connection ID
    /// - `side`: Client or Server
    ///
    /// **Returns**: (client_secret, server_secret)
    fn derive_initial_secrets(
        &self,
        version: u32,
        dcid: &ConnectionId,
        side: Side,
    ) -> Result<(Bytes, Bytes)>;

    /// Derive packet protection keys from TLS secret
    ///
    /// **Parameters**:
    /// - `secret`: TLS traffic secret
    /// - `cipher_suite`: TLS cipher suite ID
    ///
    /// **Returns**: (packet_key, packet_iv, hp_key)
    fn derive_packet_keys(
        &self,
        secret: &[u8],
        cipher_suite: u16,
    ) -> Result<(Bytes, Bytes, Bytes)>;

    /// Derive next generation of keys (key update, RFC 9001 Section 6)
    ///
    /// Used for 1-RTT key updates after handshake completes.
    fn update_keys(&self, secret: &[u8]) -> Result<Bytes>;
}

// ============================================================================
// Packet Protection (Unified Interface)
// ============================================================================

/// Packet Protection (Combines AEAD + Header Protection)
///
/// High-level interface for protecting/unprotecting entire packets.
/// Delegates to AEAD and HeaderProtection providers.
pub trait PacketProtection: Send + Sync {
    /// Protect an outgoing packet (encrypt + apply header protection)
    ///
    /// **In-place operation**: Modifies `packet` buffer.
    ///
    /// **Parameters**:
    /// - `level`: Encryption level (determines keys)
    /// - `packet_number`: Full packet number
    /// - `packet`: Mutable buffer containing unprotected packet
    /// - `header_len`: Length of packet header (before payload)
    ///
    /// **Returns**: Final packet length (may be longer due to auth tag)
    fn protect_packet(
        &self,
        level: CryptoLevel,
        packet_number: PacketNumber,
        packet: &mut [u8],
        header_len: usize,
    ) -> Result<usize>;

    /// Unprotect an incoming packet (remove header protection + decrypt)
    ///
    /// **In-place operation**: Modifies `packet` buffer.
    ///
    /// **Parameters**:
    /// - `level`: Encryption level
    /// - `packet`: Mutable buffer containing protected packet
    ///
    /// **Returns**: (packet_number, header_len, payload_len)
    fn unprotect_packet(
        &self,
        level: CryptoLevel,
        packet: &mut [u8],
    ) -> Result<(PacketNumber, usize, usize)>;

    /// Check if keys are available for a given level
    fn has_keys(&self, level: CryptoLevel) -> bool;

    /// Install keys for a specific encryption level
    ///
    /// Called when TLS handshake provides new secrets.
    fn install_keys(
        &mut self,
        level: CryptoLevel,
        packet_key: Bytes,
        packet_iv: Bytes,
        hp_key: Bytes,
    ) -> Result<()>;

    /// Discard keys for a specific level (RFC 9001 Section 4.9)
    ///
    /// Called when transitioning to next encryption level.
    fn discard_keys(&mut self, level: CryptoLevel);
}

// ============================================================================
// TLS Session Interface
// ============================================================================

/// TLS Session (Handshake State Machine)
///
/// RFC 9001 Section 4: QUIC uses TLS 1.3 for key exchange and authentication.
/// This trait wraps a TLS library (rustls, BoringSSL, etc.) and provides
/// QUIC-specific handshake operations.
///
/// **Critical Design**: QUIC controls crypto frame transmission, not TLS.
/// TLS provides crypto data to send, QUIC decides when/how to send it.
pub trait TlsSession: Send + core::fmt::Debug {
    /// Process incoming CRYPTO frame data
    ///
    /// Feeds TLS handshake messages to the TLS engine.
    ///
    /// **Parameters**:
    /// - `level`: Encryption level of CRYPTO frame
    /// - `data`: Handshake data from CRYPTO frame
    ///
    /// **Returns**: State change (keys ready, handshake complete, etc.)
    fn process_crypto_data(&mut self, level: CryptoLevel, data: &[u8]) -> Result<TlsEvent>;

    /// Get outgoing CRYPTO data to send
    ///
    /// Returns data that should be sent in CRYPTO frames.
    ///
    /// **Returns**: (level, data) - May be empty if nothing to send
    fn crypto_data_to_send(&mut self) -> Option<(CryptoLevel, Bytes)>;

    /// Check if handshake is complete
    fn is_handshake_complete(&self) -> bool;

    /// Get negotiated ALPN protocol
    fn alpn_protocol(&self) -> Option<&[u8]>;

    /// Get peer's certificate chain (for validation)
    fn peer_certificates(&self) -> Option<&[Bytes]>;

    /// Trigger key update (RFC 9001 Section 6)
    fn initiate_key_update(&mut self) -> Result<()>;
}

/// TLS Event (Handshake State Changes)
#[derive(Debug, Clone)]
pub enum TlsEvent {
    /// New encryption keys available
    KeysReady {
        level: CryptoLevel,
        /// TLS traffic secret (use with KeySchedule to derive packet keys)
        secret: Bytes,
    },

    /// Handshake has completed successfully
    HandshakeComplete,

    /// TLS alert received (error)
    Alert { code: u8, message: Bytes },

    /// No state change
    None,
}

// ============================================================================
// Crypto Backend (Top-Level Interface)
// ============================================================================

/// Crypto Backend (Unified Cryptography Provider)
///
/// Factory trait for creating crypto components. Implementations provide
/// all crypto primitives needed for QUIC.
///
/// **Design Rationale**: Single trait for DI (dependency injection).
/// Test implementations can mock all crypto at once.
pub trait CryptoBackend: Send + Sync {
    /// Create AEAD provider for cipher suite
    fn create_aead(&self, cipher_suite: u16) -> Result<Box<dyn AeadProvider>>;

    /// Create header protection provider for cipher suite
    fn create_header_protection(
        &self,
        cipher_suite: u16,
    ) -> Result<Box<dyn HeaderProtectionProvider>>;

    /// Create key schedule
    fn create_key_schedule(&self) -> Box<dyn KeySchedule>;

    /// Create TLS session for handshake
    ///
    /// **Parameters**:
    /// - `side`: Client or Server
    /// - `server_name`: SNI for client, ignored for server
    /// - `alpn_protocols`: Offered/accepted ALPN protocols
    fn create_tls_session(
        &self,
        side: Side,
        server_name: Option<&str>,
        alpn_protocols: &[&[u8]],
    ) -> Result<Box<dyn TlsSession>>;
}
