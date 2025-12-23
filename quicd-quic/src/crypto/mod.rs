//! # QUIC Cryptography Abstraction (RFC 9001)
//!
//! Pluggable crypto backend traits for TLS providers (rustls, boring, etc).
//! The QUIC state machine does NOT implement crypto - it delegates to backends.

pub mod backend;

#[cfg(feature = "boring-crypto")]
pub mod boring_backend;

pub use backend::{
    AeadProvider, CryptoBackend, CryptoLevel, HeaderProtectionProvider, KeySchedule,
    PacketProtection, TlsEvent, TlsSession,
};

#[cfg(feature = "boring-crypto")]
pub use boring_backend::BoringCryptoBackend;

// Type alias for main binary compatibility
pub use backend::CryptoLevel as EncryptionLevel;
