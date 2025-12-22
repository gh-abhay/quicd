//! # QUIC Cryptography Abstraction (RFC 9001)
//!
//! Pluggable crypto backend traits for TLS providers (rustls, boring, etc).
//! The QUIC state machine does NOT implement crypto - it delegates to backends.

pub mod backend;

pub use backend::{
    AeadProvider, CryptoBackend, CryptoLevel, HeaderProtectionProvider, KeySchedule,
    PacketProtection, TlsSession,
};
