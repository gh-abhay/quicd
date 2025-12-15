//! Cryptographic primitives and traits.

mod traits;
pub mod kdf;
pub mod ring_initial;

#[cfg(feature = "rustls-tls")]
pub mod rustls_impl;
#[cfg(feature = "boringssl")]
pub mod boringssl_impl;

pub use traits::{CryptoContext, PacketKey, HeaderProtectionKey, EncryptionLevel, DummyCryptoProvider};
pub use ring_initial::{RingPacketKey, RingHeaderProtectionKey};
#[cfg(feature = "rustls-tls")]
pub use rustls_impl::RustlsCryptoContext;
#[cfg(feature = "boringssl")]
pub use boringssl_impl::BoringSslCryptoContext;
