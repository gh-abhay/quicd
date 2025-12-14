//! Cryptographic primitives and traits.

mod traits;
#[cfg(feature = "rustls-tls")]
pub mod rustls_impl;
#[cfg(feature = "boringssl")]
pub mod boringssl_impl;

pub use traits::{CryptoContext, PacketKey, HeaderProtectionKey, EncryptionLevel, DummyCryptoProvider};
#[cfg(feature = "rustls-tls")]
pub use rustls_impl::RustlsCryptoContext;
#[cfg(feature = "boringssl")]
pub use boringssl_impl::BoringSslCryptoContext;
