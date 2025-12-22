//! # QUIC Packet Layer (RFC 9000 Section 12-17)
//!
//! Zero-copy packet parsing and serialization.

pub mod header;
pub mod number;
pub mod space;

pub use header::{Header, HeaderForm, HeaderProtectionRemover, LongHeader, PacketParser, PacketType, ShortHeader};
pub use number::{PacketNumberDecoder, PacketNumberEncoder, PacketNumberLen};
pub use space::PacketNumberSpaceState;

