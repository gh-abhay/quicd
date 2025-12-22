//! # QUIC Packet Layer (RFC 9000 Section 12-17)
//!
//! Zero-copy packet parsing and serialization for all QUIC packet types.
//!
//! ## Packet Types (RFC 9000 Section 17)
//!
//! QUIC defines two packet header forms:
//! - **Long Header**: Used during handshake (Initial, 0-RTT, Handshake, Retry)
//! - **Short Header**: Used for 1-RTT protected packets
//!
//! ## Header Protection (RFC 9001 Section 5.4)
//!
//! Packet and connection ID protection is applied to prevent ossification.
//! The first byte and packet number are encrypted using a sample from the
//! packet payload. This module provides traits for in-place header protection
//! removal without buffer copying.
//!
//! ## Zero-Copy Design
//!
//! All packet parsing returns references to the original buffer with lifetime
//! parameters. This enables processing without memory allocation.

pub mod header;
pub mod number;
pub mod space;
pub mod types;
pub mod parser;
pub mod protection;

// Re-export specific types to avoid ambiguity
pub use header::{Header, HeaderForm, PacketType};
pub use number::PacketNumberLen;
pub use space::PacketNumberSpaceState;
pub use types::{LongHeader, ShortHeader, LongPacketType, ParsedPacket, DatagramInput, DatagramOutput};

// Parser traits - use qualified names to avoid conflict
pub use parser::{
    PacketParser as PacketParserTrait,
    PacketSerializer,
    PacketCoalescer,
    PacketNumberDecoder as PnDecoder,
    PacketNumberEncoder as PnEncoder,
    HeaderProtectionRemover as HpRemover,
};
pub use protection::{HeaderProtectionProvider, InPlaceHeaderProtectionRemover};

