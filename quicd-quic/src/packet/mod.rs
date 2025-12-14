//! Packet definitions and parsing.

mod header;
mod packet;
mod connection_id;

pub use header::{Header, PacketType, PacketNumber, packet_number_len};
pub use packet::{Packet, decode_packet_number};
pub use connection_id::{ConnectionId, ConnectionIdGenerator};
