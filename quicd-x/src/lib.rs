//! Common interfaces shared between the `quicd` core and pluggable QUIC applications.

mod error;
mod events;
mod factory;
mod handle;
mod server;

pub use crate::error::ConnectionError;
pub use crate::events::{AppEvent, TransportEvent};
pub use crate::factory::QuicAppFactory;
pub use crate::handle::{
    ConnectionHandle, ConnectionId, ConnectionStats, RecvStream, SendStream, StreamId,
    TransportControls,
};
pub use crate::server::{
    new_connection_handle, new_recv_stream, new_send_stream, EgressCommand, StreamWriteCmd,
};
