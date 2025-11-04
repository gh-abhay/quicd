use std::net::SocketAddr;
use std::time::Instant;

use bytes::Bytes;

use crate::handle::{RecvStream, SendStream, StreamId};

/// Events raised by the worker runtime toward an application task.
#[derive(Debug)]
pub enum AppEvent {
    /// Transport handshake completed; application can start protocol work.
    HandshakeCompleted {
        alpn: String,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        negotiated_at: Instant,
    },
    /// Peer opened a new stream.
    NewStream {
        stream_id: StreamId,
        bidirectional: bool,
        recv_stream: RecvStream,
        send_stream: Option<SendStream>,
    },
    /// Peer finished sending data on a stream.
    StreamFinished { stream_id: StreamId },
    /// Stream was explicitly closed or reset.
    StreamClosed {
        stream_id: StreamId,
        app_initiated: bool,
        error_code: u64,
    },
    /// Unreliable datagram payload from the peer.
    Datagram { payload: Bytes },
    /// Flow-control parameters updated (e.g. max streams changed).
    ConnectionCapacityChanged,
    /// Transport-level signal delivered to the application.
    TransportEvent(TransportEvent),
    /// Connection is closing; application should start tearing down state.
    ConnectionClosing {
        error_code: u64,
        reason: Option<Bytes>,
    },
}

/// Transport scoped events that are independent of application protocols.
#[derive(Debug)]
pub enum TransportEvent {
    /// Peer migrated to a new network path.
    PathMigrated { new_peer_addr: SocketAddr },
    /// Effective MTU changed for the connection.
    MtuUpdated { mtu: usize },
    /// Congestion control state changed.
    CongestionStateChanged { state: String, bytes_in_flight: u64 },
    /// Catch-all for transport events that do not have a dedicated variant yet.
    Other { kind: String },
}
