//! # Protocol Layer - QUIC Protocol Handling
//!
//! This module implements the protocol layer for SuperD, handling QUIC protocol
//! operations including encryption, decryption, connection state management,
//! and congestion control.
//!
//! ## Architecture
//!
//! Based on industry best practices from Cloudflare, Discord, and Tokio:
//!
//! ```text
//! Network I/O Tasks (I/O-bound)
//!         ↓
//!    Load Balancer
//!         ↓
//! Protocol Tasks (CPU-bound) ← Multiple per Network Task
//!         ↓
//! Application Layer
//! ```
//!
//! ## Design Rationale
//!
//! ### Separation from Network I/O
//!
//! QUIC protocol processing is **CPU-intensive**, not I/O-bound:
//! - **Cryptographic operations**: TLS 1.3 handshake, packet encryption/decryption
//! - **State management**: Connection state, stream multiplexing, flow control
//! - **Congestion control**: BBR, Cubic, loss detection algorithms
//! - **ACK processing**: Tracking packet acknowledgments, retransmissions
//!
//! This is fundamentally different from network I/O which is memory-bound.
//!
//! ### Scaling Strategy
//!
//! Following Cloudflare and Discord's approach:
//! - **Network tasks**: 1 per physical core (I/O-bound, kernel limited)
//! - **Protocol tasks**: 2-4x network tasks (CPU-bound, scales with crypto load)
//! - **Fan-out pattern**: Each network task distributes to multiple protocol tasks
//!
//! ## Performance Characteristics
//!
//! - **Throughput**: 100K+ connections per protocol task
//! - **Latency**: Sub-millisecond protocol processing (excluding crypto)
//! - **Crypto overhead**: Typically 60-80% of protocol processing time
//! - **Memory**: ~50-100KB per active connection
//!
//! ## Example
//!
//! ```rust,no_run
//! use superd::config::Config;
//! use superd::network::{NetworkToProtocol, ProtocolToNetwork};
//! use superd::protocol::quic_handler::start_protocol_layer;
//! use tokio::sync::{broadcast, mpsc};
//!
//! # fn main() {
//! let mut config = Config::default();
//! config.protocol_threads = 2;
//!
//! let mut network_to_protocol_receivers = Vec::new();
//! let mut protocol_to_network_senders = Vec::new();
//!
//! for _ in 0..config.protocol_threads {
//!     let (net_tx, net_rx) = mpsc::unbounded_channel::<NetworkToProtocol>();
//!     let (proto_tx, _proto_rx) = mpsc::unbounded_channel::<ProtocolToNetwork>();
//!
//!     // In production the senders are passed to the network layer.
//!     let _ = net_tx;
//!     protocol_to_network_senders.push(proto_tx);
//!     network_to_protocol_receivers.push(net_rx);
//! }
//!
//! let (shutdown_tx, _shutdown_rx) = broadcast::channel::<()>(1);
//!
//! start_protocol_layer(
//!     &config,
//!     network_to_protocol_receivers,
//!     protocol_to_network_senders,
//!     shutdown_tx,
//! ).unwrap();
//! # }
//! ```

pub mod quic_handler;

use std::net::SocketAddr;
use tokio::sync::mpsc;

use crate::network::zerocopy_buffer::ZeroCopyBuffer;

/// Messages from protocol layer to application layer
///
/// Protocol tasks forward parsed QUIC stream data to application tasks.
/// Application tasks are spawned dynamically per-stream, not pre-allocated.
#[derive(Debug)]
pub enum ProtocolToApplication {
    /// New QUIC stream opened - spawn application task based on ALPN
    NewStream {
        conn_id: u64,
        stream_id: u64,
        peer_addr: SocketAddr,
        alpn: String, // Application protocol: "h3", "ws", custom, etc.
    },
    /// Data received on a QUIC stream
    StreamData {
        conn_id: u64,
        stream_id: u64,
        data: ZeroCopyBuffer,
    },
    /// Stream closed - application task should terminate
    StreamClosed {
        conn_id: u64,
        stream_id: u64,
        reason: String,
    },
    /// Connection closed - all stream tasks for this connection should terminate
    ConnectionClosed { conn_id: u64, reason: String },
}

/// Messages from application layer to protocol layer
#[derive(Debug)]
pub enum ApplicationToProtocol {
    /// Send data on a QUIC stream
    SendData {
        conn_id: u64,
        stream_id: u64,
        data: ZeroCopyBuffer,
    },
    /// Close a connection
    CloseConnection { conn_id: u64 },
}

/// Channel types for protocol <-> application communication
pub type ToApplicationSender = mpsc::UnboundedSender<ProtocolToApplication>;
pub type ToApplicationReceiver = mpsc::UnboundedReceiver<ProtocolToApplication>;
pub type FromApplicationSender = mpsc::UnboundedSender<ApplicationToProtocol>;
pub type FromApplicationReceiver = mpsc::UnboundedReceiver<ApplicationToProtocol>;
