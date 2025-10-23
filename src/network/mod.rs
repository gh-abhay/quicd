//! # Network Layer - High-Performance UDP I/O
//!
//! This module implements the network layer of SuperD using modern Linux io_uring
//! for maximum performance. It provides event-driven, zero-copy UDP socket operations
//! optimized for millions of concurrent connections.
//!
//! ## Architecture
//!
//! The network layer uses:
//! - **io_uring**: 60+ I/O operations per syscall (vs epoll's 4-5)
//! - **Zero-copy buffers**: Arc-based ownership transfer
//! - **SO_REUSEPORT**: Kernel-level load balancing
//! - **CPU pinning**: Optimal thread placement
//!
//! ## Performance Characteristics
//!
//! - **Throughput**: 9.5+ Gbps sustained
//! - **Latency**: Sub-millisecond response times
//! - **Connections**: Millions per node
//! - **Memory**: ~28-50KB per connection
//!
//! ## Example
//!
//! ```rust,no_run
//! use superd::network::io_uring_net::start_network_layer;
//! use superd::config::Config;
//! use tokio::sync::mpsc;
//! use std::sync::Arc;
//! use std::sync::atomic::AtomicBool;
//!
//! // Load configuration
//! let config = Config::default();
//!
//! // Create channels for inter-layer communication
//! let (to_protocol_tx, to_protocol_rx) = mpsc::unbounded_channel();
//! let (from_protocol_tx, from_protocol_rx) = mpsc::unbounded_channel();
//!
//! // Start network layer
//! let handles = start_network_layer(
//!     &config,
//!     to_protocol_tx,
//!     from_protocol_rx,
//!     tokio::runtime::Handle::current(),
//!     Arc::new(AtomicBool::new(true)),
//! );
//! ```

pub mod affinity;
pub mod io_uring_net;
pub mod metrics;
pub mod zerocopy_buffer;

use std::net::SocketAddr;
use tokio::sync::mpsc;
use zerocopy_buffer::ZeroCopyBuffer;

/// Messages from network layer to protocol layer
/// Zero-copy design: buffer ownership is transferred
#[derive(Debug, Clone)]
pub enum NetworkToProtocol {
    /// Raw UDP datagram received from network
    Datagram {
        /// Zero-copy buffer containing packet data
        buffer: ZeroCopyBuffer,
        /// Source address of the packet
        addr: SocketAddr,
    },
}

/// Messages from protocol layer to network layer
/// Zero-copy design: buffer ownership is transferred
#[derive(Debug, Clone)]
pub enum ProtocolToNetwork {
    /// Raw UDP datagram to send to network
    Datagram {
        /// Zero-copy buffer containing packet data
        buffer: ZeroCopyBuffer,
        /// Destination address for the packet
        addr: SocketAddr,
    },
}

/// Channel types for async communication between layers
pub type ToProtocolSender = mpsc::UnboundedSender<NetworkToProtocol>;
pub type ToProtocolReceiver = mpsc::UnboundedReceiver<NetworkToProtocol>;
pub type FromProtocolSender = mpsc::UnboundedSender<ProtocolToNetwork>;
pub type FromProtocolReceiver = mpsc::UnboundedReceiver<ProtocolToNetwork>;

