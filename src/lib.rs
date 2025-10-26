//! # SuperD - High-Performance UDP Socket Service
//!
//! A modern, high-throughput UDP server built with Rust, featuring:
//! - **io_uring**: Linux's cutting-edge async I/O for maximum performance
//! - **Zero-Copy Architecture**: Buffers flow through the stack without copying
//! - **Event-Driven I/O**: Inspired by NGINX and ejabberd patterns
//! - **Sans-IO Design**: Clean separation of network, protocol, and application layers
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │   Application Layer (Dynamic Per-Stream Tasks)  │
//! │   • Spawned on-demand per QUIC stream          │
//! │   • ALPN-based routing (HTTP/3, WebSocket, etc) │
//! │   • Ephemeral: lifecycle tied to stream        │
//! └────────────────────┬────────────────────────────┘
//!                      │ Stream Data
//! ┌────────────────────▼────────────────────────────┐
//! │      Protocol Layer - QUIC (Async Tasks)        │
//! │   • CPU-bound: TLS 1.3 crypto operations       │
//! │   • Connection state & congestion control       │
//! │   • 2-4x network tasks (crypto scaling)         │
//! └────────────────────┬────────────────────────────┘
//!                      │ Encrypted Packets
//! ┌────────────────────▼────────────────────────────┐
//! │  Network Layer (Async io_uring Tasks)           │
//! │   • I/O-bound: raw socket operations           │
//! │   • 1 task per physical core                   │
//! │   • SO_REUSEPORT load balancing                 │
//! │   • Fan-out to protocol tasks                   │
//! └─────────────────────────────────────────────────┘
//! ```
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use superd::config::Config;
//!
//! // Load default configuration
//! let config = Config::default();
//!
//! // Validate configuration
//! config.validate().expect("Invalid configuration");
//!
//! // Print configuration summary
//! config.print_summary();
//!
//! // Start the server (see main.rs for full example)
//! ```
//!
//! ## Performance
//!
//! - **Throughput**: 9.5+ Gbps per node
//! - **Latency**: Sub-millisecond
//! - **Connections**: Millions per node
//! - **Memory**: ~28-50KB per connection

pub mod config;
pub mod error;
pub mod network;
pub mod protocol;
pub mod telemetry;
pub mod application;

/// Inter-layer communication messages
pub mod messages {
    use std::net::SocketAddr;
    use crate::network::zerocopy_buffer::ZeroCopyBuffer;

    /// Messages from Network Layer to Protocol Layer
    #[derive(Debug)]
    pub enum NetworkToProtocol {
        Datagram {
            buffer: ZeroCopyBuffer,
            addr: SocketAddr,
        },
    }

    /// Messages from Protocol Layer to Network Layer
    #[derive(Debug)]
    pub enum ProtocolToNetwork {
        Datagram {
            buffer: ZeroCopyBuffer,
            addr: SocketAddr,
        },
    }

    /// Messages from Protocol Layer to Application Layer
    #[derive(Debug)]
    pub enum ProtocolToApplication {
        /// New connection established with negotiated ALPN
        NewConnection {
            conn_id: u64,
            peer_addr: SocketAddr,
            alpn: String,
        },
        /// New stream opened on existing connection
        NewStream {
            conn_id: u64,
            stream_id: u64,
            peer_addr: SocketAddr,
            alpn: String,
        },
        /// Stream data received
        StreamData {
            conn_id: u64,
            stream_id: u64,
            data: ZeroCopyBuffer,
            fin: bool,
        },
        /// Connection closed
        ConnectionClosed {
            conn_id: u64,
        },
    }

    /// Messages from Application Layer to Protocol Layer
    #[derive(Debug)]
    pub enum ApplicationToProtocol {
        /// Send data on a stream
        SendData {
            conn_id: u64,
            stream_id: u64,
            data: ZeroCopyBuffer,
            fin: bool,
        },
        /// Close a stream
        CloseStream {
            conn_id: u64,
            stream_id: u64,
        },
        /// Close a connection
        CloseConnection {
            conn_id: u64,
        },
    }
}
