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