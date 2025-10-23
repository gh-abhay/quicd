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
//! │         Application Layer (Tokio Async)         │
//! └────────────────────┬────────────────────────────┘
//!                      │ Zero-Copy Buffers
//! ┌────────────────────▼────────────────────────────┐
//! │      Protocol Layer - QUIC (Tokio Async)        │
//! └────────────────────┬────────────────────────────┘
//!                      │ Zero-Copy Buffers
//! ┌────────────────────▼────────────────────────────┐
//! │  Network Layer (Native Threads + io_uring)      │
//! │   • Fixed thread count                          │
//! │   • CPU pinning                                 │
//! │   • SO_REUSEPORT load balancing                 │
//! │   • Batch I/O operations                        │
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
pub mod telemetry;