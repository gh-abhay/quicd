//! # Application Layer - Protocol-Specific Handlers
//!
//! This module implements application protocol handlers for SuperD.
//! Supports HTTP/3 based content serving and WebTransport APIs.
//!
//! ## Architecture
//!
//! ```text
//! Protocol Layer (QUIC)
//!         ↓
//! Application Dispatcher (ALPN + Request Type Routing)
//!         ↓
//! Content Handler (HTTP/3) / WebTransport Handler (HTTP/3 + WT)
//! ```
//!
//! ## Design Principles
//!
//! - **Dynamic Task Spawning**: Tasks created per-stream, not pre-allocated
//! - **ALPN + Content-Based Routing**: Protocol + request characteristics determine handler
//! - **Zero-Copy Data Flow**: Buffers passed directly between layers
//! - **Ephemeral Tasks**: Tasks live only as long as their streams
//!
//! ## Supported Use Cases
//!
//! - **HTTP/3 Content Serving**: CDN-like content delivery with HTTP/3
//! - **WebTransport APIs**: Real-time bidirectional communication over HTTP/3
//!
//! ## Performance Characteristics
//!
//! - **Task Creation**: Lightweight, sub-millisecond spawn time
//! - **Memory**: Minimal per-task overhead (~8KB base)
//! - **Concurrency**: Thousands of concurrent application tasks
//! - **Scalability**: Automatic load distribution across cores

pub mod content;
pub mod dispatcher;
pub mod webtransport;

use std::net::SocketAddr;
use tokio::sync::mpsc;

use crate::network::zerocopy_buffer::ZeroCopyBuffer;

/// Application protocol types
#[derive(Debug, Clone, PartialEq)]
pub enum ApplicationProtocol {
    /// HTTP/3 Content Serving (CDN-like functionality)
    Http3Content,
    /// WebTransport APIs (real-time bidirectional communication)
    WebTransport,
}

impl ApplicationProtocol {
    /// Parse ALPN string to protocol type
    pub fn from_alpn(alpn: &str) -> Option<Self> {
        match alpn {
            "h3" => Some(Self::Http3Content), // Default to content serving for h3
            "h3-29" | "h3-30" | "h3-31" | "h3-32" => Some(Self::Http3Content), // Draft versions
            _ => None,                        // Unknown protocols not supported
        }
    }

    /// Convert to ALPN string
    pub fn to_alpn(&self) -> &'static str {
        match self {
            Self::Http3Content | Self::WebTransport => "h3", // Both use h3 ALPN
        }
    }
}

/// Application task context
#[derive(Debug)]
pub struct ApplicationContext {
    /// Unique connection identifier
    pub conn_id: u64,
    /// Stream identifier within the connection
    pub stream_id: u64,
    /// Peer address for logging/security
    pub peer_addr: SocketAddr,
    /// Negotiated application protocol
    pub protocol: ApplicationProtocol,
}

/// Application task result
pub type ApplicationResult<T> = Result<T, ApplicationError>;

/// Application layer errors
#[derive(Debug, thiserror::Error)]
pub enum ApplicationError {
    #[error("HTTP/3 error: {0}")]
    Http3(#[from] quiche::h3::Error),

    #[error("Stream error: {0}")]
    Stream(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Channel error: {0}")]
    ChannelError(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Channel types for application <-> protocol communication
pub type ToProtocolSender = mpsc::UnboundedSender<super::messages::ApplicationToProtocol>;
pub type ToProtocolReceiver = mpsc::UnboundedReceiver<super::messages::ApplicationToProtocol>;
pub type FromProtocolSender = mpsc::UnboundedSender<super::messages::ProtocolToApplication>;
pub type FromProtocolReceiver = mpsc::UnboundedReceiver<super::messages::ProtocolToApplication>;
