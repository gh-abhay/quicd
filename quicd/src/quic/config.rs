//! QUIC protocol configuration.
//!
//! Configuration for the QUIC layer including:
//! - Transport parameters
//! - Congestion control algorithm
//! - Connection limits and timeouts
//! - TLS/crypto settings

// Re-export from quicd-x for backward compatibility
pub use quicd_x::QuicTransportConfig as QuicConfig;
