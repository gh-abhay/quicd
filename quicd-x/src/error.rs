use thiserror::Error;

/// Errors surfaced to applications and worker integrations for a connection lifecycle.
#[derive(Debug, Error)]
pub enum ConnectionError {
    /// Connection has been closed; reason is provided when available.
    #[error("connection closed: {0}")]
    Closed(String),
    /// Application-specific failure propagated through the interface.
    #[error("application error: {0}")]
    App(String),
    /// I/O level failure, typically related to network operations.
    #[error("i/o error: {0}")]
    Io(String),
    /// Stream level failure.
    #[error("stream error: {0}")]
    Stream(String),
    /// QUIC transport level failure.
    #[error("transport error: {0}")]
    Transport(String),
}
