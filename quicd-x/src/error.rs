use thiserror::Error;

/// Errors surfaced to applications and worker integrations for a connection lifecycle.
///
/// This enum represents all possible error conditions that applications may encounter
/// when interacting with the quicd-x interface. Errors can originate from:
/// - QUIC transport layer failures
/// - Stream-level issues
/// - Application logic errors
/// - Worker thread unavailability
///
/// # Non-Blocking Design
///
/// All errors are returned immediately via channel replies or events.
/// No blocking or waiting occurs.
#[derive(Debug, Error)]
pub enum ConnectionError {
    /// Connection has been closed or worker is unavailable.
    ///
    /// This indicates either:
    /// - The connection was closed (gracefully or due to error)
    /// - The worker thread is no longer responsive
    /// - The worker is severely overloaded (channel dropped)
    ///
    /// This is a terminal error for the connection. Any subsequent operations
    /// on this connection will fail immediately. Applications should clean up
    /// resources and terminate the connection handler task.
    #[error("connection closed: {0}")]
    Closed(String),

    /// Application-specific failure propagated through the interface.
    ///
    /// This represents errors from application logic or misconfiguration.
    /// Examples:
    /// - Stream not found
    /// - Invalid parameters
    /// - Internal application error
    #[error("application error: {0}")]
    App(String),

    /// I/O level failure, typically related to network operations.
    ///
    /// This represents system-level I/O errors:
    /// - Socket errors
    /// - Buffer allocation failures
    /// - Network stack errors
    #[error("i/o error: {0}")]
    Io(String),

    /// Stream-level failure specific to a particular stream.
    ///
    /// This indicates an error affecting a specific stream but not necessarily
    /// the entire connection. Other streams on the connection may continue.
    /// Examples:
    /// - Stream send failure
    /// - Stream reset by peer
    /// - Stream data corruption
    #[error("stream error: {0}")]
    Stream(String),

    /// QUIC transport layer failure.
    ///
    /// This represents errors from the QUIC protocol itself:
    /// - Connection timeout
    /// - Handshake failure
    /// - Flow control violations
    /// - Protocol state violations
    #[error("transport error: {0}")]
    Transport(String),
}
