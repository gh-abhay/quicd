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

    /// QUIC protocol error with RFC-compliant error code.
    ///
    /// This variant includes the QUIC error code as defined in RFC 9000.
    /// Common error codes:
    /// - 0x00: NO_ERROR
    /// - 0x01: INTERNAL_ERROR
    /// - 0x02: CONNECTION_REFUSED
    /// - 0x03: FLOW_CONTROL_ERROR
    /// - 0x04: STREAM_LIMIT_ERROR
    /// - 0x05: STREAM_STATE_ERROR
    /// - 0x0A: PROTOCOL_VIOLATION
    /// - 0x0D: INVALID_TOKEN
    ///
    /// Applications can use this for RFC-compliant error reporting.
    #[error("quic error (code=0x{code:x}): {message}")]
    QuicError {
        /// QUIC error code from RFC 9000
        code: u64,
        /// Human-readable error description
        message: String,
    },

    /// TLS handshake failure during connection establishment.
    ///
    /// This indicates a failure in the TLS 1.3 handshake that is required
    /// for all QUIC connections. Common causes:
    /// - Certificate validation failure
    /// - Cipher suite mismatch
    /// - ALPN negotiation failure
    /// - Invalid TLS configuration
    #[error("tls handshake failed: {0}")]
    TlsFail(String),

    /// Operation would block due to flow control or stream limits.
    ///
    /// The application should wait for an unblocked event before retrying.
    /// This is not a fatal error; the connection remains valid.
    #[error("operation blocked: {0}")]
    Blocked(String),

    /// Non-blocking operation would block (no data available or buffer full).
    ///
    /// Returned by try_read() when no data is available, or try_write() when
    /// the send buffer is full. This is not an error condition - the application
    /// should wait for a readable/writable event and retry.
    ///
    /// This error indicates the operation cannot complete immediately without
    /// blocking, which is expected in non-blocking I/O patterns.
    #[error("would block")]
    WouldBlock,

    /// Stream is in an invalid state for the requested operation.
    ///
    /// Examples:
    /// - Trying to write to a receive-only stream
    /// - Trying to read from a send-only stream
    /// - Operating on a closed stream
    #[error("stream state error: {0}")]
    StreamState(String),
}

/// RFC 9000 compliant QUIC transport error codes.
///
/// These error codes are defined in RFC 9000 Section 20.
/// Applications should use these when closing connections or resetting streams
/// to ensure interoperability with other QUIC implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum QuicErrorCode {
    /// No error (graceful close).
    NoError = 0x00,

    /// Internal implementation error.
    InternalError = 0x01,

    /// Connection refused or not accepted by server.
    ConnectionRefused = 0x02,

    /// Flow control error (data exceeded limits).
    FlowControlError = 0x03,

    /// Stream limit error (too many streams).
    StreamLimitError = 0x04,

    /// Stream state error (invalid operation for current state).
    StreamStateError = 0x05,

    /// Final size error (stream size changed).
    FinalSizeError = 0x06,

    /// Frame encoding error.
    FrameEncodingError = 0x07,

    /// Transport parameter error.
    TransportParameterError = 0x08,

    /// Connection ID limit error.
    ConnectionIdLimitError = 0x09,

    /// Protocol violation detected.
    ProtocolViolation = 0x0A,

    /// Invalid token received.
    InvalidToken = 0x0B,

    /// Application error (application-specific closure).
    ApplicationError = 0x0C,

    /// Crypto buffer limit exceeded.
    CryptoBufferExceeded = 0x0D,

    /// Key update error.
    KeyUpdateError = 0x0E,

    /// AEAD limit reached.
    AeadLimitReached = 0x0F,

    /// No available path after migration.
    NoAvailablePath = 0x10,
}

impl QuicErrorCode {
    /// Convert to u64 for use in QUIC frames.
    pub fn as_u64(self) -> u64 {
        self as u64
    }

    /// Create from u64, returning None for unknown codes.
    pub fn from_u64(code: u64) -> Option<Self> {
        match code {
            0x00 => Some(Self::NoError),
            0x01 => Some(Self::InternalError),
            0x02 => Some(Self::ConnectionRefused),
            0x03 => Some(Self::FlowControlError),
            0x04 => Some(Self::StreamLimitError),
            0x05 => Some(Self::StreamStateError),
            0x06 => Some(Self::FinalSizeError),
            0x07 => Some(Self::FrameEncodingError),
            0x08 => Some(Self::TransportParameterError),
            0x09 => Some(Self::ConnectionIdLimitError),
            0x0A => Some(Self::ProtocolViolation),
            0x0B => Some(Self::InvalidToken),
            0x0C => Some(Self::ApplicationError),
            0x0D => Some(Self::CryptoBufferExceeded),
            0x0E => Some(Self::KeyUpdateError),
            0x0F => Some(Self::AeadLimitReached),
            0x10 => Some(Self::NoAvailablePath),
            _ => None,
        }
    }

    /// Get human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::NoError => "no error",
            Self::InternalError => "internal error",
            Self::ConnectionRefused => "connection refused",
            Self::FlowControlError => "flow control error",
            Self::StreamLimitError => "stream limit error",
            Self::StreamStateError => "stream state error",
            Self::FinalSizeError => "final size error",
            Self::FrameEncodingError => "frame encoding error",
            Self::TransportParameterError => "transport parameter error",
            Self::ConnectionIdLimitError => "connection ID limit error",
            Self::ProtocolViolation => "protocol violation",
            Self::InvalidToken => "invalid token",
            Self::ApplicationError => "application error",
            Self::CryptoBufferExceeded => "crypto buffer exceeded",
            Self::KeyUpdateError => "key update error",
            Self::AeadLimitReached => "AEAD limit reached",
            Self::NoAvailablePath => "no available path",
        }
    }
}
