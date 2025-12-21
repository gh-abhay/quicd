//! QUIC Error Types
//!
//! RFC 9000 Section 20 defines two error domains:
//! - **Transport Errors**: Protocol violations at the QUIC layer
//! - **Application Errors**: Application-specific errors carried over QUIC

#![forbid(unsafe_code)]

use core::fmt;

/// Transport Error Codes as defined in RFC 9000 Section 20.1
///
/// These errors trigger immediate connection closure and are sent in
/// CONNECTION_CLOSE frames of type 0x1c.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum TransportError {
    /// No error (0x00) - Used for graceful shutdown
    NoError = 0x00,
    
    /// Internal Error (0x01) - Implementation error
    InternalError = 0x01,
    
    /// Connection Refused (0x02) - Server refuses connection
    ConnectionRefused = 0x02,
    
    /// Flow Control Error (0x03) - Peer exceeded flow control limits
    FlowControlError = 0x03,
    
    /// Stream Limit Error (0x04) - Stream limit exceeded
    StreamLimitError = 0x04,
    
    /// Stream State Error (0x05) - Frame received in invalid stream state
    StreamStateError = 0x05,
    
    /// Final Size Error (0x06) - Final size violation
    FinalSizeError = 0x06,
    
    /// Frame Encoding Error (0x07) - Frame encoding error
    FrameEncodingError = 0x07,
    
    /// Transport Parameter Error (0x08) - Invalid transport parameters
    TransportParameterError = 0x08,
    
    /// Connection ID Limit Error (0x09) - Connection ID limit exceeded
    ConnectionIdLimitError = 0x09,
    
    /// Protocol Violation (0x0a) - Generic protocol violation
    ProtocolViolation = 0x0a,
    
    /// Invalid Token (0x0b) - Invalid stateless reset token
    InvalidToken = 0x0b,
    
    /// Application Error (0x0c) - Application closed connection
    ApplicationError = 0x0c,
    
    /// Crypto Buffer Exceeded (0x0d) - CRYPTO data buffer overflowed
    CryptoBufferExceeded = 0x0d,
    
    /// Key Update Error (0x0e) - Key update error
    KeyUpdateError = 0x0e,
    
    /// AEAD Limit Reached (0x0f) - AEAD usage limit reached
    AeadLimitReached = 0x0f,
    
    /// No Viable Path (0x10) - No viable network path
    NoViablePath = 0x10,
}

/// Application Protocol Error Code (RFC 9000 Section 20.2)
///
/// Application-defined error codes carried in CONNECTION_CLOSE frames
/// of type 0x1d. The semantics are defined by the application protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplicationError(pub u64);

/// Crypto Error Codes (RFC 9001 Section 4.8)
///
/// TLS alert codes are transformed into QUIC CRYPTO_ERROR codes
/// by adding 0x0100 to the TLS alert value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoError {
    /// TLS alert code + 0x0100
    pub code: u64,
}

/// Generic Result Type for QUIC Operations
pub type Result<T> = core::result::Result<T, Error>;

/// Unified Error Type for QUIC State Machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Transport-level protocol error
    Transport(TransportError),
    
    /// Application-level error
    Application(ApplicationError),
    
    /// Cryptographic error (TLS alert)
    Crypto(CryptoError),
    
    /// Buffer too small for operation
    BufferTooSmall,
    
    /// Invalid input data
    InvalidInput,
    
    /// Operation would block (needs more data)
    WouldBlock,
    
    /// Connection is closed
    ConnectionClosed,
    
    /// Stream does not exist
    StreamNotFound,
    
    /// Malformed packet
    MalformedPacket,
    
    /// Unsupported QUIC version
    UnsupportedVersion,
    
    /// Invalid packet (RFC 8999 invariants violated)
    InvalidPacket,
    
    /// Invalid transport parameter
    InvalidTransportParameter,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Transport(e) => write!(f, "Transport error: {:?}", e),
            Error::Application(e) => write!(f, "Application error: {}", e.0),
            Error::Crypto(e) => write!(f, "Crypto error: 0x{:x}", e.code),
            Error::BufferTooSmall => write!(f, "Buffer too small"),
            Error::InvalidInput => write!(f, "Invalid input"),
            Error::WouldBlock => write!(f, "Would block"),
            Error::ConnectionClosed => write!(f, "Connection closed"),
            Error::StreamNotFound => write!(f, "Stream not found"),
            Error::MalformedPacket => write!(f, "Malformed packet"),
            Error::UnsupportedVersion => write!(f, "Unsupported version"),
            Error::InvalidPacket => write!(f, "Invalid packet"),
            Error::InvalidTransportParameter => write!(f, "Invalid transport parameter"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl From<TransportError> for Error {
    fn from(e: TransportError) -> Self {
        Error::Transport(e)
    }
}

impl From<ApplicationError> for Error {
    fn from(e: ApplicationError) -> Self {
        Error::Application(e)
    }
}

impl From<CryptoError> for Error {
    fn from(e: CryptoError) -> Self {
        Error::Crypto(e)
    }
}
