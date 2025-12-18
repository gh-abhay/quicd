//! HTTP/3 error types and error code mappings per RFC 9114 Section 8.
//!
//! This module defines all error types used throughout the HTTP/3 implementation
//! and maps them to the standardized HTTP/3 error codes defined in RFC 9114 Section 8.1.

use std::fmt;
use thiserror::Error;

/// HTTP/3 error codes as defined in RFC 9114 Section 8.1.
///
/// These error codes are used for both connection-level and stream-level errors.
/// Connection errors cause the entire connection to be closed.
/// Stream errors cause only the affected stream to be reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum ErrorCode {
    /// H3_NO_ERROR (0x0100): No error. This is used when the connection or stream
    /// needs to be closed, but there is no error to signal.
    NoError = 0x0100,

    /// H3_GENERAL_PROTOCOL_ERROR (0x0101): Peer violated protocol requirements in
    /// a way that does not match a more specific error code, or endpoint declines
    /// to use the more specific error code.
    GeneralProtocolError = 0x0101,

    /// H3_INTERNAL_ERROR (0x0102): An internal error has occurred in the HTTP stack.
    InternalError = 0x0102,

    /// H3_STREAM_CREATION_ERROR (0x0103): The endpoint detected that its peer
    /// created a stream that it will not accept.
    StreamCreationError = 0x0103,

    /// H3_CLOSED_CRITICAL_STREAM (0x0104): A stream required by the HTTP/3
    /// connection was closed or reset.
    ClosedCriticalStream = 0x0104,

    /// H3_FRAME_UNEXPECTED (0x0105): A frame was received that was not permitted
    /// in the current state or on the current stream.
    FrameUnexpected = 0x0105,

    /// H3_FRAME_ERROR (0x0106): A frame that fails to satisfy layout requirements
    /// or with an invalid size was received.
    FrameError = 0x0106,

    /// H3_EXCESSIVE_LOAD (0x0107): The endpoint detected that its peer is
    /// exhibiting a behavior that might be generating excessive load.
    ExcessiveLoad = 0x0107,

    /// H3_ID_ERROR (0x0108): A Stream ID or Push ID was used incorrectly,
    /// such as exceeding a limit, reducing a limit, or being reused.
    IdError = 0x0108,

    /// H3_SETTINGS_ERROR (0x0109): An endpoint detected an error in the payload
    /// of a SETTINGS frame.
    SettingsError = 0x0109,

    /// H3_MISSING_SETTINGS (0x010a): No SETTINGS frame was received at the
    /// beginning of the control stream.
    MissingSettings = 0x010a,

    /// H3_REQUEST_REJECTED (0x010b): A server rejected a request without
    /// performing any application processing.
    RequestRejected = 0x010b,

    /// H3_REQUEST_CANCELLED (0x010c): The request or its response (including
    /// pushed response) is cancelled.
    RequestCancelled = 0x010c,

    /// H3_REQUEST_INCOMPLETE (0x010d): The client's stream terminated without
    /// containing a fully formed request.
    RequestIncomplete = 0x010d,

    /// H3_MESSAGE_ERROR (0x010e): An HTTP message was malformed and cannot be processed.
    MessageError = 0x010e,

    /// H3_CONNECT_ERROR (0x010f): The TCP connection established in response to
    /// a CONNECT request was reset or abnormally closed.
    ConnectError = 0x010f,

    /// H3_VERSION_FALLBACK (0x0110): The requested operation cannot be served
    /// over HTTP/3. The peer should retry over HTTP/1.1.
    VersionFallback = 0x0110,

    /// H3_QPACK_DECOMPRESSION_FAILED (0x0200): The decoder failed to interpret
    /// an encoded field section and is not able to continue decoding that field section.
    QpackDecompressionFailed = 0x0200,

    /// H3_QPACK_ENCODER_STREAM_ERROR (0x0201): The decoder failed to interpret
    /// an encoder instruction received on the encoder stream.
    QpackEncoderStreamError = 0x0201,

    /// H3_QPACK_DECODER_STREAM_ERROR (0x0202): The encoder failed to interpret
    /// a decoder instruction received on the decoder stream.
    QpackDecoderStreamError = 0x0202,
}

impl ErrorCode {
    /// Convert error code to u64 for use in QUIC error codes.
    pub fn to_code(self) -> u64 {
        self as u64
    }

    /// Convert from u64 error code.
    pub fn from_code(code: u64) -> Option<Self> {
        match code {
            0x0100 => Some(Self::NoError),
            0x0101 => Some(Self::GeneralProtocolError),
            0x0102 => Some(Self::InternalError),
            0x0103 => Some(Self::StreamCreationError),
            0x0104 => Some(Self::ClosedCriticalStream),
            0x0105 => Some(Self::FrameUnexpected),
            0x0106 => Some(Self::FrameError),
            0x0107 => Some(Self::ExcessiveLoad),
            0x0108 => Some(Self::IdError),
            0x0109 => Some(Self::SettingsError),
            0x010a => Some(Self::MissingSettings),
            0x010b => Some(Self::RequestRejected),
            0x010c => Some(Self::RequestCancelled),
            0x010d => Some(Self::RequestIncomplete),
            0x010e => Some(Self::MessageError),
            0x010f => Some(Self::ConnectError),
            0x0110 => Some(Self::VersionFallback),
            0x0200 => Some(Self::QpackDecompressionFailed),
            0x0201 => Some(Self::QpackEncoderStreamError),
            0x0202 => Some(Self::QpackDecoderStreamError),
            _ => None,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoError => write!(f, "H3_NO_ERROR"),
            Self::GeneralProtocolError => write!(f, "H3_GENERAL_PROTOCOL_ERROR"),
            Self::InternalError => write!(f, "H3_INTERNAL_ERROR"),
            Self::StreamCreationError => write!(f, "H3_STREAM_CREATION_ERROR"),
            Self::ClosedCriticalStream => write!(f, "H3_CLOSED_CRITICAL_STREAM"),
            Self::FrameUnexpected => write!(f, "H3_FRAME_UNEXPECTED"),
            Self::FrameError => write!(f, "H3_FRAME_ERROR"),
            Self::ExcessiveLoad => write!(f, "H3_EXCESSIVE_LOAD"),
            Self::IdError => write!(f, "H3_ID_ERROR"),
            Self::SettingsError => write!(f, "H3_SETTINGS_ERROR"),
            Self::MissingSettings => write!(f, "H3_MISSING_SETTINGS"),
            Self::RequestRejected => write!(f, "H3_REQUEST_REJECTED"),
            Self::RequestCancelled => write!(f, "H3_REQUEST_CANCELLED"),
            Self::RequestIncomplete => write!(f, "H3_REQUEST_INCOMPLETE"),
            Self::MessageError => write!(f, "H3_MESSAGE_ERROR"),
            Self::ConnectError => write!(f, "H3_CONNECT_ERROR"),
            Self::VersionFallback => write!(f, "H3_VERSION_FALLBACK"),
            Self::QpackDecompressionFailed => write!(f, "H3_QPACK_DECOMPRESSION_FAILED"),
            Self::QpackEncoderStreamError => write!(f, "H3_QPACK_ENCODER_STREAM_ERROR"),
            Self::QpackDecoderStreamError => write!(f, "H3_QPACK_DECODER_STREAM_ERROR"),
        }
    }
}

/// Result type for HTTP/3 operations.
pub type Result<T> = std::result::Result<T, Error>;

/// HTTP/3 error type encompassing all failure modes.
#[derive(Debug, Error)]
pub enum Error {
    /// I/O error from underlying QUIC stream operations.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Protocol violation error with specific HTTP/3 error code.
    #[error("Protocol error ({code}): {message}")]
    Protocol {
        code: ErrorCode,
        message: String,
    },

    /// QPACK compression/decompression error.
    #[error("QPACK error: {0}")]
    Qpack(#[from] quicd_qpack::Error),

    /// Frame parsing error.
    #[error("Frame parsing error: {0}")]
    FrameParsing(String),

    /// Invalid HTTP message format.
    #[error("Invalid HTTP message: {0}")]
    InvalidMessage(String),

    /// Connection is closed.
    #[error("Connection closed")]
    ConnectionClosed,

    /// Stream is closed or reset.
    #[error("Stream closed: {0}")]
    StreamClosed(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Internal error (should not occur in production).
    #[error("Internal error: {0}")]
    Internal(String),
}

impl Error {
    /// Create a protocol error with specific error code.
    pub fn protocol(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::Protocol {
            code,
            message: message.into(),
        }
    }

    /// Map error to HTTP/3 error code for connection/stream abort.
    ///
    /// This determines which error code to send when closing a connection
    /// or resetting a stream due to this error.
    pub fn to_error_code(&self) -> ErrorCode {
        match self {
            Self::Protocol { code, .. } => *code,
            Self::Qpack(qpack_err) => {
                // Map QPACK errors to appropriate H3 error codes
                match qpack_err {
                    quicd_qpack::Error::DecoderStreamError(_) => {
                        ErrorCode::QpackDecoderStreamError
                    }
                    quicd_qpack::Error::EncoderStreamError(_) => {
                        ErrorCode::QpackEncoderStreamError
                    }
                    _ => ErrorCode::QpackDecompressionFailed,
                }
            }
            Self::FrameParsing(_) => ErrorCode::FrameError,
            Self::InvalidMessage(_) => ErrorCode::MessageError,
            Self::ConnectionClosed | Self::StreamClosed(_) => ErrorCode::NoError,
            Self::Config(_) => ErrorCode::InternalError,
            Self::Internal(_) => ErrorCode::InternalError,
            Self::Io(_) => ErrorCode::InternalError,
        }
    }

    /// Check if this error is a connection error (closes entire connection).
    ///
    /// Returns true if the error requires connection-level abort.
    /// Returns false if it's a stream-level error only.
    pub fn is_connection_error(&self) -> bool {
        match self {
            Self::Protocol { code, .. } => matches!(
                code,
                ErrorCode::GeneralProtocolError
                    | ErrorCode::InternalError
                    | ErrorCode::StreamCreationError
                    | ErrorCode::ClosedCriticalStream
                    | ErrorCode::FrameUnexpected
                    | ErrorCode::ExcessiveLoad
                    | ErrorCode::IdError
                    | ErrorCode::SettingsError
                    | ErrorCode::MissingSettings
                    | ErrorCode::QpackDecompressionFailed
                    | ErrorCode::QpackEncoderStreamError
                    | ErrorCode::QpackDecoderStreamError
            ),
            Self::Qpack(_) => true, // QPACK errors are connection errors
            Self::FrameParsing(_) => true, // Frame errors on control stream are connection errors
            Self::Config(_) => true,
            Self::Internal(_) => true,
            // Stream-level errors
            Self::InvalidMessage(_) | Self::StreamClosed(_) => false,
            // I/O and connection closed depend on context
            Self::Io(_) | Self::ConnectionClosed => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_round_trip() {
        let codes = vec![
            ErrorCode::NoError,
            ErrorCode::GeneralProtocolError,
            ErrorCode::InternalError,
            ErrorCode::QpackDecompressionFailed,
        ];

        for code in codes {
            let num = code.to_code();
            let parsed = ErrorCode::from_code(num).unwrap();
            assert_eq!(code, parsed);
        }
    }

    #[test]
    fn test_error_code_display() {
        assert_eq!(ErrorCode::NoError.to_string(), "H3_NO_ERROR");
        assert_eq!(
            ErrorCode::GeneralProtocolError.to_string(),
            "H3_GENERAL_PROTOCOL_ERROR"
        );
        assert_eq!(
            ErrorCode::QpackDecompressionFailed.to_string(),
            "H3_QPACK_DECOMPRESSION_FAILED"
        );
    }

    #[test]
    fn test_error_mapping() {
        let err = Error::protocol(ErrorCode::SettingsError, "invalid settings");
        assert_eq!(err.to_error_code(), ErrorCode::SettingsError);
        assert!(err.is_connection_error());

        let err = Error::InvalidMessage("missing :method".to_string());
        assert_eq!(err.to_error_code(), ErrorCode::MessageError);
        assert!(!err.is_connection_error());
    }
}
