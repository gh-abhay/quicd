//! Error types for QUIC protocol operations.

use thiserror::Error;

/// QUIC protocol errors per RFC 9000 Section 20.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// No error (0x00).
    #[error("no error")]
    NoError,
    
    /// Internal error (0x01).
    #[error("internal error")]
    InternalError,
    
    /// Connection refused (0x02).
    #[error("connection refused")]
    ConnectionRefused,
    
    /// Flow control error (0x03).
    #[error("flow control error")]
    FlowControlError,
    
    /// Stream limit error (0x04).
    #[error("stream limit error")]
    StreamLimitError,
    
    /// Stream state error (0x05).
    #[error("stream state error")]
    StreamStateError,
    
    /// Final size error (0x06).
    #[error("final size error")]
    FinalSizeError,
    
    /// Frame encoding error (0x07).
    #[error("frame encoding error")]
    FrameEncodingError,
    
    /// Transport parameter error (0x08).
    #[error("transport parameter error")]
    TransportParameterError,
    
    /// Connection ID limit error (0x09).
    #[error("connection ID limit error")]
    ConnectionIdLimitError,
    
    /// Protocol violation (0x0A).
    #[error("protocol violation")]
    ProtocolViolation,
    
    /// Invalid token (0x0B).
    #[error("invalid token")]
    InvalidToken,
    
    /// Application error (0x0C).
    #[error("application error")]
    ApplicationError,
    
    /// Crypto buffer exceeded (0x0D).
    #[error("crypto buffer exceeded")]
    CryptoBufferExceeded,
    
    /// Key update error (0x0E).
    #[error("key update error")]
    KeyUpdateError,
    
    /// AEAD limit reached (0x0F).
    #[error("AEAD limit reached")]
    AeadLimitReached,
    
    /// No viable path (0x10).
    #[error("no viable path")]
    NoViablePath,
    
    /// Crypto error (0x0100-0x01FF).
    #[error("crypto error: {0:#x}")]
    Crypto(u16),
}

impl Error {
    /// Convert error to wire format error code.
    pub fn to_wire(&self) -> u64 {
        match self {
            Error::NoError => 0x00,
            Error::InternalError => 0x01,
            Error::ConnectionRefused => 0x02,
            Error::FlowControlError => 0x03,
            Error::StreamLimitError => 0x04,
            Error::StreamStateError => 0x05,
            Error::FinalSizeError => 0x06,
            Error::FrameEncodingError => 0x07,
            Error::TransportParameterError => 0x08,
            Error::ConnectionIdLimitError => 0x09,
            Error::ProtocolViolation => 0x0A,
            Error::InvalidToken => 0x0B,
            Error::ApplicationError => 0x0C,
            Error::CryptoBufferExceeded => 0x0D,
            Error::KeyUpdateError => 0x0E,
            Error::AeadLimitReached => 0x0F,
            Error::NoViablePath => 0x10,
            Error::Crypto(code) => 0x0100 + (*code as u64),
        }
    }
    
    /// Convert wire format error code to error.
    pub fn from_wire(code: u64) -> Self {
        match code {
            0x00 => Error::NoError,
            0x01 => Error::InternalError,
            0x02 => Error::ConnectionRefused,
            0x03 => Error::FlowControlError,
            0x04 => Error::StreamLimitError,
            0x05 => Error::StreamStateError,
            0x06 => Error::FinalSizeError,
            0x07 => Error::FrameEncodingError,
            0x08 => Error::TransportParameterError,
            0x09 => Error::ConnectionIdLimitError,
            0x0A => Error::ProtocolViolation,
            0x0B => Error::InvalidToken,
            0x0C => Error::ApplicationError,
            0x0D => Error::CryptoBufferExceeded,
            0x0E => Error::KeyUpdateError,
            0x0F => Error::AeadLimitReached,
            0x10 => Error::NoViablePath,
            0x0100..=0x01FF => Error::Crypto(((code - 0x0100) & 0xFF) as u16),
            _ => Error::InternalError,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_error_wire_format() {
        assert_eq!(Error::NoError.to_wire(), 0x00);
        assert_eq!(Error::InternalError.to_wire(), 0x01);
        assert_eq!(Error::ProtocolViolation.to_wire(), 0x0A);
        
        let crypto_err = Error::Crypto(42);
        assert_eq!(crypto_err.to_wire(), 0x0100 + 42);
        
        assert_eq!(Error::from_wire(0x00), Error::NoError);
        assert_eq!(Error::from_wire(0x0A), Error::ProtocolViolation);
        assert_eq!(Error::from_wire(0x0142), Error::Crypto(0x42));
    }
}
