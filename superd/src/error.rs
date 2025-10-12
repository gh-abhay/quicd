//! Error types and handling for superd
//!
//! This module provides comprehensive error types with proper context
//! for production debugging and monitoring.

use thiserror::Error;

/// Main error type for superd operations
///
/// Provides detailed context for debugging in production environments.
/// Each variant includes the specific subsystem that failed.
#[derive(Error, Debug)]
pub enum SuperdError {
    /// QUIC protocol error
    #[error("QUIC protocol error: {context}: {source}")]
    Quic {
        context: String,
        #[source]
        source: quic::QuicError,
    },
    
    /// I/O error from network operations
    #[error("Network I/O error: {context}: {source}")]
    Io {
        context: String,
        #[source]
        source: io::IoError,
    },
    
    /// Service error from application logic
    #[error("Service error: {context}: {source}")]
    Service {
        context: String,
        #[source]
        source: services::ServiceError,
    },
    
    /// Standard I/O error
    #[error("System I/O error: {context}: {source}")]
    StdIo {
        context: String,
        #[source]
        source: std::io::Error,
    },
    
    /// Channel communication error
    #[error("Channel communication error: {0}")]
    Channel(String),
    
    /// Task join error
    #[error("Task failed: {context}: {source}")]
    TaskJoin {
        context: String,
        #[source]
        source: tokio::task::JoinError,
    },
    
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),
    
    /// Resource limit exceeded
    #[error("Resource limit exceeded: {0}")]
    ResourceLimit(String),
    
    /// Connection limit reached
    #[error("Maximum connections ({0}) reached")]
    ConnectionLimit(usize),
    
    /// Shutdown requested
    #[error("Shutdown requested")]
    Shutdown,
}

/// Result type alias for superd operations
pub type Result<T> = std::result::Result<T, SuperdError>;

/// Extension trait for adding context to errors
pub trait ErrorContext<T> {
    /// Add context to an error
    fn context(self, context: impl Into<String>) -> Result<T>;
    
    /// Add context using a closure (lazy evaluation)
    fn with_context<F>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> String;
}

impl<T, E> ErrorContext<T> for std::result::Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn context(self, context: impl Into<String>) -> Result<T> {
        self.map_err(|_e| {
            let context = context.into();
            // For now, use generic channel error
            // In production, you might want more specific error type matching
            SuperdError::Channel(context)
        })
    }
    
    fn with_context<F>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> String,
    {
        self.map_err(|e| SuperdError::Channel(format!("{}: {}", f(), e)))
    }
}

// Allow conversion from specific error types
impl From<quic::QuicError> for SuperdError {
    fn from(err: quic::QuicError) -> Self {
        SuperdError::Quic {
            context: "QUIC operation failed".to_string(),
            source: err,
        }
    }
}

impl From<io::IoError> for SuperdError {
    fn from(err: io::IoError) -> Self {
        SuperdError::Io {
            context: "I/O operation failed".to_string(),
            source: err,
        }
    }
}

impl From<services::ServiceError> for SuperdError {
    fn from(err: services::ServiceError) -> Self {
        SuperdError::Service {
            context: "Service operation failed".to_string(),
            source: err,
        }
    }
}

impl From<std::io::Error> for SuperdError {
    fn from(err: std::io::Error) -> Self {
        SuperdError::StdIo {
            context: "System I/O failed".to_string(),
            source: err,
        }
    }
}

impl From<tokio::task::JoinError> for SuperdError {
    fn from(err: tokio::task::JoinError) -> Self {
        SuperdError::TaskJoin {
            context: "Task join failed".to_string(),
            source: err,
        }
    }
}
