/// Custom error types for SuperD
/// Provides specific error handling instead of generic anyhow
use std::fmt;
use std::io;
use std::net::AddrParseError;

/// Main error type for SuperD operations
#[derive(Debug)]
pub enum Error {
    /// Configuration errors
    Config(ConfigError),
    /// Network I/O errors
    Network(NetworkError),
    /// System resource errors
    System(SystemError),
    /// Telemetry errors
    Telemetry(TelemetryError),
    /// I/O errors
    Io(io::Error),
    /// TOML parsing errors
    Toml(toml::de::Error),
    /// Other errors
    Other(String),
}

#[derive(Debug)]
pub enum ConfigError {
    /// Invalid listen address
    InvalidListenAddress(String),
    /// Invalid thread count
    InvalidThreadCount(String),
    /// Configuration file not found
    FileNotFound(String),
    /// Configuration validation failed
    ValidationFailed(String),
}

#[derive(Debug)]
pub enum NetworkError {
    /// Socket creation failed
    SocketCreationFailed(String),
    /// Socket binding failed
    SocketBindFailed(String),
    /// I/O operation failed
    IoOperationFailed(String),
    /// Buffer pool not initialized
    BufferPoolNotInitialized,
    /// Thread spawn failed
    ThreadSpawnFailed(String),
    /// Invalid configuration
    InvalidConfiguration(String),
}

#[derive(Debug)]
pub enum SystemError {
    /// CPU detection failed
    CpuDetectionFailed,
    /// Memory detection failed
    MemoryDetectionFailed,
    /// CPU affinity not supported
    CpuAffinityNotSupported,
    /// Insufficient system resources
    InsufficientResources(String),
}

#[derive(Debug)]
pub enum TelemetryError {
    /// OpenTelemetry initialization failed
    OtelInitFailed(String),
    /// Metrics export failed
    MetricsExportFailed(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Config(e) => write!(f, "Configuration error: {}", e),
            Error::Network(e) => write!(f, "Network error: {}", e),
            Error::System(e) => write!(f, "System error: {}", e),
            Error::Telemetry(e) => write!(f, "Telemetry error: {}", e),
            Error::Io(e) => write!(f, "I/O error: {}", e),
            Error::Toml(e) => write!(f, "TOML parsing error: {}", e),
            Error::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::InvalidListenAddress(addr) => {
                write!(f, "Invalid listen address: {}", addr)
            }
            ConfigError::InvalidThreadCount(msg) => {
                write!(f, "Invalid thread count: {}", msg)
            }
            ConfigError::FileNotFound(path) => {
                write!(f, "Configuration file not found: {}", path)
            }
            ConfigError::ValidationFailed(msg) => {
                write!(f, "Configuration validation failed: {}", msg)
            }
        }
    }
}

impl fmt::Display for NetworkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkError::SocketCreationFailed(msg) => {
                write!(f, "Socket creation failed: {}", msg)
            }
            NetworkError::SocketBindFailed(msg) => {
                write!(f, "Socket bind failed: {}", msg)
            }
            NetworkError::IoOperationFailed(msg) => {
                write!(f, "I/O operation failed: {}", msg)
            }
            NetworkError::BufferPoolNotInitialized => {
                write!(f, "Buffer pool not initialized")
            }
            NetworkError::ThreadSpawnFailed(msg) => {
                write!(f, "Thread spawn failed: {}", msg)
            }
            NetworkError::InvalidConfiguration(msg) => {
                write!(f, "Invalid network configuration: {}", msg)
            }
        }
    }
}

impl fmt::Display for SystemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SystemError::CpuDetectionFailed => {
                write!(f, "CPU detection failed")
            }
            SystemError::MemoryDetectionFailed => {
                write!(f, "Memory detection failed")
            }
            SystemError::CpuAffinityNotSupported => {
                write!(f, "CPU affinity not supported on this system")
            }
            SystemError::InsufficientResources(msg) => {
                write!(f, "Insufficient system resources: {}", msg)
            }
        }
    }
}

impl fmt::Display for TelemetryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TelemetryError::OtelInitFailed(msg) => {
                write!(f, "OpenTelemetry initialization failed: {}", msg)
            }
            TelemetryError::MetricsExportFailed(msg) => {
                write!(f, "Metrics export failed: {}", msg)
            }
        }
    }
}

impl std::error::Error for Error {}
impl std::error::Error for ConfigError {}
impl std::error::Error for NetworkError {}
impl std::error::Error for SystemError {}
impl std::error::Error for TelemetryError {}

// Conversion implementations
impl From<ConfigError> for Error {
    fn from(err: ConfigError) -> Self {
        Error::Config(err)
    }
}

impl From<NetworkError> for Error {
    fn from(err: NetworkError) -> Self {
        Error::Network(err)
    }
}

impl From<SystemError> for Error {
    fn from(err: SystemError) -> Self {
        Error::System(err)
    }
}

impl From<TelemetryError> for Error {
    fn from(err: TelemetryError) -> Self {
        Error::Telemetry(err)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<toml::de::Error> for Error {
    fn from(err: toml::de::Error) -> Self {
        Error::Toml(err)
    }
}

impl From<AddrParseError> for Error {
    fn from(err: AddrParseError) -> Self {
        Error::Config(ConfigError::InvalidListenAddress(err.to_string()))
    }
}

impl From<quiche::Error> for Error {
    fn from(err: quiche::Error) -> Self {
        Error::Network(NetworkError::IoOperationFailed(format!(
            "QUIC error: {}",
            err
        )))
    }
}

impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Self {
        Error::Other(err.to_string())
    }
}
