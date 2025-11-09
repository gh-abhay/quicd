use thiserror::Error;

/// Errors specific to HTTP/3 protocol handling.
#[derive(Debug, Error)]
pub enum H3Error {
    #[error("frame parsing error: {0}")]
    FrameParse(String),
    #[error("QPACK error: {0}")]
    Qpack(String),
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("stream error: {0}")]
    Stream(String),
    #[error("connection error: {0}")]
    Connection(String),
}

/// HTTP/3 error codes as defined in RFC 9114 Section 8.1.
/// These are in the range 0x100-0x110.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H3ErrorCode {
    // 0x100-0x103: General protocol errors
    NoError = 0x100,
    GeneralProtocolError = 0x101,
    InternalError = 0x102,
    StreamCreationError = 0x103,
    
    // 0x104-0x107: Frame parsing errors
    ClosedCriticalStream = 0x104,
    FrameUnexpected = 0x105,
    FrameError = 0x106,
    ExcessiveLoad = 0x107,
    
    // 0x108-0x10B: QPACK errors
    IdError = 0x108,
    SettingsError = 0x109,
    MissingSettings = 0x10A,
    RequestRejected = 0x10B,
    
    // 0x10C-0x10F: Request/response errors
    RequestIncomplete = 0x10C,
    MessageError = 0x10D,
    ConnectError = 0x10E,
    VersionFallback = 0x10F,
    
    // 0x110: Push-related error
    WrongStream = 0x110,
}

impl H3ErrorCode {
    /// Convert an error code value to the corresponding enum variant.
    pub fn from_u64(value: u64) -> Option<Self> {
        match value {
            0x100 => Some(H3ErrorCode::NoError),
            0x101 => Some(H3ErrorCode::GeneralProtocolError),
            0x102 => Some(H3ErrorCode::InternalError),
            0x103 => Some(H3ErrorCode::StreamCreationError),
            0x104 => Some(H3ErrorCode::ClosedCriticalStream),
            0x105 => Some(H3ErrorCode::FrameUnexpected),
            0x106 => Some(H3ErrorCode::FrameError),
            0x107 => Some(H3ErrorCode::ExcessiveLoad),
            0x108 => Some(H3ErrorCode::IdError),
            0x109 => Some(H3ErrorCode::SettingsError),
            0x10A => Some(H3ErrorCode::MissingSettings),
            0x10B => Some(H3ErrorCode::RequestRejected),
            0x10C => Some(H3ErrorCode::RequestIncomplete),
            0x10D => Some(H3ErrorCode::MessageError),
            0x10E => Some(H3ErrorCode::ConnectError),
            0x10F => Some(H3ErrorCode::VersionFallback),
            0x110 => Some(H3ErrorCode::WrongStream),
            _ => None,
        }
    }
    
    /// Convert the enum variant to its u64 value.
    pub fn to_u64(self) -> u64 {
        self as u64
    }
    
    /// Get a human-readable description of the error.
    pub fn description(&self) -> &'static str {
        match self {
            H3ErrorCode::NoError => "No error",
            H3ErrorCode::GeneralProtocolError => "General protocol error",
            H3ErrorCode::InternalError => "Internal error",
            H3ErrorCode::StreamCreationError => "Stream creation error",
            H3ErrorCode::ClosedCriticalStream => "Closed critical stream",
            H3ErrorCode::FrameUnexpected => "Frame unexpected",
            H3ErrorCode::FrameError => "Frame error",
            H3ErrorCode::ExcessiveLoad => "Excessive load",
            H3ErrorCode::IdError => "ID error",
            H3ErrorCode::SettingsError => "Settings error",
            H3ErrorCode::MissingSettings => "Missing settings",
            H3ErrorCode::RequestRejected => "Request rejected",
            H3ErrorCode::RequestIncomplete => "Request incomplete",
            H3ErrorCode::MessageError => "Message error",
            H3ErrorCode::ConnectError => "Connect error",
            H3ErrorCode::VersionFallback => "Version fallback",
            H3ErrorCode::WrongStream => "Wrong stream",
        }
    }
}