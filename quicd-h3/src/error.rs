use thiserror::Error;

pub type Result<T> = std::result::Result<T, H3Error>;

#[derive(Error, Debug)]
pub enum H3Error {
    #[error("H3 Frame Error")]
    FrameError,
    #[error("H3 Stream Error")]
    StreamError,
    #[error("H3 Compression Error")]
    CompressionError,
    #[error("H3 Internal Error")]
    InternalError,
    #[error("IO Error: {0}")]
    Io(#[from] std::io::Error),
    #[error("QUIC Error: {0}")]
    Quic(#[from] anyhow::Error),
}
