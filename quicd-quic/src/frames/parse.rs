//! # Frame Parsing (RFC 9000 Section 12.4)
//!
//! Zero-copy frame parsing with iterator-based API.

#![forbid(unsafe_code)]

use super::types::*;
use crate::error::{Error, Result, TransportError};
use crate::types::VarIntCodec;

/// Frame Parser Trait
///
/// Parses frames from a packet payload using zero-copy techniques.
/// All frame data references the input buffer via lifetimes.
///
/// **Design Rationale**:
/// - Lifetime 'a binds all frame data to input buffer
/// - No heap allocations during parsing
/// - Iterator pattern allows streaming frame processing
pub trait FrameParser {
    /// Parse a single frame from buffer
    ///
    /// Returns parsed frame and number of bytes consumed.
    /// Frame data borrows from input buffer.
    fn parse_frame<'a>(&self, buf: &'a [u8]) -> Result<(Frame<'a>, usize)>;

    /// Create an iterator over frames in a payload
    ///
    /// Allows processing multiple frames without repeated parsing.
    fn iter_frames<'a>(&'a self, payload: &'a [u8]) -> FrameIterator<'a, Self>
    where
        Self: Sized,
    {
        FrameIterator {
            parser: self,
            buf: payload,
            offset: 0,
        }
    }
}

/// Frame Iterator (Zero-Copy)
///
/// Iterates over frames in a packet payload without copying.
pub struct FrameIterator<'a, P: FrameParser + ?Sized> {
    parser: &'a P,
    buf: &'a [u8],
    offset: usize,
}

impl<'a, P: FrameParser + ?Sized> Iterator for FrameIterator<'a, P> {
    type Item = Result<Frame<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.buf.len() {
            return None;
        }

        match self.parser.parse_frame(&self.buf[self.offset..]) {
            Ok((frame, consumed)) => {
                self.offset += consumed;
                Some(Ok(frame))
            }
            Err(e) => {
                // On error, stop iteration
                self.offset = self.buf.len();
                Some(Err(e))
            }
        }
    }
}

// ============================================================================
// Default Frame Parser Implementation Skeleton
// ============================================================================

/// Default frame parser implementation
pub struct DefaultFrameParser;

impl FrameParser for DefaultFrameParser {
    fn parse_frame<'a>(&self, buf: &'a [u8]) -> Result<(Frame<'a>, usize)> {
        // Skeleton - implementation would decode frame type and dispatch to specific parsers
        unimplemented!("Skeleton - no implementation required")
    }
}

impl DefaultFrameParser {
    /// Parse STREAM frame
    fn parse_stream_frame<'a>(&self, frame_type: u64, buf: &'a [u8]) -> Result<(StreamFrame<'a>, usize)> {
        unimplemented!("Skeleton")
    }

    /// Parse ACK frame
    fn parse_ack_frame<'a>(&self, buf: &'a [u8]) -> Result<(AckFrame<'a>, usize)> {
        unimplemented!("Skeleton")
    }

    /// Parse CRYPTO frame
    fn parse_crypto_frame<'a>(&self, buf: &'a [u8]) -> Result<(CryptoFrame<'a>, usize)> {
        unimplemented!("Skeleton")
    }

    /// Parse CONNECTION_CLOSE frame
    fn parse_connection_close<'a>(&self, is_app: bool, buf: &'a [u8]) -> Result<(Frame<'a>, usize)> {
        unimplemented!("Skeleton")
    }
}

// ============================================================================
// Frame Serialization Trait (Buffer Injection Pattern)
// ============================================================================

/// Frame Serializer
///
/// Serializes frames into caller-provided buffers (no internal allocation).
///
/// **Critical Design**: Follows buffer injection pattern - caller provides
/// bytes::BytesMut and serializer writes directly into it.
pub trait FrameSerializer {
    /// Serialize a frame into the provided buffer
    ///
    /// **Parameters**:
    /// - `frame`: Frame to serialize (may contain borrowed data)
    /// - `buf`: Mutable buffer to write into
    ///
    /// **Returns**: Number of bytes written
    fn serialize_frame(&self, frame: &Frame, buf: &mut bytes::BytesMut) -> Result<usize>;

    /// Calculate the serialized size of a frame
    ///
    /// Used for pre-allocation and packet size planning.
    fn frame_size(&self, frame: &Frame) -> usize;
}

/// Default frame serializer implementation
pub struct DefaultFrameSerializer;

impl FrameSerializer for DefaultFrameSerializer {
    fn serialize_frame(&self, frame: &Frame, buf: &mut bytes::BytesMut) -> Result<usize> {
        unimplemented!("Skeleton - no implementation required")
    }

    fn frame_size(&self, frame: &Frame) -> usize {
        unimplemented!("Skeleton - no implementation required")
    }
}
