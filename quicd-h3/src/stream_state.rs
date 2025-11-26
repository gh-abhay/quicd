//! HTTP/3 stream state machine and frame buffering.
//!
//! This module implements per-stream state tracking according to RFC 9114,
//! including frame buffering for handling frames that span multiple reads.

use bytes::{Bytes, BytesMut};
use crate::error::H3Error;
use crate::frames::H3Frame;

/// State of an HTTP/3 stream per RFC 9114.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Stream is idle (not yet used)
    Idle,
    /// Stream is open - can send/receive frames
    Open,
    /// Local side has sent FIN
    HalfClosedLocal,
    /// Remote side has sent FIN
    HalfClosedRemote,
    /// Stream is fully closed
    Closed,
}

/// Context for parsing frames on a stream, with buffering for partial frames.
/// PERF #32: Limits buffer size to prevent memory exhaustion attacks
pub struct StreamFrameParser {
    /// Buffered data waiting to be parsed
    buffer: BytesMut,
    /// Current stream state
    state: StreamState,
    /// Whether HEADERS frame has been received
    headers_received: bool,
    /// Whether DATA frames have been received
    data_received: bool,
    /// Whether trailing HEADERS (trailers) have been received
    trailers_received: bool,
    /// Stream ID for error reporting
    stream_id: u64,
}

/// Maximum buffer size per stream to prevent memory exhaustion
/// Default: 1 MB (configurable in production)
const MAX_STREAM_BUFFER_SIZE: usize = 1024 * 1024;

impl StreamFrameParser {
    /// Create a new parser for a stream.
    /// PERF #30: Pre-allocate buffer to reduce reallocations
    pub fn new(stream_id: u64) -> Self {
        // Pre-allocate 16KB for typical frame sizes (HEADERS ~4KB, DATA varies)
        const INITIAL_BUFFER_CAPACITY: usize = 16 * 1024;
        Self {
            buffer: BytesMut::with_capacity(INITIAL_BUFFER_CAPACITY),
            state: StreamState::Idle,
            headers_received: false,
            data_received: false,
            trailers_received: false,
            stream_id,
        }
    }

    /// Get the current stream state.
    pub fn state(&self) -> StreamState {
        self.state
    }

    /// Mark stream as open.
    pub fn mark_open(&mut self) {
        if self.state == StreamState::Idle {
            self.state = StreamState::Open;
        }
    }

    /// Mark stream as half-closed (remote sent FIN).
    pub fn mark_half_closed_remote(&mut self) {
        match self.state {
            StreamState::Open => self.state = StreamState::HalfClosedRemote,
            StreamState::HalfClosedLocal => self.state = StreamState::Closed,
            _ => {}
        }
    }

    /// Mark stream as half-closed (local sent FIN).
    pub fn mark_half_closed_local(&mut self) {
        match self.state {
            StreamState::Open => self.state = StreamState::HalfClosedLocal,
            StreamState::HalfClosedRemote => self.state = StreamState::Closed,
            _ => {}
        }
    }

    /// Add data to the buffer for parsing.
    /// PERF #31: Minimize copies by using efficient extension
    /// PERF #32: Enforces buffer size limit
    pub fn add_data(&mut self, data: Bytes) -> Result<(), H3Error> {
        // PERF #32: Check buffer size limit before adding data
        let new_size = self.buffer.len() + data.len();
        if new_size > MAX_STREAM_BUFFER_SIZE {
            return Err(H3Error::Connection(format!(
                "Stream {} buffer size {} exceeds maximum {}",
                self.stream_id, new_size, MAX_STREAM_BUFFER_SIZE
            )));
        }
        
        // Reserve space if needed to avoid multiple reallocations
        let remaining_cap = self.buffer.capacity() - self.buffer.len();
        if remaining_cap < data.len() {
            self.buffer.reserve(data.len());
        }
        self.buffer.extend_from_slice(&data);
        Ok(())
    }

    /// Try to parse the next complete frame from the buffer.
    ///
    /// Returns:
    /// - `Ok(Some(frame))` if a complete frame was parsed
    /// - `Ok(None)` if more data is needed
    /// - `Err(error)` if parsing failed
    pub fn parse_next_frame(&mut self) -> Result<Option<H3Frame>, H3Error> {
        if self.buffer.is_empty() {
            return Ok(None);
        }

        // Try to parse a frame
        match H3Frame::parse_bytes(&self.buffer.clone().freeze()) {
            Ok((frame, consumed)) => {
                // Validate frame is allowed in current state
                self.validate_frame(&frame)?;

                // Remove consumed bytes from buffer
                let _ = self.buffer.split_to(consumed);

                // Update state based on frame type
                self.update_state_for_frame(&frame)?;

                Ok(Some(frame))
            }
            Err(H3Error::FrameParse(ref msg)) if msg.contains("buffer too small") => {
                // Need more data
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Validate that a frame type is allowed in the current stream state.
    fn validate_frame(&self, frame: &H3Frame) -> Result<(), H3Error> {
        use H3Frame::*;

        match self.state {
            StreamState::Idle => {
                // Should not receive frames on idle stream
                return Err(H3Error::Http(format!(
                    "received frame on idle stream {}",
                    self.stream_id
                )));
            }
            StreamState::Closed => {
                // Should not receive frames on closed stream
                return Err(H3Error::Http(format!(
                    "received frame on closed stream {}",
                    self.stream_id
                )));
            }
            StreamState::HalfClosedRemote => {
                // Remote has sent FIN, should not receive more frames
                return Err(H3Error::Http(format!(
                    "received frame on half-closed (remote) stream {}",
                    self.stream_id
                )));
            }
            _ => {}
        }

        // RFC 9114 Section 4.1: Invalid frame sequences
        match frame {
            Headers { .. } => {
                if self.trailers_received {
                    return Err(H3Error::Http(
                        "HEADERS after trailers is invalid".into()
                    ));
                }
                // HEADERS can be initial headers or trailers
            }
            Data { .. } => {
                if !self.headers_received {
                    return Err(H3Error::Http(
                        "DATA before HEADERS is invalid".into()
                    ));
                }
                if self.trailers_received {
                    return Err(H3Error::Http(
                        "DATA after trailers is invalid".into()
                    ));
                }
            }
            PushPromise { .. } => {
                // PUSH_PROMISE can appear before, after, or interleaved with response
                // frames, so it's generally allowed
            }
            Priority { .. } => {
                // PRIORITY can appear at any time
            }
            _ => {
                // Other frame types are allowed (including reserved/unknown)
            }
        }

        Ok(())
    }

    /// Update internal state based on the frame that was parsed.
    fn update_state_for_frame(&mut self, frame: &H3Frame) -> Result<(), H3Error> {
        match frame {
            H3Frame::Headers { .. } => {
                if !self.headers_received {
                    self.headers_received = true;
                } else if self.data_received {
                    // HEADERS after DATA = trailers
                    self.trailers_received = true;
                } else {
                    // Multiple HEADERS before DATA is invalid
                    return Err(H3Error::Http(
                        "multiple HEADERS frames before DATA".into()
                    ));
                }
            }
            H3Frame::Data { .. } => {
                self.data_received = true;
            }
            _ => {}
        }

        Ok(())
    }

    /// Check if there's any buffered data remaining.
    pub fn has_buffered_data(&self) -> bool {
        !self.buffer.is_empty()
    }

    /// Get the number of buffered bytes.
    pub fn buffered_bytes(&self) -> usize {
        self.buffer.len()
    }
    
    /// Get the remaining capacity before reallocation.
    /// PERF #30: Useful for monitoring buffer efficiency
    pub fn remaining_capacity(&self) -> usize {
        self.buffer.capacity() - self.buffer.len()
    }

    /// Clear all buffered data (for error recovery).
    /// PERF #30: Retains capacity to avoid reallocation on next use
    pub fn clear_buffer(&mut self) {
        self.buffer.clear();
        // Note: clear() retains capacity, which is what we want
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_parser_basic() {
        let mut parser = StreamFrameParser::new(4);
        parser.mark_open();
        assert_eq!(parser.state(), StreamState::Open);
    }

    #[test]
    fn test_frame_sequence_validation() {
        let mut parser = StreamFrameParser::new(4);
        parser.mark_open();

        // Create a HEADERS frame
        let headers = H3Frame::Headers {
            encoded_headers: Bytes::from("test"),
        };
        let headers_data = headers.encode();

        parser.add_data(headers_data).unwrap();
        let result = parser.parse_next_frame();
        assert!(result.is_ok());

        // Now try DATA frame
        let data = H3Frame::Data {
            data: Bytes::from("body"),
        };
        let data_bytes = data.encode();

        parser.add_data(data_bytes).unwrap();
        let result = parser.parse_next_frame();
        assert!(result.is_ok());

        // Trailers (HEADERS after DATA) should be allowed
        let trailers = H3Frame::Headers {
            encoded_headers: Bytes::from("trailer"),
        };
        let trailers_data = trailers.encode();

        parser.add_data(trailers_data).unwrap();
        let result = parser.parse_next_frame();
        assert!(result.is_ok());
        assert!(parser.trailers_received);
    }

    #[test]
    fn test_data_before_headers_rejected() {
        let mut parser = StreamFrameParser::new(4);
        parser.mark_open();

        // Try DATA before HEADERS
        let data = H3Frame::Data {
            data: Bytes::from("body"),
        };
        let data_bytes = data.encode();

        parser.add_data(data_bytes).unwrap();
        let result = parser.parse_next_frame();
        assert!(result.is_err());
    }

    #[test]
    fn test_partial_frame_buffering() {
        let mut parser = StreamFrameParser::new(4);
        parser.mark_open();

        let headers = H3Frame::Headers {
            encoded_headers: Bytes::from("test"),
        };
        let full_data = headers.encode();

        // Add only part of the frame
        let partial = full_data.slice(0..full_data.len() / 2);
        parser.add_data(partial).unwrap();

        // Should return None (need more data)
        let result = parser.parse_next_frame();
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());

        // Add remaining data
        let remaining = full_data.slice(full_data.len() / 2..);
        parser.add_data(remaining).unwrap();

        // Now should parse successfully
        let result = parser.parse_next_frame();
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn test_stream_state_transitions() {
        let mut parser = StreamFrameParser::new(4);
        assert_eq!(parser.state(), StreamState::Idle);

        parser.mark_open();
        assert_eq!(parser.state(), StreamState::Open);

        parser.mark_half_closed_remote();
        assert_eq!(parser.state(), StreamState::HalfClosedRemote);

        parser.mark_half_closed_local();
        assert_eq!(parser.state(), StreamState::Closed);
    }
}
