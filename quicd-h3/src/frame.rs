//! HTTP/3 frame definitions and parsing per RFC 9114 Section 7.
//!
//! HTTP/3 frames all have the following format:
//! ```text
//! HTTP/3 Frame {
//!   Type (i),          // Variable-length integer
//!   Length (i),        // Variable-length integer
//!   Frame Payload (..),
//! }
//! ```
//!
//! This module implements parsing and serialization for all frame types
//! defined in RFC 9114 Section 7.2.

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::error::{Error, ErrorCode, Result};
use crate::varint;

/// HTTP/3 frame type identifiers per RFC 9114 Section 7.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum FrameType {
    /// DATA frame (0x00): Conveys arbitrary, variable-length sequences of bytes
    /// associated with HTTP request or response messages.
    Data = 0x00,

    /// HEADERS frame (0x01): Carries an HTTP field section that is encoded using QPACK.
    Headers = 0x01,

    /// CANCEL_PUSH frame (0x03): Requests cancellation of a server push prior to
    /// the push stream being received.
    CancelPush = 0x03,

    /// SETTINGS frame (0x04): Conveys configuration parameters that affect how
    /// endpoints communicate.
    Settings = 0x04,

    /// PUSH_PROMISE frame (0x05): Carries a promised request header section on a
    /// request stream.
    PushPromise = 0x05,

    /// GOAWAY frame (0x07): Initiates graceful shutdown of an HTTP/3 connection.
    Goaway = 0x07,

    /// MAX_PUSH_ID frame (0x0d): Used by clients to control the number of server
    /// pushes that the server can initiate.
    MaxPushId = 0x0d,
}

impl FrameType {
    pub fn from_u64(value: u64) -> Option<Self> {
        match value {
            0x00 => Some(Self::Data),
            0x01 => Some(Self::Headers),
            0x03 => Some(Self::CancelPush),
            0x04 => Some(Self::Settings),
            0x05 => Some(Self::PushPromise),
            0x07 => Some(Self::Goaway),
            0x0d => Some(Self::MaxPushId),
            _ => None,
        }
    }

    pub fn to_u64(self) -> u64 {
        self as u64
    }
}

/// HTTP/3 frame envelope with type and payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// DATA frame (0x00).
    Data(DataFrame),

    /// HEADERS frame (0x01).
    Headers(HeadersFrame),

    /// CANCEL_PUSH frame (0x03).
    CancelPush(CancelPushFrame),

    /// SETTINGS frame (0x04).
    Settings(SettingsFrame),

    /// PUSH_PROMISE frame (0x05).
    PushPromise(PushPromiseFrame),

    /// GOAWAY frame (0x07).
    Goaway(GoawayFrame),

    /// MAX_PUSH_ID frame (0x0d).
    MaxPushId(MaxPushIdFrame),

    /// Unknown/reserved frame type. Per RFC 9114, implementations MUST ignore
    /// frames of unknown types.
    Unknown { frame_type: u64, payload: Bytes },
}

impl Frame {
    /// Get the frame type.
    pub fn frame_type(&self) -> u64 {
        match self {
            Self::Data(_) => FrameType::Data.to_u64(),
            Self::Headers(_) => FrameType::Headers.to_u64(),
            Self::CancelPush(_) => FrameType::CancelPush.to_u64(),
            Self::Settings(_) => FrameType::Settings.to_u64(),
            Self::PushPromise(_) => FrameType::PushPromise.to_u64(),
            Self::Goaway(_) => FrameType::Goaway.to_u64(),
            Self::MaxPushId(_) => FrameType::MaxPushId.to_u64(),
            Self::Unknown { frame_type, .. } => *frame_type,
        }
    }

    /// Check if this frame type is valid on a request/response stream.
    pub fn is_valid_on_request_stream(&self) -> bool {
        matches!(
            self,
            Self::Data(_) | Self::Headers(_) | Self::PushPromise(_) | Self::Unknown { .. }
        )
    }

    /// Check if this frame type is valid on a control stream.
    pub fn is_valid_on_control_stream(&self) -> bool {
        matches!(
            self,
            Self::Settings(_)
                | Self::CancelPush(_)
                | Self::Goaway(_)
                | Self::MaxPushId(_)
                | Self::Unknown { .. }
        )
    }
}

/// DATA frame (0x00) - RFC 9114 Section 7.2.1.
///
/// Conveys arbitrary, variable-length sequences of bytes associated with HTTP
/// request or response content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataFrame {
    /// Payload bytes.
    pub payload: Bytes,
}

/// HEADERS frame (0x01) - RFC 9114 Section 7.2.2.
///
/// Carries an encoded field section via QPACK compression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadersFrame {
    /// QPACK-encoded field section.
    pub encoded_field_section: Bytes,
}

/// CANCEL_PUSH frame (0x03) - RFC 9114 Section 7.2.3.
///
/// Requests cancellation of a server push. Can be sent by client or server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CancelPushFrame {
    /// Push ID of the server push to cancel.
    pub push_id: u64,
}

/// SETTINGS frame (0x04) - RFC 9114 Section 7.2.4.
///
/// Conveys configuration parameters. MUST be sent as the first frame on each
/// control stream by both client and server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsFrame {
    /// Settings parameters as identifier-value pairs.
    pub settings: Vec<Setting>,
}

/// Individual setting parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Setting {
    /// Setting identifier (variable-length integer).
    pub identifier: SettingId,
    /// Setting value (variable-length integer).
    pub value: u64,
}

/// Settings identifiers per RFC 9114 Section 7.2.4.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingId {
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY (0x01): Maximum size of QPACK dynamic table.
    QpackMaxTableCapacity,

    /// SETTINGS_MAX_FIELD_SECTION_SIZE (0x06): Maximum size of field section sender will accept.
    MaxFieldSectionSize,

    /// SETTINGS_QPACK_BLOCKED_STREAMS (0x07): Maximum number of streams that can be blocked
    /// waiting for QPACK dynamic table updates.
    QpackBlockedStreams,

    /// Reserved/unknown setting (used for greasing).
    Reserved(u64),
}

impl SettingId {
    pub fn from_u64(value: u64) -> Self {
        match value {
            0x01 => Self::QpackMaxTableCapacity,
            0x06 => Self::MaxFieldSectionSize,
            0x07 => Self::QpackBlockedStreams,
            other => Self::Reserved(other),
        }
    }

    pub fn to_u64(self) -> u64 {
        match self {
            Self::QpackMaxTableCapacity => 0x01,
            Self::MaxFieldSectionSize => 0x06,
            Self::QpackBlockedStreams => 0x07,
            Self::Reserved(id) => id,
        }
    }
}

/// PUSH_PROMISE frame (0x05) - RFC 9114 Section 7.2.5.
///
/// Sent on a request stream to announce a server push.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushPromiseFrame {
    /// Push ID that identifies the server push.
    pub push_id: u64,
    /// QPACK-encoded field section describing the promised request.
    pub encoded_field_section: Bytes,
}

/// GOAWAY frame (0x07) - RFC 9114 Section 7.2.6.
///
/// Initiates graceful shutdown of connection. Indicates the last stream ID
/// that will be processed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoawayFrame {
    /// Stream ID or push ID (depending on context) of the last request/push
    /// that will be processed.
    pub id: u64,
}

/// MAX_PUSH_ID frame (0x0d) - RFC 9114 Section 7.2.7.
///
/// Sent by client to control the number of server pushes the server can initiate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxPushIdFrame {
    /// Maximum push ID that the sender is willing to receive.
    pub push_id: u64,
}

/// Frame parser for reading frames from QUIC streams.
///
/// Handles partial reads and buffering of incomplete frames.
pub struct FrameParser {
    /// Buffer for accumulating partial frame data.
    buffer: BytesMut,
    /// Current parsing state.
    state: ParserState,
}

#[derive(Debug, Clone, Copy)]
enum ParserState {
    /// Reading frame type varint.
    ReadingType,
    /// Reading frame length varint.
    ReadingLength { frame_type: u64 },
    /// Reading frame payload.
    ReadingPayload { frame_type: u64, length: usize },
}

impl Default for FrameParser {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameParser {
    /// Create a new frame parser.
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::new(),
            state: ParserState::ReadingType,
        }
    }

    /// Parse frames from incoming data.
    ///
    /// Returns a vector of parsed frames. The parser buffers partial frames
    /// internally and returns them when complete.
    ///
    /// # Errors
    ///
    /// Returns error if frame format is invalid.
    pub fn parse(&mut self, data: Bytes) -> Result<Vec<Frame>> {
        eprintln!(
            "FrameParser::parse: received {} bytes, current buffer: {} bytes",
            data.len(),
            self.buffer.len()
        );
        self.buffer.extend_from_slice(&data);
        let mut frames = Vec::new();

        loop {
            let initial_len = self.buffer.len();

            match self.state {
                ParserState::ReadingType => {
                    if let Some(frame_type) = try_read_varint(&mut self.buffer)? {
                        eprintln!("FrameParser: Read frame type: 0x{:x}", frame_type);
                        self.state = ParserState::ReadingLength { frame_type };
                    } else {
                        break; // Need more data
                    }
                }

                ParserState::ReadingLength { frame_type } => {
                    if let Some(length) = try_read_varint(&mut self.buffer)? {
                        eprintln!(
                            "FrameParser: Read frame length: {} for type 0x{:x}",
                            length, frame_type
                        );
                        if length > u64::MAX {
                            return Err(Error::protocol(
                                ErrorCode::FrameError,
                                format!("frame length too large: {}", length),
                            ));
                        }
                        self.state = ParserState::ReadingPayload {
                            frame_type,
                            length: length as usize,
                        };
                    } else {
                        break; // Need more data
                    }
                }

                ParserState::ReadingPayload { frame_type, length } => {
                    eprintln!(
                        "FrameParser: ReadingPayload, need {} bytes, have {}",
                        length,
                        self.buffer.len()
                    );
                    if self.buffer.len() < length {
                        break; // Need more data
                    }

                    let payload = self.buffer.split_to(length).freeze();
                    eprintln!(
                        "FrameParser: Parsing frame type 0x{:x} with {} byte payload",
                        frame_type,
                        payload.len()
                    );
                    let frame = parse_frame_payload(frame_type, payload)?;
                    frames.push(frame);

                    self.state = ParserState::ReadingType;
                    // Continue loop to parse more frames - we made progress by completing a frame
                    continue;
                }
            }

            // Safety check: ensure we made progress (consumed bytes from buffer)
            // This prevents infinite loops when we can't parse anything
            if self.buffer.len() == initial_len {
                break;
            }
        }

        eprintln!(
            "FrameParser::parse: returning {} frames, {} bytes buffered",
            frames.len(),
            self.buffer.len()
        );
        Ok(frames)
    }

    /// Get the number of buffered bytes.
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }
}

/// Try to read a complete varint from the buffer without consuming on failure.
fn try_read_varint(buf: &mut BytesMut) -> Result<Option<u64>> {
    if buf.is_empty() {
        return Ok(None);
    }

    let first = buf[0];
    let len = match first >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    };

    if buf.len() < len {
        return Ok(None); // Incomplete varint
    }

    let value = varint::decode_buf(buf)?;
    Ok(Some(value))
}

/// Parse frame payload based on frame type.
fn parse_frame_payload(frame_type: u64, payload: Bytes) -> Result<Frame> {
    match FrameType::from_u64(frame_type) {
        Some(FrameType::Data) => Ok(Frame::Data(DataFrame { payload })),

        Some(FrameType::Headers) => Ok(Frame::Headers(HeadersFrame {
            encoded_field_section: payload,
        })),

        Some(FrameType::CancelPush) => {
            let mut buf = payload.clone();
            let push_id = varint::decode_buf(&mut buf)?;
            if buf.has_remaining() {
                return Err(Error::protocol(
                    ErrorCode::FrameError,
                    "CANCEL_PUSH frame has extra bytes",
                ));
            }
            Ok(Frame::CancelPush(CancelPushFrame { push_id }))
        }

        Some(FrameType::Settings) => {
            let mut buf = payload.clone();
            let mut settings = Vec::new();

            while buf.has_remaining() {
                let identifier = varint::decode_buf(&mut buf)?;
                let value = varint::decode_buf(&mut buf)?;
                settings.push(Setting {
                    identifier: SettingId::from_u64(identifier),
                    value,
                });
            }

            Ok(Frame::Settings(SettingsFrame { settings }))
        }

        Some(FrameType::PushPromise) => {
            let mut buf = payload.clone();
            let push_id = varint::decode_buf(&mut buf)?;
            let encoded_field_section = buf.copy_to_bytes(buf.remaining());

            Ok(Frame::PushPromise(PushPromiseFrame {
                push_id,
                encoded_field_section,
            }))
        }

        Some(FrameType::Goaway) => {
            let mut buf = payload.clone();
            let id = varint::decode_buf(&mut buf)?;
            if buf.has_remaining() {
                return Err(Error::protocol(
                    ErrorCode::FrameError,
                    "GOAWAY frame has extra bytes",
                ));
            }
            Ok(Frame::Goaway(GoawayFrame { id }))
        }

        Some(FrameType::MaxPushId) => {
            let mut buf = payload.clone();
            let push_id = varint::decode_buf(&mut buf)?;
            if buf.has_remaining() {
                return Err(Error::protocol(
                    ErrorCode::FrameError,
                    "MAX_PUSH_ID frame has extra bytes",
                ));
            }
            Ok(Frame::MaxPushId(MaxPushIdFrame { push_id }))
        }

        None => {
            // Unknown/reserved frame type - must be ignored per RFC 9114
            Ok(Frame::Unknown {
                frame_type,
                payload,
            })
        }
    }
}

/// Serialize a frame to bytes.
///
/// # Errors
///
/// Returns error if serialization fails.
pub fn write_frame(frame: &Frame, buf: &mut BytesMut) -> Result<()> {
    match frame {
        Frame::Data(f) => {
            varint::encode_buf(FrameType::Data.to_u64(), buf)?;
            varint::encode_buf(f.payload.len() as u64, buf)?;
            buf.put_slice(&f.payload);
        }

        Frame::Headers(f) => {
            varint::encode_buf(FrameType::Headers.to_u64(), buf)?;
            varint::encode_buf(f.encoded_field_section.len() as u64, buf)?;
            buf.put_slice(&f.encoded_field_section);
        }

        Frame::CancelPush(f) => {
            varint::encode_buf(FrameType::CancelPush.to_u64(), buf)?;
            let payload_len = varint::encoded_len(f.push_id);
            varint::encode_buf(payload_len as u64, buf)?;
            varint::encode_buf(f.push_id, buf)?;
        }

        Frame::Settings(f) => {
            varint::encode_buf(FrameType::Settings.to_u64(), buf)?;

            // Calculate payload length
            let mut payload_len = 0;
            for setting in &f.settings {
                payload_len += varint::encoded_len(setting.identifier.to_u64());
                payload_len += varint::encoded_len(setting.value);
            }
            varint::encode_buf(payload_len as u64, buf)?;

            // Write settings
            for setting in &f.settings {
                varint::encode_buf(setting.identifier.to_u64(), buf)?;
                varint::encode_buf(setting.value, buf)?;
            }
        }

        Frame::PushPromise(f) => {
            varint::encode_buf(FrameType::PushPromise.to_u64(), buf)?;
            let payload_len = varint::encoded_len(f.push_id) + f.encoded_field_section.len();
            varint::encode_buf(payload_len as u64, buf)?;
            varint::encode_buf(f.push_id, buf)?;
            buf.put_slice(&f.encoded_field_section);
        }

        Frame::Goaway(f) => {
            varint::encode_buf(FrameType::Goaway.to_u64(), buf)?;
            let payload_len = varint::encoded_len(f.id);
            varint::encode_buf(payload_len as u64, buf)?;
            varint::encode_buf(f.id, buf)?;
        }

        Frame::MaxPushId(f) => {
            varint::encode_buf(FrameType::MaxPushId.to_u64(), buf)?;
            let payload_len = varint::encoded_len(f.push_id);
            varint::encode_buf(payload_len as u64, buf)?;
            varint::encode_buf(f.push_id, buf)?;
        }

        Frame::Unknown {
            frame_type,
            payload,
        } => {
            varint::encode_buf(*frame_type, buf)?;
            varint::encode_buf(payload.len() as u64, buf)?;
            buf.put_slice(payload);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_frame_roundtrip() {
        let frame = Frame::Data(DataFrame {
            payload: Bytes::from_static(b"hello world"),
        });

        let mut buf = BytesMut::new();
        write_frame(&frame, &mut buf).unwrap();

        let mut parser = FrameParser::new();
        let frames = parser.parse(buf.freeze()).unwrap();

        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0], frame);
    }

    #[test]
    fn test_settings_frame_roundtrip() {
        let frame = Frame::Settings(SettingsFrame {
            settings: vec![
                Setting {
                    identifier: SettingId::QpackMaxTableCapacity,
                    value: 4096,
                },
                Setting {
                    identifier: SettingId::MaxFieldSectionSize,
                    value: 16384,
                },
                Setting {
                    identifier: SettingId::QpackBlockedStreams,
                    value: 100,
                },
            ],
        });

        let mut buf = BytesMut::new();
        write_frame(&frame, &mut buf).unwrap();

        let mut parser = FrameParser::new();
        let frames = parser.parse(buf.freeze()).unwrap();

        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0], frame);
    }

    #[test]
    fn test_multiple_frames() {
        let frames_to_encode = vec![
            Frame::Settings(SettingsFrame {
                settings: vec![Setting {
                    identifier: SettingId::QpackMaxTableCapacity,
                    value: 4096,
                }],
            }),
            Frame::Data(DataFrame {
                payload: Bytes::from_static(b"test"),
            }),
            Frame::Goaway(GoawayFrame { id: 42 }),
        ];

        let mut buf = BytesMut::new();
        for frame in &frames_to_encode {
            write_frame(frame, &mut buf).unwrap();
        }

        let mut parser = FrameParser::new();
        let parsed_frames = parser.parse(buf.freeze()).unwrap();

        assert_eq!(parsed_frames.len(), frames_to_encode.len());
        for (parsed, original) in parsed_frames.iter().zip(frames_to_encode.iter()) {
            assert_eq!(parsed, original);
        }
    }

    #[test]
    fn test_partial_frame_buffering() {
        let frame = Frame::Data(DataFrame {
            payload: Bytes::from_static(b"hello world"),
        });

        let mut buf = BytesMut::new();
        write_frame(&frame, &mut buf).unwrap();

        let serialized = buf.freeze();
        let split_point = serialized.len() / 2;

        let mut parser = FrameParser::new();

        // Parse first half - should return no frames
        let frames1 = parser.parse(serialized.slice(..split_point)).unwrap();
        assert_eq!(frames1.len(), 0);

        // Parse second half - should return complete frame
        let frames2 = parser.parse(serialized.slice(split_point..)).unwrap();
        assert_eq!(frames2.len(), 1);
        assert_eq!(frames2[0], frame);
    }

    #[test]
    fn test_frame_type_validation() {
        let data_frame = Frame::Data(DataFrame {
            payload: Bytes::new(),
        });
        assert!(data_frame.is_valid_on_request_stream());
        assert!(!data_frame.is_valid_on_control_stream());

        let settings_frame = Frame::Settings(SettingsFrame { settings: vec![] });
        assert!(!settings_frame.is_valid_on_request_stream());
        assert!(settings_frame.is_valid_on_control_stream());
    }
}
