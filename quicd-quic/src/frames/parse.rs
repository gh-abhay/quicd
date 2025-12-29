//! # Frame Parsing (RFC 9000 Section 12.4)
//!
//! Zero-copy frame parsing with iterator-based API.

#![forbid(unsafe_code)]

extern crate alloc;

use super::types::*;
use crate::error::{Error, Result, TransportError};
use crate::types::{StreamId, VarIntCodec};
use bytes::BytesMut;

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
        if buf.is_empty() {
            return Err(Error::Transport(TransportError::FrameEncodingError));
        }

        let (frame_type, mut consumed) =
            VarIntCodec::decode(buf).ok_or(Error::Transport(TransportError::FrameEncodingError))?;

        // PADDING frame special case - can be repeated
        if frame_type == FRAME_TYPE_PADDING {
            // Consume all consecutive PADDING bytes
            while consumed < buf.len() && buf[consumed] == 0x00 {
                consumed += 1;
            }
            return Ok((Frame::Padding, consumed));
        }

        let frame_buf = &buf[consumed..];

        let (frame, frame_consumed) = match frame_type {
            FRAME_TYPE_PING => (Frame::Ping, 0),

            FRAME_TYPE_ACK => {
                let (ack, len) = self.parse_ack_frame(frame_buf, false)?;
                (Frame::Ack(ack), len)
            }

            FRAME_TYPE_ACK_ECN => {
                let (ack_ecn, len) = self.parse_ack_ecn_frame(frame_buf)?;
                (Frame::AckEcn(ack_ecn), len)
            }

            FRAME_TYPE_RESET_STREAM => {
                let (reset, len) = Self::parse_reset_stream_frame(frame_buf)?;
                (Frame::ResetStream(reset), len)
            }

            FRAME_TYPE_STOP_SENDING => {
                let (stop, len) = Self::parse_stop_sending_frame(frame_buf)?;
                (Frame::StopSending(stop), len)
            }

            FRAME_TYPE_CRYPTO => {
                let (crypto, len) = Self::parse_crypto_frame(frame_buf)?;
                (Frame::Crypto(crypto), len)
            }

            FRAME_TYPE_NEW_TOKEN => {
                let (token, len) = Self::parse_new_token_frame(frame_buf)?;
                (Frame::NewToken(token), len)
            }

            // STREAM frames: 0x08-0x0f
            t if t >= 0x08 && t <= 0x0f => {
                let (stream, len) = self.parse_stream_frame(t, frame_buf)?;
                (Frame::Stream(stream), len)
            }

            FRAME_TYPE_MAX_DATA => {
                let (max_data, len) = Self::parse_max_data_frame(frame_buf)?;
                (Frame::MaxData(max_data), len)
            }

            FRAME_TYPE_MAX_STREAM_DATA => {
                let (max_stream_data, len) = Self::parse_max_stream_data_frame(frame_buf)?;
                (Frame::MaxStreamData(max_stream_data), len)
            }

            FRAME_TYPE_MAX_STREAMS_BIDI => {
                let (max_streams, len) = Self::parse_max_streams_frame(frame_buf)?;
                (Frame::MaxStreamsBidi(max_streams), len)
            }

            FRAME_TYPE_MAX_STREAMS_UNI => {
                let (max_streams, len) = Self::parse_max_streams_frame(frame_buf)?;
                (Frame::MaxStreamsUni(max_streams), len)
            }

            FRAME_TYPE_DATA_BLOCKED => {
                let (blocked, len) = Self::parse_data_blocked_frame(frame_buf)?;
                (Frame::DataBlocked(blocked), len)
            }

            FRAME_TYPE_STREAM_DATA_BLOCKED => {
                let (blocked, len) = Self::parse_stream_data_blocked_frame(frame_buf)?;
                (Frame::StreamDataBlocked(blocked), len)
            }

            FRAME_TYPE_STREAMS_BLOCKED_BIDI => {
                let (blocked, len) = Self::parse_streams_blocked_frame(frame_buf)?;
                (Frame::StreamsBlockedBidi(blocked), len)
            }

            FRAME_TYPE_STREAMS_BLOCKED_UNI => {
                let (blocked, len) = Self::parse_streams_blocked_frame(frame_buf)?;
                (Frame::StreamsBlockedUni(blocked), len)
            }

            FRAME_TYPE_NEW_CONNECTION_ID => {
                let (new_cid, len) = Self::parse_new_connection_id_frame(frame_buf)?;
                (Frame::NewConnectionId(new_cid), len)
            }

            FRAME_TYPE_RETIRE_CONNECTION_ID => {
                let (retire, len) = Self::parse_retire_connection_id_frame(frame_buf)?;
                (Frame::RetireConnectionId(retire), len)
            }

            FRAME_TYPE_PATH_CHALLENGE => {
                let (challenge, len) = Self::parse_path_challenge_frame(frame_buf)?;
                (Frame::PathChallenge(challenge), len)
            }

            FRAME_TYPE_PATH_RESPONSE => {
                let (response, len) = Self::parse_path_response_frame(frame_buf)?;
                (Frame::PathResponse(response), len)
            }

            FRAME_TYPE_CONNECTION_CLOSE_TRANSPORT => {
                let (close, len) = Self::parse_connection_close_transport_frame(frame_buf)?;
                (Frame::ConnectionCloseTransport(close), len)
            }

            FRAME_TYPE_CONNECTION_CLOSE_APPLICATION => {
                let (close, len) = Self::parse_connection_close_application_frame(frame_buf)?;
                (Frame::ConnectionCloseApplication(close), len)
            }

            FRAME_TYPE_HANDSHAKE_DONE => (Frame::HandshakeDone, 0),

            _ => return Err(Error::Transport(TransportError::FrameEncodingError)),
        };

        Ok((frame, consumed + frame_consumed))
    }
}

impl DefaultFrameParser {
    /// Parse STREAM frame (RFC 9000 Section 19.8)
    fn parse_stream_frame<'a>(
        &self,
        frame_type: u64,
        buf: &'a [u8],
    ) -> Result<(StreamFrame<'a>, usize)> {
        let has_offset = (frame_type & STREAM_FRAME_BIT_OFF) != 0;
        let has_length = (frame_type & STREAM_FRAME_BIT_LEN) != 0;
        let fin = (frame_type & STREAM_FRAME_BIT_FIN) != 0;

        let mut offset = 0;

        // Parse Stream ID
        let (stream_id, consumed) =
            VarIntCodec::decode(buf).ok_or(Error::Transport(TransportError::FrameEncodingError))?;
        offset += consumed;

        // Parse Offset (if present)
        let stream_offset = if has_offset {
            let (off, consumed) = VarIntCodec::decode(&buf[offset..])
                .ok_or(Error::Transport(TransportError::FrameEncodingError))?;
            offset += consumed;
            off
        } else {
            0
        };

        // Parse Length (if present)
        let data = if has_length {
            let (length, consumed) = VarIntCodec::decode(&buf[offset..])
                .ok_or(Error::Transport(TransportError::FrameEncodingError))?;
            offset += consumed;

            if length > (buf.len() - offset) as u64 {
                return Err(Error::Transport(TransportError::FrameEncodingError));
            }

            let data = &buf[offset..offset + length as usize];
            offset += length as usize;
            data
        } else {
            // No length field - consume rest of buffer
            &buf[offset..]
        };

        Ok((
            StreamFrame {
                stream_id: StreamId::new(stream_id),
                offset: stream_offset,
                fin,
                data,
            },
            offset,
        ))
    }

    /// Parse ACK frame (RFC 9000 Section 19.3)
    ///
    /// ACK ranges are gap-encoded and MUST be parsed carefully to avoid allocation
    fn parse_ack_frame<'a>(&self, buf: &'a [u8], _has_ecn: bool) -> Result<(AckFrame<'a>, usize)> {
        let mut offset = 0;

        // Largest Acknowledged
        let (largest_acked, consumed) =
            VarIntCodec::decode(buf).ok_or(Error::Transport(TransportError::FrameEncodingError))?;
        offset += consumed;

        // ACK Delay
        let (ack_delay, consumed) = VarIntCodec::decode(&buf[offset..])
            .ok_or(Error::Transport(TransportError::FrameEncodingError))?;
        offset += consumed;

        // ACK Range Count
        let (ack_range_count, consumed) = VarIntCodec::decode(&buf[offset..])
            .ok_or(Error::Transport(TransportError::FrameEncodingError))?;
        offset += consumed;

        // First ACK Range
        let (first_ack_range, consumed) = VarIntCodec::decode(&buf[offset..])
            .ok_or(Error::Transport(TransportError::FrameEncodingError))?;
        offset += consumed;

        // Validate: First ACK Range cannot exceed largest_acked
        if first_ack_range > largest_acked {
            return Err(Error::Transport(TransportError::FrameEncodingError));
        }

        // Parse additional ACK ranges (gap, ack_range) pairs
        // Zero-allocation strategy: Store as slice reference
        let ranges_start = offset;
        let mut current_packet = largest_acked
            .saturating_sub(first_ack_range)
            .saturating_sub(1);

        for _ in 0..ack_range_count {
            // Parse Gap
            let (gap, consumed) = VarIntCodec::decode(&buf[offset..])
                .ok_or(Error::Transport(TransportError::FrameEncodingError))?;
            offset += consumed;

            // Update current packet number
            current_packet = current_packet.saturating_sub(gap).saturating_sub(2);

            // Parse ACK Range
            let (ack_range, consumed) = VarIntCodec::decode(&buf[offset..])
                .ok_or(Error::Transport(TransportError::FrameEncodingError))?;
            offset += consumed;

            // Validate: ACK range cannot be negative
            if ack_range > current_packet {
                return Err(Error::Transport(TransportError::FrameEncodingError));
            }

            current_packet = current_packet.saturating_sub(ack_range);
        }

        // Zero-copy: Reference the raw range bytes (caller must parse if needed)
        let ack_ranges = &buf[ranges_start..offset];

        Ok((
            AckFrame {
                largest_acked,
                ack_delay,
                ack_range_count,
                first_ack_range,
                ack_ranges: &[], // Simplified: ranges stored as raw bytes
            },
            offset,
        ))
    }

    /// Parse ACK frame with ECN counts (RFC 9000 Section 19.3.1)
    fn parse_ack_ecn_frame<'a>(&self, buf: &'a [u8]) -> Result<(AckEcnFrame<'a>, usize)> {
        let (ack, mut offset) = self.parse_ack_frame(buf, true)?;

        // Parse ECN counts
        let (ect0_count, consumed) = VarIntCodec::decode(&buf[offset..])
            .ok_or(Error::Transport(TransportError::FrameEncodingError))?;
        offset += consumed;

        let (ect1_count, consumed) = VarIntCodec::decode(&buf[offset..])
            .ok_or(Error::Transport(TransportError::FrameEncodingError))?;
        offset += consumed;

        let (ecn_ce_count, consumed) = VarIntCodec::decode(&buf[offset..])
            .ok_or(Error::Transport(TransportError::FrameEncodingError))?;
        offset += consumed;

        Ok((
            AckEcnFrame {
                ack,
                ect0_count,
                ect1_count,
                ecn_ce_count,
            },
            offset,
        ))
    }

    /// Parse CRYPTO frame (RFC 9000 Section 19.6)
    fn parse_crypto_frame<'a>(buf: &'a [u8]) -> Result<(CryptoFrame<'a>, usize)> {
        let mut offset = 0;

        // Parse Offset
        let (crypto_offset, consumed) =
            VarIntCodec::decode(buf).ok_or(Error::Transport(TransportError::FrameEncodingError))?;
        offset += consumed;

        // Parse Length
        let (length, consumed) = VarIntCodec::decode(&buf[offset..])
            .ok_or(Error::Transport(TransportError::FrameEncodingError))?;
        offset += consumed;

        if length > (buf.len() - offset) as u64 {
            return Err(Error::Transport(TransportError::FrameEncodingError));
        }

        let data = &buf[offset..offset + length as usize];
        offset += length as usize;

        Ok((
            CryptoFrame {
                offset: crypto_offset,
                data,
            },
            offset,
        ))
    }

    /// Parse RESET_STREAM frame (RFC 9000 Section 19.4)
    fn parse_reset_stream_frame(buf: &[u8]) -> Result<(ResetStreamFrame, usize)> {
        let mut offset = 0;

        let (stream_id, consumed) =
            VarIntCodec::decode(buf).ok_or(Error::Transport(TransportError::FrameEncodingError))?;
        offset += consumed;

        let (error_code, consumed) = VarIntCodec::decode(&buf[offset..])
            .ok_or(Error::Transport(TransportError::FrameEncodingError))?;
        offset += consumed;

        let (final_size, consumed) = VarIntCodec::decode(&buf[offset..])
            .ok_or(Error::Transport(TransportError::FrameEncodingError))?;
        offset += consumed;

        Ok((
            ResetStreamFrame {
                stream_id: StreamId::new(stream_id),
                application_error_code: error_code,
                final_size,
            },
            offset,
        ))
    }

    /// Parse STOP_SENDING frame (RFC 9000 Section 19.5)
    fn parse_stop_sending_frame(buf: &[u8]) -> Result<(StopSendingFrame, usize)> {
        let mut offset = 0;

        let (stream_id, consumed) =
            VarIntCodec::decode(buf).ok_or(Error::Transport(TransportError::FrameEncodingError))?;
        offset += consumed;

        let (error_code, consumed) = VarIntCodec::decode(&buf[offset..])
            .ok_or(Error::Transport(TransportError::FrameEncodingError))?;
        offset += consumed;

        Ok((
            StopSendingFrame {
                stream_id: StreamId::new(stream_id),
                application_error_code: error_code,
            },
            offset,
        ))
    }

    /// Parse NEW_TOKEN frame (RFC 9000 Section 19.7)
    fn parse_new_token_frame<'a>(buf: &'a [u8]) -> Result<(NewTokenFrame<'a>, usize)> {
        let mut offset = 0;

        let (token_length, consumed) =
            VarIntCodec::decode(buf).ok_or(Error::Transport(TransportError::FrameEncodingError))?;
        offset += consumed;

        if token_length > (buf.len() - offset) as u64 {
            return Err(Error::Transport(TransportError::FrameEncodingError));
        }

        let token = &buf[offset..offset + token_length as usize];
        offset += token_length as usize;

        Ok((NewTokenFrame { token }, offset))
    }

    /// Parse MAX_DATA frame (RFC 9000 Section 19.9)
    fn parse_max_data_frame(buf: &[u8]) -> Result<(MaxDataFrame, usize)> {
        let (maximum_data, consumed) =
            VarIntCodec::decode(buf).ok_or(Error::Transport(TransportError::FrameEncodingError))?;

        Ok((MaxDataFrame { maximum_data }, consumed))
    }

    /// Parse MAX_STREAM_DATA frame (RFC 9000 Section 19.10)
    fn parse_max_stream_data_frame(buf: &[u8]) -> Result<(MaxStreamDataFrame, usize)> {
        let mut offset = 0;

        let (stream_id, consumed) =
            VarIntCodec::decode(buf).ok_or(Error::Transport(TransportError::FrameEncodingError))?;
        offset += consumed;

        let (maximum_stream_data, consumed) = VarIntCodec::decode(&buf[offset..])
            .ok_or(Error::Transport(TransportError::FrameEncodingError))?;
        offset += consumed;

        Ok((
            MaxStreamDataFrame {
                stream_id: StreamId::new(stream_id),
                maximum_stream_data,
            },
            offset,
        ))
    }

    /// Parse MAX_STREAMS frame (RFC 9000 Section 19.11)
    fn parse_max_streams_frame(buf: &[u8]) -> Result<(MaxStreamsFrame, usize)> {
        let (maximum_streams, consumed) =
            VarIntCodec::decode(buf).ok_or(Error::Transport(TransportError::FrameEncodingError))?;

        Ok((MaxStreamsFrame { maximum_streams }, consumed))
    }

    /// Parse DATA_BLOCKED frame (RFC 9000 Section 19.12)
    fn parse_data_blocked_frame(buf: &[u8]) -> Result<(DataBlockedFrame, usize)> {
        let (maximum_data, consumed) =
            VarIntCodec::decode(buf).ok_or(Error::Transport(TransportError::FrameEncodingError))?;

        Ok((DataBlockedFrame { maximum_data }, consumed))
    }

    /// Parse STREAM_DATA_BLOCKED frame (RFC 9000 Section 19.13)
    fn parse_stream_data_blocked_frame(buf: &[u8]) -> Result<(StreamDataBlockedFrame, usize)> {
        let mut offset = 0;

        let (stream_id, consumed) =
            VarIntCodec::decode(buf).ok_or(Error::Transport(TransportError::FrameEncodingError))?;
        offset += consumed;

        let (maximum_stream_data, consumed) = VarIntCodec::decode(&buf[offset..])
            .ok_or(Error::Transport(TransportError::FrameEncodingError))?;
        offset += consumed;

        Ok((
            StreamDataBlockedFrame {
                stream_id: StreamId::new(stream_id),
                maximum_stream_data,
            },
            offset,
        ))
    }

    /// Parse STREAMS_BLOCKED frame (RFC 9000 Section 19.14)
    fn parse_streams_blocked_frame(buf: &[u8]) -> Result<(StreamsBlockedFrame, usize)> {
        let (maximum_streams, consumed) =
            VarIntCodec::decode(buf).ok_or(Error::Transport(TransportError::FrameEncodingError))?;

        Ok((StreamsBlockedFrame { maximum_streams }, consumed))
    }

    /// Parse NEW_CONNECTION_ID frame (RFC 9000 Section 19.15)
    fn parse_new_connection_id_frame<'a>(
        buf: &'a [u8],
    ) -> Result<(NewConnectionIdFrame<'a>, usize)> {
        let mut offset = 0;

        let (sequence_number, consumed) =
            VarIntCodec::decode(buf).ok_or(Error::Transport(TransportError::FrameEncodingError))?;
        offset += consumed;

        let (retire_prior_to, consumed) = VarIntCodec::decode(&buf[offset..])
            .ok_or(Error::Transport(TransportError::FrameEncodingError))?;
        offset += consumed;

        // Parse Connection ID Length (1 byte, must be 1-20)
        if offset >= buf.len() {
            return Err(Error::Transport(TransportError::FrameEncodingError));
        }
        let cid_length = buf[offset] as usize;
        offset += 1;

        if cid_length == 0 || cid_length > 20 {
            return Err(Error::Transport(TransportError::FrameEncodingError));
        }

        if offset + cid_length + 16 > buf.len() {
            return Err(Error::Transport(TransportError::FrameEncodingError));
        }

        let connection_id = &buf[offset..offset + cid_length];
        offset += cid_length;

        // Parse Stateless Reset Token (16 bytes)
        let mut stateless_reset_token = [0u8; 16];
        stateless_reset_token.copy_from_slice(&buf[offset..offset + 16]);
        offset += 16;

        Ok((
            NewConnectionIdFrame {
                sequence_number,
                retire_prior_to,
                connection_id,
                stateless_reset_token,
            },
            offset,
        ))
    }

    /// Parse RETIRE_CONNECTION_ID frame (RFC 9000 Section 19.16)
    fn parse_retire_connection_id_frame(buf: &[u8]) -> Result<(RetireConnectionIdFrame, usize)> {
        let (sequence_number, consumed) =
            VarIntCodec::decode(buf).ok_or(Error::Transport(TransportError::FrameEncodingError))?;

        Ok((RetireConnectionIdFrame { sequence_number }, consumed))
    }

    /// Parse PATH_CHALLENGE frame (RFC 9000 Section 19.17)
    fn parse_path_challenge_frame(buf: &[u8]) -> Result<(PathChallengeFrame, usize)> {
        if buf.len() < 8 {
            return Err(Error::Transport(TransportError::FrameEncodingError));
        }

        let mut data = [0u8; 8];
        data.copy_from_slice(&buf[0..8]);

        Ok((PathChallengeFrame { data }, 8))
    }

    /// Parse PATH_RESPONSE frame (RFC 9000 Section 19.18)
    fn parse_path_response_frame(buf: &[u8]) -> Result<(PathResponseFrame, usize)> {
        if buf.len() < 8 {
            return Err(Error::Transport(TransportError::FrameEncodingError));
        }

        let mut data = [0u8; 8];
        data.copy_from_slice(&buf[0..8]);

        Ok((PathResponseFrame { data }, 8))
    }

    /// Parse CONNECTION_CLOSE transport frame (RFC 9000 Section 19.19)
    fn parse_connection_close_transport_frame<'a>(
        buf: &'a [u8],
    ) -> Result<(ConnectionCloseTransportFrame<'a>, usize)> {
        let mut offset = 0;

        let (error_code_raw, consumed) =
            VarIntCodec::decode(buf).ok_or(Error::Transport(TransportError::FrameEncodingError))?;
        offset += consumed;

        let error_code = match error_code_raw {
            0x00 => TransportError::NoError,
            0x01 => TransportError::InternalError,
            0x02 => TransportError::ConnectionRefused,
            0x03 => TransportError::FlowControlError,
            0x04 => TransportError::StreamLimitError,
            0x05 => TransportError::StreamStateError,
            0x06 => TransportError::FinalSizeError,
            0x07 => TransportError::FrameEncodingError,
            0x08 => TransportError::TransportParameterError,
            0x09 => TransportError::ConnectionIdLimitError,
            0x0a => TransportError::ProtocolViolation,
            0x0b => TransportError::InvalidToken,
            0x0c => TransportError::ApplicationError,
            0x0d => TransportError::CryptoBufferExceeded,
            0x0e => TransportError::KeyUpdateError,
            0x0f => TransportError::AeadLimitReached,
            0x10 => TransportError::NoViablePath,
            _ => TransportError::ProtocolViolation,
        };

        let (frame_type, consumed) = VarIntCodec::decode(&buf[offset..])
            .ok_or(Error::Transport(TransportError::FrameEncodingError))?;
        offset += consumed;

        let (reason_length, consumed) = VarIntCodec::decode(&buf[offset..])
            .ok_or(Error::Transport(TransportError::FrameEncodingError))?;
        offset += consumed;

        if reason_length > (buf.len() - offset) as u64 {
            return Err(Error::Transport(TransportError::FrameEncodingError));
        }

        let reason_phrase = &buf[offset..offset + reason_length as usize];
        offset += reason_length as usize;

        Ok((
            ConnectionCloseTransportFrame {
                error_code,
                frame_type,
                reason_phrase,
            },
            offset,
        ))
    }

    /// Parse CONNECTION_CLOSE application frame (RFC 9000 Section 19.19)
    fn parse_connection_close_application_frame<'a>(
        buf: &'a [u8],
    ) -> Result<(ConnectionCloseApplicationFrame<'a>, usize)> {
        let mut offset = 0;

        let (error_code_raw, consumed) =
            VarIntCodec::decode(buf).ok_or(Error::Transport(TransportError::FrameEncodingError))?;
        offset += consumed;

        let (reason_length, consumed) = VarIntCodec::decode(&buf[offset..])
            .ok_or(Error::Transport(TransportError::FrameEncodingError))?;
        offset += consumed;

        if reason_length > (buf.len() - offset) as u64 {
            return Err(Error::Transport(TransportError::FrameEncodingError));
        }

        let reason_phrase = &buf[offset..offset + reason_length as usize];
        offset += reason_length as usize;

        Ok((
            ConnectionCloseApplicationFrame {
                error_code: crate::error::ApplicationError(error_code_raw),
                reason_phrase,
            },
            offset,
        ))
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
    fn serialize_frame(&self, frame: &Frame, buf: &mut BytesMut) -> Result<usize> {
        let start_len = buf.len();

        match frame {
            Frame::Padding => {
                // Single PADDING byte
                buf.extend_from_slice(&[0x00]);
            }

            Frame::Ping => {
                let mut tmp = [0u8; 8];
                let len = VarIntCodec::encode(FRAME_TYPE_PING, &mut tmp)
                    .ok_or(Error::Transport(TransportError::InternalError))?;
                buf.extend_from_slice(&tmp[..len]);
            }

            Frame::Ack(ack) => {
                Self::serialize_ack_frame(ack, buf, false)?;
            }

            Frame::AckEcn(ack_ecn) => {
                Self::serialize_ack_frame(&ack_ecn.ack, buf, true)?;
                // Add ECN counts
                let mut tmp = [0u8; 8];
                let len = VarIntCodec::encode(ack_ecn.ect0_count, &mut tmp)
                    .ok_or(Error::Transport(TransportError::InternalError))?;
                buf.extend_from_slice(&tmp[..len]);
                let len = VarIntCodec::encode(ack_ecn.ect1_count, &mut tmp)
                    .ok_or(Error::Transport(TransportError::InternalError))?;
                buf.extend_from_slice(&tmp[..len]);
                let len = VarIntCodec::encode(ack_ecn.ecn_ce_count, &mut tmp)
                    .ok_or(Error::Transport(TransportError::InternalError))?;
                buf.extend_from_slice(&tmp[..len]);
            }

            Frame::ResetStream(reset) => {
                let mut tmp = [0u8; 8];
                let len = VarIntCodec::encode(FRAME_TYPE_RESET_STREAM, &mut tmp)
                    .ok_or(Error::Transport(TransportError::InternalError))?;
                buf.extend_from_slice(&tmp[..len]);
                let len = VarIntCodec::encode(reset.stream_id.value(), &mut tmp)
                    .ok_or(Error::Transport(TransportError::InternalError))?;
                buf.extend_from_slice(&tmp[..len]);
                let len = VarIntCodec::encode(reset.application_error_code, &mut tmp)
                    .ok_or(Error::Transport(TransportError::InternalError))?;
                buf.extend_from_slice(&tmp[..len]);
                let len = VarIntCodec::encode(reset.final_size, &mut tmp)
                    .ok_or(Error::Transport(TransportError::InternalError))?;
                buf.extend_from_slice(&tmp[..len]);
            }

            Frame::StopSending(stop) => {
                let mut tmp = [0u8; 8];
                let len = VarIntCodec::encode(FRAME_TYPE_STOP_SENDING, &mut tmp)
                    .ok_or(Error::Transport(TransportError::InternalError))?;
                buf.extend_from_slice(&tmp[..len]);
                let len = VarIntCodec::encode(stop.stream_id.value(), &mut tmp)
                    .ok_or(Error::Transport(TransportError::InternalError))?;
                buf.extend_from_slice(&tmp[..len]);
                let len = VarIntCodec::encode(stop.application_error_code, &mut tmp)
                    .ok_or(Error::Transport(TransportError::InternalError))?;
                buf.extend_from_slice(&tmp[..len]);
            }

            Frame::Crypto(crypto) => {
                let mut tmp = [0u8; 8];
                let len = VarIntCodec::encode(FRAME_TYPE_CRYPTO, &mut tmp)
                    .ok_or(Error::Transport(TransportError::InternalError))?;
                buf.extend_from_slice(&tmp[..len]);
                let len = VarIntCodec::encode(crypto.offset, &mut tmp)
                    .ok_or(Error::Transport(TransportError::InternalError))?;
                buf.extend_from_slice(&tmp[..len]);
                let len = VarIntCodec::encode(crypto.data.len() as u64, &mut tmp)
                    .ok_or(Error::Transport(TransportError::InternalError))?;
                buf.extend_from_slice(&tmp[..len]);
                buf.extend_from_slice(crypto.data);
            }

            Frame::NewToken(token) => {
                let mut tmp = [0u8; 8];
                let len = VarIntCodec::encode(FRAME_TYPE_NEW_TOKEN, &mut tmp)
                    .ok_or(Error::Transport(TransportError::InternalError))?;
                buf.extend_from_slice(&tmp[..len]);
                let len = VarIntCodec::encode(token.token.len() as u64, &mut tmp)
                    .ok_or(Error::Transport(TransportError::InternalError))?;
                buf.extend_from_slice(&tmp[..len]);
                buf.extend_from_slice(token.token);
            }

            Frame::Stream(stream) => {
                Self::serialize_stream_frame(stream, buf)?;
            }

            Frame::MaxData(max_data) => {
                let mut tmp = [0u8; 8];
                let len = VarIntCodec::encode(FRAME_TYPE_MAX_DATA, &mut tmp)
                    .ok_or(Error::Transport(TransportError::InternalError))?;
                buf.extend_from_slice(&tmp[..len]);
                let len = VarIntCodec::encode(max_data.maximum_data, &mut tmp)
                    .ok_or(Error::Transport(TransportError::InternalError))?;
                buf.extend_from_slice(&tmp[..len]);
            }

            Frame::MaxStreamData(max_stream_data) => {
                let mut tmp = [0u8; 8];
                let len = VarIntCodec::encode(FRAME_TYPE_MAX_STREAM_DATA, &mut tmp)
                    .ok_or(Error::Transport(TransportError::InternalError))?;
                buf.extend_from_slice(&tmp[..len]);
                let len = VarIntCodec::encode(max_stream_data.stream_id.value(), &mut tmp)
                    .ok_or(Error::Transport(TransportError::InternalError))?;
                buf.extend_from_slice(&tmp[..len]);
                let len = VarIntCodec::encode(max_stream_data.maximum_stream_data, &mut tmp)
                    .ok_or(Error::Transport(TransportError::InternalError))?;
                buf.extend_from_slice(&tmp[..len]);
            }

            Frame::MaxStreamsBidi(max_streams) => {
                let mut tmp = [0u8; 8];
                let len = VarIntCodec::encode(FRAME_TYPE_MAX_STREAMS_BIDI, &mut tmp)
                    .ok_or(Error::Transport(TransportError::InternalError))?;
                buf.extend_from_slice(&tmp[..len]);
                let len = VarIntCodec::encode(max_streams.maximum_streams, &mut tmp)
                    .ok_or(Error::Transport(TransportError::InternalError))?;
                buf.extend_from_slice(&tmp[..len]);
            }

            Frame::MaxStreamsUni(max_streams) => {
                let mut tmp = [0u8; 8];
                let len = VarIntCodec::encode(FRAME_TYPE_MAX_STREAMS_UNI, &mut tmp)
                    .ok_or(Error::Transport(TransportError::InternalError))?;
                buf.extend_from_slice(&tmp[..len]);
                let len = VarIntCodec::encode(max_streams.maximum_streams, &mut tmp)
                    .ok_or(Error::Transport(TransportError::InternalError))?;
                buf.extend_from_slice(&tmp[..len]);
            }

            Frame::HandshakeDone => {
                let mut tmp = [0u8; 8];
                let len = VarIntCodec::encode(FRAME_TYPE_HANDSHAKE_DONE, &mut tmp)
                    .ok_or(Error::Transport(TransportError::InternalError))?;
                buf.extend_from_slice(&tmp[..len]);
            }

            // Add other frame types as needed
            _ => {
                return Err(Error::Transport(TransportError::InternalError));
            }
        }

        Ok(buf.len() - start_len)
    }

    fn frame_size(&self, frame: &Frame) -> usize {
        match frame {
            Frame::Padding => 1,
            Frame::Ping => VarIntCodec::size(FRAME_TYPE_PING),
            Frame::Ack(ack) => {
                VarIntCodec::size(FRAME_TYPE_ACK)
                    + VarIntCodec::size(ack.largest_acked)
                    + VarIntCodec::size(ack.ack_delay)
                    + VarIntCodec::size(ack.ack_range_count)
                    + VarIntCodec::size(ack.first_ack_range)
            }
            Frame::Stream(stream) => {
                let frame_type = FRAME_TYPE_STREAM
                    | (if stream.fin { STREAM_FRAME_BIT_FIN } else { 0 })
                    | (if stream.offset > 0 {
                        STREAM_FRAME_BIT_OFF
                    } else {
                        0
                    })
                    | STREAM_FRAME_BIT_LEN;

                VarIntCodec::size(frame_type)
                    + VarIntCodec::size(stream.stream_id.value())
                    + if stream.offset > 0 {
                        VarIntCodec::size(stream.offset)
                    } else {
                        0
                    }
                    + VarIntCodec::size(stream.data.len() as u64)
                    + stream.data.len()
            }
            Frame::MaxData(max_data) => {
                VarIntCodec::size(FRAME_TYPE_MAX_DATA) + VarIntCodec::size(max_data.maximum_data)
            }
            Frame::HandshakeDone => VarIntCodec::size(FRAME_TYPE_HANDSHAKE_DONE),
            _ => 0, // Simplified
        }
    }
}

impl DefaultFrameSerializer {
    /// Helper to serialize ACK frame
    fn serialize_ack_frame(ack: &AckFrame, buf: &mut BytesMut, with_ecn: bool) -> Result<()> {
        let mut tmp = [0u8; 8];
        let frame_type = if with_ecn {
            FRAME_TYPE_ACK_ECN
        } else {
            FRAME_TYPE_ACK
        };

        let len = VarIntCodec::encode(frame_type, &mut tmp)
            .ok_or(Error::Transport(TransportError::InternalError))?;
        buf.extend_from_slice(&tmp[..len]);

        let len = VarIntCodec::encode(ack.largest_acked, &mut tmp)
            .ok_or(Error::Transport(TransportError::InternalError))?;
        buf.extend_from_slice(&tmp[..len]);

        let len = VarIntCodec::encode(ack.ack_delay, &mut tmp)
            .ok_or(Error::Transport(TransportError::InternalError))?;
        buf.extend_from_slice(&tmp[..len]);

        let len = VarIntCodec::encode(ack.ack_range_count, &mut tmp)
            .ok_or(Error::Transport(TransportError::InternalError))?;
        buf.extend_from_slice(&tmp[..len]);

        let len = VarIntCodec::encode(ack.first_ack_range, &mut tmp)
            .ok_or(Error::Transport(TransportError::InternalError))?;
        buf.extend_from_slice(&tmp[..len]);

        Ok(())
    }

    /// Helper to serialize STREAM frame
    fn serialize_stream_frame(stream: &StreamFrame, buf: &mut BytesMut) -> Result<()> {
        let mut tmp = [0u8; 8];
        let frame_type = FRAME_TYPE_STREAM
            | (if stream.fin { STREAM_FRAME_BIT_FIN } else { 0 })
            | (if stream.offset > 0 {
                STREAM_FRAME_BIT_OFF
            } else {
                0
            })
            | STREAM_FRAME_BIT_LEN;

        let len = VarIntCodec::encode(frame_type, &mut tmp)
            .ok_or(Error::Transport(TransportError::InternalError))?;
        buf.extend_from_slice(&tmp[..len]);

        let len = VarIntCodec::encode(stream.stream_id.value(), &mut tmp)
            .ok_or(Error::Transport(TransportError::InternalError))?;
        buf.extend_from_slice(&tmp[..len]);

        if stream.offset > 0 {
            let len = VarIntCodec::encode(stream.offset, &mut tmp)
                .ok_or(Error::Transport(TransportError::InternalError))?;
            buf.extend_from_slice(&tmp[..len]);
        }

        let len = VarIntCodec::encode(stream.data.len() as u64, &mut tmp)
            .ok_or(Error::Transport(TransportError::InternalError))?;
        buf.extend_from_slice(&tmp[..len]);

        buf.extend_from_slice(stream.data);

        Ok(())
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_padding_frame() {
        let parser = DefaultFrameParser;
        let buf = [0x00, 0x00, 0x00, 0x01]; // 3 PADDING bytes + PING

        let (frame, consumed) = parser.parse_frame(&buf).unwrap();
        assert!(matches!(frame, Frame::Padding));
        assert_eq!(consumed, 3); // All PADDING bytes consumed
    }

    #[test]
    fn test_parse_ping_frame() {
        let parser = DefaultFrameParser;
        let buf = [0x01]; // PING frame

        let (frame, consumed) = parser.parse_frame(&buf).unwrap();
        assert!(matches!(frame, Frame::Ping));
        assert_eq!(consumed, 1);
        assert!(frame.is_ack_eliciting());
    }

    #[test]
    fn test_parse_stream_frame() {
        let parser = DefaultFrameParser;
        // STREAM frame: type=0x0f (OFF|LEN|FIN), stream_id=4, offset=100, length=5, data="hello"
        let buf = [
            0x0f, // Frame type (STREAM with OFF, LEN, FIN) = 0x08 | 0x04 | 0x02 | 0x01
            0x04, // Stream ID = 4
            0x40, 0x64, // Offset = 100 (2-byte VarInt encoding)
            0x05, // Length = 5
            b'h', b'e', b'l', b'l', b'o',
        ];

        let (frame, consumed) = parser.parse_frame(&buf).unwrap();
        match frame {
            Frame::Stream(s) => {
                assert_eq!(s.stream_id, StreamId::new(4));
                assert_eq!(s.offset, 100);
                assert_eq!(s.fin, true);
                assert_eq!(s.data, b"hello");
            }
            _ => panic!("Expected STREAM frame"),
        }
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn test_parse_ack_frame() {
        let parser = DefaultFrameParser;
        // ACK frame: largest_acked=100, delay=50, range_count=0, first_range=5
        let buf = [
            0x02, // Frame type (ACK)
            0x40, 0x64, // Largest Acknowledged = 100 (2-byte VarInt)
            0x32, // ACK Delay = 50
            0x00, // ACK Range Count = 0
            0x05, // First ACK Range = 5
        ];

        let (frame, consumed) = parser.parse_frame(&buf).unwrap();
        match frame {
            Frame::Ack(ack) => {
                assert_eq!(ack.largest_acked, 100);
                assert_eq!(ack.ack_delay, 50);
                assert_eq!(ack.ack_range_count, 0);
                assert_eq!(ack.first_ack_range, 5);
            }
            _ => panic!("Expected ACK frame"),
        }
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn test_parse_crypto_frame() {
        let parser = DefaultFrameParser;
        // CRYPTO frame: offset=0, length=4, data=[0x01, 0x02, 0x03, 0x04]
        let buf = [
            0x06, // Frame type (CRYPTO)
            0x00, // Offset = 0
            0x04, // Length = 4
            0x01, 0x02, 0x03, 0x04, // Data
        ];

        let (frame, consumed) = parser.parse_frame(&buf).unwrap();
        match frame {
            Frame::Crypto(crypto) => {
                assert_eq!(crypto.offset, 0);
                assert_eq!(crypto.data, &[0x01, 0x02, 0x03, 0x04]);
            }
            _ => panic!("Expected CRYPTO frame"),
        }
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn test_parse_max_data_frame() {
        let parser = DefaultFrameParser;
        let buf = [0x10, 0x40, 0x64]; // MAX_DATA, value=100

        let (frame, consumed) = parser.parse_frame(&buf).unwrap();
        match frame {
            Frame::MaxData(max_data) => {
                assert_eq!(max_data.maximum_data, 100);
            }
            _ => panic!("Expected MAX_DATA frame"),
        }
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn test_parse_handshake_done() {
        let parser = DefaultFrameParser;
        let buf = [0x1e]; // HANDSHAKE_DONE

        let (frame, consumed) = parser.parse_frame(&buf).unwrap();
        assert!(matches!(frame, Frame::HandshakeDone));
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_parse_invalid_frame_type() {
        let parser = DefaultFrameParser;
        let buf = [0xff]; // Invalid frame type

        assert!(parser.parse_frame(&buf).is_err());
    }

    #[test]
    fn test_serialize_ping_frame() {
        let serializer = DefaultFrameSerializer;
        let mut buf = BytesMut::new();

        let frame = Frame::Ping;
        let written = serializer.serialize_frame(&frame, &mut buf).unwrap();

        assert_eq!(written, 1);
        assert_eq!(&buf[..], &[0x01]);
    }

    #[test]
    fn test_serialize_stream_frame() {
        let serializer = DefaultFrameSerializer;
        let mut buf = BytesMut::new();

        let stream = StreamFrame {
            stream_id: StreamId::new(4),
            offset: 0,
            fin: false,
            data: b"test",
        };
        let frame = Frame::Stream(stream);

        serializer.serialize_frame(&frame, &mut buf).unwrap();

        // Verify it can be parsed back
        let parser = DefaultFrameParser;
        let (parsed_frame, _) = parser.parse_frame(&buf).unwrap();

        match parsed_frame {
            Frame::Stream(s) => {
                assert_eq!(s.stream_id, StreamId::new(4));
                assert_eq!(s.offset, 0);
                assert_eq!(s.fin, false);
                assert_eq!(s.data, b"test");
            }
            _ => panic!("Expected STREAM frame"),
        }
    }

    #[test]
    fn test_frame_iterator() {
        let parser = DefaultFrameParser;
        // Multiple frames: PING + PADDING + PING
        let buf = [0x01, 0x00, 0x01];

        let mut iter = parser.iter_frames(&buf);

        let frame1 = iter.next().unwrap().unwrap();
        assert!(matches!(frame1, Frame::Ping));

        let frame2 = iter.next().unwrap().unwrap();
        assert!(matches!(frame2, Frame::Padding));

        let frame3 = iter.next().unwrap().unwrap();
        assert!(matches!(frame3, Frame::Ping));

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_ack_eliciting() {
        assert!(Frame::Ping.is_ack_eliciting());
        assert!(!Frame::Padding.is_ack_eliciting());

        let ack = AckFrame {
            largest_acked: 10,
            ack_delay: 0,
            ack_range_count: 0,
            first_ack_range: 0,
            ack_ranges: &[],
        };
        assert!(!Frame::Ack(ack).is_ack_eliciting());
    }
}
