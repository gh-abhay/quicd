use bytes::{BufMut, Bytes, BytesMut};

use crate::error::H3Error;

/// HTTP/3 frame types as defined in RFC 9114.
#[derive(Debug, Clone, PartialEq)]
pub enum H3Frame {
    Data { data: Bytes },
    Headers { encoded_headers: Bytes },
    Priority { priority: Priority },
    CancelPush { push_id: u64 },
    Settings { settings: Vec<Setting> },
    PushPromise { push_id: u64, encoded_headers: Bytes },
    GoAway { stream_id: u64 },
    MaxPushId { push_id: u64 },
    DuplicatePush { push_id: u64 },
    Reserved { frame_type: u64, payload: Bytes },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Priority {
    pub prioritized_element_type: u8,
    pub element_id: u64,
    pub priority_element_type: u8,
    pub priority_id: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Setting {
    pub identifier: u64,
    pub value: u64,
}

impl H3Frame {
    /// Parses a frame from the given buffer (slice-based, makes copies).
    pub fn parse(buf: &[u8]) -> Result<(H3Frame, usize), H3Error> {
        let mut cursor = 0;

        // Parse frame type (variable-length integer)
        let (frame_type, type_len) = Self::decode_varint(&buf[cursor..])?;
        cursor += type_len;

        // Validate frame type is not HTTP/2 reserved type (RFC 9114 Section 7.2.8)
        Self::validate_frame_type(frame_type)?;

        // Parse length (variable-length integer)
        let (length, len_len) = Self::decode_varint(&buf[cursor..])?;
        cursor += len_len;

        // Verify redundant length encoding is minimal (RFC 9114 Section 7.1)
        Self::validate_varint_encoding(&buf[cursor - len_len..cursor], length)?;

        let length = length as usize;
        if buf.len() < cursor + length {
            return Err(H3Error::FrameParse("buffer too small for frame payload".into()));
        }

        let payload = &buf[cursor..cursor + length];
        let consumed = cursor + length;

        let frame = match frame_type {
            0x0 => H3Frame::Data { data: Bytes::copy_from_slice(payload) },
            0x1 => H3Frame::Headers { encoded_headers: Bytes::copy_from_slice(payload) },
            0x2 => H3Frame::Priority { priority: Priority::parse(payload)? },
            0x3 => {
                let (push_id, _) = Self::decode_varint(payload)
                    .map_err(|_| H3Error::FrameParse("CANCEL_PUSH push_id parse error".into()))?;
                H3Frame::CancelPush { push_id }
            }
            0x4 => H3Frame::Settings { settings: Setting::parse_settings(payload)? },
            0x5 => {
                let (push_id, consumed) = Self::decode_varint(payload)
                    .map_err(|_| H3Error::FrameParse("PUSH_PROMISE push_id parse error".into()))?;
                let encoded_headers = Bytes::copy_from_slice(&payload[consumed..]);
                H3Frame::PushPromise { push_id, encoded_headers }
            }
            0x7 => {
                let (stream_id, _) = Self::decode_varint(payload)
                    .map_err(|_| H3Error::FrameParse("GOAWAY stream_id parse error".into()))?;
                H3Frame::GoAway { stream_id }
            }
            0xD => {
                let (push_id, _) = Self::decode_varint(payload)
                    .map_err(|_| H3Error::FrameParse("MAX_PUSH_ID push_id parse error".into()))?;
                H3Frame::MaxPushId { push_id }
            }
            0xE => {
                let (push_id, _) = Self::decode_varint(payload)
                    .map_err(|_| H3Error::FrameParse("DUPLICATE_PUSH push_id parse error".into()))?;
                H3Frame::DuplicatePush { push_id }
            }
            _ => H3Frame::Reserved { frame_type, payload: Bytes::copy_from_slice(payload) },
        };

        Ok((frame, consumed))
    }

    /// Parses a frame from a Bytes buffer (zero-copy using Bytes::slice).
    /// This is more efficient than parse() when the input is already a Bytes buffer.
    pub fn parse_bytes(buf: &Bytes) -> Result<(H3Frame, usize), H3Error> {
        let mut cursor = 0;

        // Parse frame type (variable-length integer)
        let (frame_type, type_len) = Self::decode_varint(&buf[cursor..])?;
        cursor += type_len;

        // Validate frame type is not HTTP/2 reserved type (RFC 9114 Section 7.2.8)
        Self::validate_frame_type(frame_type)?;

        // Parse length (variable-length integer)
        let (length, len_len) = Self::decode_varint(&buf[cursor..])?;
        cursor += len_len;

        // Verify redundant length encoding is minimal (RFC 9114 Section 7.1)
        Self::validate_varint_encoding(&buf[cursor - len_len..cursor], length)?;

        // GAP #5 FIX: Validate frame size to prevent DoS (RFC 9114 Section 7.1)
        // Maximum frame payload size: 16 MB (configurable in production)
        const MAX_FRAME_SIZE: u64 = 16 * 1024 * 1024;
        if length > MAX_FRAME_SIZE {
            return Err(H3Error::Connection(format!(
                "H3_EXCESSIVE_LOAD: Frame size {} exceeds maximum {}",
                length, MAX_FRAME_SIZE
            )));
        }

        let length = length as usize;
        if buf.len() < cursor + length {
            return Err(H3Error::FrameParse("buffer too small for frame payload".into()));
        }

        let payload_start = cursor;
        let payload_end = cursor + length;
        let consumed = payload_end;

        let frame = match frame_type {
            0x0 => H3Frame::Data { 
                data: buf.slice(payload_start..payload_end) 
            },
            0x1 => H3Frame::Headers { 
                encoded_headers: buf.slice(payload_start..payload_end) 
            },
            0x2 => H3Frame::Priority { 
                priority: Priority::parse(&buf[payload_start..payload_end])? 
            },
            0x3 => {
                let (push_id, _) = Self::decode_varint(&buf[payload_start..payload_end])
                    .map_err(|_| H3Error::FrameParse("CANCEL_PUSH push_id parse error".into()))?;
                H3Frame::CancelPush { push_id }
            }
            0x4 => H3Frame::Settings { 
                settings: Setting::parse_settings(&buf[payload_start..payload_end])? 
            },
            0x5 => {
                let (push_id, header_start) = Self::decode_varint(&buf[payload_start..payload_end])
                    .map_err(|_| H3Error::FrameParse("PUSH_PROMISE push_id parse error".into()))?;
                let encoded_headers = buf.slice(payload_start + header_start..payload_end);
                H3Frame::PushPromise { push_id, encoded_headers }
            }
            0x7 => {
                let (stream_id, _) = Self::decode_varint(&buf[payload_start..payload_end])
                    .map_err(|_| H3Error::FrameParse("GOAWAY stream_id parse error".into()))?;
                H3Frame::GoAway { stream_id }
            }
            0xD => {
                let (push_id, _) = Self::decode_varint(&buf[payload_start..payload_end])
                    .map_err(|_| H3Error::FrameParse("MAX_PUSH_ID push_id parse error".into()))?;
                H3Frame::MaxPushId { push_id }
            }
            0xE => {
                let (push_id, _) = Self::decode_varint(&buf[payload_start..payload_end])
                    .map_err(|_| H3Error::FrameParse("DUPLICATE_PUSH push_id parse error".into()))?;
                H3Frame::DuplicatePush { push_id }
            }
            _ => H3Frame::Reserved { 
                frame_type, 
                payload: buf.slice(payload_start..payload_end) 
            },
        };

        Ok((frame, consumed))
    }

    /// Encodes the frame into bytes.
    pub fn encode(&self) -> Bytes {
        // Pre-allocate buffer based on frame type to reduce reallocations
        let estimated_size = self.estimate_encoded_size();
        let mut buf = BytesMut::with_capacity(estimated_size);

        match self {
            H3Frame::Data { data } => {
                Self::encode_varint(&mut buf, 0x0);
                Self::encode_varint(&mut buf, data.len() as u64);
                buf.extend_from_slice(data);
            }
            H3Frame::Headers { encoded_headers } => {
                Self::encode_varint(&mut buf, 0x1);
                Self::encode_varint(&mut buf, encoded_headers.len() as u64);
                buf.extend_from_slice(encoded_headers);
            }
            H3Frame::Priority { priority } => {
                Self::encode_varint(&mut buf, 0x2);
                let mut payload = BytesMut::new();
                priority.encode(&mut payload);
                Self::encode_varint(&mut buf, payload.len() as u64);
                buf.extend_from_slice(&payload);
            }
            H3Frame::CancelPush { push_id } => {
                Self::encode_varint(&mut buf, 0x3);
                let mut payload = BytesMut::new();
                Self::encode_varint(&mut payload, *push_id);
                Self::encode_varint(&mut buf, payload.len() as u64);
                buf.extend_from_slice(&payload);
            }
            H3Frame::Settings { settings } => {
                Self::encode_varint(&mut buf, 0x4);
                let mut payload = BytesMut::new();
                for setting in settings {
                    Self::encode_varint(&mut payload, setting.identifier);
                    Self::encode_varint(&mut payload, setting.value);
                }
                Self::encode_varint(&mut buf, payload.len() as u64);
                buf.extend_from_slice(&payload);
            }
            H3Frame::PushPromise { push_id, encoded_headers } => {
                Self::encode_varint(&mut buf, 0x5);
                let mut payload = BytesMut::new();
                Self::encode_varint(&mut payload, *push_id);
                payload.extend_from_slice(encoded_headers);
                Self::encode_varint(&mut buf, payload.len() as u64);
                buf.extend_from_slice(&payload);
            }
            H3Frame::GoAway { stream_id } => {
                Self::encode_varint(&mut buf, 0x7);
                let mut payload = BytesMut::new();
                Self::encode_varint(&mut payload, *stream_id);
                Self::encode_varint(&mut buf, payload.len() as u64);
                buf.extend_from_slice(&payload);
            }
            H3Frame::MaxPushId { push_id } => {
                Self::encode_varint(&mut buf, 0xD);
                let mut payload = BytesMut::new();
                Self::encode_varint(&mut payload, *push_id);
                Self::encode_varint(&mut buf, payload.len() as u64);
                buf.extend_from_slice(&payload);
            }
            H3Frame::DuplicatePush { push_id } => {
                Self::encode_varint(&mut buf, 0xE);
                let mut payload = BytesMut::new();
                Self::encode_varint(&mut payload, *push_id);
                Self::encode_varint(&mut buf, payload.len() as u64);
                buf.extend_from_slice(&payload);
            }
            H3Frame::Reserved { frame_type, payload } => {
                Self::encode_varint(&mut buf, *frame_type);
                Self::encode_varint(&mut buf, payload.len() as u64);
                buf.extend_from_slice(payload);
            }
        }

        buf.freeze()
    }

    /// Estimate the encoded size of a frame for buffer pre-allocation.
    /// This provides a conservative upper bound to avoid reallocations.
    fn estimate_encoded_size(&self) -> usize {
        match self {
            H3Frame::Data { data } => {
                // type (1) + length varint (max 8) + data
                16 + data.len()
            }
            H3Frame::Headers { encoded_headers } => {
                // type (1) + length varint (max 8) + headers
                16 + encoded_headers.len()
            }
            H3Frame::Priority { .. } => {
                // type + length + priority fields (small)
                32
            }
            H3Frame::CancelPush { .. } | H3Frame::GoAway { .. } 
            | H3Frame::MaxPushId { .. } | H3Frame::DuplicatePush { .. } => {
                // type + length + varint push_id/stream_id
                32
            }
            H3Frame::Settings { settings } => {
                // type + length + (id + value) per setting
                16 + settings.len() * 16
            }
            H3Frame::PushPromise { encoded_headers, .. } => {
                // type + length + push_id + headers
                32 + encoded_headers.len()
            }
            H3Frame::Reserved { payload, .. } => {
                // type + length + payload
                16 + payload.len()
            }
        }
    }

    /// Encode a varint to bytes (for testing)
    pub fn encode_varint_to_bytes(value: u64) -> Vec<u8> {
        let mut buf = bytes::BytesMut::new();
        Self::encode_varint(&mut buf, value);
        buf.to_vec()
    }

    /// Decodes a variable-length integer from the buffer.
    /// Returns (value, bytes_consumed)
    pub fn decode_varint(buf: &[u8]) -> Result<(u64, usize), H3Error> {
        if buf.is_empty() {
            return Err(H3Error::FrameParse("empty buffer for varint".into()));
        }

        let first = buf[0];
        let prefix = first >> 6;
        let mut value = (first & 0x3F) as u64;
        let mut consumed = 1;

        match prefix {
            0 => {
                // 1 byte: 00vvvvvv (6 bits)
                // value already set
            }
            1 => {
                // 2 bytes: 01vvvvvv vvvvvvvv (14 bits total)
                if buf.len() < 2 {
                    return Err(H3Error::FrameParse("incomplete 2-byte varint".into()));
                }
                value = (value << 8) | (buf[1] as u64);
                consumed = 2;
            }
            2 => {
                // 4 bytes: 10vvvvvv vvvvvvvv vvvvvvvv vvvvvvvv (30 bits total)
                if buf.len() < 4 {
                    return Err(H3Error::FrameParse("incomplete 4-byte varint".into()));
                }
                value = (value << 8) | (buf[1] as u64);
                value = (value << 8) | (buf[2] as u64);
                value = (value << 8) | (buf[3] as u64);
                consumed = 4;
            }
            3 => {
                // 8 bytes: 11vvvvvv ... (62 bits total)
                if buf.len() < 8 {
                    return Err(H3Error::FrameParse("incomplete 8-byte varint".into()));
                }
                value = (value << 8) | (buf[1] as u64);
                value = (value << 8) | (buf[2] as u64);
                value = (value << 8) | (buf[3] as u64);
                value = (value << 8) | (buf[4] as u64);
                value = (value << 8) | (buf[5] as u64);
                value = (value << 8) | (buf[6] as u64);
                value = (value << 8) | (buf[7] as u64);
                consumed = 8;
            }
            _ => unreachable!(),
        }

        Ok((value, consumed))
    }

    /// Encodes a value as a variable-length integer.
    fn encode_varint(buf: &mut BytesMut, value: u64) {
        if value < (1 << 6) {
            // 1 byte
            buf.put_u8((value as u8) & 0x3F);
        } else if value < (1 << 14) {
            // 2 bytes
            buf.put_u8(0x40 | ((value >> 8) as u8));
            buf.put_u8(value as u8);
        } else if value < (1 << 30) {
            // 4 bytes
            buf.put_u8(0x80 | ((value >> 24) as u8));
            buf.put_u8((value >> 16) as u8);
            buf.put_u8((value >> 8) as u8);
            buf.put_u8(value as u8);
        } else {
            // 8 bytes
            buf.put_u8(0xC0 | ((value >> 56) as u8));
            buf.put_u8((value >> 48) as u8);
            buf.put_u8((value >> 40) as u8);
            buf.put_u8((value >> 32) as u8);
            buf.put_u8((value >> 24) as u8);
            buf.put_u8((value >> 16) as u8);
            buf.put_u8((value >> 8) as u8);
            buf.put_u8(value as u8);
        }
    }

    /// Validates that a frame type is not an HTTP/2 reserved type.
    /// RFC 9114 Section 7.2.8: Frame types that were used in HTTP/2 where there is no
    /// corresponding HTTP/3 frame have been reserved and MUST NOT be sent.
    fn validate_frame_type(frame_type: u64) -> Result<(), H3Error> {
        match frame_type {
            // PRIORITY (0x02) is valid in HTTP/3 but acts differently
            // CANCEL_PUSH (0x03) reuses RST_STREAM code point, but is valid
            0x06 => Err(H3Error::Connection("FRAME_UNEXPECTED: PING frame from HTTP/2 not allowed in HTTP/3".into())),
            0x08 => Err(H3Error::Connection("FRAME_UNEXPECTED: WINDOW_UPDATE frame from HTTP/2 not allowed in HTTP/3".into())),
            0x09 => Err(H3Error::Connection("FRAME_UNEXPECTED: CONTINUATION frame from HTTP/2 not allowed in HTTP/3".into())),
            _ => Ok(()),
        }
    }

    /// Validates that a varint is encoded minimally (no redundant length encoding).
    /// RFC 9114 Section 7.1: Redundant length encodings MUST be verified to be self-consistent.
    fn validate_varint_encoding(encoded: &[u8], value: u64) -> Result<(), H3Error> {
        if encoded.is_empty() {
            return Err(H3Error::FrameParse("empty varint encoding".into()));
        }

        let prefix = encoded[0] >> 6;
        let expected_len = match prefix {
            0 => 1,
            1 => 2,
            2 => 4,
            3 => 8,
            _ => unreachable!(),
        };

        if encoded.len() < expected_len {
            return Err(H3Error::FrameParse("incomplete varint encoding".into()));
        }

        // Check if value could have been encoded in fewer bytes
        let minimal_len = if value < (1 << 6) {
            1
        } else if value < (1 << 14) {
            2
        } else if value < (1 << 30) {
            4
        } else {
            8
        };

        if expected_len > minimal_len {
            return Err(H3Error::FrameParse(
                format!("redundant varint encoding: value {} encoded in {} bytes, minimal is {} bytes", 
                    value, expected_len, minimal_len)
            ));
        }

        Ok(())
    }

    /// Checks if a frame type is reserved for greasing (0x1f * N + 0x21).
    /// RFC 9114 Section 7.2.8: These frames have no semantics and can be sent for padding.
    pub fn is_reserved_frame_type(frame_type: u64) -> bool {
        if frame_type < 0x21 {
            return false;
        }
        (frame_type - 0x21) % 0x1f == 0
    }
}

impl Priority {
    fn parse(payload: &[u8]) -> Result<Self, H3Error> {
        if payload.is_empty() {
            return Err(H3Error::FrameParse("PRIORITY payload is empty".into()));
        }
        
        let prioritized_element_type = payload[0];
        let mut cursor = 1;
        
        // Parse Element ID (variable-length integer)
        let (element_id, id_len) = H3Frame::decode_varint(&payload[cursor..])
            .map_err(|_| H3Error::FrameParse("invalid element ID in PRIORITY frame".into()))?;
        cursor += id_len;
        
        if cursor >= payload.len() {
            return Err(H3Error::FrameParse("PRIORITY payload too short for priority element type".into()));
        }
        
        let priority_element_type = payload[cursor];
        cursor += 1;
        
        // Parse Priority ID (variable-length integer)
        let (priority_id, _pid_len) = H3Frame::decode_varint(&payload[cursor..])
            .map_err(|_| H3Error::FrameParse("invalid priority ID in PRIORITY frame".into()))?;
        
        Ok(Priority {
            prioritized_element_type,
            element_id,
            priority_element_type,
            priority_id,
        })
    }
    
    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.prioritized_element_type);
        H3Frame::encode_varint(buf, self.element_id);
        buf.put_u8(self.priority_element_type);
        H3Frame::encode_varint(buf, self.priority_id);
    }
}

impl Setting {
    fn parse_settings(payload: &[u8]) -> Result<Vec<Self>, H3Error> {
        let mut settings = Vec::new();
        let mut cursor = 0;
        
        while cursor < payload.len() {
            // Parse identifier (variable-length integer)
            let (identifier, id_len) = H3Frame::decode_varint(&payload[cursor..])?;
            cursor += id_len;
            
            // Parse value (variable-length integer)
            let (value, val_len) = H3Frame::decode_varint(&payload[cursor..])?;
            cursor += val_len;
            
            settings.push(Setting { identifier, value });
        }
        
        Ok(settings)
    }
}