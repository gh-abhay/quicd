use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io::Cursor;

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
    /// Parses a frame from the given buffer.
    pub fn parse(buf: &[u8]) -> Result<(H3Frame, usize), H3Error> {
        let mut cursor = 0;

        // Parse frame type (variable-length integer)
        let (frame_type, type_len) = Self::decode_varint(&buf[cursor..])?;
        cursor += type_len;

        // Parse length (variable-length integer)
        let (length, len_len) = Self::decode_varint(&buf[cursor..])?;
        cursor += len_len;

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
                if payload.len() < 8 {
                    return Err(H3Error::FrameParse("CANCEL_PUSH payload too small".into()));
                }
                let push_id = Cursor::new(payload).get_u64();
                H3Frame::CancelPush { push_id }
            }
            0x4 => H3Frame::Settings { settings: Setting::parse_settings(payload)? },
            0x5 => {
                if payload.len() < 8 {
                    return Err(H3Error::FrameParse("PUSH_PROMISE payload too small".into()));
                }
                let mut cursor = Cursor::new(payload);
                let push_id = cursor.get_u64();
                let encoded_headers = Bytes::copy_from_slice(&payload[8..]);
                H3Frame::PushPromise { push_id, encoded_headers }
            }
            0x7 => {
                if payload.len() < 8 {
                    return Err(H3Error::FrameParse("GOAWAY payload too small".into()));
                }
                let stream_id = Cursor::new(payload).get_u64();
                H3Frame::GoAway { stream_id }
            }
            0xD => {
                if payload.len() < 8 {
                    return Err(H3Error::FrameParse("MAX_PUSH_ID payload too small".into()));
                }
                let push_id = Cursor::new(payload).get_u64();
                H3Frame::MaxPushId { push_id }
            }
            0xE => {
                if payload.len() < 8 {
                    return Err(H3Error::FrameParse("DUPLICATE_PUSH payload too small".into()));
                }
                let push_id = Cursor::new(payload).get_u64();
                H3Frame::DuplicatePush { push_id }
            }
            _ => H3Frame::Reserved { frame_type, payload: Bytes::copy_from_slice(payload) },
        };

        Ok((frame, consumed))
    }

    /// Encodes the frame into bytes.
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::new();

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
                Self::encode_varint(&mut buf, 8);
                buf.put_u64(*push_id);
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
                let payload_len = 8 + encoded_headers.len();
                Self::encode_varint(&mut buf, payload_len as u64);
                buf.put_u64(*push_id);
                buf.extend_from_slice(encoded_headers);
            }
            H3Frame::GoAway { stream_id } => {
                Self::encode_varint(&mut buf, 0x7);
                Self::encode_varint(&mut buf, 8);
                buf.put_u64(*stream_id);
            }
            H3Frame::MaxPushId { push_id } => {
                Self::encode_varint(&mut buf, 0xD);
                Self::encode_varint(&mut buf, 8);
                buf.put_u64(*push_id);
            }
            H3Frame::DuplicatePush { push_id } => {
                Self::encode_varint(&mut buf, 0xE);
                Self::encode_varint(&mut buf, 8);
                buf.put_u64(*push_id);
            }
            H3Frame::Reserved { frame_type, payload } => {
                Self::encode_varint(&mut buf, *frame_type);
                Self::encode_varint(&mut buf, payload.len() as u64);
                buf.extend_from_slice(payload);
            }
        }

        buf.freeze()
    }

    /// Decodes a variable-length integer from the buffer.
    /// Returns (value, bytes_consumed)
    fn decode_varint(buf: &[u8]) -> Result<(u64, usize), H3Error> {
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