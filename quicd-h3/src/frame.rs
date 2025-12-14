use bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::error::{H3Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Data = 0x00,
    Headers = 0x01,
    CancelPush = 0x03,
    Settings = 0x04,
    PushPromise = 0x05,
    GoAway = 0x07,
    MaxPushId = 0x0D,
    Reserved, // For unknown types
}

impl From<u64> for FrameType {
    fn from(v: u64) -> Self {
        match v {
            0x00 => FrameType::Data,
            0x01 => FrameType::Headers,
            0x03 => FrameType::CancelPush,
            0x04 => FrameType::Settings,
            0x05 => FrameType::PushPromise,
            0x07 => FrameType::GoAway,
            0x0D => FrameType::MaxPushId,
            _ => FrameType::Reserved,
        }
    }
}

#[derive(Debug)]
pub enum H3Frame {
    Data(Bytes),
    Headers(Bytes),
    Settings(Vec<(u64, u64)>),
    GoAway(u64),
    Unknown(u64, Bytes), // Type, Payload
}

impl H3Frame {
    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            H3Frame::Data(data) => {
                encode_varint(0x00, buf);
                encode_varint(data.len() as u64, buf);
                buf.extend_from_slice(data);
            }
            H3Frame::Headers(data) => {
                encode_varint(0x01, buf);
                encode_varint(data.len() as u64, buf);
                buf.extend_from_slice(data);
            }
            H3Frame::Settings(settings) => {
                let mut payload = BytesMut::new();
                for (id, val) in settings {
                    encode_varint(*id, &mut payload);
                    encode_varint(*val, &mut payload);
                }
                encode_varint(0x04, buf);
                encode_varint(payload.len() as u64, buf);
                buf.extend_from_slice(&payload);
            }
            H3Frame::GoAway(id) => {
                let mut payload = BytesMut::new();
                encode_varint(*id, &mut payload);
                encode_varint(0x07, buf);
                encode_varint(payload.len() as u64, buf);
                buf.extend_from_slice(&payload);
            }
            H3Frame::Unknown(ty, data) => {
                encode_varint(*ty, buf);
                encode_varint(data.len() as u64, buf);
                buf.extend_from_slice(data);
            }
        }
    }

    pub fn decode(buf: &mut Bytes) -> Result<Option<H3Frame>> {
        if buf.is_empty() {
            return Ok(None);
        }
        
        let mut cursor = std::io::Cursor::new(&*buf);
        let ty = match decode_varint(&mut cursor) {
            Some(t) => t,
            None => return Ok(None), // Incomplete
        };
        let len = match decode_varint(&mut cursor) {
            Some(l) => l,
            None => return Ok(None), // Incomplete
        };
        
        let header_len = cursor.position() as usize;
        if buf.len() < header_len + len as usize {
            return Ok(None); // Incomplete payload
        }
        
        buf.advance(header_len);
        let payload = buf.split_to(len as usize);
        
        match FrameType::from(ty) {
            FrameType::Data => Ok(Some(H3Frame::Data(payload))),
            FrameType::Headers => Ok(Some(H3Frame::Headers(payload))),
            FrameType::Settings => {
                let mut settings = Vec::new();
                let mut p = std::io::Cursor::new(&*payload);
                while p.position() < payload.len() as u64 {
                    let id = decode_varint(&mut p).ok_or(H3Error::FrameError)?;
                    let val = decode_varint(&mut p).ok_or(H3Error::FrameError)?;
                    settings.push((id, val));
                }
                Ok(Some(H3Frame::Settings(settings)))
            }
            FrameType::GoAway => {
                let mut p = std::io::Cursor::new(&*payload);
                let id = decode_varint(&mut p).ok_or(H3Error::FrameError)?;
                Ok(Some(H3Frame::GoAway(id)))
            }
            _ => Ok(Some(H3Frame::Unknown(ty, payload))),
        }
    }
}

fn encode_varint(v: u64, buf: &mut BytesMut) {
    if v <= 63 {
        buf.put_u8(v as u8);
    } else if v <= 16383 {
        buf.put_u16((v as u16) | 0x4000);
    } else if v <= 1073741823 {
        buf.put_u32((v as u32) | 0x80000000);
    } else {
        buf.put_u64(v | 0xC000000000000000);
    }
}

fn decode_varint<B: Buf>(buf: &mut B) -> Option<u64> {
    if !buf.has_remaining() { return None; }
    let first = buf.chunk()[0];
    let len = match first >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    };
    
    if buf.remaining() < len { return None; }
    
    let val = match len {
        1 => buf.get_u8() as u64,
        2 => (buf.get_u16() & 0x3FFF) as u64,
        4 => (buf.get_u32() & 0x3FFFFFFF) as u64,
        8 => (buf.get_u64() & 0x3FFFFFFFFFFFFFFF),
        _ => unreachable!(),
    };
    Some(val)
}
