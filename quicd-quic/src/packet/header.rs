use crate::packet::ConnectionId;
use bytes::{Buf, BufMut, Bytes};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Initial,
    ZeroRTT,
    Handshake,
    Retry,
    VersionNegotiation,
    Short1RTT,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PacketNumber(pub u64);

// ...

#[derive(Debug, Clone)]
pub struct Header {
    pub packet_type: PacketType,
    pub version: u32,
    pub dcid: ConnectionId,
    pub scid: Option<ConnectionId>,
    pub token: Option<Bytes>,
    pub packet_number: Option<PacketNumber>, // None for VersionNegotiation and Retry
    pub packet_number_len: usize,
    pub key_phase: bool, // Only for Short Header
    pub payload_len: Option<u64>, // Length of Packet Number + Payload (from Length field)
}

#[derive(Error, Debug)]
pub enum HeaderError {
    #[error("Buffer too short")]
    BufferTooShort,
    #[error("Invalid packet type")]
    InvalidPacketType,
    #[error("Invalid version")]
    InvalidVersion,
    #[error("Invalid Connection ID length")]
    InvalidCidLen,
}

impl Header {
    pub fn parse<B: Buf>(buf: &mut B, dcid_len: usize) -> Result<Self, HeaderError> {
        if !buf.has_remaining() {
            return Err(HeaderError::BufferTooShort);
        }
        
        let first = buf.chunk()[0];
        let is_long = (first & 0x80) != 0;
        
        if is_long {
            Self::parse_long(buf)
        } else {
            Self::parse_short(buf, dcid_len)
        }
    }

    fn parse_long<B: Buf>(buf: &mut B) -> Result<Self, HeaderError> {
        if buf.remaining() < 5 {
            return Err(HeaderError::BufferTooShort);
        }
        
        let first = buf.get_u8();
        let version = buf.get_u32();
        
        if version == 0 {
            // Version Negotiation
            // DCID Len, DCID, SCID Len, SCID
            if buf.remaining() < 1 { return Err(HeaderError::BufferTooShort); }
            let dcid_len = buf.get_u8() as usize;
            if buf.remaining() < dcid_len { return Err(HeaderError::BufferTooShort); }
            let dcid_bytes = buf.copy_to_bytes(dcid_len);
            let dcid = ConnectionId::new(&dcid_bytes).map_err(|_| HeaderError::InvalidCidLen)?;
            
            if buf.remaining() < 1 { return Err(HeaderError::BufferTooShort); }
            let scid_len = buf.get_u8() as usize;
            if buf.remaining() < scid_len { return Err(HeaderError::BufferTooShort); }
            let scid_bytes = buf.copy_to_bytes(scid_len);
            let scid = ConnectionId::new(&scid_bytes).map_err(|_| HeaderError::InvalidCidLen)?;
            
            return Ok(Header {
                packet_type: PacketType::VersionNegotiation,
                version,
                dcid,
                scid: Some(scid),
                token: None,
                packet_number: None,
                packet_number_len: 0,
                key_phase: false,
                payload_len: None,
            });
        }
        
        // Regular Long Header
        let dcid_len = buf.get_u8() as usize;
        if buf.remaining() < dcid_len { return Err(HeaderError::BufferTooShort); }
        let dcid_bytes = buf.copy_to_bytes(dcid_len);
        let dcid = ConnectionId::new(&dcid_bytes).map_err(|_| HeaderError::InvalidCidLen)?;
        
        if buf.remaining() < 1 { return Err(HeaderError::BufferTooShort); }
        let scid_len = buf.get_u8() as usize;
        if buf.remaining() < scid_len { return Err(HeaderError::BufferTooShort); }
        let scid_bytes = buf.copy_to_bytes(scid_len);
        let scid = ConnectionId::new(&scid_bytes).map_err(|_| HeaderError::InvalidCidLen)?;
        
        let type_bits = (first & 0x30) >> 4;
        let packet_type = match type_bits {
            0x0 => PacketType::Initial,
            0x1 => PacketType::ZeroRTT,
            0x2 => PacketType::Handshake,
            0x3 => PacketType::Retry,
            _ => unreachable!(),
        };
        
        let mut token = None;
        if packet_type == PacketType::Initial {
            let token_len = parse_varint(buf)?;
            if buf.remaining() < token_len as usize { return Err(HeaderError::BufferTooShort); }
            token = Some(buf.copy_to_bytes(token_len as usize));
        } else if packet_type == PacketType::Retry {
             return Ok(Header {
                 packet_type,
                 version,
                 dcid,
                 scid: Some(scid),
                 token: None, // Handled in Packet
                 packet_number: None,
                 packet_number_len: 0,
                 key_phase: false,
                 payload_len: None,
             });
        }
        
        // Length field (varint) - length of Packet Number + Payload
        let length = parse_varint(buf)?;
        
        let pn_len = (first & 0x03) as usize + 1;
        
        Ok(Header {
            packet_type,
            version,
            dcid,
            scid: Some(scid),
            token,
            packet_number: None, // Decoded later after header protection removal
            packet_number_len: pn_len,
            key_phase: false,
            payload_len: Some(length),
        })
    }

    fn parse_short<B: Buf>(buf: &mut B, dcid_len: usize) -> Result<Self, HeaderError> {
        if buf.remaining() < 1 + dcid_len {
            return Err(HeaderError::BufferTooShort);
        }
        
        let first = buf.get_u8();
        let dcid_bytes = buf.copy_to_bytes(dcid_len);
        let dcid = ConnectionId::new(&dcid_bytes).map_err(|_| HeaderError::InvalidCidLen)?;
        
        let key_phase = (first & 0x04) != 0;
        let pn_len = (first & 0x03) as usize + 1;
        
        Ok(Header {
            packet_type: PacketType::Short1RTT,
            version: 0, // Short header has no version
            dcid,
            scid: None,
            token: None,
            packet_number: None, // Decoded later
            packet_number_len: pn_len,
            key_phase,
            payload_len: None,
        })
    }

    pub fn new_long(
        packet_type: PacketType,
        version: u32,
        dcid: ConnectionId,
        scid: ConnectionId,
        packet_number: u64,
    ) -> Self {
        Self {
            packet_type,
            version,
            dcid,
            scid: Some(scid),
            token: None,
            packet_number: Some(PacketNumber(packet_number)),
            packet_number_len: 0,
            key_phase: false,
            payload_len: None,
        }
    }

    pub fn new_short(
        dcid: ConnectionId,
        packet_number: u64,
        key_phase: bool,
        _dcid_len: usize,
    ) -> Self {
        Self {
            packet_type: PacketType::Short1RTT,
            version: 0,
            dcid,
            scid: None,
            token: None,
            packet_number: Some(PacketNumber(packet_number)),
            packet_number_len: 0,
            key_phase,
            payload_len: None,
        }
    }

    pub fn write<B: BufMut>(&self, buf: &mut B) {
        let pn = self.packet_number.unwrap().0;
        let pn_len = if self.packet_number_len > 0 { self.packet_number_len } else { 4 };
        
        let mut first_byte = 0u8;
        if self.packet_type == PacketType::Short1RTT {
            first_byte |= 0x40;
            if self.key_phase { first_byte |= 0x04; }
            first_byte |= (pn_len as u8 - 1) & 0x03;
            buf.put_u8(first_byte);
            
            buf.put_slice(self.dcid.as_ref());
        } else {
            first_byte |= 0x80;
            first_byte |= 0x40;
            let type_bits = match self.packet_type {
                PacketType::Initial => 0x00,
                PacketType::ZeroRTT => 0x10,
                PacketType::Handshake => 0x20,
                PacketType::Retry => 0x30,
                _ => 0,
            };
            first_byte |= type_bits;
            first_byte |= (pn_len as u8 - 1) & 0x03;
            buf.put_u8(first_byte);
            
            buf.put_u32(self.version);
            
            buf.put_u8(self.dcid.len() as u8);
            buf.put_slice(self.dcid.as_ref());
            
            let scid = self.scid.as_ref().unwrap();
            buf.put_u8(scid.len() as u8);
            buf.put_slice(scid.as_ref());
            
            if self.packet_type == PacketType::Initial {
                let token = self.token.as_ref().map(|t| t.as_ref()).unwrap_or(&[]);
                write_varint_buf(buf, token.len() as u64);
                buf.put_slice(token);
            }
            
            if let Some(len) = self.payload_len {
                write_varint_buf(buf, len);
            } else {
                write_varint_buf(buf, 0);
            }
        }
        
        let mask = match pn_len {
            1 => 0xFF,
            2 => 0xFFFF,
            3 => 0xFFFFFF,
            4 => 0xFFFFFFFF,
            _ => 0xFFFFFFFF,
        };
        let truncated_pn = pn & mask;
        
        match pn_len {
            1 => buf.put_u8(truncated_pn as u8),
            2 => buf.put_u16(truncated_pn as u16),
            3 => {
                buf.put_u8((truncated_pn >> 16) as u8);
                buf.put_u16((truncated_pn & 0xFFFF) as u16);
            }
            4 => buf.put_u32(truncated_pn as u32),
            _ => buf.put_u32(truncated_pn as u32),
        }
    }
    
    pub fn len(&self) -> usize {
        let mut len = 0;
        if self.packet_type == PacketType::Short1RTT {
            len += 1;
            len += self.dcid.len();
            len += if self.packet_number_len > 0 { self.packet_number_len } else { 4 };
        } else {
            len += 1;
            len += 4;
            len += 1 + self.dcid.len();
            len += 1 + self.scid.as_ref().map(|s| s.len()).unwrap_or(0);
            if self.packet_type == PacketType::Initial {
                let token_len = self.token.as_ref().map(|t| t.len()).unwrap_or(0);
                len += varint_len(token_len as u64) + token_len;
            }
            len += varint_len(self.payload_len.unwrap_or(0));
            len += if self.packet_number_len > 0 { self.packet_number_len } else { 4 };
        }
        len
    }
}

fn write_varint_buf<B: BufMut>(buf: &mut B, val: u64) {
    if val <= 63 {
        buf.put_u8(val as u8);
    } else if val <= 16383 {
        buf.put_u16((val as u16) | 0x4000);
    } else if val <= 1073741823 {
        buf.put_u32((val as u32) | 0x80000000);
    } else {
        buf.put_u64(val | 0xC000000000000000);
    }
}

fn varint_len(val: u64) -> usize {
    if val <= 63 { 1 }
    else if val <= 16383 { 2 }
    else if val <= 1073741823 { 4 }
    else { 8 }
}

pub fn packet_number_len(pn: u64, largest_acked: u64) -> usize {
    let diff = if pn > largest_acked { pn - largest_acked } else { largest_acked - pn };
    let range = diff * 2;
    if range < (1 << 8) { 1 }
    else if range < (1 << 16) { 2 }
    else if range < (1 << 24) { 3 }
    else { 4 }
}

fn parse_varint<B: Buf>(buf: &mut B) -> Result<u64, HeaderError> {
    if !buf.has_remaining() { return Err(HeaderError::BufferTooShort); }
    let first = buf.chunk()[0];
    let prefix = first >> 6;
    let len = 1 << prefix;
    
    if buf.remaining() < len { return Err(HeaderError::BufferTooShort); }
    
    let val = match len {
        1 => buf.get_u8() as u64,
        2 => (buf.get_u16() & 0x3FFF) as u64,
        4 => (buf.get_u32() & 0x3FFFFFFF) as u64,
        8 => (buf.get_u64() & 0x3FFFFFFFFFFFFFFF),
        _ => unreachable!(),
    };
    Ok(val)
}
