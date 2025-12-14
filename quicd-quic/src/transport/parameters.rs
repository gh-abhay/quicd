use crate::packet::ConnectionId;
use bytes::{Buf, BufMut, BytesMut};
use anyhow::{Result, anyhow};

#[derive(Debug, Clone, PartialEq)]
pub struct TransportParameters {
    pub original_destination_connection_id: Option<ConnectionId>,
    pub max_idle_timeout: u64, // milliseconds
    pub stateless_reset_token: Option<[u8; 16]>,
    pub max_udp_payload_size: u64,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub ack_delay_exponent: u64,
    pub max_ack_delay: u64, // milliseconds
    pub disable_active_migration: bool,
    pub active_connection_id_limit: u64,
    pub initial_source_connection_id: Option<ConnectionId>,
    pub retry_source_connection_id: Option<ConnectionId>,
}

impl Default for TransportParameters {
    fn default() -> Self {
        Self {
            original_destination_connection_id: None,
            max_idle_timeout: 0,
            stateless_reset_token: None,
            max_udp_payload_size: 65527,
            initial_max_data: 0,
            initial_max_stream_data_bidi_local: 0,
            initial_max_stream_data_bidi_remote: 0,
            initial_max_stream_data_uni: 0,
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 0,
            ack_delay_exponent: 3,
            max_ack_delay: 25,
            disable_active_migration: false,
            active_connection_id_limit: 2,
            initial_source_connection_id: None,
            retry_source_connection_id: None,
        }
    }
}

impl TransportParameters {
    pub fn encode(&self, buf: &mut BytesMut) {
        // Helper to write param
        fn write_param(buf: &mut BytesMut, id: u64, val: &[u8]) {
            write_varint(buf, id);
            write_varint(buf, val.len() as u64);
            buf.put_slice(val);
        }
        
        fn write_varint_param(buf: &mut BytesMut, id: u64, val: u64) {
            // Check defaults
            match id {
                0x01 if val == 0 => return,
                0x03 if val == 65527 => return,
                0x04..=0x09 if val == 0 => return,
                0x0a if val == 3 => return,
                0x0b if val == 25 => return,
                0x0e if val == 2 => return,
                _ => {}
            }

            let mut tmp = [0u8; 8];
            let len = encode_varint(val, &mut tmp);
            write_param(buf, id, &tmp[..len]);
        }

        if let Some(cid) = &self.original_destination_connection_id {
            write_param(buf, 0x00, cid.as_bytes());
        }
        
        write_varint_param(buf, 0x01, self.max_idle_timeout);
        
        if let Some(token) = &self.stateless_reset_token {
            write_param(buf, 0x02, token);
        }
        
        write_varint_param(buf, 0x03, self.max_udp_payload_size);
        write_varint_param(buf, 0x04, self.initial_max_data);
        write_varint_param(buf, 0x05, self.initial_max_stream_data_bidi_local);
        write_varint_param(buf, 0x06, self.initial_max_stream_data_bidi_remote);
        write_varint_param(buf, 0x07, self.initial_max_stream_data_uni);
        write_varint_param(buf, 0x08, self.initial_max_streams_bidi);
        write_varint_param(buf, 0x09, self.initial_max_streams_uni);
        write_varint_param(buf, 0x0a, self.ack_delay_exponent);
        write_varint_param(buf, 0x0b, self.max_ack_delay);
        
        if self.disable_active_migration {
            write_param(buf, 0x0c, &[]);
        }
        
        write_varint_param(buf, 0x0e, self.active_connection_id_limit);
        
        if let Some(cid) = &self.initial_source_connection_id {
            write_param(buf, 0x0f, cid.as_bytes());
        }
        
        if let Some(cid) = &self.retry_source_connection_id {
            write_param(buf, 0x10, cid.as_bytes());
        }
    }

    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self> {
        let mut params = Self::default();
        
        while buf.has_remaining() {
            let id = parse_varint(buf)?;
            let len = parse_varint(buf)?;
            
            if buf.remaining() < len as usize {
                return Err(anyhow!("Buffer too short for param length"));
            }
            
            // We need to read the value.
            // Since we can't easily peek/slice without consuming in generic Buf,
            // we'll copy to a small buffer or handle specific types.
            // But `len` can be large? No, params are small.
            
            let mut val_buf = buf.copy_to_bytes(len as usize);
            
            match id {
                0x00 => params.original_destination_connection_id = Some(ConnectionId::new(&val_buf).map_err(|_| anyhow!("Invalid CID"))?),
                0x01 => params.max_idle_timeout = parse_varint(&mut val_buf)?,
                0x02 => {
                    if val_buf.len() != 16 { return Err(anyhow!("Invalid Stateless Reset Token length")); }
                    let mut token = [0u8; 16];
                    val_buf.copy_to_slice(&mut token);
                    params.stateless_reset_token = Some(token);
                }
                0x03 => params.max_udp_payload_size = parse_varint(&mut val_buf)?,
                0x04 => params.initial_max_data = parse_varint(&mut val_buf)?,
                0x05 => params.initial_max_stream_data_bidi_local = parse_varint(&mut val_buf)?,
                0x06 => params.initial_max_stream_data_bidi_remote = parse_varint(&mut val_buf)?,
                0x07 => params.initial_max_stream_data_uni = parse_varint(&mut val_buf)?,
                0x08 => params.initial_max_streams_bidi = parse_varint(&mut val_buf)?,
                0x09 => params.initial_max_streams_uni = parse_varint(&mut val_buf)?,
                0x0a => params.ack_delay_exponent = parse_varint(&mut val_buf)?,
                0x0b => params.max_ack_delay = parse_varint(&mut val_buf)?,
                0x0c => params.disable_active_migration = true,
                0x0e => params.active_connection_id_limit = parse_varint(&mut val_buf)?,
                0x0f => params.initial_source_connection_id = Some(ConnectionId::new(&val_buf).map_err(|_| anyhow!("Invalid CID"))?),
                0x10 => params.retry_source_connection_id = Some(ConnectionId::new(&val_buf).map_err(|_| anyhow!("Invalid CID"))?),
                _ => {
                    // Ignore unknown parameters
                }
            }
        }
        
        Ok(params)
    }
    
    /// Validate transport parameters per RFC 9000 Section 18.2
    pub fn validate(&self) -> Result<()> {
        // ack_delay_exponent must be <= 20
        if self.ack_delay_exponent > 20 {
            return Err(anyhow!("ack_delay_exponent must be <= 20, got {}", self.ack_delay_exponent));
        }
        
        // max_ack_delay must be < 2^14 milliseconds
        if self.max_ack_delay >= (1 << 14) {
            return Err(anyhow!("max_ack_delay must be < 2^14 ms, got {}", self.max_ack_delay));
        }
        
        // active_connection_id_limit must be >= 2
        if self.active_connection_id_limit < 2 {
            return Err(anyhow!("active_connection_id_limit must be >= 2, got {}", self.active_connection_id_limit));
        }
        
        // max_udp_payload_size must be >= 1200
        if self.max_udp_payload_size < 1200 {
            return Err(anyhow!("max_udp_payload_size must be >= 1200, got {}", self.max_udp_payload_size));
        }
        
        Ok(())
    }
}

fn write_varint(buf: &mut BytesMut, val: u64) {
    if val < 64 {
        buf.put_u8(val as u8);
    } else if val < 16384 {
        buf.put_u16((val as u16) | 0x4000);
    } else if val < 1073741824 {
        buf.put_u32((val as u32) | 0x80000000);
    } else {
        buf.put_u64(val | 0xC000000000000000);
    }
}

fn encode_varint(val: u64, buf: &mut [u8]) -> usize {
    if val < 64 {
        buf[0] = val as u8;
        1
    } else if val < 16384 {
        let v = (val as u16) | 0x4000;
        buf[0] = (v >> 8) as u8;
        buf[1] = v as u8;
        2
    } else if val < 1073741824 {
        let v = (val as u32) | 0x80000000;
        buf[0] = (v >> 24) as u8;
        buf[1] = (v >> 16) as u8;
        buf[2] = (v >> 8) as u8;
        buf[3] = v as u8;
        4
    } else {
        let v = val | 0xC000000000000000;
        buf[0] = (v >> 56) as u8;
        buf[1] = (v >> 48) as u8;
        buf[2] = (v >> 40) as u8;
        buf[3] = (v >> 32) as u8;
        buf[4] = (v >> 24) as u8;
        buf[5] = (v >> 16) as u8;
        buf[6] = (v >> 8) as u8;
        buf[7] = v as u8;
        8
    }
}

fn parse_varint<B: Buf>(buf: &mut B) -> Result<u64> {
    if !buf.has_remaining() { return Err(anyhow!("Buffer too short")); }
    let first = buf.chunk()[0];
    let prefix = first >> 6;
    let len = 1 << prefix;
    
    if buf.remaining() < len { return Err(anyhow!("Buffer too short")); }
    
    let val = match len {
        1 => buf.get_u8() as u64,
        2 => (buf.get_u16() & 0x3FFF) as u64,
        4 => (buf.get_u32() & 0x3FFFFFFF) as u64,
        8 => (buf.get_u64() & 0x3FFFFFFFFFFFFFFF),
        _ => unreachable!(),
    };
    Ok(val)
}
