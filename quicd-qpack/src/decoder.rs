//! QPACK Decoder implementation per RFC 9204.
//! 
//! Lock-free, zero-copy decoder with:
//! - Header block parsing
//! - Encoder stream instruction processing
//! - Blocked stream handling
//! - Decoder stream instruction generation

use bytes::Bytes;
use std::collections::{HashMap, VecDeque};

#[cfg(test)]
use bytes::BytesMut;

use crate::error::{QpackError, Result};
use crate::header_block::{EncodedPrefix, FieldLine};
use crate::instructions::{DecoderInstruction, EncoderInstruction};
use crate::static_table;
use crate::table::DynamicTable;

/// Decoded header field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderField {
    pub name: Bytes,
    pub value: Bytes,
}

/// QPACK Decoder state.
pub struct Decoder {
    /// Dynamic table (owned by decoder for write access).
    table: DynamicTable,
    
    /// Decoder stream instruction queue.
    decoder_stream_buffer: VecDeque<Bytes>,
    
    /// Blocked header blocks awaiting dynamic table entries.
    /// Maps stream_id -> (required_insert_count, encoded_block)
    blocked_streams: HashMap<u64, (u64, Bytes)>,
    
    /// Maximum blocked streams allowed.
    max_blocked_streams: usize,
}

impl Decoder {
    /// Create a new decoder.
    pub fn new(max_table_capacity: usize, max_blocked_streams: usize) -> Self {
        let mut table = DynamicTable::new(max_table_capacity);
        let _ = table.set_capacity(max_table_capacity);
        
        Self {
            table,
            decoder_stream_buffer: VecDeque::new(),
            blocked_streams: HashMap::new(),
            max_blocked_streams,
        }
    }
    
    /// Get immutable reference to dynamic table (for testing/inspection).
    pub fn table(&self) -> &DynamicTable {
        &self.table
    }
    
    /// Decode a header block.
    /// 
    /// # Arguments
    /// * `stream_id` - HTTP/3 stream ID
    /// * `data` - Encoded header block bytes
    /// 
    /// # Returns
    /// Vector of decoded header fields, or blocks if entries not available
    pub fn decode(&mut self, stream_id: u64, data: Bytes) -> Result<Vec<HeaderField>> {
        // Decode prefix
        let max_entries = self.table.capacity() as u64 / 32;
        let total_inserted = self.table.insert_count();
        
        let (prefix, mut offset) = EncodedPrefix::decode(&data, max_entries, total_inserted)?;
        
        // Check if we need to block
        let insert_count = self.table.insert_count();
        if prefix.required_insert_count > insert_count {
            // Block this stream
            if self.blocked_streams.len() >= self.max_blocked_streams {
                return Err(QpackError::BlockedStreamLimitExceeded);
            }
            self.blocked_streams
                .insert(stream_id, (prefix.required_insert_count, data));
            return Err(QpackError::DecompressionFailed(
                "Header block blocked on dynamic table".into(),
            ));
        }
        
        let base = prefix.base();
        let mut headers = Vec::new();
        
        // Decode field lines
        while offset < data.len() {
            let (field_line, consumed) = FieldLine::decode(&data[offset..], base)?;
            offset += consumed;
            
            let header = self.resolve_field_line(field_line)?;
            headers.push(header);
        }
        
        // Send Section Acknowledgement
        let ack = DecoderInstruction::SectionAck { stream_id };
        self.decoder_stream_buffer.push_back(ack.encode());
        
        Ok(headers)
    }
    
    /// Process encoder stream instruction.
    pub fn process_encoder_instruction(&mut self, data: &[u8]) -> Result<()> {
        let mut offset = 0;
        
        while offset < data.len() {
            let (inst, consumed) = EncoderInstruction::decode(&data[offset..])?;
            offset += consumed;
            
            match inst {
                EncoderInstruction::SetCapacity { capacity } => {
                    self.handle_set_capacity(capacity as usize)?;
                }
                
                EncoderInstruction::InsertWithNameRef {
                    is_static,
                    name_index,
                    value,
                } => {
                    self.handle_insert_with_name_ref(is_static, name_index, value)?;
                }
                
                EncoderInstruction::InsertLiteral { name, value } => {
                    self.handle_insert_literal(name, value)?;
                }
                
                EncoderInstruction::Duplicate { index } => {
                    self.handle_duplicate(index)?;
                }
            }
            
            // Check if any blocked streams can now be decoded
            self.process_blocked_streams()?;
        }
        
        Ok(())
    }
    
    /// Get next decoder stream instruction (if any).
    pub fn poll_decoder_stream(&mut self) -> Option<Bytes> {
        self.decoder_stream_buffer.pop_front()
    }
    
    /// Drain all decoder stream instructions.
    pub fn drain_decoder_stream(&mut self) -> Vec<Bytes> {
        self.decoder_stream_buffer.drain(..).collect()
    }
    
    /// Cancel a stream (e.g., on stream reset).
    pub fn cancel_stream(&mut self, stream_id: u64) {
        if self.blocked_streams.remove(&stream_id).is_some() {
            let cancel = DecoderInstruction::StreamCancel { stream_id };
            self.decoder_stream_buffer.push_back(cancel.encode());
        }
    }
    
    /// Resolve a field line to a header field.
    fn resolve_field_line(&self, field_line: FieldLine) -> Result<HeaderField> {
        match field_line {
            FieldLine::IndexedStatic { index } => {
                let entry = static_table::get(index as usize)
                    .ok_or(QpackError::InvalidStaticIndex(index))?;
                Ok(HeaderField {
                    name: Bytes::copy_from_slice(entry.name),
                    value: Bytes::copy_from_slice(entry.value),
                })
            }
            
            FieldLine::IndexedDynamic { absolute_index } => {
                let entry = self
                    .table
                    .get(absolute_index)
                    .ok_or(QpackError::InvalidDynamicIndex(absolute_index))?;
                Ok(HeaderField {
                    name: entry.name.clone(),
                    value: entry.value.clone(),
                })
            }
            
            FieldLine::IndexedDynamicPost { index } => {
                // Post-base index: base + index
                let base = self.table.insert_count();
                let absolute_index = base + index;
                let entry = self
                    .table
                    .get(absolute_index)
                    .ok_or(QpackError::InvalidDynamicIndex(absolute_index))?;
                Ok(HeaderField {
                    name: entry.name.clone(),
                    value: entry.value.clone(),
                })
            }
            
            FieldLine::LiteralStaticName {
                name_index,
                value,
                never_indexed: _,
            } => {
                let entry = static_table::get(name_index as usize)
                    .ok_or(QpackError::InvalidStaticIndex(name_index))?;
                Ok(HeaderField {
                    name: Bytes::copy_from_slice(entry.name),
                    value,
                })
            }
            
            FieldLine::LiteralDynamicName {
                name_index,
                value,
                never_indexed: _,
            } => {
                let entry = self
                    .table
                    .get(name_index)
                    .ok_or(QpackError::InvalidDynamicIndex(name_index))?;
                Ok(HeaderField {
                    name: entry.name.clone(),
                    value,
                })
            }
            
            FieldLine::LiteralName {
                name,
                value,
                never_indexed: _,
            } => Ok(HeaderField { name, value }),
            
            FieldLine::LiteralPostBaseName {
                name_index,
                value,
                never_indexed: _,
            } => {
                let base = self.table.insert_count();
                let absolute_index = base + name_index;
                let entry = self
                    .table
                    .get(absolute_index)
                    .ok_or(QpackError::InvalidDynamicIndex(absolute_index))?;
                Ok(HeaderField {
                    name: entry.name.clone(),
                    value,
                })
            }
        }
    }
    
    /// Handle Set Capacity instruction.
    fn handle_set_capacity(&mut self, capacity: usize) -> Result<()> {
        self.table.set_capacity(capacity)?;
        Ok(())
    }
    
    /// Handle Insert With Name Reference instruction.
    fn handle_insert_with_name_ref(
        &mut self,
        is_static: bool,
        name_index: u64,
        value: Bytes,
    ) -> Result<()> {
        let name = if is_static {
            let entry = static_table::get(name_index as usize)
                .ok_or(QpackError::InvalidStaticIndex(name_index))?;
            Bytes::copy_from_slice(entry.name)
        } else {
            let entry = self
                .table
                .get(name_index)
                .ok_or(QpackError::InvalidDynamicIndex(name_index))?;
            entry.name.clone()
        };
        
        self.table.insert(name, value)?;
        
        // Emit Insert Count Increment
        let inc = DecoderInstruction::InsertCountIncrement { increment: 1 };
        self.decoder_stream_buffer.push_back(inc.encode());
        
        Ok(())
    }
    
    /// Handle Insert Literal instruction.
    fn handle_insert_literal(&mut self, name: Bytes, value: Bytes) -> Result<()> {
        self.table.insert(name, value)?;
        
        // Emit Insert Count Increment
        let inc = DecoderInstruction::InsertCountIncrement { increment: 1 };
        self.decoder_stream_buffer.push_back(inc.encode());
        
        Ok(())
    }
    
    /// Handle Duplicate instruction.
    fn handle_duplicate(&mut self, index: u64) -> Result<()> {
        let entry = self
            .table
            .get(index)
            .ok_or(QpackError::InvalidDynamicIndex(index))?;
        
        let name = entry.name.clone();
        let value = entry.value.clone();
        
        self.table.insert(name, value)?;
        
        // Emit Insert Count Increment
        let inc = DecoderInstruction::InsertCountIncrement { increment: 1 };
        self.decoder_stream_buffer.push_back(inc.encode());
        
        Ok(())
    }
    
    /// Try to decode blocked streams after dynamic table update.
    fn process_blocked_streams(&mut self) -> Result<()> {
        let insert_count = self.table.insert_count();
        let mut unblocked = Vec::new();
        
        for (stream_id, (ric, _)) in &self.blocked_streams {
            if *ric <= insert_count {
                unblocked.push(*stream_id);
            }
        }
        
        for stream_id in unblocked {
            if let Some((_, data)) = self.blocked_streams.remove(&stream_id) {
                // Retry decoding
                let _ = self.decode(stream_id, data);
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_decode_static_only() {
        let mut decoder = Decoder::new(4096, 100);
        
        // Manually construct simple header block with static entries
        let mut data = BytesMut::new();
        
        // Prefix: RIC=0, Delta=0
        data.extend_from_slice(&[0x00, 0x00]);
        
        // Indexed static :method=GET (index 17)
        data.extend_from_slice(&[0xC0 | 17]); // 11xxxxxx with index 17
        
        let headers = decoder.decode(0, data.freeze()).unwrap();
        
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].name.as_ref(), b":method");
        assert_eq!(headers[0].value.as_ref(), b"GET");
    }
    
    #[test]
    fn test_process_set_capacity() {
        let mut decoder = Decoder::new(4096, 100);
        
        let inst = EncoderInstruction::SetCapacity { capacity: 2048 };
        decoder.process_encoder_instruction(&inst.encode()).unwrap();
        
        assert_eq!(decoder.table.capacity(), 2048);
    }
}
