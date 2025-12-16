//! Full QPACK encoder implementation.
//!
//! Encodes HTTP header field sections using QPACK compression per RFC 9204.

use crate::{
    dynamic_table::DynamicTable,
    error::{Error, Result},
    field_line::FieldLine,
    instructions::{DecoderInstruction, EncoderInstruction},
    {integer, huffman, static_table},
};
use bytes::{Bytes, BytesMut};
use std::collections::HashMap;

/// Reference tracking for blocked streams.
#[derive(Debug)]
struct StreamRef {
    required_insert_count: u64,
}

/// QPACK encoder.
pub struct Encoder {
    dynamic_table: DynamicTable,
    max_blocked_streams: usize,
    blocked_streams: HashMap<u64, StreamRef>,
    known_received_count: u64,
    use_huffman: bool,
}

impl Encoder {
    /// Creates a new encoder with the given dynamic table capacity.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum dynamic table size in bytes
    /// * `max_blocked_streams` - Maximum number of streams that can be blocked
    pub fn new(capacity: usize, max_blocked_streams: usize) -> Self {
        Self {
            dynamic_table: DynamicTable::new(capacity, capacity),
            max_blocked_streams,
            blocked_streams: HashMap::new(),
            known_received_count: 0,
            use_huffman: true,
        }
    }

    /// Sets whether to use Huffman encoding for strings.
    pub fn set_use_huffman(&mut self, use_huffman: bool) {
        self.use_huffman = use_huffman;
    }

    /// Encodes a field section for the given stream.
    ///
    /// Returns the encoded field section bytes and any encoder instructions
    /// that should be sent on the encoder stream.
    pub fn encode_field_section(
        &mut self,
        stream_id: u64,
        fields: &[FieldLine],
    ) -> Result<(Bytes, Vec<EncoderInstruction>)> {
        let mut encoder_instructions = Vec::new();
        let mut field_section = Vec::new();
        
        let base = self.dynamic_table.insert_count();
        let mut required_insert_count = 0u64;

        // Encode each field
        for field in fields {
            let (repr_bytes, new_ric) = self.encode_field_line(
                field,
                base,
                &mut encoder_instructions,
            )?;
            field_section.extend_from_slice(&repr_bytes);
            required_insert_count = required_insert_count.max(new_ric);
        }

        // Encode prefix
        let mut prefix = Vec::new();
        self.encode_prefix(required_insert_count, base, &mut prefix)?;

        // Combine prefix and field section
        let mut result = BytesMut::with_capacity(prefix.len() + field_section.len());
        result.extend_from_slice(&prefix);
        result.extend_from_slice(&field_section);

        // Track blocked streams
        if required_insert_count > 0 {
            if self.blocked_streams.len() >= self.max_blocked_streams {
                return Err(Error::TooManyBlockedStreams(
                    self.blocked_streams.len() + 1,
                    self.max_blocked_streams,
                ));
            }
            self.blocked_streams.insert(stream_id, StreamRef { required_insert_count });
        }

        Ok((result.freeze(), encoder_instructions))
    }

    /// Encodes a single field line.
    fn encode_field_line(
        &mut self,
        field: &FieldLine,
        base: u64,
        encoder_instructions: &mut Vec<EncoderInstruction>,
    ) -> Result<(Vec<u8>, u64)> {
        let mut buf = Vec::new();
        let mut required_insert_count = 0u64;

        // Try static table exact match
        if let Some(index) = static_table::find_exact(
            &String::from_utf8_lossy(&field.name),
            &String::from_utf8_lossy(&field.value),
        ) {
            // Indexed from static table (1T with T=1)
            let mut temp = [0u8; 16];
            let n = integer::encode(index as u64, 6, 0xC0, &mut temp);
            buf.extend_from_slice(&temp[..n]);
            return Ok((buf, 0));
        }

        // Try dynamic table (only use acknowledged entries)
        if self.known_received_count > 0 {
            // Check if we can reference dynamic table entries
            for abs_idx in 0..self.known_received_count.min(self.dynamic_table.insert_count()) {
                if let Some(entry) = self.dynamic_table.get_absolute(abs_idx) {
                    if entry.name == field.name && entry.value == field.value {
                        // Found exact match in acknowledged dynamic table
                        if abs_idx < base {
                            // Use relative indexing (1T with T=0)
                            let relative_idx = base - abs_idx - 1;
                            let mut temp = [0u8; 16];
                            let n = integer::encode(relative_idx, 6, 0x80, &mut temp);
                            buf.extend_from_slice(&temp[..n]);
                            required_insert_count = abs_idx + 1;
                        } else {
                            // Use post-base indexing (0001)
                            let post_base_idx = abs_idx - base;
                            let mut temp = [0u8; 16];
                            let n = integer::encode(post_base_idx, 4, 0x10, &mut temp);
                            buf.extend_from_slice(&temp[..n]);
                            required_insert_count = abs_idx + 1;
                        }
                        return Ok((buf, required_insert_count));
                    }
                }
            }
        }

        // Try static table name match
        let static_name_matches: Vec<_> = static_table::find_by_name(
            &String::from_utf8_lossy(&field.name)
        ).collect();
        
        if let Some((static_idx, _)) = static_name_matches.first() {
            // Literal with static name reference (01NT with T=1, N=Huffman for value)
            let mut temp = [0u8; 16];
            let pattern = if self.use_huffman { 0x70 } else { 0x50 }; // 01NT with T=1
            let n = integer::encode(*static_idx as u64, 4, pattern, &mut temp);
            buf.extend_from_slice(&temp[..n]);
            encode_string(&field.value, self.use_huffman, 8, 0x00, &mut buf);
            
            // Opportunistically insert into dynamic table for future use
            if field.size() <= self.dynamic_table.capacity() / 4 {
                let _ = self.dynamic_table.insert(field.clone());
                encoder_instructions.push(EncoderInstruction::InsertWithNameRef {
                    is_static: true,
                    name_index: *static_idx as u64,
                    value: field.value.clone(),
                    huffman_value: self.use_huffman,
                });
            }
            
            return Ok((buf, 0));
        }

        // Literal with literal name (001N) - no reference possible
        // Manually encode to use correct Huffman bit position
        if self.use_huffman {
            let mut encoded_name = Vec::new();
            huffman::encode(&field.name, &mut encoded_name);
            let mut temp = [0u8; 16];
            let n = integer::encode(encoded_name.len() as u64, 3, 0x30, &mut temp); // 001N with N=1
            buf.extend_from_slice(&temp[..n]);
            buf.extend_from_slice(&encoded_name);
        } else {
            let mut temp = [0u8; 16];
            let n = integer::encode(field.name.len() as u64, 3, 0x20, &mut temp); // 001N with N=0
            buf.extend_from_slice(&temp[..n]);
            buf.extend_from_slice(&field.name);
        }
        
        // Value uses standard string encoding with H bit at position 7
        encode_string(&field.value, self.use_huffman, 8, 0x00, &mut buf);

        // Insert into dynamic table for future use
        if field.size() <= self.dynamic_table.capacity() / 2 {
            let _ = self.dynamic_table.insert(field.clone());
            encoder_instructions.push(EncoderInstruction::InsertWithLiteralName {
                name: field.name.clone(),
                huffman_name: self.use_huffman,
                value: field.value.clone(),
                huffman_value: self.use_huffman,
            });
        }

        Ok((buf, required_insert_count))
    }

    /// Encodes the field section prefix.
    fn encode_prefix(&self, required_insert_count: u64, base: u64, buf: &mut Vec<u8>) -> Result<()> {
        // Calculate max entries
        let max_entries = if self.dynamic_table.capacity() == 0 {
            0
        } else {
            self.dynamic_table.capacity() / 32
        };

        // Encode Required Insert Count
        let enc_insert_count = if required_insert_count == 0 {
            0
        } else {
            let full_range = 2 * max_entries as u64;
            (required_insert_count % full_range) + 1
        };

        let mut temp = [0u8; 16];
        let n = integer::encode(enc_insert_count, 8, 0x00, &mut temp);
        buf.extend_from_slice(&temp[..n]);

        // Encode Base (S bit + Delta Base)
        if base >= required_insert_count {
            let delta = base - required_insert_count;
            let m = integer::encode(delta, 7, 0x00, &mut temp);
            buf.extend_from_slice(&temp[..m]);
        } else {
            let delta = required_insert_count - base - 1;
            let m = integer::encode(delta, 7, 0x80, &mut temp);
            buf.extend_from_slice(&temp[..m]);
        }

        Ok(())
    }

    /// Processes a decoder instruction.
    pub fn process_decoder_instruction(&mut self, instruction: &DecoderInstruction) -> Result<()> {
        match instruction {
            DecoderInstruction::SectionAck { stream_id } => {
                if let Some(stream_ref) = self.blocked_streams.remove(stream_id) {
                    // Update known received count
                    if stream_ref.required_insert_count > self.known_received_count {
                        self.known_received_count = stream_ref.required_insert_count;
                    }
                }
            }
            DecoderInstruction::StreamCancel { stream_id } => {
                self.blocked_streams.remove(stream_id);
            }
            DecoderInstruction::InsertCountIncrement { increment } => {
                self.known_received_count += increment;
                if self.known_received_count > self.dynamic_table.insert_count() {
                    return Err(Error::DecoderStreamError(
                        "known received count exceeds insert count".into()
                    ));
                }
            }
        }
        Ok(())
    }

    /// Returns the current dynamic table capacity.
    pub fn capacity(&self) -> usize {
        self.dynamic_table.capacity()
    }

    /// Sets a new dynamic table capacity.
    pub fn set_capacity(&mut self, capacity: usize) -> Result<EncoderInstruction> {
        self.dynamic_table.set_capacity(capacity)?;
        Ok(EncoderInstruction::SetCapacity { capacity: capacity as u64 })
    }
}

/// Encodes a string literal with Huffman encoding option.
fn encode_string(data: &[u8], use_huffman: bool, prefix_bits: u8, prefix_mask: u8, buf: &mut Vec<u8>) {
    let huffman = use_huffman && huffman::encoded_size(data) < data.len();
    
    if huffman {
        let mut encoded = Vec::new();
        huffman::encode(data, &mut encoded);
        
        let mut temp = [0u8; 16];
        let n = integer::encode(encoded.len() as u64, prefix_bits - 1, prefix_mask | 0x80, &mut temp);
        buf.extend_from_slice(&temp[..n]);
        buf.extend_from_slice(&encoded);
    } else {
        let mut temp = [0u8; 16];
        let n = integer::encode(data.len() as u64, prefix_bits - 1, prefix_mask, &mut temp);
        buf.extend_from_slice(&temp[..n]);
        buf.extend_from_slice(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encoder_creation() {
        let encoder = Encoder::new(4096, 100);
        assert_eq!(encoder.capacity(), 4096);
    }

    #[test]
    fn test_encode_static_table() {
        let mut encoder = Encoder::new(4096, 100);
        let fields = vec![
            FieldLine::new(":method", "GET"),
            FieldLine::new(":path", "/"),
        ];

        let (encoded, instructions) = encoder.encode_field_section(0, &fields).unwrap();
        assert!(!encoded.is_empty());
        assert!(instructions.is_empty()); // No dynamic table insertions
    }

    #[test]
    fn test_encode_literal() {
        let mut encoder = Encoder::new(4096, 100);
        let fields = vec![
            FieldLine::new("custom-header", "custom-value"),
        ];

        let (encoded, _) = encoder.encode_field_section(0, &fields).unwrap();
        assert!(!encoded.is_empty());
    }
}
