//! Full QPACK decoder implementation.
//!
//! Decodes QPACK-compressed HTTP header field sections per RFC 9204.

use crate::{
    dynamic_table::DynamicTable,
    error::{Error, Result},
    field_line::FieldLine,
    instructions::{DecoderInstruction, EncoderInstruction},
    {huffman, integer, static_table},
};
use bytes::Bytes;
use std::collections::{HashMap, VecDeque};

/// A blocked stream waiting for dynamic table entries.
struct BlockedStream {
    stream_id: u64,
    required_insert_count: u64,
    #[allow(dead_code)]
    data: Vec<u8>,
}

/// QPACK decoder.
pub struct Decoder {
    dynamic_table: DynamicTable,
    max_blocked_streams: usize,
    blocked_streams: VecDeque<BlockedStream>,
    decoded_sections: HashMap<u64, u64>, // stream_id -> required insert count
}

impl Decoder {
    /// Creates a new decoder with the given dynamic table capacity.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum dynamic table size in bytes
    /// * `max_blocked_streams` - Maximum number of streams that can be blocked
    pub fn new(capacity: usize, max_blocked_streams: usize) -> Self {
        Self {
            dynamic_table: DynamicTable::new(capacity, capacity),
            max_blocked_streams,
            blocked_streams: VecDeque::new(),
            decoded_sections: HashMap::new(),
        }
    }

    /// Decodes a field section from the given stream.
    ///
    /// Returns the decoded field lines, or an error if decoding fails
    /// or the stream is blocked.
    pub fn decode_field_section(&mut self, stream_id: u64, data: &[u8]) -> Result<Vec<FieldLine>> {
        // Decode prefix
        let (required_insert_count, base, mut pos) = self.decode_prefix(data)?;

        // Check if we can decode now
        if required_insert_count > self.dynamic_table.insert_count() {
            // Stream is blocked
            if self.blocked_streams.len() >= self.max_blocked_streams {
                return Err(Error::TooManyBlockedStreams(
                    self.blocked_streams.len() + 1,
                    self.max_blocked_streams,
                ));
            }
            self.blocked_streams.push_back(BlockedStream {
                stream_id,
                required_insert_count,
                data: data.to_vec(),
            });
            return Err(Error::Blocked(stream_id));
        }

        // Decode field lines
        let mut fields = Vec::new();
        while pos < data.len() {
            let (field, consumed) =
                self.decode_field_line(&data[pos..], base, required_insert_count)?;
            fields.push(field);
            pos += consumed;
        }

        // Track for acknowledgment
        if required_insert_count > 0 {
            self.decoded_sections
                .insert(stream_id, required_insert_count);
        }

        Ok(fields)
    }

    /// Decodes the field section prefix.
    fn decode_prefix(&self, data: &[u8]) -> Result<(u64, u64, usize)> {
        if data.is_empty() {
            return Err(Error::Incomplete(1));
        }

        // Decode Required Insert Count
        let (enc_insert_count, mut pos) = integer::decode(8, data)?;

        let max_entries = if self.dynamic_table.capacity() == 0 {
            0
        } else {
            self.dynamic_table.capacity() / 32
        };

        let required_insert_count = if enc_insert_count == 0 {
            0
        } else {
            let full_range = 2 * max_entries as u64;
            if enc_insert_count > full_range {
                return Err(Error::DecompressionFailed(
                    "encoded insert count exceeds full range".into(),
                ));
            }

            let max_value = self.dynamic_table.insert_count() + max_entries as u64;
            let max_wrapped = (max_value / full_range) * full_range;
            let mut req_insert_count = max_wrapped + enc_insert_count - 1;

            if req_insert_count > max_value {
                if req_insert_count <= full_range {
                    return Err(Error::DecompressionFailed(
                        "invalid required insert count".into(),
                    ));
                }
                req_insert_count -= full_range;
            }

            if req_insert_count == 0 {
                return Err(Error::DecompressionFailed(
                    "required insert count cannot be zero when encoded as non-zero".into(),
                ));
            }

            req_insert_count
        };

        // Decode Base
        if pos >= data.len() {
            return Err(Error::Incomplete(1));
        }

        let sign = (data[pos] & 0x80) != 0;
        let (delta_base, delta_consumed) = integer::decode(7, &data[pos..])?;
        pos += delta_consumed;

        let base = if sign {
            if delta_base >= required_insert_count {
                return Err(Error::DecompressionFailed(
                    "invalid base calculation".into(),
                ));
            }
            required_insert_count - delta_base - 1
        } else {
            required_insert_count + delta_base
        };

        Ok((required_insert_count, base, pos))
    }

    /// Decodes a single field line representation.
    fn decode_field_line(
        &self,
        data: &[u8],
        base: u64,
        required_insert_count: u64,
    ) -> Result<(FieldLine, usize)> {
        if data.is_empty() {
            return Err(Error::Incomplete(1));
        }

        let first_byte = data[0];

        if (first_byte & 0x80) != 0 {
            // Indexed field line (1T)
            let is_static = (first_byte & 0x40) != 0;
            let (index, consumed) = integer::decode(6, data)?;

            if is_static {
                // Static table
                let entry = static_table::get(index as usize)
                    .ok_or_else(|| Error::DecompressionFailed("invalid static index".into()))?;
                Ok((FieldLine::new(entry.name, entry.value), consumed))
            } else {
                // Dynamic table (relative indexing)
                let absolute_index = base
                    .checked_sub(index + 1)
                    .ok_or_else(|| Error::DecompressionFailed("invalid relative index".into()))?;

                if absolute_index >= required_insert_count {
                    return Err(Error::DecompressionFailed(
                        "reference exceeds required insert count".into(),
                    ));
                }

                let entry = self
                    .dynamic_table
                    .get_absolute(absolute_index)
                    .ok_or_else(|| Error::DecompressionFailed("invalid dynamic index".into()))?;
                Ok((entry.clone(), consumed))
            }
        } else if (first_byte & 0xF0) == 0x10 {
            // Indexed field line with post-base index (0001)
            let (index, consumed) = integer::decode(4, data)?;
            let absolute_index = base + index;

            if absolute_index >= required_insert_count {
                return Err(Error::DecompressionFailed(
                    "post-base reference exceeds required insert count".into(),
                ));
            }

            let entry = self
                .dynamic_table
                .get_absolute(absolute_index)
                .ok_or_else(|| Error::DecompressionFailed("invalid post-base index".into()))?;
            Ok((entry.clone(), consumed))
        } else if (first_byte & 0xF0) == 0x00 {
            // Literal field line with post-base name reference (0000)
            let (name_index, mut pos) = integer::decode(3, data)?;
            let absolute_index = base + name_index;

            let name = self
                .dynamic_table
                .get_absolute(absolute_index)
                .map(|e| e.name.clone())
                .ok_or_else(|| Error::DecompressionFailed("invalid post-base name index".into()))?;

            let (value, value_consumed) = decode_string(8, &data[pos..])?;
            pos += value_consumed;

            Ok((FieldLine::new(name, value), pos))
        } else if (first_byte & 0xC0) == 0x40 {
            // Literal field line with name reference (01NT)
            let is_static = (first_byte & 0x10) != 0;
            let (name_index, mut pos) = integer::decode(4, data)?;

            let name = if is_static {
                static_table::get(name_index as usize)
                    .map(|e| Bytes::from(e.name))
                    .ok_or_else(|| Error::DecompressionFailed("invalid static name index".into()))?
            } else {
                let absolute_index = base.checked_sub(name_index + 1).ok_or_else(|| {
                    Error::DecompressionFailed("invalid relative name index".into())
                })?;
                self.dynamic_table
                    .get_absolute(absolute_index)
                    .map(|e| e.name.clone())
                    .ok_or_else(|| {
                        Error::DecompressionFailed("invalid dynamic name index".into())
                    })?
            };

            let (value, value_consumed) = decode_string(8, &data[pos..])?;
            pos += value_consumed;

            Ok((FieldLine::new(name, value), pos))
        } else {
            // Literal field line with literal name (001N)
            // For this representation, N (Huffman bit for name) is at bit 4, not bit 7
            if data.is_empty() {
                return Err(Error::Incomplete(1));
            }

            let huffman_name = (data[0] & 0x10) != 0; // Bit 4 is the N flag
            let (name_len, consumed) = integer::decode(3, data)?; // 3 bits for length (prefix_bits - 1)
            let name_len = name_len as usize;

            if consumed + name_len > data.len() {
                return Err(Error::Incomplete(consumed + name_len - data.len()));
            }

            let name_data = &data[consumed..consumed + name_len];
            let name = if huffman_name {
                let mut decoded = Vec::new();
                huffman::decode(name_data, &mut decoded)?;
                Bytes::from(decoded)
            } else {
                Bytes::copy_from_slice(name_data)
            };

            let mut pos = consumed + name_len;

            // Value uses standard string encoding with H bit at position 7
            let (value, value_consumed) = decode_string(8, &data[pos..])?;
            pos += value_consumed;

            Ok((FieldLine::new(name, value), pos))
        }
    }

    /// Processes an encoder instruction.
    ///
    /// Returns decoder instructions that should be sent on the decoder stream.
    pub fn process_encoder_instruction(
        &mut self,
        instruction: &EncoderInstruction,
    ) -> Result<Vec<DecoderInstruction>> {
        let mut decoder_instructions = Vec::new();

        match instruction {
            EncoderInstruction::SetCapacity { capacity } => {
                self.dynamic_table.set_capacity(*capacity as usize)?;
            }
            EncoderInstruction::InsertWithNameRef {
                is_static,
                name_index,
                value,
                ..
            } => {
                let name = if *is_static {
                    static_table::get(*name_index as usize)
                        .map(|e| Bytes::from(e.name))
                        .ok_or_else(|| {
                            Error::EncoderStreamError("invalid static name reference".into())
                        })?
                } else {
                    self.dynamic_table
                        .get_relative(*name_index, self.dynamic_table.insert_count())
                        .map(|e| e.name.clone())
                        .ok_or_else(|| {
                            Error::EncoderStreamError("invalid dynamic name reference".into())
                        })?
                };

                let field = FieldLine::new(name, value.clone());
                self.dynamic_table.insert(field)?;

                // Generate insert count increment
                decoder_instructions
                    .push(DecoderInstruction::InsertCountIncrement { increment: 1 });
            }
            EncoderInstruction::InsertWithLiteralName { name, value, .. } => {
                let field = FieldLine::new(name.clone(), value.clone());
                self.dynamic_table.insert(field)?;

                decoder_instructions
                    .push(DecoderInstruction::InsertCountIncrement { increment: 1 });
            }
            EncoderInstruction::Duplicate { index } => {
                let field = self
                    .dynamic_table
                    .get_relative(*index, self.dynamic_table.insert_count())
                    .ok_or_else(|| Error::EncoderStreamError("invalid duplicate index".into()))?
                    .clone();
                self.dynamic_table.insert(field)?;

                decoder_instructions
                    .push(DecoderInstruction::InsertCountIncrement { increment: 1 });
            }
        }

        // Try to unblock streams
        self.try_unblock_streams(&mut decoder_instructions)?;

        Ok(decoder_instructions)
    }

    /// Tries to unblock any blocked streams that can now be decoded.
    fn try_unblock_streams(
        &mut self,
        _decoder_instructions: &mut Vec<DecoderInstruction>,
    ) -> Result<()> {
        let mut unblocked = Vec::new();

        for (idx, blocked) in self.blocked_streams.iter().enumerate() {
            if blocked.required_insert_count <= self.dynamic_table.insert_count() {
                unblocked.push(idx);
            }
        }

        // Remove unblocked streams (in reverse order to maintain indices)
        for idx in unblocked.into_iter().rev() {
            self.blocked_streams.remove(idx);
        }

        Ok(())
    }

    /// Generates a section acknowledgment for the given stream.
    pub fn acknowledge_section(&mut self, stream_id: u64) -> Option<DecoderInstruction> {
        self.decoded_sections
            .remove(&stream_id)
            .map(|_| DecoderInstruction::SectionAck { stream_id })
    }

    /// Cancels a stream, removing it from the blocked streams list.
    pub fn cancel_stream(&mut self, stream_id: u64) -> DecoderInstruction {
        self.blocked_streams.retain(|s| s.stream_id != stream_id);
        DecoderInstruction::StreamCancel { stream_id }
    }

    /// Returns the current dynamic table capacity.
    pub fn capacity(&self) -> usize {
        self.dynamic_table.capacity()
    }
}

/// Decodes a string literal.
fn decode_string(prefix_bits: u8, data: &[u8]) -> Result<(Bytes, usize)> {
    if data.is_empty() {
        return Err(Error::Incomplete(1));
    }

    let huffman = (data[0] & 0x80) != 0;
    let (len, consumed) = integer::decode(prefix_bits - 1, data)?;
    let len = len as usize;

    if consumed + len > data.len() {
        return Err(Error::Incomplete(consumed + len - data.len()));
    }

    let string_data = &data[consumed..consumed + len];
    let result = if huffman {
        let mut decoded = Vec::new();
        huffman::decode(string_data, &mut decoded)?;
        Bytes::from(decoded)
    } else {
        Bytes::copy_from_slice(string_data)
    };

    Ok((result, consumed + len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decoder_creation() {
        let decoder = Decoder::new(4096, 100);
        assert_eq!(decoder.capacity(), 4096);
    }

    #[test]
    fn test_decode_static_indexed() {
        let mut decoder = Decoder::new(4096, 100);

        // Encode :method GET (static index 17, 0xC0 | 17 = 0xD1)
        // Prefix: RIC=0, Base=0
        let data = vec![
            0x00, // Required Insert Count = 0
            0x00, // Delta Base = 0
            0xD1, // Indexed static 17 (:method GET)
        ];

        let fields = decoder.decode_field_section(0, &data).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(&fields[0].name[..], b":method");
        assert_eq!(&fields[0].value[..], b"GET");
    }

    #[test]
    fn test_decode_literal() {
        let mut decoder = Decoder::new(4096, 100);

        // Literal with literal name: 001N + name + value
        // Name: "test" (4 bytes)
        // Value: "value" (5 bytes)
        let data = vec![
            0x00, // Required Insert Count = 0
            0x00, // Delta Base = 0
            0x24, // Literal with literal name, name length = 4
            b't', b'e', b's', b't', 0x05, // Value length = 5
            b'v', b'a', b'l', b'u', b'e',
        ];

        let fields = decoder.decode_field_section(0, &data).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(&fields[0].name[..], b"test");
        assert_eq!(&fields[0].value[..], b"value");
    }
}
