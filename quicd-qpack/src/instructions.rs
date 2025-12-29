//! QPACK encoder and decoder stream instructions.
//!
//! Defines types for all instructions sent on encoder and decoder streams
//! per RFC 9204 Sections 4.3 and 4.4.

use crate::error::{Error, Result};
use crate::{huffman, integer};
use bytes::Bytes;

/// Encoder stream instructions (Section 4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncoderInstruction {
    /// Set Dynamic Table Capacity (Section 4.3.1).
    SetCapacity { capacity: u64 },

    /// Insert with Name Reference (Section 4.3.2).
    InsertWithNameRef {
        is_static: bool,
        name_index: u64,
        value: Bytes,
        huffman_value: bool,
    },

    /// Insert with Literal Name (Section 4.3.3).
    InsertWithLiteralName {
        name: Bytes,
        huffman_name: bool,
        value: Bytes,
        huffman_value: bool,
    },

    /// Duplicate (Section 4.3.4).
    Duplicate { index: u64 },
}

/// Decoder stream instructions (Section 4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecoderInstruction {
    /// Section Acknowledgment (Section 4.4.1).
    SectionAck { stream_id: u64 },

    /// Stream Cancellation (Section 4.4.2).
    StreamCancel { stream_id: u64 },

    /// Insert Count Increment (Section 4.4.3).
    InsertCountIncrement { increment: u64 },
}

/// Encodes a string literal (RFC 7541 Section 5.2 / RFC 9204 Section 4.1.2).
fn encode_string(
    data: &[u8],
    huffman: bool,
    prefix_bits: u8,
    prefix_mask: u8,
    buf: &mut Vec<u8>,
) -> usize {
    let start = buf.len();

    if huffman {
        let mut encoded = Vec::new();
        huffman::encode(data, &mut encoded);

        let mut temp = [0u8; 16];
        let n = integer::encode(
            encoded.len() as u64,
            prefix_bits - 1,
            prefix_mask | 0x80,
            &mut temp,
        );
        buf.extend_from_slice(&temp[..n]);
        buf.extend_from_slice(&encoded);
    } else {
        let mut temp = [0u8; 16];
        let n = integer::encode(data.len() as u64, prefix_bits - 1, prefix_mask, &mut temp);
        buf.extend_from_slice(&temp[..n]);
        buf.extend_from_slice(data);
    }

    buf.len() - start
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

impl EncoderInstruction {
    /// Encodes the instruction to bytes.
    pub fn encode(&self, buf: &mut Vec<u8>) -> usize {
        let start = buf.len();
        match self {
            EncoderInstruction::SetCapacity { capacity } => {
                // 001xxxxx
                let mut temp = [0u8; 16];
                let n = integer::encode(*capacity, 5, 0b001_00000, &mut temp);
                buf.extend_from_slice(&temp[..n]);
            }
            EncoderInstruction::InsertWithNameRef {
                is_static,
                name_index,
                value,
                huffman_value,
            } => {
                // 1Txxxxxx
                let t_bit = if *is_static { 0x40 } else { 0x00 };
                let mut temp = [0u8; 16];
                let n = integer::encode(*name_index, 6, 0x80 | t_bit, &mut temp);
                buf.extend_from_slice(&temp[..n]);
                encode_string(value, *huffman_value, 8, 0x00, buf);
            }
            EncoderInstruction::InsertWithLiteralName {
                name,
                huffman_name,
                value,
                huffman_value,
            } => {
                // 01xxxxxx
                encode_string(name, *huffman_name, 6, 0x40, buf);
                encode_string(value, *huffman_value, 8, 0x00, buf);
            }
            EncoderInstruction::Duplicate { index } => {
                // 000xxxxx
                let mut temp = [0u8; 16];
                let n = integer::encode(*index, 5, 0b000_00000, &mut temp);
                buf.extend_from_slice(&temp[..n]);
            }
        }
        buf.len() - start
    }

    /// Decodes an instruction from bytes.
    pub fn decode(data: &[u8]) -> Result<(Self, usize)> {
        if data.is_empty() {
            return Err(Error::Incomplete(1));
        }

        let first_byte = data[0];

        if (first_byte & 0x80) != 0 {
            // 1Txxxxxx - Insert with Name Reference
            let is_static = (first_byte & 0x40) != 0;
            let (name_index, mut consumed) = integer::decode(6, data)?;
            let (value, value_consumed) = decode_string(8, &data[consumed..])?;
            consumed += value_consumed;
            let huffman_value = (data[consumed - value_consumed] & 0x80) != 0;

            Ok((
                EncoderInstruction::InsertWithNameRef {
                    is_static,
                    name_index,
                    value,
                    huffman_value,
                },
                consumed,
            ))
        } else if (first_byte & 0xC0) == 0x40 {
            // 01xxxxxx - Insert with Literal Name
            let (name, mut consumed) = decode_string(6, data)?;
            let huffman_name = (data[0] & 0x20) != 0;
            let (value, value_consumed) = decode_string(8, &data[consumed..])?;
            consumed += value_consumed;
            let huffman_value = (data[consumed - value_consumed] & 0x80) != 0;

            Ok((
                EncoderInstruction::InsertWithLiteralName {
                    name,
                    huffman_name,
                    value,
                    huffman_value,
                },
                consumed,
            ))
        } else if (first_byte & 0xE0) == 0x20 {
            // 001xxxxx - Set Dynamic Table Capacity
            let (capacity, consumed) = integer::decode(5, data)?;
            Ok((EncoderInstruction::SetCapacity { capacity }, consumed))
        } else if (first_byte & 0xE0) == 0x00 {
            // 000xxxxx - Duplicate
            let (index, consumed) = integer::decode(5, data)?;
            Ok((EncoderInstruction::Duplicate { index }, consumed))
        } else {
            Err(Error::EncoderStreamError(
                "invalid instruction prefix".into(),
            ))
        }
    }
}

impl DecoderInstruction {
    /// Encodes the instruction to bytes.
    pub fn encode(&self, buf: &mut Vec<u8>) -> usize {
        let start = buf.len();
        match self {
            DecoderInstruction::SectionAck { stream_id } => {
                // 1xxxxxxx
                let mut temp = [0u8; 16];
                let n = integer::encode(*stream_id, 7, 0b1_0000000, &mut temp);
                buf.extend_from_slice(&temp[..n]);
            }
            DecoderInstruction::StreamCancel { stream_id } => {
                // 01xxxxxx
                let mut temp = [0u8; 16];
                let n = integer::encode(*stream_id, 6, 0b01_000000, &mut temp);
                buf.extend_from_slice(&temp[..n]);
            }
            DecoderInstruction::InsertCountIncrement { increment } => {
                // 00xxxxxx
                let mut temp = [0u8; 16];
                let n = integer::encode(*increment, 6, 0b00_000000, &mut temp);
                buf.extend_from_slice(&temp[..n]);
            }
        }
        buf.len() - start
    }

    /// Decodes an instruction from bytes.
    pub fn decode(data: &[u8]) -> Result<(Self, usize)> {
        if data.is_empty() {
            return Err(Error::Incomplete(1));
        }

        let first_byte = data[0];

        if (first_byte & 0x80) != 0 {
            // 1xxxxxxx - Section Acknowledgment
            let (stream_id, consumed) = integer::decode(7, data)?;
            Ok((DecoderInstruction::SectionAck { stream_id }, consumed))
        } else if (first_byte & 0xC0) == 0x40 {
            // 01xxxxxx - Stream Cancellation
            let (stream_id, consumed) = integer::decode(6, data)?;
            Ok((DecoderInstruction::StreamCancel { stream_id }, consumed))
        } else {
            // 00xxxxxx - Insert Count Increment
            let (increment, consumed) = integer::decode(6, data)?;
            if increment == 0 {
                return Err(Error::DecoderStreamError(
                    "increment must be non-zero".into(),
                ));
            }
            Ok((
                DecoderInstruction::InsertCountIncrement { increment },
                consumed,
            ))
        }
    }
}

