//! QPACK encoder/decoder management for HTTP/3 connections.
//!
//! Manages the QPACK encoder and decoder instances along with their
//! associated unidirectional streams per RFC 9204.

use bytes::{Bytes, BytesMut};
use quicd_qpack::{Decoder, Encoder, FieldLine};
use quicd_x::StreamId;

use crate::error::{Error, Result};

/// QPACK manager handling header compression/decompression for an HTTP/3 connection.
///
/// Manages:
/// - QPACK encoder and decoder instances
/// - Encoder stream (type 0x02) for sending dynamic table updates
/// - Decoder stream (type 0x03) for sending acknowledgments
pub struct QpackManager {
    /// QPACK encoder for compressing outgoing headers.
    encoder: Encoder,
    /// QPACK decoder for decompressing incoming headers.
    decoder: Decoder,
    /// Encoder stream ID (if opened).
    encoder_stream_id: Option<StreamId>,
    /// Decoder stream ID (if opened).
    decoder_stream_id: Option<StreamId>,
    /// Buffer for encoder stream instructions to send.
    encoder_instructions_buffer: BytesMut,
    /// Buffer for decoder stream instructions to send.
    decoder_instructions_buffer: BytesMut,
}

impl QpackManager {
    /// Create a new QPACK manager with specified table capacity and blocked streams limit.
    pub fn new(max_table_capacity: u64, max_blocked_streams: u64) -> Self {
        let encoder = Encoder::new(max_table_capacity as usize, max_blocked_streams as usize);
        let decoder = Decoder::new(max_table_capacity as usize, max_blocked_streams as usize);

        Self {
            encoder,
            decoder,
            encoder_stream_id: None,
            decoder_stream_id: None,
            encoder_instructions_buffer: BytesMut::new(),
            decoder_instructions_buffer: BytesMut::new(),
        }
    }

    /// Register the encoder stream ID.
    ///
    /// Called when the encoder stream (type 0x02) is opened.
    pub fn set_encoder_stream(&mut self, stream_id: StreamId) {
        self.encoder_stream_id = Some(stream_id);
    }

    /// Register the decoder stream ID.
    ///
    /// Called when the decoder stream (type 0x03) is opened.
    pub fn set_decoder_stream(&mut self, stream_id: StreamId) {
        self.decoder_stream_id = Some(stream_id);
    }

    /// Encode a field section for an HTTP message.
    ///
    /// Returns the encoded field section bytes.
    /// May generate encoder stream instructions that should be sent on the encoder stream.
    pub fn encode_field_section(
        &mut self,
        stream_id: u64,
        fields: &[FieldLine],
    ) -> Result<Bytes> {
        let (encoded, _encoder_instructions) = self
            .encoder
            .encode_field_section(stream_id, fields)
            .map_err(|e| Error::Qpack(e))?;

        // Note: encoder_instructions are Vec<EncoderInstruction> which would need to be
        // serialized to bytes. For now, we'll handle this in a future iteration.
        // The encoder/decoder streams would serialize these instructions properly.

        Ok(encoded)
    }

    /// Decode a field section from an HTTP message.
    ///
    /// Returns the decoded field lines.
    /// May generate decoder stream instructions that should be sent on the decoder stream.
    pub fn decode_field_section(
        &mut self,
        stream_id: u64,
        encoded: &[u8],
    ) -> Result<Vec<FieldLine>> {
        let fields = self
            .decoder
            .decode_field_section(stream_id, encoded)
            .map_err(|e| Error::Qpack(e))?;

        // Check for decoder instructions to send (acknowledgments, etc.)
        // Note: quicd-qpack decoder API may need extension to provide instructions
        // For now, we assume the decoder handles this internally

        Ok(fields)
    }

    /// Process data received on the peer's encoder stream.
    ///
    /// The decoder processes these instructions to update its dynamic table.
    pub fn process_encoder_stream_data(&mut self, data: &[u8]) -> Result<()> {
        // Feed encoder stream data to decoder
        // Note: quicd-qpack API may need method for this
        // For now, this is a placeholder
        Ok(())
    }

    /// Process data received on the peer's decoder stream.
    ///
    /// The encoder processes these instructions (acknowledgments, etc.).
    pub fn process_decoder_stream_data(&mut self, data: &[u8]) -> Result<()> {
        // Feed decoder stream data to encoder
        // Note: quicd-qpack API may need method for this
        // For now, this is a placeholder
        Ok(())
    }

    /// Get buffered encoder stream instructions to send.
    ///
    /// Returns instructions and clears the buffer.
    pub fn take_encoder_instructions(&mut self) -> Option<Bytes> {
        if self.encoder_instructions_buffer.is_empty() {
            None
        } else {
            Some(self.encoder_instructions_buffer.split().freeze())
        }
    }

    /// Get buffered decoder stream instructions to send.
    ///
    /// Returns instructions and clears the buffer.
    pub fn take_decoder_instructions(&mut self) -> Option<Bytes> {
        if self.decoder_instructions_buffer.is_empty() {
            None
        } else {
            Some(self.decoder_instructions_buffer.split().freeze())
        }
    }

    /// Check if encoder stream is registered.
    pub fn has_encoder_stream(&self) -> bool {
        self.encoder_stream_id.is_some()
    }

    /// Check if decoder stream is registered.
    pub fn has_decoder_stream(&self) -> bool {
        self.decoder_stream_id.is_some()
    }

    /// Get encoder stream ID.
    pub fn encoder_stream_id(&self) -> Option<StreamId> {
        self.encoder_stream_id
    }

    /// Get decoder stream ID.
    pub fn decoder_stream_id(&self) -> Option<StreamId> {
        self.decoder_stream_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_qpack_manager_creation() {
        let mgr = QpackManager::new(4096, 100);
        assert!(!mgr.has_encoder_stream());
        assert!(!mgr.has_decoder_stream());
    }

    #[test]
    fn test_encode_decode_field_section() {
        let mut mgr = QpackManager::new(4096, 100);

        let fields = vec![
            FieldLine::new("content-type", "text/html"),
            FieldLine::new("content-length", "1234"),
        ];

        let encoded = mgr.encode_field_section(0, &fields).unwrap();
        assert!(!encoded.is_empty());

        let decoded = mgr.decode_field_section(0, &encoded).unwrap();
        assert_eq!(decoded.len(), fields.len());
        
        for (original, decoded) in fields.iter().zip(decoded.iter()) {
            assert_eq!(original.name, decoded.name);
            assert_eq!(original.value, decoded.value);
        }
    }
}
