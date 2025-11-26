//! QPACK encoder and decoder stream management per RFC 9204.
//!
//! This module manages the dedicated unidirectional streams used for
//! QPACK dynamic table updates and feedback.

// use bytes::{Bytes, BytesMut};
use crate::error::H3Error;
use crate::qpack::{QpackCodec, QpackInstruction};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Manager for QPACK encoder and decoder streams.
///
/// Per RFC 9204 Section 4.2, each endpoint opens:
/// - One encoder stream (type 0x02) for sending dynamic table instructions
/// - One decoder stream (type 0x03) for sending acknowledgments and cancellations
pub struct QpackStreamManager {
    /// Encoder stream ID (if set)
    encoder_stream_id: Option<u64>,
    /// Decoder stream ID (if set)
    decoder_stream_id: Option<u64>,
    /// Encoder stream for sending instructions to peer
    encoder_stream: Option<quicd_x::SendStream>,
    /// Decoder stream for sending feedback to peer
    decoder_stream: Option<quicd_x::SendStream>,
    /// Pending encoder instructions to send
    pending_encoder_instructions: Vec<QpackInstruction>,
    /// Pending decoder instructions to send
    pending_decoder_instructions: Vec<QpackInstruction>,
    /// Track streams that are blocked waiting for dynamic table updates
    blocked_streams: std::collections::HashSet<u64>,
}

impl QpackStreamManager {
    /// Create a new QPACK stream manager.
    pub fn new() -> Self {
        Self {
            encoder_stream_id: None,
            decoder_stream_id: None,
            encoder_stream: None,
            decoder_stream: None,
            pending_encoder_instructions: Vec::new(),
            pending_decoder_instructions: Vec::new(),
            blocked_streams: std::collections::HashSet::new(),
        }
    }
    
    /// Check if encoder stream has been set.
    pub fn has_encoder_stream(&self) -> bool {
        self.encoder_stream_id.is_some()
    }
    
    /// Check if decoder stream has been set.
    pub fn has_decoder_stream(&self) -> bool {
        self.decoder_stream_id.is_some()
    }

    /// Set the encoder stream (after it's opened).
    pub fn set_encoder_stream(&mut self, stream: quicd_x::SendStream) {
        self.encoder_stream = Some(stream);
    }

    /// Set the decoder stream (after it's opened).
    pub fn set_decoder_stream(&mut self, stream: quicd_x::SendStream) {
        self.decoder_stream = Some(stream);
    }

    /// Open the QPACK encoder and decoder streams.
    ///
    /// This should be called during connection initialization.
    pub async fn initialize_streams(
        &mut self,
        handle: &quicd_x::ConnectionHandle,
    ) -> Result<(), H3Error> {
        // Request to open encoder stream (type 0x02)
        let _encoder_request_id = handle.open_uni()
            .map_err(|e| H3Error::Connection(format!("failed to open encoder stream: {:?}", e)))?;
        
        // Request to open decoder stream (type 0x03)
        let _decoder_request_id = handle.open_uni()
            .map_err(|e| H3Error::Connection(format!("failed to open decoder stream: {:?}", e)))?;

        // Store request IDs for correlation with UniStreamOpened events
        // The caller (H3Session) will need to call set_encoder_stream/set_decoder_stream
        // when the streams are opened
        
        Ok(())
    }

    /// Process an instruction received on the peer's encoder stream.
    ///
    /// Per RFC 9204 Section 4.2, the encoder stream carries instructions that
    /// modify the dynamic table.
    pub async fn process_encoder_instruction(
        &mut self,
        instruction: QpackInstruction,
    ) -> Result<(), H3Error> {
        let mut codec = self.codec.lock().await;
        
        match instruction {
            QpackInstruction::SetDynamicTableCapacity { capacity } => {
                // Update dynamic table capacity
                codec.set_table_capacity(capacity as usize);
            }
            QpackInstruction::InsertWithNameReference { static_table, name_index, value } => {
                // Insert entry into dynamic table
                let name = if static_table {
                    codec.get_static_entry(name_index as usize)
                        .ok_or_else(|| H3Error::Qpack("invalid static table index".into()))?
                        .0
                        .clone()
                } else {
                    codec.get_absolute(name_index as usize)
                        .ok_or_else(|| H3Error::Qpack("invalid dynamic table index".into()))?
                        .0
                        .clone()
                };
                
                codec.insert(name, value);
            }
            QpackInstruction::InsertWithLiteralName { name, value } => {
                codec.insert(name, value);
            }
            QpackInstruction::Duplicate { index } => {
                codec.duplicate(index as usize);
            }
            _ => {
                return Err(H3Error::Qpack(format!(
                    "unexpected instruction on encoder stream: {:?}",
                    instruction
                )));
            }
        }

        Ok(())
    }

    /// Process an instruction received on the peer's decoder stream.
    ///
    /// Per RFC 9204 Section 4.2, the decoder stream carries acknowledgments
    /// and cancellations.
    pub async fn process_decoder_instruction(
        &mut self,
        instruction: QpackInstruction,
    ) -> Result<(), H3Error> {
        let mut codec = self.codec.lock().await;
        
        match instruction {
            QpackInstruction::SectionAcknowledgment { stream_id } => {
                // Section was successfully decoded
                self.blocked_streams.remove(&stream_id);
                let current_count = codec.known_received_count();
                codec.update_known_received_count(current_count + 1);
            }
            QpackInstruction::StreamCancellation { stream_id } => {
                // Stream was cancelled, release references
                self.blocked_streams.remove(&stream_id);
            }
            QpackInstruction::InsertCountIncrement { increment } => {
                // Update known received count
                let current_count = codec.known_received_count();
                codec.update_known_received_count(
                    current_count + increment as usize
                );
            }
            _ => {
                return Err(H3Error::Qpack(format!(
                    "unexpected instruction on decoder stream: {:?}",
                    instruction
                )));
            }
        }

        Ok(())
    }

    /// Send a Section Acknowledgment on the decoder stream.
    ///
    /// Per RFC 9204 Section 4.4.1, this is sent after successfully decoding
    /// a header section that references the dynamic table.
    pub async fn send_section_acknowledgment(&mut self, stream_id: u64) -> Result<(), H3Error> {
        let instruction = QpackInstruction::SectionAcknowledgment { stream_id };
        self.pending_decoder_instructions.push(instruction);
        self.flush_decoder_stream().await
    }

    /// Send a Stream Cancellation on the decoder stream.
    ///
    /// Per RFC 9204 Section 4.4.2, this is sent when a stream is cancelled
    /// before the header section is fully processed.
    pub async fn send_stream_cancellation(&mut self, stream_id: u64) -> Result<(), H3Error> {
        let instruction = QpackInstruction::StreamCancellation { stream_id };
        self.pending_decoder_instructions.push(instruction);
        self.flush_decoder_stream().await
    }

    /// Send an Insert Count Increment on the decoder stream.
    ///
    /// Per RFC 9204 Section 4.4.3, this indicates that more entries have been
    /// processed and can be evicted from the dynamic table.
    pub async fn send_insert_count_increment(&mut self, increment: u64) -> Result<(), H3Error> {
        let instruction = QpackInstruction::InsertCountIncrement { increment };
        self.pending_decoder_instructions.push(instruction);
        self.flush_decoder_stream().await
    }

    /// Flush pending instructions on the decoder stream.
    async fn flush_decoder_stream(&mut self) -> Result<(), H3Error> {
        if self.pending_decoder_instructions.is_empty() {
            return Ok(());
        }

        let stream = self.decoder_stream.as_mut()
            .ok_or_else(|| H3Error::Qpack("decoder stream not initialized".into()))?;

        let codec = self.codec.lock().await;
        
        for instruction in self.pending_decoder_instructions.drain(..) {
            let data = codec.encode_instruction(&instruction)?;
            stream.write(data, false).await
                .map_err(|e| H3Error::Stream(format!("failed to write to decoder stream: {:?}", e)))?;
        }

        Ok(())
    }

    /// Send an instruction on the encoder stream.
    pub async fn send_encoder_instruction(
        &mut self,
        instruction: QpackInstruction,
    ) -> Result<(), H3Error> {
        self.pending_encoder_instructions.push(instruction);
        self.flush_encoder_stream().await
    }

    /// Flush pending instructions on the encoder stream.
    async fn flush_encoder_stream(&mut self) -> Result<(), H3Error> {
        if self.pending_encoder_instructions.is_empty() {
            return Ok(());
        }

        let stream = self.encoder_stream.as_mut()
            .ok_or_else(|| H3Error::Qpack("encoder stream not initialized".into()))?;

        let codec = self.codec.lock().await;
        
        for instruction in self.pending_encoder_instructions.drain(..) {
            let data = codec.encode_instruction(&instruction)?;
            stream.write(data, false).await
                .map_err(|e| H3Error::Stream(format!("failed to write to encoder stream: {:?}", e)))?;
        }

        Ok(())
    }

    /// Mark a stream as blocked waiting for dynamic table updates.
    pub fn mark_stream_blocked(&mut self, stream_id: u64) {
        self.blocked_streams.insert(stream_id);
    }

    /// Check if a stream is blocked.
    pub fn is_stream_blocked(&self, stream_id: u64) -> bool {
        self.blocked_streams.contains(&stream_id)
    }

    /// Get the number of currently blocked streams.
    pub fn blocked_stream_count(&self) -> usize {
        self.blocked_streams.len()
    }

    /// Check if we can encode a header section without blocking.
    ///
    /// This checks against the QPACK_BLOCKED_STREAMS limit.
    pub async fn can_encode_without_blocking(&self) -> bool {
        let codec = self.codec.lock().await;
        self.blocked_streams.len() < codec.known_received_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_qpack_manager_creation() {
        let codec = Arc::new(Mutex::new(QpackCodec::new()));
        let manager = QpackStreamManager::new(codec);
        assert_eq!(manager.blocked_stream_count(), 0);
    }

    #[tokio::test]
    async fn test_blocked_stream_tracking() {
        let codec = Arc::new(Mutex::new(QpackCodec::new()));
        let mut manager = QpackStreamManager::new(codec);
        
        manager.mark_stream_blocked(4);
        assert!(manager.is_stream_blocked(4));
        assert_eq!(manager.blocked_stream_count(), 1);
    }

    #[tokio::test]
    async fn test_encoder_instruction_processing() {
        let codec = Arc::new(Mutex::new(QpackCodec::new()));
        let mut manager = QpackStreamManager::new(codec.clone());
        
        // Set initial capacity
        codec.lock().await.set_max_table_capacity(4096);
        
        let instruction = QpackInstruction::InsertWithLiteralName {
            name: "x-custom".to_string(),
            value: "value".to_string(),
        };
        
        let result = manager.process_encoder_instruction(instruction).await;
        assert!(result.is_ok());
        
        // Verify entry was inserted
        let codec_guard = codec.lock().await;
        assert_eq!(codec_guard.insert_count(), 1);
    }
}
