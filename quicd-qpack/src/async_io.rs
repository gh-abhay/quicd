//! Async I/O support for QPACK encoder and decoder streams.
//!
//! Provides async wrappers around encoder/decoder that integrate with
//! tokio's AsyncWrite/AsyncRead traits for zero-copy streaming operations.

#[cfg(feature = "async")]
pub mod async_support {
    use bytes::Bytes;
    use tokio::io::{AsyncWrite, AsyncWriteExt};

    use crate::error::Result;
    use crate::{Decoder, Encoder};

    /// Async encoder wrapper with streaming support.
    pub struct AsyncEncoder {
        encoder: Encoder,
    }

    impl AsyncEncoder {
        /// Create a new async encoder.
        pub fn new(max_table_capacity: usize, max_blocked_streams: usize) -> Self {
            Self {
                encoder: Encoder::new(max_table_capacity, max_blocked_streams),
            }
        }

        /// Get mutable reference to underlying encoder.
        pub fn encoder_mut(&mut self) -> &mut Encoder {
            &mut self.encoder
        }

        /// Get immutable reference to underlying encoder.
        pub fn encoder(&self) -> &Encoder {
            &self.encoder
        }

        /// Encode headers and write to encoder stream asynchronously.
        ///
        /// # Arguments
        /// * `stream_id` - HTTP/3 stream ID
        /// * `headers` - List of (name, value) pairs
        /// * `encoder_stream` - Async writer for encoder stream instructions
        ///
        /// # Returns
        /// Encoded header block bytes
        pub async fn encode_with_stream<W>(
            &mut self,
            stream_id: u64,
            headers: &[(&[u8], &[u8])],
            encoder_stream: &mut W,
        ) -> Result<Bytes>
        where
            W: AsyncWrite + Unpin,
        {
            // Encode headers
            let encoded = self.encoder.encode(stream_id, headers)?;

            // Flush any pending encoder stream instructions
            while let Some(inst) = self.encoder.poll_encoder_stream() {
                encoder_stream.write_all(&inst).await?;
            }

            Ok(encoded)
        }

        /// Process decoder instruction asynchronously.
        pub async fn process_decoder_instruction(&mut self, data: &[u8]) -> Result<()> {
            self.encoder.process_decoder_instruction(data)
        }
    }

    /// Async decoder wrapper with streaming support.
    pub struct AsyncDecoder {
        decoder: Decoder,
    }

    impl AsyncDecoder {
        /// Create a new async decoder.
        pub fn new(max_table_capacity: usize, max_blocked_streams: usize) -> Self {
            Self {
                decoder: Decoder::new(max_table_capacity, max_blocked_streams),
            }
        }

        /// Create a new async decoder with custom timeout.
        pub fn with_timeout(
            max_table_capacity: usize,
            max_blocked_streams: usize,
            timeout: std::time::Duration,
        ) -> Self {
            Self {
                decoder: Decoder::with_timeout(max_table_capacity, max_blocked_streams, timeout),
            }
        }

        /// Get mutable reference to underlying decoder.
        pub fn decoder_mut(&mut self) -> &mut Decoder {
            &mut self.decoder
        }

        /// Get immutable reference to underlying decoder.
        pub fn decoder(&self) -> &Decoder {
            &self.decoder
        }

        /// Decode header block and write to decoder stream asynchronously.
        ///
        /// # Arguments
        /// * `stream_id` - HTTP/3 stream ID
        /// * `data` - Encoded header block bytes
        /// * `decoder_stream` - Async writer for decoder stream instructions
        ///
        /// # Returns
        /// Vector of decoded header fields
        pub async fn decode_with_stream<W>(
            &mut self,
            stream_id: u64,
            data: Bytes,
            decoder_stream: &mut W,
        ) -> Result<Vec<crate::HeaderField>>
        where
            W: AsyncWrite + Unpin,
        {
            // Decode headers
            let headers = self.decoder.decode(stream_id, data)?;

            // Flush any pending decoder stream instructions
            while let Some(inst) = self.decoder.poll_decoder_stream() {
                decoder_stream.write_all(&inst).await?;
            }

            Ok(headers)
        }

        /// Process encoder instruction asynchronously.
        pub async fn process_encoder_instruction(&mut self, data: &[u8]) -> Result<Vec<(u64, Vec<crate::HeaderField>)>> {
            self.decoder.process_encoder_instruction(data)
        }
    }
}

#[cfg(feature = "async")]
pub use async_support::{AsyncDecoder, AsyncEncoder};
