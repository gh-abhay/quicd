//! # Transport Parameters (RFC 9000 Section 7.4, 18)
//!
//! Encoding, decoding, and negotiation of QUIC transport parameters.

#![forbid(unsafe_code)]

use crate::error::{Error, Result, TransportError};
use crate::types::{ConnectionId, StatelessResetToken, VarInt};
use bytes::{Bytes, BytesMut};
use core::time::Duration;

/// Transport Parameter IDs (RFC 9000 Section 18.2)
pub const PARAM_ORIGINAL_DESTINATION_CONNECTION_ID: u64 = 0x00;
pub const PARAM_MAX_IDLE_TIMEOUT: u64 = 0x01;
pub const PARAM_STATELESS_RESET_TOKEN: u64 = 0x02;
pub const PARAM_MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
pub const PARAM_INITIAL_MAX_DATA: u64 = 0x04;
pub const PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
pub const PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
pub const PARAM_INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
pub const PARAM_INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
pub const PARAM_INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
pub const PARAM_ACK_DELAY_EXPONENT: u64 = 0x0a;
pub const PARAM_MAX_ACK_DELAY: u64 = 0x0b;
pub const PARAM_DISABLE_ACTIVE_MIGRATION: u64 = 0x0c;
pub const PARAM_PREFERRED_ADDRESS: u64 = 0x0d;
pub const PARAM_ACTIVE_CONNECTION_ID_LIMIT: u64 = 0x0e;
pub const PARAM_INITIAL_SOURCE_CONNECTION_ID: u64 = 0x0f;
pub const PARAM_RETRY_SOURCE_CONNECTION_ID: u64 = 0x10;

/// Transport Parameters (RFC 9000 Section 18)
///
/// Negotiated during handshake via TLS extension.
#[derive(Debug, Clone)]
pub struct TransportParameters {
    /// Original Destination Connection ID (server only)
    pub original_destination_connection_id: Option<ConnectionId>,

    /// Max idle timeout (milliseconds)
    pub max_idle_timeout: Duration,

    /// Stateless reset token (server only, 16 bytes)
    pub stateless_reset_token: Option<StatelessResetToken>,

    /// Maximum UDP payload size (bytes)
    pub max_udp_payload_size: usize,

    /// Initial maximum data (connection-level flow control)
    pub initial_max_data: u64,

    /// Initial maximum stream data (bidirectional, local-initiated)
    pub initial_max_stream_data_bidi_local: u64,

    /// Initial maximum stream data (bidirectional, remote-initiated)
    pub initial_max_stream_data_bidi_remote: u64,

    /// Initial maximum stream data (unidirectional)
    pub initial_max_stream_data_uni: u64,

    /// Initial maximum bidirectional streams
    pub initial_max_streams_bidi: u64,

    /// Initial maximum unidirectional streams
    pub initial_max_streams_uni: u64,

    /// ACK delay exponent (default 3)
    pub ack_delay_exponent: u8,

    /// Maximum ACK delay (milliseconds, default 25)
    pub max_ack_delay: Duration,

    /// Disable active migration flag
    pub disable_active_migration: bool,

    /// Preferred address (server only)
    pub preferred_address: Option<PreferredAddress>,

    /// Active connection ID limit (default 2)
    pub active_connection_id_limit: u64,

    /// Initial Source Connection ID
    pub initial_source_connection_id: Option<ConnectionId>,

    /// Retry Source Connection ID (if Retry packet was sent)
    pub retry_source_connection_id: Option<ConnectionId>,
}

impl TransportParameters {
    /// Create default client parameters
    pub fn default_client() -> Self {
        Self {
            original_destination_connection_id: None,
            max_idle_timeout: Duration::from_secs(30),
            stateless_reset_token: None,
            max_udp_payload_size: 65527,
            initial_max_data: 1048576, // 1 MB
            initial_max_stream_data_bidi_local: 262144, // 256 KB
            initial_max_stream_data_bidi_remote: 262144,
            initial_max_stream_data_uni: 262144,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
            ack_delay_exponent: 3,
            max_ack_delay: Duration::from_millis(25),
            disable_active_migration: false,
            preferred_address: None,
            active_connection_id_limit: 2,
            initial_source_connection_id: None,
            retry_source_connection_id: None,
        }
    }

    /// Create default server parameters
    pub fn default_server() -> Self {
        let mut params = Self::default_client();
        // Server can provide stateless reset token
        params.stateless_reset_token = None; // Set by implementation
        params
    }

    /// Validate parameters (RFC 9000 Section 18.2)
    pub fn validate(&self) -> Result<()> {
        // Max UDP payload size must be >= 1200
        if self.max_udp_payload_size < 1200 {
            return Err(Error::Transport(TransportError::TransportParameterError));
        }

        // ACK delay exponent must be <= 20
        if self.ack_delay_exponent > 20 {
            return Err(Error::Transport(TransportError::TransportParameterError));
        }

        // Max ACK delay must be < 2^14 milliseconds
        if self.max_ack_delay.as_millis() >= (1 << 14) {
            return Err(Error::Transport(TransportError::TransportParameterError));
        }

        // Active connection ID limit must be >= 2
        if self.active_connection_id_limit < 2 {
            return Err(Error::Transport(TransportError::TransportParameterError));
        }

        Ok(())
    }
}

/// Preferred Address (RFC 9000 Section 18.2)
///
/// Server's preferred address for client to migrate to.
#[derive(Debug, Clone)]
pub struct PreferredAddress {
    /// IPv4 address (4 bytes)
    pub ipv4_address: Option<[u8; 4]>,

    /// IPv4 port
    pub ipv4_port: u16,

    /// IPv6 address (16 bytes)
    pub ipv6_address: Option<[u8; 16]>,

    /// IPv6 port
    pub ipv6_port: u16,

    /// Connection ID for preferred address
    pub connection_id: ConnectionId,

    /// Stateless reset token for preferred address
    pub stateless_reset_token: StatelessResetToken,
}

/// Transport Parameters Codec
///
/// Encodes/decodes transport parameters for TLS extension.
pub trait TransportParametersCodec {
    /// Encode parameters into buffer
    fn encode(&self, params: &TransportParameters, buf: &mut BytesMut) -> Result<()>;

    /// Decode parameters from buffer
    fn decode(&self, buf: &[u8]) -> Result<TransportParameters>;
}

/// Default transport parameters codec
pub struct DefaultTransportParametersCodec;

impl TransportParametersCodec for DefaultTransportParametersCodec {
    fn encode(&self, params: &TransportParameters, buf: &mut BytesMut) -> Result<()> {
        unimplemented!("Skeleton - no implementation required")
    }

    fn decode(&self, buf: &[u8]) -> Result<TransportParameters> {
        unimplemented!("Skeleton - no implementation required")
    }
}
