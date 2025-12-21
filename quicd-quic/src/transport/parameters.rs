//! # Transport Parameters (RFC 9000 Section 7.4)
//!
//! Transport parameters are exchanged during the TLS handshake to negotiate
//! connection configuration and capabilities.
//!
//! ## Parameter Exchange
//!
//! - **Client**: Sends parameters in TLS ClientHello (via quic_transport_parameters extension)
//! - **Server**: Sends parameters in TLS EncryptedExtensions
//!
//! ## Critical Parameters
//!
//! Some parameters MUST be validated:
//! - `initial_source_connection_id`: Must match the connection ID used
//! - `original_destination_connection_id`: Must match the first packet's DCID
//! - `max_idle_timeout`: Connection will close after this period of inactivity
//! - Flow control limits: `initial_max_data`, `initial_max_stream_data_*`
//!
//! ## Encoding (RFC 9000 Section 18)
//!
//! Transport parameters are encoded as TLV (Type-Length-Value):
//! ```text
//! Transport Parameter {
//!   Type (varint),
//!   Length (varint),
//!   Value (variable length),
//! }
//! ```

#![forbid(unsafe_code)]

use crate::error::{Error, Result, TransportError};
use core::time::Duration;
use alloc::vec::Vec;

// ============================================================================
// Transport Parameter IDs (RFC 9000 Section 18.2)
// ============================================================================

/// Transport parameter type identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum TransportParamId {
    OriginalDestinationConnectionId = 0x00,
    MaxIdleTimeout = 0x01,
    StatelessResetToken = 0x02,
    MaxUdpPayloadSize = 0x03,
    InitialMaxData = 0x04,
    InitialMaxStreamDataBidiLocal = 0x05,
    InitialMaxStreamDataBidiRemote = 0x06,
    InitialMaxStreamDataUni = 0x07,
    InitialMaxStreamsBidi = 0x08,
    InitialMaxStreamsUni = 0x09,
    AckDelayExponent = 0x0a,
    MaxAckDelay = 0x0b,
    DisableActiveMigration = 0x0c,
    PreferredAddress = 0x0d,
    ActiveConnectionIdLimit = 0x0e,
    InitialSourceConnectionId = 0x0f,
    RetrySourceConnectionId = 0x10,
}

// ============================================================================
// Transport Parameters Structure
// ============================================================================

/// Transport Parameters (RFC 9000 Section 7.4)
///
/// This struct contains all QUIC transport parameters with their default values.
#[derive(Debug, Clone)]
pub struct TransportParameters {
    // Connection IDs
    /// Original destination connection ID (server only)
    pub original_destination_connection_id: Option<Vec<u8>>,
    
    /// Initial source connection ID
    pub initial_source_connection_id: Option<Vec<u8>>,
    
    /// Retry source connection ID (server only, if Retry packet was sent)
    pub retry_source_connection_id: Option<Vec<u8>>,
    
    // Timeouts
    /// Maximum idle timeout in milliseconds (0 = disabled)
    /// 
    /// **Default**: 0 (no timeout)
    pub max_idle_timeout: Duration,
    
    /// Maximum ACK delay in milliseconds
    ///
    /// **Default**: 25ms
    /// **Max**: 2^14 - 1 (16383ms)
    pub max_ack_delay: Duration,
    
    // Flow Control Limits
    /// Initial maximum data (connection-level flow control)
    ///
    /// **Default**: 0 (no data can be sent)
    pub initial_max_data: u64,
    
    /// Initial maximum stream data for bidirectional streams (local)
    ///
    /// **Default**: 0
    pub initial_max_stream_data_bidi_local: u64,
    
    /// Initial maximum stream data for bidirectional streams (remote)
    ///
    /// **Default**: 0
    pub initial_max_stream_data_bidi_remote: u64,
    
    /// Initial maximum stream data for unidirectional streams
    ///
    /// **Default**: 0
    pub initial_max_stream_data_uni: u64,
    
    /// Initial maximum number of bidirectional streams
    ///
    /// **Default**: 0 (no streams allowed)
    pub initial_max_streams_bidi: u64,
    
    /// Initial maximum number of unidirectional streams
    ///
    /// **Default**: 0 (no streams allowed)
    pub initial_max_streams_uni: u64,
    
    // Other Parameters
    /// Maximum UDP payload size endpoint is willing to receive
    ///
    /// **Default**: 65527 (max UDP payload)
    /// **Min**: 1200 (required by RFC 9000)
    pub max_udp_payload_size: u64,
    
    /// Exponent for decoding ACK delay field
    ///
    /// **Default**: 3
    /// **Max**: 20
    pub ack_delay_exponent: u8,
    
    /// Maximum number of connection IDs endpoint is willing to store
    ///
    /// **Default**: 2
    /// **Min**: 2
    pub active_connection_id_limit: u64,
    
    /// Stateless reset token (server only)
    pub stateless_reset_token: Option<[u8; 16]>,
    
    /// Disable active connection migration
    ///
    /// **Default**: false
    pub disable_active_migration: bool,
    
    /// Preferred address for migration (server only)
    pub preferred_address: Option<PreferredAddress>,
}

impl Default for TransportParameters {
    fn default() -> Self {
        Self {
            original_destination_connection_id: None,
            initial_source_connection_id: None,
            retry_source_connection_id: None,
            max_idle_timeout: Duration::from_secs(0),
            max_ack_delay: Duration::from_millis(25),
            initial_max_data: 0,
            initial_max_stream_data_bidi_local: 0,
            initial_max_stream_data_bidi_remote: 0,
            initial_max_stream_data_uni: 0,
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 0,
            max_udp_payload_size: 65527,
            ack_delay_exponent: 3,
            active_connection_id_limit: 2,
            stateless_reset_token: None,
            disable_active_migration: false,
            preferred_address: None,
        }
    }
}

impl TransportParameters {
    /// Validate transport parameters (RFC 9000 Section 7.4)
    ///
    /// Checks for:
    /// - `max_udp_payload_size` >= 1200
    /// - `ack_delay_exponent` <= 20
    /// - `max_ack_delay` < 2^14
    /// - `active_connection_id_limit` >= 2
    pub fn validate(&self) -> Result<()> {
        // RFC 9000 Section 18.2: max_udp_payload_size must be at least 1200
        if self.max_udp_payload_size < 1200 {
            return Err(Error::Transport(TransportError::TransportParameterError));
        }
        
        // RFC 9000 Section 18.2: ack_delay_exponent must be <= 20
        if self.ack_delay_exponent > 20 {
            return Err(Error::Transport(TransportError::TransportParameterError));
        }
        
        // RFC 9000 Section 18.2: max_ack_delay must be < 2^14
        if self.max_ack_delay >= Duration::from_millis(16384) {
            return Err(Error::Transport(TransportError::TransportParameterError));
        }
        
        // RFC 9000 Section 18.2: active_connection_id_limit must be >= 2
        if self.active_connection_id_limit < 2 {
            return Err(Error::Transport(TransportError::TransportParameterError));
        }
        
        Ok(())
    }
    
    /// Compute the actual ACK delay from the encoded value
    ///
    /// ACK delay is encoded as a varint and scaled by 2^ack_delay_exponent microseconds.
    pub fn decode_ack_delay(&self, encoded: u64) -> Duration {
        let micros = encoded << self.ack_delay_exponent;
        Duration::from_micros(micros)
    }
    
    /// Encode an ACK delay value according to ack_delay_exponent
    pub fn encode_ack_delay(&self, delay: Duration) -> u64 {
        let micros = delay.as_micros() as u64;
        micros >> self.ack_delay_exponent
    }
}

// ============================================================================
// Preferred Address (RFC 9000 Section 18.2)
// ============================================================================

/// Preferred Address (server only)
///
/// The server can provide an alternative address for the client to migrate to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreferredAddress {
    /// IPv4 address (4 bytes)
    pub ipv4_address: Option<[u8; 4]>,
    
    /// IPv4 port
    pub ipv4_port: u16,
    
    /// IPv6 address (16 bytes)
    pub ipv6_address: Option<[u8; 16]>,
    
    /// IPv6 port
    pub ipv6_port: u16,
    
    /// Connection ID for the preferred address
    pub connection_id: Vec<u8>,
    
    /// Stateless reset token for the preferred address
    pub stateless_reset_token: [u8; 16],
}

// ============================================================================
// Transport Parameters Encoder/Decoder Trait
// ============================================================================

/// Transport Parameters Codec
///
/// Defines the interface for encoding and decoding transport parameters
/// for the TLS handshake.
///
/// **RFC 9000 Section 18**: Transport parameters are encoded as a sequence
/// of type-length-value tuples.
pub trait TransportParametersCodec {
    /// Encode transport parameters to bytes
    ///
    /// Returns the encoded buffer suitable for inclusion in the TLS handshake.
    fn encode(&self, params: &TransportParameters) -> Result<Vec<u8>>;
    
    /// Decode transport parameters from bytes
    ///
    /// Parses the buffer received from the TLS handshake.
    ///
    /// **Errors**:
    /// - `TransportParameterError` if encoding is malformed
    /// - `ProtocolViolation` if required parameters are missing
    fn decode(&self, data: &[u8]) -> Result<TransportParameters>;
}

// ============================================================================
// Constants
// ============================================================================

/// Default maximum idle timeout (0 = disabled)
pub const DEFAULT_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(0);

/// Default maximum ACK delay (25ms)
pub const DEFAULT_MAX_ACK_DELAY: Duration = Duration::from_millis(25);

/// Maximum value for max_ack_delay (2^14 - 1 ms)
pub const MAX_ACK_DELAY_LIMIT: Duration = Duration::from_millis(16383);

/// Default ACK delay exponent (3)
pub const DEFAULT_ACK_DELAY_EXPONENT: u8 = 3;

/// Maximum ACK delay exponent (20)
pub const MAX_ACK_DELAY_EXPONENT: u8 = 20;

/// Minimum UDP payload size (1200 bytes)
pub const MIN_UDP_PAYLOAD_SIZE: u64 = 1200;

/// Default maximum UDP payload size (65527 bytes)
pub const DEFAULT_MAX_UDP_PAYLOAD_SIZE: u64 = 65527;

/// Minimum active connection ID limit (2)
pub const MIN_ACTIVE_CONNECTION_ID_LIMIT: u64 = 2;

/// Default active connection ID limit (2)
pub const DEFAULT_ACTIVE_CONNECTION_ID_LIMIT: u64 = 2;
