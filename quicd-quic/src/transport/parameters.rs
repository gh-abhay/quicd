//! # Transport Parameters (RFC 9000 Section 18)
//!
//! Transport parameters are exchanged during the TLS handshake to
//! configure connection behavior. Each parameter is encoded as a
//! type-length-value (TLV) tuple.
//!
//! ## Parameter Types (RFC 9000 Section 18.2)
//!
//! Core parameters include flow control limits, idle timeout,
//! maximum packet sizes, and connection IDs.

extern crate alloc;

use crate::error::*;
use crate::types::*;
use bytes::{Bytes, BytesMut};

/// Transport Parameter ID (RFC 9000 Section 18.2)
pub type TransportParameterId = VarInt;

// Transport Parameter IDs
pub const TP_ORIGINAL_DESTINATION_CONNECTION_ID: TransportParameterId = 0x00;
pub const TP_MAX_IDLE_TIMEOUT: TransportParameterId = 0x01;
pub const TP_STATELESS_RESET_TOKEN: TransportParameterId = 0x02;
pub const TP_MAX_UDP_PAYLOAD_SIZE: TransportParameterId = 0x03;
pub const TP_INITIAL_MAX_DATA: TransportParameterId = 0x04;
pub const TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: TransportParameterId = 0x05;
pub const TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: TransportParameterId = 0x06;
pub const TP_INITIAL_MAX_STREAM_DATA_UNI: TransportParameterId = 0x07;
pub const TP_INITIAL_MAX_STREAMS_BIDI: TransportParameterId = 0x08;
pub const TP_INITIAL_MAX_STREAMS_UNI: TransportParameterId = 0x09;
pub const TP_ACK_DELAY_EXPONENT: TransportParameterId = 0x0a;
pub const TP_MAX_ACK_DELAY: TransportParameterId = 0x0b;
pub const TP_DISABLE_ACTIVE_MIGRATION: TransportParameterId = 0x0c;
pub const TP_PREFERRED_ADDRESS: TransportParameterId = 0x0d;
pub const TP_ACTIVE_CONNECTION_ID_LIMIT: TransportParameterId = 0x0e;
pub const TP_INITIAL_SOURCE_CONNECTION_ID: TransportParameterId = 0x0f;
pub const TP_RETRY_SOURCE_CONNECTION_ID: TransportParameterId = 0x10;

/// Transport Parameters Structure (RFC 9000 Section 18)
///
/// Contains all QUIC configuration parameters exchanged during handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportParameters {
    // Connection IDs
    pub original_destination_connection_id: Option<ConnectionId>,
    pub initial_source_connection_id: Option<ConnectionId>,
    pub retry_source_connection_id: Option<ConnectionId>,

    // Stateless Reset
    pub stateless_reset_token: Option<[u8; 16]>,

    // Idle Timeout
    pub max_idle_timeout: Option<VarInt>, // milliseconds

    // Flow Control
    pub initial_max_data: VarInt,
    pub initial_max_stream_data_bidi_local: VarInt,
    pub initial_max_stream_data_bidi_remote: VarInt,
    pub initial_max_stream_data_uni: VarInt,

    // Stream Limits
    pub initial_max_streams_bidi: VarInt,
    pub initial_max_streams_uni: VarInt,

    // Packet Size
    pub max_udp_payload_size: Option<VarInt>, // default: 65527

    // ACK Parameters
    pub ack_delay_exponent: Option<VarInt>, // default: 3
    pub max_ack_delay: Option<VarInt>,      // milliseconds, default: 25

    // Migration
    pub disable_active_migration: bool,
    pub preferred_address: Option<PreferredAddress>,

    // Connection ID Management
    pub active_connection_id_limit: Option<VarInt>, // default: 2

    // Extension Parameters
    pub unknown_parameters: alloc::vec::Vec<(TransportParameterId, Bytes)>,
}

impl Default for TransportParameters {
    fn default() -> Self {
        Self::default_client()
    }
}

impl TransportParameters {
    /// Create default client parameters
    pub fn default_client() -> Self {
        Self {
            original_destination_connection_id: None,
            initial_source_connection_id: None,
            retry_source_connection_id: None,
            stateless_reset_token: None,
            max_idle_timeout: Some(DEFAULT_IDLE_TIMEOUT.as_millis() as VarInt),
            initial_max_data: DEFAULT_INITIAL_MAX_DATA,
            initial_max_stream_data_bidi_local: DEFAULT_INITIAL_MAX_STREAM_DATA_BIDI,
            initial_max_stream_data_bidi_remote: DEFAULT_INITIAL_MAX_STREAM_DATA_BIDI,
            initial_max_stream_data_uni: DEFAULT_INITIAL_MAX_STREAM_DATA_UNI,
            initial_max_streams_bidi: DEFAULT_MAX_STREAMS_BIDI,
            initial_max_streams_uni: DEFAULT_MAX_STREAMS_UNI,
            max_udp_payload_size: Some(DEFAULT_MAX_UDP_PAYLOAD_SIZE as VarInt),
            ack_delay_exponent: Some(3),
            max_ack_delay: Some(25),
            disable_active_migration: false,
            preferred_address: None,
            active_connection_id_limit: Some(2),
            unknown_parameters: alloc::vec::Vec::new(),
        }
    }

    /// Create default server parameters
    pub fn default_server() -> Self {
        let mut params = Self::default_client();
        // Server can provide stateless reset token
        params.stateless_reset_token = None; // Set by implementation
        params
    }

    /// Validate transport parameters
    ///
    /// Checks that all parameters are within valid ranges per RFC 9000.
    pub fn validate(&self) -> Result<()> {
        // max_udp_payload_size must be >= 1200
        if let Some(size) = self.max_udp_payload_size {
            if size < 1200 {
                return Err(Error::Transport(TransportError::TransportParameterError));
            }
        }

        // ack_delay_exponent must be <= 20
        if let Some(exp) = self.ack_delay_exponent {
            if exp > 20 {
                return Err(Error::Transport(TransportError::TransportParameterError));
            }
        }

        // max_ack_delay must be < 2^14
        if let Some(delay) = self.max_ack_delay {
            if delay >= (1 << 14) {
                return Err(Error::Transport(TransportError::TransportParameterError));
            }
        }

        // active_connection_id_limit must be >= 2
        if let Some(limit) = self.active_connection_id_limit {
            if limit < 2 {
                return Err(Error::Transport(TransportError::TransportParameterError));
            }
        }

        Ok(())
    }
}

/// Preferred Address (RFC 9000 Section 18.2)
///
/// Allows server to advertise an alternative address for connection migration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreferredAddress {
    /// IPv4 address (4 bytes)
    pub ipv4_address: Option<[u8; 4]>,

    /// IPv4 port
    pub ipv4_port: Option<u16>,

    /// IPv6 address (16 bytes)
    pub ipv6_address: Option<[u8; 16]>,

    /// IPv6 port
    pub ipv6_port: Option<u16>,

    /// Connection ID for preferred address
    pub connection_id: ConnectionId,

    /// Stateless reset token for preferred address
    pub stateless_reset_token: [u8; 16],
}

/// Transport Parameters Codec
///
/// Encodes and decodes transport parameters in TLV format.
pub trait TransportParametersCodec {
    /// Encode transport parameters into a buffer
    ///
    /// Returns the number of bytes written.
    fn encode(&self, params: &TransportParameters, buf: &mut BytesMut) -> Result<usize>;

    /// Decode transport parameters from a buffer
    ///
    /// Returns the decoded parameters and number of bytes consumed.
    fn decode(&self, buf: &[u8]) -> Result<TransportParameters>;
}

/// Transport Parameters Builder
///
/// Fluent interface for constructing transport parameters.
pub struct TransportParametersBuilder {
    params: TransportParameters,
}

impl TransportParametersBuilder {
    /// Create a new builder with default values
    pub fn new() -> Self {
        Self {
            params: TransportParameters::default(),
        }
    }

    /// Set original destination connection ID
    pub fn original_destination_connection_id(mut self, cid: ConnectionId) -> Self {
        self.params.original_destination_connection_id = Some(cid);
        self
    }

    /// Set initial source connection ID
    pub fn initial_source_connection_id(mut self, cid: ConnectionId) -> Self {
        self.params.initial_source_connection_id = Some(cid);
        self
    }

    /// Set stateless reset token
    pub fn stateless_reset_token(mut self, token: [u8; 16]) -> Self {
        self.params.stateless_reset_token = Some(token);
        self
    }

    /// Set max idle timeout (milliseconds)
    pub fn max_idle_timeout(mut self, timeout: VarInt) -> Self {
        self.params.max_idle_timeout = Some(timeout);
        self
    }

    /// Set initial max data
    pub fn initial_max_data(mut self, max_data: VarInt) -> Self {
        self.params.initial_max_data = max_data;
        self
    }

    /// Set initial max stream data for bidirectional streams (local)
    pub fn initial_max_stream_data_bidi_local(mut self, max_data: VarInt) -> Self {
        self.params.initial_max_stream_data_bidi_local = max_data;
        self
    }

    /// Set initial max stream data for bidirectional streams (remote)
    pub fn initial_max_stream_data_bidi_remote(mut self, max_data: VarInt) -> Self {
        self.params.initial_max_stream_data_bidi_remote = max_data;
        self
    }

    /// Set initial max stream data for unidirectional streams
    pub fn initial_max_stream_data_uni(mut self, max_data: VarInt) -> Self {
        self.params.initial_max_stream_data_uni = max_data;
        self
    }

    /// Set initial max bidirectional streams
    pub fn initial_max_streams_bidi(mut self, max_streams: VarInt) -> Self {
        self.params.initial_max_streams_bidi = max_streams;
        self
    }

    /// Set initial max unidirectional streams
    pub fn initial_max_streams_uni(mut self, max_streams: VarInt) -> Self {
        self.params.initial_max_streams_uni = max_streams;
        self
    }

    /// Set max UDP payload size
    pub fn max_udp_payload_size(mut self, size: VarInt) -> Self {
        self.params.max_udp_payload_size = Some(size);
        self
    }

    /// Set ACK delay exponent
    pub fn ack_delay_exponent(mut self, exponent: VarInt) -> Self {
        self.params.ack_delay_exponent = Some(exponent);
        self
    }

    /// Set max ACK delay (milliseconds)
    pub fn max_ack_delay(mut self, delay: VarInt) -> Self {
        self.params.max_ack_delay = Some(delay);
        self
    }

    /// Disable active migration
    pub fn disable_active_migration(mut self) -> Self {
        self.params.disable_active_migration = true;
        self
    }

    /// Set preferred address
    pub fn preferred_address(mut self, addr: PreferredAddress) -> Self {
        self.params.preferred_address = Some(addr);
        self
    }

    /// Set active connection ID limit
    pub fn active_connection_id_limit(mut self, limit: VarInt) -> Self {
        self.params.active_connection_id_limit = Some(limit);
        self
    }

    /// Build the transport parameters
    pub fn build(self) -> Result<TransportParameters> {
        self.params.validate()?;
        Ok(self.params)
    }
}

impl Default for TransportParametersBuilder {
    fn default() -> Self {
        Self::new()
    }
}
