//! # Connection ID Management (RFC 9000 Section 5.1)
//!
//! Pluggable connection ID generation and rotation for QUIC connections.
//!
//! ## Architecture
//!
//! The library provides a trait-based system where:
//! - **quicd-quic library**: Manages CID lifecycle, sequence numbers, rotation
//! - **quicd server**: Provides eBPF-aware CID generator with routing cookies
//!
//! ## eBPF Integration
//!
//! The quicd server embeds routing cookies in connection IDs which are
//! extracted by kernel-space eBPF programs to route packets to specific
//! worker threads. This enables zero-contention connection affinity.

#![forbid(unsafe_code)]

extern crate alloc;
use crate::error::{Error, Result};
use crate::types::{ConnectionId, StatelessResetToken};
use alloc::collections::BTreeMap as HashMap;
use alloc::vec::Vec;
use bytes::Bytes;

/// Connection ID Generator Trait
///
/// **Pluggable Design**: Implementations can embed arbitrary routing
/// information in connection IDs (e.g., eBPF routing cookies).
///
/// **Requirements**:
/// - Generated CIDs MUST be unique within a connection
/// - CIDs SHOULD be unpredictable to external observers
/// - CIDs MUST be between 0 and 20 bytes (RFC 9000 Section 5.1)
pub trait ConnectionIdGenerator: Send + Sync + core::fmt::Debug {
    /// Generate a new connection ID
    ///
    /// **Context**: `sequence_number` tracks issuance order (starts at 0).
    /// Implementations can use this to vary routing if needed.
    fn generate_cid(&mut self, sequence_number: u64) -> Result<ConnectionId>;

    /// Calculate stateless reset token for a connection ID
    ///
    /// **RFC 9000 Section 10.3.2**: Token = HMAC(static_key, cid)[0..16]
    ///
    /// This allows server to recognize connections without state.
    fn calculate_reset_token(&self, cid: &ConnectionId) -> StatelessResetToken;
}

/// Connection ID Manager
///
/// Manages the lifecycle of connection IDs for a single connection:
/// - Issues NEW_CONNECTION_ID frames with increasing sequence numbers
/// - Retires old CIDs via RETIRE_CONNECTION_ID
/// - Tracks active_connection_id_limit from peer
#[derive(Debug)]
pub struct ConnectionIdManager {
    /// Connection ID generator (pluggable)
    generator: Box<dyn ConnectionIdGenerator>,

    /// Active connection IDs (keyed by sequence number)
    active_cids: HashMap<u64, ActiveConnectionId>,

    /// Next sequence number to issue
    next_sequence_number: u64,

    /// Retired CID sequence numbers (pending acknowledgment)
    retired_sequence_numbers: Vec<u64>,

    /// Peer's active_connection_id_limit
    peer_cid_limit: u64,

    /// Our active_connection_id_limit (how many we can receive)
    local_cid_limit: u64,
}

/// Active Connection ID Entry
#[derive(Debug, Clone)]
struct ActiveConnectionId {
    /// Sequence number
    sequence_number: u64,

    /// Connection ID value
    connection_id: ConnectionId,

    /// Stateless reset token for this CID
    reset_token: StatelessResetToken,

    /// Whether this CID has been advertised to peer
    advertised: bool,
}

impl ConnectionIdManager {
    /// Create new CID manager
    ///
    /// **Parameters**:
    /// - `generator`: Pluggable CID generator (e.g., eBPF-aware)
    /// - `initial_cid`: Connection ID from handshake (sequence 0)
    /// - `local_cid_limit`: How many CIDs we can track from peer
    pub fn new(
        generator: Box<dyn ConnectionIdGenerator>,
        initial_cid: ConnectionId,
        local_cid_limit: u64,
    ) -> Self {
        let reset_token = generator.calculate_reset_token(&initial_cid);

        let mut active_cids = HashMap::new();
        active_cids.insert(
            0,
            ActiveConnectionId {
                sequence_number: 0,
                connection_id: initial_cid,
                reset_token,
                advertised: true, // Initial CID sent in handshake
            },
        );

        Self {
            generator,
            active_cids,
            next_sequence_number: 1,
            retired_sequence_numbers: Vec::new(),
            peer_cid_limit: 2, // Default minimum (RFC 9000 Section 5.1)
            local_cid_limit,
        }
    }

    /// Set peer's active_connection_id_limit from transport parameters
    pub fn set_peer_cid_limit(&mut self, limit: u64) {
        self.peer_cid_limit = limit;
    }

    /// Get local CID limit (for transport parameters)
    pub fn local_cid_limit(&self) -> u64 {
        self.local_cid_limit
    }

    /// Generate and issue new connection IDs
    ///
    /// **Returns**: List of (sequence_number, cid, reset_token) tuples
    /// to send in NEW_CONNECTION_ID frames.
    ///
    /// **RFC 9000 Section 5.1.1**: Endpoint SHOULD ensure peer has
    /// sufficient unused CIDs.
    pub fn issue_new_cids(&mut self, count: usize) -> Result<Vec<NewConnectionIdData>> {
        let mut new_cids = Vec::new();

        for _ in 0..count {
            // Check if we would exceed peer's limit
            if self.active_cids.len() >= self.peer_cid_limit as usize {
                break;
            }

            let seq_num = self.next_sequence_number;
            let cid = self.generator.generate_cid(seq_num)?;
            let reset_token = self.generator.calculate_reset_token(&cid);

            self.active_cids.insert(
                seq_num,
                ActiveConnectionId {
                    sequence_number: seq_num,
                    connection_id: cid.clone(),
                    reset_token,
                    advertised: false,
                },
            );

            new_cids.push(NewConnectionIdData {
                sequence_number: seq_num,
                connection_id: cid,
                reset_token,
                retire_prior_to: 0, // Don't force retirement
            });

            self.next_sequence_number += 1;
        }

        Ok(new_cids)
    }

    /// Mark CIDs as advertised (after sending NEW_CONNECTION_ID)
    pub fn mark_advertised(&mut self, sequence_numbers: &[u64]) {
        for &seq_num in sequence_numbers {
            if let Some(cid_entry) = self.active_cids.get_mut(&seq_num) {
                cid_entry.advertised = true;
            }
        }
    }

    /// Handle RETIRE_CONNECTION_ID frame from peer
    ///
    /// **RFC 9000 Section 5.1.2**: Peer no longer uses this CID.
    pub fn retire_cid(&mut self, sequence_number: u64) -> Result<()> {
        if sequence_number >= self.next_sequence_number {
            return Err(Error::Transport(
                crate::error::TransportError::ProtocolViolation,
            ));
        }

        // Remove from active set
        self.active_cids.remove(&sequence_number);

        // Track for cleanup
        self.retired_sequence_numbers.push(sequence_number);

        Ok(())
    }

    /// Request retirement of old CIDs (peer should send RETIRE_CONNECTION_ID)
    ///
    /// **Use case**: Rotate CIDs for privacy or load balancing.
    ///
    /// **Returns**: `retire_prior_to` value to include in NEW_CONNECTION_ID.
    pub fn request_retirement(&mut self, retire_prior_to: u64) -> Result<u64> {
        if retire_prior_to >= self.next_sequence_number {
            return Err(Error::InvalidInput);
        }

        Ok(retire_prior_to)
    }

    /// Get current active CID (for sending packets)
    ///
    /// Returns the CID with the highest sequence number.
    pub fn current_cid(&self) -> Option<&ConnectionId> {
        self.active_cids
            .values()
            .max_by_key(|entry| entry.sequence_number)
            .map(|entry| &entry.connection_id)
    }

    /// Get stateless reset token for a specific CID
    pub fn get_reset_token(&self, cid: &ConnectionId) -> Option<StatelessResetToken> {
        self.active_cids
            .values()
            .find(|entry| entry.connection_id.as_bytes() == cid.as_bytes())
            .map(|entry| entry.reset_token)
    }

    /// Get number of active CIDs
    pub fn active_count(&self) -> usize {
        self.active_cids.len()
    }

    /// Get number of retired CIDs pending cleanup
    pub fn retired_count(&self) -> usize {
        self.retired_sequence_numbers.len()
    }
}

/// Data for NEW_CONNECTION_ID frame
#[derive(Debug, Clone)]
pub struct NewConnectionIdData {
    /// Sequence number
    pub sequence_number: u64,

    /// New connection ID value
    pub connection_id: ConnectionId,

    /// Stateless reset token
    pub reset_token: StatelessResetToken,

    /// Retire all CIDs with sequence < this value
    pub retire_prior_to: u64,
}

/// Default Connection ID Generator (Random)
///
/// Generates random connection IDs without routing information.
/// Used for testing or simple deployments without eBPF.
#[derive(Debug)]
pub struct RandomConnectionIdGenerator {
    /// Static secret for reset token generation
    reset_secret: [u8; 32],
}

impl RandomConnectionIdGenerator {
    /// Create new random CID generator
    pub fn new(reset_secret: [u8; 32]) -> Self {
        Self { reset_secret }
    }

    /// Simple HMAC for reset tokens (placeholder)
    fn compute_hmac(&self, data: &[u8]) -> [u8; 32] {
        let mut result = [0u8; 32];
        for (i, byte) in data.iter().enumerate() {
            result[i % 32] ^= byte.wrapping_add(self.reset_secret[i % 32]);
        }
        result
    }
}

impl ConnectionIdGenerator for RandomConnectionIdGenerator {
    fn generate_cid(&mut self, sequence_number: u64) -> Result<ConnectionId> {
        // Generate 8-byte CID (simple pseudo-random)
        let mut cid_bytes = [0u8; 8];

        // Use sequence number as seed (not cryptographically secure!)
        for i in 0..8 {
            cid_bytes[i] = ((sequence_number >> (i * 8)) as u8)
                .wrapping_mul(i as u8 + 1)
                .wrapping_add(0x42);
        }

        ConnectionId::from_slice(&cid_bytes).ok_or(Error::InvalidInput)
    }

    fn calculate_reset_token(&self, cid: &ConnectionId) -> StatelessResetToken {
        let hmac = self.compute_hmac(cid.as_bytes());

        let mut token = [0u8; 16];
        token.copy_from_slice(&hmac[0..16]);

        StatelessResetToken::from(token)
    }
}

