//! # Loss Detection Traits (RFC 9002 Section 6)
//!
//! Detects packet loss and triggers retransmission.

#![forbid(unsafe_code)]

use crate::types::{Instant, PacketNumber, PacketNumberSpace};

/// Packet Sent Information
///
/// Metadata tracked for each sent packet to detect loss.
#[derive(Debug, Clone)]
pub struct PacketSentInfo {
    /// Packet number
    pub packet_number: PacketNumber,

    /// Packet number space
    pub space: PacketNumberSpace,

    /// Time packet was sent
    pub time_sent: Instant,

    /// Size of packet in bytes
    pub sent_bytes: usize,

    /// Whether packet is ACK-eliciting
    pub is_ack_eliciting: bool,

    /// Whether packet is in flight (counts toward bytes_in_flight)
    pub in_flight: bool,
}

/// Recovery State (Per-Connection)
///
/// Tracks state for loss detection and congestion control.
#[derive(Debug, Clone)]
pub struct RecoveryState {
    /// Time of last ACK-eliciting packet sent
    pub time_of_last_ack_eliciting_packet: Option<Instant>,

    /// Largest acknowledged packet number per space
    pub largest_acked_packet: [Option<PacketNumber>; 3],

    /// Loss time (when to check for losses by time threshold)
    pub loss_time: [Option<Instant>; 3],

    /// PTO count (probe timeout count, for exponential backoff)
    pub pto_count: u32,
}

impl RecoveryState {
    pub fn new() -> Self {
        Self {
            time_of_last_ack_eliciting_packet: None,
            largest_acked_packet: [None, None, None],
            loss_time: [None, None, None],
            pto_count: 0,
        }
    }
}

impl Default for RecoveryState {
    fn default() -> Self {
        Self::new()
    }
}
