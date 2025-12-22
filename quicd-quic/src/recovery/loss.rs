//! # Loss Detection (RFC 9002 Sections 5-6)
//!
//! Implements QUIC loss detection mechanism:
//! - Packet loss detection using time/packet thresholds
//! - Probe Timeout (PTO) for retransmission
//! - Per-packet-number-space tracking

extern crate alloc;

use crate::types::*;
use crate::error::*;
use core::time::Duration;

/// Loss Detection Algorithm Trait (RFC 9002 Section 6)
///
/// Detects packet loss using time and packet thresholds.
pub trait LossDetector: Send {
    /// Process an ACK frame
    ///
    /// Updates sent packet tracking and detects newly acknowledged
    /// and lost packets.
    ///
    /// Returns (newly_acked, newly_lost)
    fn on_ack_received(
        &mut self,
        space: PacketNumberSpace,
        largest_acked: PacketNumber,
        ack_delay: Duration,
        ack_ranges: &[(PacketNumber, PacketNumber)],
        recv_time: Instant,
    ) -> Result<(alloc::vec::Vec<PacketNumber>, alloc::vec::Vec<PacketNumber>)>;
    
    /// Check for loss due to time threshold
    ///
    /// Called periodically to detect packets that exceeded loss_time threshold.
    fn detect_lost_packets(
        &mut self,
        space: PacketNumberSpace,
        now: Instant,
    ) -> alloc::vec::Vec<PacketNumber>;
    
    /// Get the next timer deadline
    ///
    /// Returns the earliest time when loss detection action is needed.
    /// This could be a loss timer or PTO timer.
    fn get_loss_detection_timer(&self) -> Option<Instant>;
    
    /// Timer expired - take action
    ///
    /// Called when the loss detection timer fires.
    /// Returns whether probes should be sent.
    fn on_loss_detection_timeout(&mut self, now: Instant) -> LossDetectionAction;
    
    /// Record a sent packet
    fn on_packet_sent(
        &mut self,
        space: PacketNumberSpace,
        packet_number: PacketNumber,
        size: usize,
        is_retransmittable: bool,
        send_time: Instant,
    );
    
    /// Get the number of PTO probes to send
    fn pto_count(&self) -> u32;
    
    /// Discard state for a packet number space
    ///
    /// Called when keys are discarded (e.g., after handshake completes).
    fn discard_pn_space(&mut self, space: PacketNumberSpace);
}

/// Loss Detection Action
///
/// Returned when loss detection timer fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossDetectionAction {
    /// No action needed
    None,
    
    /// Send probe packets
    SendProbe {
        /// Packet number space to probe
        space: PacketNumberSpace,
        /// Number of probe packets to send
        count: u32,
    },
    
    /// Check for lost packets
    CheckLoss {
        /// Packet number space to check
        space: PacketNumberSpace,
    },
}

/// Sent Packet Tracker
///
/// Tracks sent packets for loss detection and RTT calculation.
pub trait SentPacketTracker: Send {
    /// Record a sent packet
    fn record_sent(
        &mut self,
        space: PacketNumberSpace,
        packet_number: PacketNumber,
        info: SentPacketInfo,
    );
    
    /// Mark packets as acknowledged
    fn on_packets_acked(
        &mut self,
        space: PacketNumberSpace,
        packet_numbers: &[PacketNumber],
    ) -> alloc::vec::Vec<SentPacketInfo>;
    
    /// Mark packets as lost
    fn on_packets_lost(
        &mut self,
        space: PacketNumberSpace,
        packet_numbers: &[PacketNumber],
    ) -> alloc::vec::Vec<SentPacketInfo>;
    
    /// Get the largest acknowledged packet number
    fn largest_acked(&self, space: PacketNumberSpace) -> Option<PacketNumber>;
    
    /// Get all sent but not acknowledged packets
    fn get_unacked_packets(
        &self,
        space: PacketNumberSpace,
    ) -> alloc::vec::Vec<&SentPacketInfo>;
    
    /// Remove all tracking for a packet number space
    fn discard_space(&mut self, space: PacketNumberSpace);
}

/// Sent Packet Info (already defined in congestion.rs, re-export)
///
/// Information about a sent packet.
#[derive(Debug, Clone)]
pub struct SentPacketInfo {
    /// Packet number
    pub packet_number: PacketNumber,
    
    /// Packet number space
    pub pn_space: PacketNumberSpace,
    
    /// Size in bytes
    pub size: usize,
    
    /// Send timestamp
    pub send_time: Instant,
    
    /// Whether this packet contains retransmittable frames
    pub is_retransmittable: bool,
    
    /// Whether this packet has been acknowledged
    pub acked: bool,
    
    /// Whether this packet has been declared lost
    pub lost: bool,
}

/// Loss Detection Configuration (RFC 9002 Appendix A)
#[derive(Debug, Clone, Copy)]
pub struct LossDetectionConfig {
    /// Time threshold for packet reordering (default: 9/8)
    ///
    /// A packet is declared lost if a packet sent later is acknowledged
    /// and at least time_threshold * max(smoothed_rtt, latest_rtt) has passed.
    pub time_threshold: f64,
    
    /// Packet threshold for reordering (default: 3)
    ///
    /// A packet is declared lost if a packet sent at least packet_threshold
    /// packets later is acknowledged.
    pub packet_threshold: u64,
    
    /// Initial RTT (default: 333ms)
    pub initial_rtt: Duration,
    
    /// Maximum ACK delay (default: 25ms)
    pub max_ack_delay: Duration,
    
    /// PTO multiplier (default: 2)
    ///
    /// Exponential backoff multiplier for PTO.
    pub pto_multiplier: u32,
}

impl Default for LossDetectionConfig {
    fn default() -> Self {
        Self {
            time_threshold: 9.0 / 8.0,
            packet_threshold: 3,
            initial_rtt: Duration::from_millis(333),
            max_ack_delay: Duration::from_millis(25),
            pto_multiplier: 2,
        }
    }
}

/// Probe Timeout (PTO) Calculator
///
/// Calculates PTO values per RFC 9002 Section 6.2.
pub trait PtoCalculator: Send {
    /// Calculate PTO for a packet number space
    ///
    /// PTO = smoothed_rtt + max(4*rttvar, 1ms) + max_ack_delay
    fn calculate_pto(&self, space: PacketNumberSpace, pto_count: u32) -> Duration;
    
    /// Get the PTO backoff multiplier
    ///
    /// Exponentially backs off: 2^pto_count
    fn pto_backoff(&self, pto_count: u32) -> u32 {
        2u32.saturating_pow(pto_count)
    }
}

/// Loss Detection State per Packet Number Space
#[derive(Debug, Clone)]
pub struct PacketNumberSpaceLossState {
    /// Largest acknowledged packet number
    pub largest_acked: Option<PacketNumber>,
    
    /// Time the most recent packet was sent
    pub time_of_last_sent_packet: Option<Instant>,
    
    /// Largest sent packet number
    pub largest_sent_packet: Option<PacketNumber>,
    
    /// Loss time for this space (when to declare losses)
    pub loss_time: Option<Instant>,
    
    /// Number of consecutive PTO timeouts
    pub pto_count: u32,
}

impl Default for PacketNumberSpaceLossState {
    fn default() -> Self {
        Self {
            largest_acked: None,
            time_of_last_sent_packet: None,
            largest_sent_packet: None,
            loss_time: None,
            pto_count: 0,
        }
    }
}
