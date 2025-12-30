//! # Loss Detection (RFC 9002 Sections 5-6)
//!
//! Implements QUIC loss detection mechanism:
//! - Packet loss detection using time/packet thresholds
//! - Probe Timeout (PTO) for retransmission
//! - Per-packet-number-space tracking

extern crate alloc;

use crate::error::*;
use crate::types::*;
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
    /// Returns (newly_acked, newly_lost) where each entry is (packet_number, size)
    fn on_ack_received(
        &mut self,
        space: PacketNumberSpace,
        largest_acked: PacketNumber,
        ack_delay: Duration,
        ack_ranges: &[(PacketNumber, PacketNumber)],
        recv_time: Instant,
    ) -> Result<(alloc::vec::Vec<(PacketNumber, usize)>, alloc::vec::Vec<(PacketNumber, usize)>)>;

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
    fn get_unacked_packets(&self, space: PacketNumberSpace) -> alloc::vec::Vec<&SentPacketInfo>;

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

// ============================================================================
// Default Loss Detection Implementation
// ============================================================================

use crate::recovery::rtt::RttEstimator;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Default Loss Detector Implementation (RFC 9002 Appendix A)
pub struct DefaultLossDetector {
    /// Configuration
    config: LossDetectionConfig,

    /// RTT estimator
    rtt_estimator: RttEstimator,

    /// Sent packets tracking (per space)
    sent_packets: [BTreeMap<PacketNumber, SentPacketInfo>; 3],

    /// Loss state per packet number space
    loss_state: [PacketNumberSpaceLossState; 3],

    /// Time of last ACK-eliciting packet sent
    time_of_last_ack_eliciting_packet: Option<Instant>,
}

impl DefaultLossDetector {
    /// Create new loss detector
    pub fn new(config: LossDetectionConfig) -> Self {
        Self {
            rtt_estimator: RttEstimator::new(config.initial_rtt),
            config,
            sent_packets: [BTreeMap::new(), BTreeMap::new(), BTreeMap::new()],
            loss_state: [
                PacketNumberSpaceLossState::default(),
                PacketNumberSpaceLossState::default(),
                PacketNumberSpaceLossState::default(),
            ],
            time_of_last_ack_eliciting_packet: None,
        }
    }

    /// Get space index
    fn space_index(space: PacketNumberSpace) -> usize {
        match space {
            PacketNumberSpace::Initial => 0,
            PacketNumberSpace::Handshake => 1,
            PacketNumberSpace::ApplicationData => 2,
        }
    }

    /// Calculate loss delay threshold (RFC 9002 Section 6.1.2)
    fn loss_delay_threshold(&self) -> core::time::Duration {
        let rtt = self
            .rtt_estimator
            .latest_rtt()
            .max(self.rtt_estimator.smoothed_rtt());
        let threshold_multiplier = self.config.time_threshold;

        // loss_delay = time_threshold * max(latest_rtt, smoothed_rtt)
        rtt.mul_f64(threshold_multiplier)
    }

    /// Detect lost packets by packet threshold (RFC 9002 Section 6.1.1)
    fn detect_by_packet_threshold(
        &mut self,
        space: PacketNumberSpace,
        largest_acked: PacketNumber,
    ) -> Vec<PacketNumber> {
        let idx = Self::space_index(space);
        let mut lost = Vec::new();

        let threshold = self.config.packet_threshold;

        // Packets sent at least packet_threshold packets before largest_acked are lost
        for (&pn, info) in &self.sent_packets[idx] {
            if pn >= largest_acked {
                break; // No more candidates
            }

            if largest_acked - pn >= threshold {
                if !info.acked && !info.lost {
                    lost.push(pn);
                }
            }
        }

        lost
    }

    /// Detect lost packets by time threshold (RFC 9002 Section 6.1.2)
    fn detect_by_time_threshold(
        &mut self,
        space: PacketNumberSpace,
        now: Instant,
    ) -> Vec<PacketNumber> {
        let idx = Self::space_index(space);
        let mut lost = Vec::new();

        let loss_delay = self.loss_delay_threshold();

        // Packets sent more than loss_delay ago are lost
        for (&pn, info) in &self.sent_packets[idx] {
            if info.acked || info.lost {
                continue;
            }

            if let Some(duration) = now.duration_since(info.send_time) {
                if duration >= loss_delay {
                    lost.push(pn);
                }
            }
        }

        lost
    }

    /// Set loss detection timer (RFC 9002 Section 6.2)
    fn set_loss_detection_timer(&mut self) {
        // Find earliest loss time across all spaces
        let mut earliest_loss_time: Option<Instant> = None;

        for state in &self.loss_state {
            if let Some(loss_time) = state.loss_time {
                earliest_loss_time = Some(match earliest_loss_time {
                    Some(earliest) if loss_time < earliest => loss_time,
                    Some(earliest) => earliest,
                    None => loss_time,
                });
            }
        }

        // Loss timer takes precedence over PTO
        if earliest_loss_time.is_some() {
            return;
        }

        // Calculate PTO timer
        // Find the first space with ACK-eliciting packets in flight
        for (idx, state) in self.loss_state.iter().enumerate() {
            if state.time_of_last_sent_packet.is_some() {
                let space = match idx {
                    0 => PacketNumberSpace::Initial,
                    1 => PacketNumberSpace::Handshake,
                    _ => PacketNumberSpace::ApplicationData,
                };

                let _pto = self.calculate_pto_for_space(space, state.pto_count);
                // Set timer would happen here in real implementation
                break;
            }
        }
    }

    /// Calculate PTO for a specific space (RFC 9002 Section 6.2)
    fn calculate_pto_for_space(
        &self,
        space: PacketNumberSpace,
        pto_count: u32,
    ) -> core::time::Duration {
        let max_ack_delay = if space == PacketNumberSpace::ApplicationData {
            self.config.max_ack_delay
        } else {
            core::time::Duration::from_secs(0)
        };

        let pto = self.rtt_estimator.pto(max_ack_delay, pto_count);
        pto
    }
}

impl LossDetector for DefaultLossDetector {
    fn on_ack_received(
        &mut self,
        space: PacketNumberSpace,
        largest_acked: PacketNumber,
        _ack_delay: core::time::Duration,
        _ack_ranges: &[(PacketNumber, PacketNumber)],
        recv_time: Instant,
    ) -> Result<(Vec<(PacketNumber, usize)>, Vec<(PacketNumber, usize)>)> {
        let idx = Self::space_index(space);

        // Update largest acknowledged
        self.loss_state[idx].largest_acked = Some(largest_acked);
        self.loss_state[idx].pto_count = 0; // Reset PTO count on ACK

        // Detect lost packets FIRST (before marking as acked)
        let mut newly_lost = Vec::new();
        let lost_pns = self.detect_by_packet_threshold(space, largest_acked);
        for pn in lost_pns {
            if let Some(info) = self.sent_packets[idx].get(&pn) {
                newly_lost.push((pn, info.size));
            }
        }

        // Find newly acknowledged packets
        let mut newly_acked = Vec::new();

        // Simple implementation: just check largest_acked
        // Full implementation would process ack_ranges
        for (&pn, info) in &mut self.sent_packets[idx] {
            if pn <= largest_acked && !info.acked && !info.lost {
                info.acked = true;
                newly_acked.push((pn, info.size));

                // Update RTT if this is the largest acked
                if pn == largest_acked && info.is_retransmittable {
                    if let Some(rtt_sample) = recv_time.duration_since(info.send_time) {
                        self.rtt_estimator.update(rtt_sample);
                    }
                }
            }
        }

        // Mark packets as lost
        for &(pn, _) in &newly_lost {
            if let Some(info) = self.sent_packets[idx].get_mut(&pn) {
                info.lost = true;
            }
        }

        Ok((newly_acked, newly_lost))
    }

    fn detect_lost_packets(&mut self, space: PacketNumberSpace, now: Instant) -> Vec<PacketNumber> {
        let lost = self.detect_by_time_threshold(space, now);

        let idx = Self::space_index(space);
        for &pn in &lost {
            if let Some(info) = self.sent_packets[idx].get_mut(&pn) {
                info.lost = true;
            }
        }

        lost
    }

    fn get_loss_detection_timer(&self) -> Option<Instant> {
        // Find earliest loss time or PTO time
        let mut earliest: Option<Instant> = None;

        for state in &self.loss_state {
            if let Some(loss_time) = state.loss_time {
                earliest = Some(match earliest {
                    Some(e) if loss_time < e => loss_time,
                    Some(e) => e,
                    None => loss_time,
                });
            }
        }

        earliest
    }

    fn on_loss_detection_timeout(&mut self, now: Instant) -> LossDetectionAction {
        // Check if any loss timers expired
        for (idx, state) in self.loss_state.iter_mut().enumerate() {
            if let Some(loss_time) = state.loss_time {
                if now >= loss_time {
                    let space = match idx {
                        0 => PacketNumberSpace::Initial,
                        1 => PacketNumberSpace::Handshake,
                        _ => PacketNumberSpace::ApplicationData,
                    };

                    state.loss_time = None;
                    return LossDetectionAction::CheckLoss { space };
                }
            }
        }

        // No loss timer - must be PTO
        // Send probe packets
        for (idx, state) in self.loss_state.iter_mut().enumerate() {
            if state.time_of_last_sent_packet.is_some() {
                let space = match idx {
                    0 => PacketNumberSpace::Initial,
                    1 => PacketNumberSpace::Handshake,
                    _ => PacketNumberSpace::ApplicationData,
                };

                state.pto_count += 1;
                let count = state.pto_count.min(2); // Send up to 2 probes

                return LossDetectionAction::SendProbe { space, count };
            }
        }

        LossDetectionAction::None
    }

    fn on_packet_sent(
        &mut self,
        space: PacketNumberSpace,
        packet_number: PacketNumber,
        size: usize,
        is_retransmittable: bool,
        send_time: Instant,
    ) {
        let idx = Self::space_index(space);

        let info = SentPacketInfo {
            packet_number,
            pn_space: space,
            size,
            send_time,
            is_retransmittable,
            acked: false,
            lost: false,
        };

        self.sent_packets[idx].insert(packet_number, info);

        self.loss_state[idx].largest_sent_packet = Some(packet_number);
        self.loss_state[idx].time_of_last_sent_packet = Some(send_time);

        if is_retransmittable {
            self.time_of_last_ack_eliciting_packet = Some(send_time);
        }

        self.set_loss_detection_timer();
    }

    fn pto_count(&self) -> u32 {
        // Return max PTO count across all spaces
        self.loss_state
            .iter()
            .map(|s| s.pto_count)
            .max()
            .unwrap_or(0)
    }

    fn discard_pn_space(&mut self, space: PacketNumberSpace) {
        let idx = Self::space_index(space);
        self.sent_packets[idx].clear();
        self.loss_state[idx] = PacketNumberSpaceLossState::default();
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

