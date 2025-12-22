//! # Loss Detection and Congestion Control (RFC 9002)
//!
//! This module defines the trait interfaces for QUIC's loss detection
//! and congestion control algorithms.
//!
//! ## RFC 9002: QUIC Loss Detection and Congestion Control
//!
//! QUIC implements:
//! - **Loss Detection**: Identifies lost packets using ACKs and timeouts
//! - **Congestion Control**: Adapts sending rate based on network conditions
//!
//! ## Design:
//! Modular trait-based design allows swapping algorithms:
//! - NewReno (default, RFC 9002 Appendix B)
//! - CUBIC
//! - BBR (experimental)

#![forbid(unsafe_code)]

use crate::error::{Error, Result};
use crate::types::{Instant, PacketNumber, PacketNumberSpace, VarInt};
use core::time::Duration;

/// Congestion Window (bytes)
///
/// Amount of data that can be in flight (unacknowledged).
pub type CongestionWindow = u64;

/// Bytes in Flight
///
/// Total bytes sent but not yet acknowledged or declared lost.
pub type BytesInFlight = u64;

/// Round Trip Time (RTT) in microseconds
pub type RttMicros = u64;

/// Packet Sent Information (RFC 9002 Section 2)
///
/// Metadata tracked for each sent packet to enable loss detection.
#[derive(Debug, Clone, Copy)]
pub struct SentPacketInfo {
    /// Packet number
    pub packet_number: PacketNumber,

    /// Packet number space
    pub pn_space: PacketNumberSpace,

    /// Time when packet was sent
    pub time_sent: Instant,

    /// Size of the packet in bytes
    pub size: usize,

    /// Is this packet ACK-eliciting?
    /// (contains frames that must be acknowledged)
    pub ack_eliciting: bool,

    /// Is this packet in flight?
    /// (counts toward congestion window)
    pub in_flight: bool,
}

/// Packet Acknowledged Information
///
/// Information about a packet that was acknowledged.
#[derive(Debug, Clone, Copy)]
pub struct AckedPacketInfo {
    /// Packet number
    pub packet_number: PacketNumber,

    /// Packet number space
    pub pn_space: PacketNumberSpace,

    /// Time when packet was sent
    pub time_sent: Instant,

    /// Size of the packet in bytes
    pub size: usize,

    /// RTT sample (time between send and ACK)
    pub rtt: Duration,
}

/// Packet Lost Information
///
/// Information about a packet that was declared lost.
#[derive(Debug, Clone, Copy)]
pub struct LostPacketInfo {
    /// Packet number
    pub packet_number: PacketNumber,

    /// Packet number space
    pub pn_space: PacketNumberSpace,

    /// Time when packet was sent
    pub time_sent: Instant,

    /// Size of the packet in bytes
    pub size: usize,
}

/// RTT Statistics (RFC 9002 Section 5)
///
/// Tracks round-trip time measurements for loss detection.
#[derive(Debug, Clone, Copy)]
pub struct RttStats {
    /// Minimum RTT observed
    pub min_rtt: Duration,

    /// Smoothed RTT (exponentially weighted moving average)
    pub smoothed_rtt: Duration,

    /// RTT variation (mean deviation)
    pub rttvar: Duration,

    /// Latest RTT measurement
    pub latest_rtt: Duration,

    /// First RTT sample taken
    pub first_rtt_sample: Option<Duration>,
}

impl Default for RttStats {
    fn default() -> Self {
        Self {
            min_rtt: Duration::from_millis(u64::MAX),
            smoothed_rtt: Duration::from_millis(333), // RFC 9002 Section 6.2.2
            rttvar: Duration::from_millis(167),        // Half of smoothed_rtt
            latest_rtt: Duration::ZERO,
            first_rtt_sample: None,
        }
    }
}

/// Loss Detection Timer Type (RFC 9002 Section 6.2)
///
/// QUIC uses different timers for loss detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossDetectionTimer {
    /// Probe Timeout (PTO): Forces sending new data to elicit ACKs
    Pto,

    /// Loss Detection: Declares packets lost after timeout
    LossDetection,
}

/// Congestion State (RFC 9002 Section 7)
///
/// State machine for congestion control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionState {
    /// Slow Start: Exponential growth
    SlowStart,

    /// Congestion Avoidance: Linear growth
    CongestionAvoidance,

    /// Recovery: After packet loss, until ACKs for new data received
    Recovery,
}

/// Congestion Control Event
///
/// Events that trigger congestion control state changes.
#[derive(Debug, Clone, Copy)]
pub enum CongestionEvent {
    /// Packet acknowledged
    PacketAcked(AckedPacketInfo),

    /// Packet lost
    PacketLost(LostPacketInfo),

    /// Explicit Congestion Notification (ECN) received
    EcnCongestion,

    /// Persistent congestion detected (RFC 9002 Section 7.6)
    PersistentCongestion,
}

/// Loss Detection Trait (RFC 9002 Sections 5-6)
///
/// Identifies lost packets using acknowledgments and timeouts.
pub trait LossDetector {
    /// Process an incoming ACK frame.
    ///
    /// Returns a list of newly acknowledged and lost packets.
    ///
    /// # RFC 9002 Section 6.1
    /// Updates RTT, identifies acknowledged packets, detects losses.
    fn on_ack_received(
        &mut self,
        pn_space: PacketNumberSpace,
        largest_acked: PacketNumber,
        ack_delay: Duration,
        now: Instant,
    ) -> Result<(Vec<AckedPacketInfo>, Vec<LostPacketInfo>)>;

    /// Called when a packet is sent.
    ///
    /// Tracks packet for loss detection and RTT measurement.
    fn on_packet_sent(&mut self, info: SentPacketInfo);

    /// Get the next loss detection timer deadline.
    ///
    /// Returns (timer_type, deadline) or None if no timer active.
    fn get_timer(&self) -> Option<(LossDetectionTimer, Instant)>;

    /// Handle loss detection timer expiration.
    ///
    /// Returns packets that should be retransmitted (PTO probe).
    fn on_timer_expired(&mut self, now: Instant) -> Result<Vec<PacketNumber>>;

    /// Get current RTT statistics
    fn rtt_stats(&self) -> &RttStats;

    /// Update RTT statistics with a new sample.
    ///
    /// # RFC 9002 Section 5.1
    /// Updates smoothed RTT and RTT variation.
    fn update_rtt(&mut self, latest_rtt: Duration, ack_delay: Duration);

    /// Get PTO (Probe Timeout) duration.
    ///
    /// # RFC 9002 Section 6.2.1
    /// PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay
    fn pto_duration(&self, pn_space: PacketNumberSpace) -> Duration;
}

/// Congestion Controller Trait (RFC 9002 Section 7)
///
/// Controls sending rate based on network conditions.
/// Pluggable design allows different algorithms (NewReno, CUBIC, BBR).
pub trait CongestionController {
    /// Get the current congestion window (bytes).
    fn congestion_window(&self) -> CongestionWindow;

    /// Get bytes currently in flight (unacknowledged).
    fn bytes_in_flight(&self) -> BytesInFlight;

    /// Check if sending is blocked by congestion control.
    fn is_cwnd_limited(&self) -> bool;

    /// Get the current congestion state.
    fn state(&self) -> CongestionState;

    /// Process a congestion control event.
    ///
    /// Updates congestion window and state based on the event.
    ///
    /// # RFC 9002 Section 7
    /// - Packet ACKed: Increase cwnd (slow start or congestion avoidance)
    /// - Packet Lost: Decrease cwnd (multiplicative decrease)
    /// - ECN: Treat as congestion signal
    fn on_congestion_event(&mut self, event: CongestionEvent, now: Instant);

    /// Called when a packet is sent.
    ///
    /// Increments bytes_in_flight if packet is in-flight.
    fn on_packet_sent(&mut self, size: usize, in_flight: bool);

    /// Called when a packet is acknowledged.
    ///
    /// Decrements bytes_in_flight, may increase cwnd.
    fn on_packet_acked(&mut self, info: &AckedPacketInfo);

    /// Called when a packet is lost.
    ///
    /// Decrements bytes_in_flight, may decrease cwnd.
    fn on_packet_lost(&mut self, info: &LostPacketInfo);

    /// Check if we can send more data (not blocked by cwnd).
    fn can_send(&self, packet_size: usize) -> bool;

    /// Get the pacing rate (bytes per second).
    ///
    /// Used to smooth out bursts of packets.
    fn pacing_rate(&self) -> Option<u64>;
}

/// NewReno Congestion Control (RFC 9002 Appendix B)
///
/// Default congestion control algorithm for QUIC.
#[derive(Debug, Clone)]
pub struct NewRenoConfig {
    /// Initial congestion window (packets)
    /// RFC 9002 Section 7.2: 10 * max_datagram_size
    pub initial_window: u64,

    /// Minimum congestion window (2 * max_datagram_size)
    pub min_window: u64,

    /// Maximum congestion window
    pub max_window: u64,

    /// Maximum datagram size (bytes)
    pub max_datagram_size: usize,

    /// Slow start threshold
    pub ssthresh: u64,

    /// Persistent congestion threshold (multiple of PTO)
    pub persistent_congestion_threshold: u32,
}

impl Default for NewRenoConfig {
    fn default() -> Self {
        let max_datagram_size = 1200;
        Self {
            initial_window: 10 * max_datagram_size as u64,
            min_window: 2 * max_datagram_size as u64,
            max_window: u64::MAX,
            max_datagram_size,
            ssthresh: u64::MAX,
            persistent_congestion_threshold: 3,
        }
    }
}

/// Recovery Manager
///
/// Coordinates loss detection and congestion control.
///
/// ## Design:
/// Combines LossDetector and CongestionController to manage
/// the complete recovery subsystem.
pub trait RecoveryManager {
    /// Get the loss detector
    fn loss_detector(&self) -> &dyn LossDetector;

    /// Get mutable loss detector
    fn loss_detector_mut(&mut self) -> &mut dyn LossDetector;

    /// Get the congestion controller
    fn congestion_controller(&self) -> &dyn CongestionController;

    /// Get mutable congestion controller
    fn congestion_controller_mut(&mut self) -> &mut dyn CongestionController;

    /// Process an ACK frame (delegates to both loss detection and congestion control)
    fn on_ack_received(
        &mut self,
        pn_space: PacketNumberSpace,
        largest_acked: PacketNumber,
        ack_delay: Duration,
        now: Instant,
    ) -> Result<()>;

    /// Called when a packet is sent
    fn on_packet_sent(&mut self, info: SentPacketInfo);

    /// Get the next timer deadline
    fn get_timer(&self) -> Option<(LossDetectionTimer, Instant)>;

    /// Handle timer expiration
    fn on_timer_expired(&mut self, now: Instant) -> Result<Vec<PacketNumber>>;

    /// Check if sending is allowed
    fn can_send(&self, packet_size: usize) -> bool;
}

/// Constants from RFC 9002
///
/// These are the recommended default values.
pub mod constants {
    use core::time::Duration;

    /// Maximum ACK delay advertised (25ms default)
    pub const MAX_ACK_DELAY: Duration = Duration::from_millis(25);

    /// Time threshold for declaring packet lost (9/8 * max(smoothed_rtt, latest_rtt))
    pub const TIME_THRESHOLD: f64 = 9.0 / 8.0;

    /// Packet threshold for declaring packet lost
    pub const PACKET_THRESHOLD: u64 = 3;

    /// Granularity of loss detection timer (1ms)
    pub const GRANULARITY: Duration = Duration::from_millis(1);

    /// Initial RTT (333ms per RFC 9002 Section 6.2.2)
    pub const INITIAL_RTT: Duration = Duration::from_millis(333);

    /// Persistent congestion duration (PTO * threshold)
    pub const PERSISTENT_CONGESTION_THRESHOLD: u32 = 3;
}
