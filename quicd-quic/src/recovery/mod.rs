//! # QUIC Loss Detection and Congestion Control (RFC 9002)
//!
//! This module defines the **trait-based architecture** for the recovery subsystem.
//! It separates concerns into three components:
//!
//! 1. **RTT Estimation**: Tracks smoothed RTT (SRTT) and RTT variance for timer calculations.
//! 2. **Loss Detection**: Determines when packets should be considered lost and triggers retransmissions.
//! 3. **Congestion Control**: Manages the congestion window (CWND) and pacing rate.
//!
//! ## Design Principles
//!
//! - **Event-Driven**: The recovery system reacts to events (packet sent, acked, lost, ack received).
//! - **Stateless Interface**: Traits do not dictate internal state representation.
//! - **Pluggable Algorithms**: Congestion control algorithms (NewReno, Cubic, BBR) can be swapped.
//! - **Zero-Allocation**: All operations use borrowed data and pre-allocated buffers.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │         Connection State Machine         │
//! └────────────────┬────────────────────────┘
//!                  │ Events: PacketSent, AckReceived
//!                  ▼
//! ┌─────────────────────────────────────────┐
//! │          Recovery Controller             │ (Orchestrates)
//! ├─────────────────────────────────────────┤
//! │ • Maintains PacketNumberSpace state      │
//! │ • Delegates to Loss Detection            │
//! │ • Delegates to Congestion Control        │
//! └────┬────────────────────┬────────────────┘
//!      │                    │
//!      ▼                    ▼
//! ┌─────────────┐    ┌──────────────────┐
//! │Loss Detector│    │Congestion Control│
//! │ (Trait)     │    │     (Trait)      │
//! └─────────────┘    └──────────────────┘
//! ```

#![forbid(unsafe_code)]

use crate::error::{Error, Result};
use crate::packet::{PacketNumber, PacketNumberSpace};
use core::time::Duration;

/// Type alias for time tracking (no_std compatible)
/// In no_std environments, callers provide monotonic time as Duration since epoch
pub type Instant = Duration;

// ============================================================================
// Recovery-Specific Types
// ============================================================================

/// Congestion Window Size (in bytes)
pub type CongestionWindow = u64;

/// Bytes in Flight (unacknowledged data)
pub type BytesInFlight = u64;

// ============================================================================
// Events: Inputs to Recovery System
// ============================================================================

/// Event: A packet was sent (RFC 9002 Section 2)
///
/// The recovery system must track all sent packets to detect loss and
/// manage congestion control.
#[derive(Debug, Clone, Copy)]
pub struct PacketSent {
    /// Packet number in its number space
    pub packet_number: PacketNumber,
    
    /// Packet number space
    pub space: PacketNumberSpace,
    
    /// Time the packet was sent
    pub time_sent: Instant,
    
    /// Size of the packet in bytes (UDP payload)
    pub size: usize,
    
    /// Whether this packet is ack-eliciting (RFC 9002 Section 2)
    /// Ack-eliciting packets contain frames other than ACK, PADDING, CONNECTION_CLOSE
    pub ack_eliciting: bool,
    
    /// Whether this packet is in-flight (counts toward bytes_in_flight)
    /// Typically true for ack-eliciting packets
    pub in_flight: bool,
}

/// Event: An ACK frame was received (RFC 9002 Section 3)
///
/// The ACK frame identifies which packets were successfully received by the peer.
#[derive(Debug, Clone, Copy)]
pub struct AckReceived<'a> {
    /// Packet number space this ACK belongs to
    pub space: PacketNumberSpace,
    
    /// Time the ACK was received
    pub time_received: Instant,
    
    /// Largest acknowledged packet number
    pub largest_acked: PacketNumber,
    
    /// ACK delay reported by peer (in microseconds)
    /// This is the delay between when the peer received the packet and sent the ACK
    pub ack_delay: Duration,
    
    /// Ranges of acknowledged packet numbers
    /// This is a zero-copy reference to the parsed ACK ranges
    pub ack_ranges: &'a [AckRange],
}

/// A range of acknowledged packet numbers [smallest, largest]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckRange {
    pub smallest: PacketNumber,
    pub largest: PacketNumber,
}

/// Event: Packet(s) declared lost (RFC 9002 Section 6)
///
/// Loss detection determines that certain packets will not be acknowledged.
#[derive(Debug, Clone, Copy)]
pub struct PacketLost {
    pub packet_number: PacketNumber,
    pub space: PacketNumberSpace,
    pub size: usize,
}

// ============================================================================
// Trait: RTT Estimator (RFC 9002 Section 5)
// ============================================================================

/// RTT Estimation for Loss Detection Timers
///
/// Tracks:
/// - `min_rtt`: Minimum RTT observed
/// - `smoothed_rtt`: Exponentially weighted moving average of RTT
/// - `rttvar`: RTT variance (used to compute PTO timeout)
///
/// **RFC Reference**: RFC 9002 Section 5
pub trait RttEstimator {
    /// Update RTT estimates based on a new RTT sample
    ///
    /// - `latest_rtt`: The most recent RTT measurement
    /// - `ack_delay`: The delay reported by the peer in the ACK frame
    /// - `time_now`: Current time (for PTO calculations)
    ///
    /// **RFC 9002 Section 5.3**: The smoothed RTT and RTT variance are updated
    /// using exponential weighted moving averages.
    fn update_rtt(&mut self, latest_rtt: Duration, ack_delay: Duration, time_now: Instant);
    
    /// Get the smoothed RTT estimate
    fn smoothed_rtt(&self) -> Duration;
    
    /// Get the minimum RTT observed
    fn min_rtt(&self) -> Duration;
    
    /// Get the RTT variance
    fn rttvar(&self) -> Duration;
    
    /// Calculate the Probe Timeout (PTO) duration (RFC 9002 Section 6.2)
    ///
    /// PTO = smoothed_rtt + max(4 * rttvar, kGranularity) + max_ack_delay
    fn pto(&self, max_ack_delay: Duration) -> Duration;
}

// ============================================================================
// Trait: Loss Detector (RFC 9002 Section 6)
// ============================================================================

/// Loss Detection State Machine
///
/// Determines when packets should be declared lost based on:
/// - **Time Threshold**: Packet is lost if it was sent longer than a threshold ago
/// - **Packet Threshold**: Packet is lost if packets sent after it have been acked
///
/// **RFC Reference**: RFC 9002 Section 6
pub trait LossDetector {
    /// Process an ACK frame and detect lost packets
    ///
    /// When an ACK is received, the loss detector:
    /// 1. Marks acknowledged packets as acked
    /// 2. Applies loss detection heuristics to declare packets lost
    ///
    /// Returns an iterator over lost packets.
    ///
    /// **RFC 9002 Section 6.1**: Loss detection uses both time-based and
    /// packet-threshold-based heuristics.
    fn on_ack_received<'a>(
        &mut self,
        ack: &AckReceived<'a>,
        rtt_estimator: &dyn RttEstimator,
        time_now: Instant,
    ) -> impl Iterator<Item = PacketLost> + 'a;
    
    /// Record a sent packet for loss tracking
    fn on_packet_sent(&mut self, sent: &PacketSent);
    
    /// Get the next loss detection timer deadline
    ///
    /// Returns `None` if no timer is needed (no ack-eliciting packets in flight).
    ///
    /// **RFC 9002 Section 6.2**: The loss detection timer is set to expire at
    /// the earliest of the PTO time or the loss time.
    fn loss_detection_timer(&self, rtt_estimator: &dyn RttEstimator) -> Option<Instant>;
    
    /// Handle loss detection timer expiration
    ///
    /// When the timer fires, packets are declared lost based on time threshold.
    ///
    /// **RFC 9002 Section 6.2.1**: On PTO, send new data if available, otherwise
    /// send a probe packet.
    fn on_loss_detection_timeout(
        &mut self,
        time_now: Instant,
        rtt_estimator: &dyn RttEstimator,
    ) -> impl Iterator<Item = PacketLost>;
}

// ============================================================================
// Trait: Congestion Controller (RFC 9002 Section 7)
// ============================================================================

/// Congestion Control Strategy Pattern
///
/// Manages the congestion window (CWND) and pacing rate. Implementations can
/// provide different algorithms:
/// - **NewReno**: RFC 9002 Appendix B (default, MUST be supported)
/// - **Cubic**: More aggressive window growth
/// - **BBR**: Bottleneck bandwidth and RTT-based
///
/// **Design Rationale**: By using a trait, the core QUIC state machine is
/// decoupled from congestion control policy. This allows:
/// - Unit testing with mock controllers
/// - Runtime selection of algorithms
/// - Custom algorithms for specific use cases
///
/// **RFC Reference**: RFC 9002 Section 7
pub trait CongestionController {
    /// Get the current congestion window (in bytes)
    fn congestion_window(&self) -> CongestionWindow;
    
    /// Get the current number of bytes in flight (unacknowledged)
    fn bytes_in_flight(&self) -> BytesInFlight;
    
    /// Check if sending is allowed (bytes_in_flight < congestion_window)
    fn can_send(&self) -> bool {
        self.bytes_in_flight() < self.congestion_window()
    }
    
    /// Event: A packet was sent (RFC 9002 Section 7.1)
    ///
    /// Updates bytes_in_flight if the packet is in-flight.
    fn on_packet_sent(&mut self, sent: &PacketSent);
    
    /// Event: Packets were acknowledged (RFC 9002 Section 7.4)
    ///
    /// The congestion controller increases the window during congestion avoidance
    /// or slow start.
    ///
    /// - `acked_bytes`: Total bytes acknowledged
    /// - `time_now`: Current time
    /// - `rtt`: Current smoothed RTT
    ///
    /// **RFC 9002 Section 7.4**: During slow start, CWND increases by the number
    /// of bytes acknowledged. During congestion avoidance, CWND increases by
    /// `max_datagram_size * bytes_acked / cwnd` per RTT.
    fn on_packets_acked(
        &mut self,
        acked_bytes: u64,
        time_now: Instant,
        rtt: Duration,
    );
    
    /// Event: Packets were lost (RFC 9002 Section 7.6)
    ///
    /// The congestion controller reduces the window and enters recovery.
    ///
    /// - `lost_bytes`: Total bytes lost
    /// - `time_now`: Current time
    ///
    /// **RFC 9002 Section 7.6**: On persistent congestion, the controller must
    /// reset to initial slow start (CWND = min_window).
    fn on_packets_lost(&mut self, lost_bytes: u64, time_now: Instant);
    
    /// Event: Congestion event detected (ECN marking or loss)
    ///
    /// **RFC 9002 Section 7.5**: ECN-CE marks indicate congestion without loss.
    fn on_congestion_event(&mut self, time_now: Instant);
}

// ============================================================================
// Helper: Time-Based Loss Detection Constants (RFC 9002 Appendix A.3)
// ============================================================================

/// Time threshold for declaring a packet lost (RFC 9002 Section 6.1.1)
///
/// A packet is declared lost if it was sent more than a time threshold ago
/// relative to when the next packet was acknowledged.
///
/// **Value**: 9/8 (1.125) of the maximum of smoothed_rtt and latest_rtt
pub const TIME_THRESHOLD_FACTOR: f64 = 1.125;

/// Packet threshold for declaring a packet lost (RFC 9002 Section 6.1.1)
///
/// A packet is declared lost if at least `PACKET_THRESHOLD` packets sent
/// after it have been acknowledged.
///
/// **Value**: 3 packets (RECOMMENDED)
pub const PACKET_THRESHOLD: u64 = 3;

/// Granularity of loss detection timers (RFC 9002 Section 6.1.2)
///
/// Timers are not set to expire sooner than this granularity to avoid
/// excessive timer processing.
pub const TIMER_GRANULARITY: Duration = Duration::from_millis(1);

/// Initial RTT value before any measurements (RFC 9002 Appendix A.2)
pub const INITIAL_RTT: Duration = Duration::from_millis(333);

/// Maximum ACK delay for calculating PTO (RFC 9002 Section 6.2)
pub const MAX_ACK_DELAY: Duration = Duration::from_millis(25);
