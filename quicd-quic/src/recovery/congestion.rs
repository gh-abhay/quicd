//! # Congestion Control Traits (RFC 9002 Section 7)
//!
//! Strategy pattern for swappable congestion control algorithms.

#![forbid(unsafe_code)]

use crate::error::{Error, Result};
use crate::types::{Instant, PacketNumber, PacketNumberSpace};
use core::time::Duration;

/// Congestion Controller Trait
///
/// RFC 9002 Section 7: Pluggable congestion control interface.
/// Implementations: NewReno, CUBIC, BBR, etc.
///
/// **Design Rationale**: Completely decoupled from QUIC transport.
/// Controller receives events and returns sending decisions.
pub trait CongestionController: Send {
    /// Record packet sent
    ///
    /// Called when a packet containing data is sent.
    fn on_packet_sent(
        &mut self,
        packet_number: PacketNumber,
        space: PacketNumberSpace,
        sent_bytes: usize,
        is_ack_eliciting: bool,
        now: Instant,
    );

    /// Record packet acknowledged
    ///
    /// Called when ACK confirms packet delivery.
    fn on_packet_acked(
        &mut self,
        packet_number: PacketNumber,
        space: PacketNumberSpace,
        sent_bytes: usize,
        now: Instant,
    );

    /// Record packet lost
    ///
    /// Called when loss detection declares packet lost.
    fn on_packet_lost(
        &mut self,
        packet_number: PacketNumber,
        space: PacketNumberSpace,
        sent_bytes: usize,
        now: Instant,
    );

    /// Handle congestion event (multiple losses in same RTT)
    fn on_congestion_event(&mut self, now: Instant);

    /// Get congestion window (bytes)
    ///
    /// Returns maximum bytes in flight.
    fn congestion_window(&self) -> usize;

    /// Get bytes in flight (currently unacknowledged)
    fn bytes_in_flight(&self) -> usize;

    /// Check if can send (not blocked by congestion)
    fn can_send(&self, bytes: usize) -> bool;

    /// Get pacing rate (bytes per second)
    ///
    /// Used for paced packet sending. Returns None if no pacing.
    fn pacing_rate(&self) -> Option<usize>;
}

/// Congestion Event (for controllers that track event-based state)
#[derive(Debug, Clone, Copy)]
pub enum CongestionEvent {
    /// Packet acknowledged
    PacketAcked { sent_time: Instant, bytes: usize },

    /// Packet declared lost
    PacketLost { sent_time: Instant, bytes: usize },

    /// Explicit congestion notification (ECN-CE mark received)
    EcnCe { now: Instant },
}

/// Congestion Controller Factory
///
/// Creates congestion controller instances with configuration.
pub trait CongestionControllerFactory: Send + Sync {
    /// Create a new congestion controller
    ///
    /// **Parameters**:
    /// - `initial_window`: Initial congestion window (bytes)
    /// - `min_window`: Minimum congestion window (bytes)
    /// - `max_window`: Maximum congestion window (bytes)
    fn create(
        &self,
        initial_window: usize,
        min_window: usize,
        max_window: usize,
    ) -> Box<dyn CongestionController>;

    /// Get algorithm name ("reno", "cubic", "bbr", etc.)
    fn name(&self) -> &'static str;
}

// ============================================================================
// Congestion Controller States
// ============================================================================

/// Congestion Control State (NewReno/CUBIC)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionState {
    /// Slow Start - exponential growth
    SlowStart,

    /// Congestion Avoidance - linear growth
    CongestionAvoidance,

    /// Recovery - after packet loss detected
    Recovery,
}

// ============================================================================
// NewReno Congestion Controller (RFC 9002 Appendix B)
// ============================================================================

/// NewReno Congestion Controller (RFC 9002 Appendix B)
///
/// Classic TCP-style congestion control with slow start, congestion avoidance,
/// and fast recovery.
#[derive(Debug)]
pub struct NewRenoCongestionController {
    /// Congestion window (bytes) - RFC 9002 B.2
    congestion_window: usize,

    /// Bytes in flight (unacknowledged)
    bytes_in_flight: usize,

    /// Slow start threshold (ssthresh) - RFC 9002 B.3
    ssthresh: usize,

    /// Current state
    state: CongestionState,

    /// Recovery start time (for exiting recovery)
    recovery_start_time: Option<Instant>,

    /// Minimum congestion window
    min_window: usize,

    /// Maximum congestion window
    max_window: usize,

    /// Maximum datagram size (MSS equivalent)
    max_datagram_size: usize,
}

impl NewRenoCongestionController {
    /// Create new NewReno controller
    ///
    /// **RFC 9002 B.1**: Initial window is typically 10 * max_datagram_size
    pub fn new(
        initial_window: usize,
        min_window: usize,
        max_window: usize,
        max_datagram_size: usize,
    ) -> Self {
        Self {
            congestion_window: initial_window.max(min_window),
            bytes_in_flight: 0,
            ssthresh: max_window, // Start with unlimited ssthresh
            state: CongestionState::SlowStart,
            recovery_start_time: None,
            min_window,
            max_window,
            max_datagram_size,
        }
    }

    /// RFC 9002 B.2: Increase congestion window on ACK
    fn on_ack_received(&mut self, acked_bytes: usize) {
        match self.state {
            CongestionState::SlowStart => {
                // Exponential growth: cwnd += acked_bytes
                self.congestion_window = self
                    .congestion_window
                    .saturating_add(acked_bytes)
                    .min(self.max_window);

                // Exit slow start when cwnd exceeds ssthresh
                if self.congestion_window >= self.ssthresh {
                    self.state = CongestionState::CongestionAvoidance;
                }
            }
            CongestionState::CongestionAvoidance => {
                // Linear growth: cwnd += (acked_bytes * MSS) / cwnd
                let increase = (acked_bytes * self.max_datagram_size) / self.congestion_window;
                self.congestion_window = self
                    .congestion_window
                    .saturating_add(increase)
                    .min(self.max_window);
            }
            CongestionState::Recovery => {
                // No cwnd increase during recovery
            }
        }
    }

    /// RFC 9002 B.3: Handle congestion event (packet loss)
    fn on_loss_detected(&mut self, now: Instant) {
        // Check if already in recovery for this RTT
        if let Some(recovery_start) = self.recovery_start_time {
            if now <= recovery_start {
                return; // Ignore losses from same or earlier time
            }
        }

        // Enter recovery
        self.recovery_start_time = Some(now);
        self.state = CongestionState::Recovery;

        // RFC 9002 B.3: Multiplicative decrease
        self.ssthresh = self.congestion_window / 2;
        self.ssthresh = self.ssthresh.max(self.min_window);

        self.congestion_window = self.ssthresh;
    }

    /// Exit recovery when new packet is acknowledged
    fn maybe_exit_recovery(&mut self, packet_sent_time: Instant) {
        if self.state == CongestionState::Recovery {
            if let Some(recovery_start) = self.recovery_start_time {
                if packet_sent_time >= recovery_start {
                    // Packet sent after recovery started was ACKed
                    self.state = CongestionState::CongestionAvoidance;
                    self.recovery_start_time = None;
                }
            }
        }
    }
}

impl CongestionController for NewRenoCongestionController {
    fn on_packet_sent(
        &mut self,
        _packet_number: PacketNumber,
        _space: PacketNumberSpace,
        sent_bytes: usize,
        is_ack_eliciting: bool,
        _now: Instant,
    ) {
        if is_ack_eliciting {
            self.bytes_in_flight = self.bytes_in_flight.saturating_add(sent_bytes);
        }
    }

    fn on_packet_acked(
        &mut self,
        _packet_number: PacketNumber,
        _space: PacketNumberSpace,
        sent_bytes: usize,
        now: Instant,
    ) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(sent_bytes);
        self.on_ack_received(sent_bytes);

        // Check if we can exit recovery
        self.maybe_exit_recovery(now);
    }

    fn on_packet_lost(
        &mut self,
        _packet_number: PacketNumber,
        _space: PacketNumberSpace,
        sent_bytes: usize,
        now: Instant,
    ) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(sent_bytes);
        self.on_loss_detected(now);
    }

    fn on_congestion_event(&mut self, now: Instant) {
        self.on_loss_detected(now);
    }

    fn congestion_window(&self) -> usize {
        self.congestion_window
    }

    fn bytes_in_flight(&self) -> usize {
        self.bytes_in_flight
    }

    fn can_send(&self, bytes: usize) -> bool {
        self.bytes_in_flight.saturating_add(bytes) <= self.congestion_window
    }

    fn pacing_rate(&self) -> Option<usize> {
        // NewReno doesn't use pacing by default
        None
    }
}

/// NewReno Factory
pub struct NewRenoFactory {
    pub max_datagram_size: usize,
}

impl CongestionControllerFactory for NewRenoFactory {
    fn create(
        &self,
        initial_window: usize,
        min_window: usize,
        max_window: usize,
    ) -> Box<dyn CongestionController> {
        Box::new(NewRenoCongestionController::new(
            initial_window,
            min_window,
            max_window,
            self.max_datagram_size,
        ))
    }

    fn name(&self) -> &'static str {
        "reno"
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

