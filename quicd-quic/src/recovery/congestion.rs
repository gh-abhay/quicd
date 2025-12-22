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
    PacketAcked {
        sent_time: Instant,
        bytes: usize,
    },

    /// Packet declared lost
    PacketLost {
        sent_time: Instant,
        bytes: usize,
    },

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

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_DATAGRAM_SIZE: usize = 1200;
    const INITIAL_WINDOW: usize = 10 * MAX_DATAGRAM_SIZE; // 12000 bytes
    const MIN_WINDOW: usize = 2 * MAX_DATAGRAM_SIZE; // 2400 bytes
    const MAX_WINDOW: usize = 1_000_000;

    fn create_controller() -> NewRenoCongestionController {
        NewRenoCongestionController::new(INITIAL_WINDOW, MIN_WINDOW, MAX_WINDOW, MAX_DATAGRAM_SIZE)
    }

    #[test]
    fn test_initial_state() {
        let cc = create_controller();
        
        assert_eq!(cc.congestion_window(), INITIAL_WINDOW);
        assert_eq!(cc.bytes_in_flight(), 0);
        assert_eq!(cc.state, CongestionState::SlowStart);
        assert!(cc.can_send(MAX_DATAGRAM_SIZE));
    }

    #[test]
    fn test_slow_start_growth() {
        let mut cc = create_controller();
        let now = Instant::from_nanos(0);

        // Send packet
        cc.on_packet_sent(1, PacketNumberSpace::ApplicationData, MAX_DATAGRAM_SIZE, true, now);
        assert_eq!(cc.bytes_in_flight(), MAX_DATAGRAM_SIZE);

        // ACK packet - slow start doubles cwnd
        cc.on_packet_acked(1, PacketNumberSpace::ApplicationData, MAX_DATAGRAM_SIZE, now);
        assert_eq!(cc.bytes_in_flight(), 0);
        assert_eq!(cc.congestion_window(), INITIAL_WINDOW + MAX_DATAGRAM_SIZE);
    }

    #[test]
    fn test_slow_start_to_congestion_avoidance() {
        let mut cc = create_controller();
        cc.ssthresh = INITIAL_WINDOW + 5000; // Set threshold
        let now = Instant::from_nanos(0);

        // Grow cwnd past ssthresh
        while cc.state == CongestionState::SlowStart {
            cc.on_ack_received(MAX_DATAGRAM_SIZE);
        }

        assert_eq!(cc.state, CongestionState::CongestionAvoidance);
    }

    #[test]
    fn test_congestion_avoidance_linear_growth() {
        let mut cc = create_controller();
        cc.state = CongestionState::CongestionAvoidance;
        cc.congestion_window = 20000;

        let initial_cwnd = cc.congestion_window();
        
        // ACK one MSS - should grow by (MSS * MSS) / cwnd
        cc.on_ack_received(MAX_DATAGRAM_SIZE);

        let expected_increase = (MAX_DATAGRAM_SIZE * MAX_DATAGRAM_SIZE) / initial_cwnd;
        assert_eq!(cc.congestion_window(), initial_cwnd + expected_increase);
    }

    #[test]
    fn test_loss_detected_multiplicative_decrease() {
        let mut cc = create_controller();
        cc.congestion_window = 20000;
        let now = Instant::from_nanos(0);

        cc.on_loss_detected(now);

        // RFC 9002: ssthresh = cwnd / 2, cwnd = ssthresh
        assert_eq!(cc.ssthresh, 10000);
        assert_eq!(cc.congestion_window(), 10000);
        assert_eq!(cc.state, CongestionState::Recovery);
    }

    #[test]
    fn test_recovery_prevents_multiple_decreases() {
        let mut cc = create_controller();
        cc.congestion_window = 20000;
        let now = Instant::from_nanos(0);

        cc.on_loss_detected(now);
        let cwnd_after_first_loss = cc.congestion_window();

        // Second loss in same RTT (same timestamp) should not decrease again
        cc.on_loss_detected(now);
        assert_eq!(cc.congestion_window(), cwnd_after_first_loss);
        
        // Third loss also at same timestamp
        cc.on_loss_detected(now);
        assert_eq!(cc.congestion_window(), cwnd_after_first_loss);
    }

    #[test]
    fn test_exit_recovery_on_new_ack() {
        let mut cc = create_controller();
        let now = Instant::from_nanos(0);
        let later = Instant::from_nanos(1_000_000_000);

        // Enter recovery
        cc.on_loss_detected(now);
        assert_eq!(cc.state, CongestionState::Recovery);

        // ACK packet sent after recovery started
        cc.maybe_exit_recovery(later);
        assert_eq!(cc.state, CongestionState::CongestionAvoidance);
    }

    #[test]
    fn test_bytes_in_flight_tracking() {
        let mut cc = create_controller();
        let now = Instant::from_nanos(0);

        // Send 3 packets
        cc.on_packet_sent(1, PacketNumberSpace::ApplicationData, 1000, true, now);
        cc.on_packet_sent(2, PacketNumberSpace::ApplicationData, 1000, true, now);
        cc.on_packet_sent(3, PacketNumberSpace::ApplicationData, 1000, true, now);
        assert_eq!(cc.bytes_in_flight(), 3000);

        // ACK 1 packet
        cc.on_packet_acked(1, PacketNumberSpace::ApplicationData, 1000, now);
        assert_eq!(cc.bytes_in_flight(), 2000);

        // Lose 1 packet
        cc.on_packet_lost(2, PacketNumberSpace::ApplicationData, 1000, now);
        assert_eq!(cc.bytes_in_flight(), 1000);
    }

    #[test]
    fn test_can_send_respects_cwnd() {
        let mut cc = create_controller();
        cc.congestion_window = 5000;
        cc.bytes_in_flight = 3000;

        // Can send 2000 bytes (cwnd - in_flight)
        assert!(cc.can_send(2000));
        assert!(cc.can_send(1000));
        assert!(!cc.can_send(2001));
    }

    #[test]
    fn test_minimum_window_enforcement() {
        let mut cc = create_controller();
        cc.congestion_window = MIN_WINDOW * 2;
        let now = Instant::from_nanos(0);

        // Multiple losses should not reduce below min_window
        for _ in 0..10 {
            cc.on_loss_detected(now);
            cc.state = CongestionState::SlowStart; // Reset to allow next loss
        }

        assert!(cc.congestion_window() >= MIN_WINDOW);
    }

    #[test]
    fn test_maximum_window_enforcement() {
        let mut cc = create_controller();
        cc.congestion_window = MAX_WINDOW - 1000;

        // Growth should not exceed max_window
        for _ in 0..100 {
            cc.on_ack_received(MAX_DATAGRAM_SIZE);
        }

        assert!(cc.congestion_window() <= MAX_WINDOW);
    }
}
