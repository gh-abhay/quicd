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
