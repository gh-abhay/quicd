//! Congestion Control (RFC 9002 Section 7)
//!
//! This module defines the trait and implementation for congestion control algorithms.
//!
//! **Supported Algorithms**:
//! - **NewReno**: RFC 9002 Appendix B (MUST be supported)
//! - **Cubic**: (Future) More aggressive window growth
//! - **BBR**: (Future) Bottleneck bandwidth and RTT-based
//!
//! ## NewReno State Machine
//!
//! ```text
//! ┌──────────────┐  bytes_acked        ┌──────────────────┐
//! │  Slow Start  │ ──────────────────> │ Congestion       │
//! │              │  (cwnd >= ssthresh) │ Avoidance        │
//! └──────────────┘                     └──────────────────┘
//!       │  ▲                                    │  ▲
//!       │  │ exit recovery                      │  │
//!       │  │                                    │  │
//!       │  │  ┌──────────────┐                 │  │
//!       └──┼─>│   Recovery   │<────────────────┘  │
//!          │  │   (loss)     │────────────────────┘
//!          │  └──────────────┘   exit recovery
//!          │
//!          └─ loss (cwnd < ssthresh) ─> Slow Start
//! ```

#![forbid(unsafe_code)]

use super::{CongestionController, CongestionWindow, BytesInFlight, PacketSent};
use core::time::{Duration, Instant};

// ============================================================================
// Constants (RFC 9002 Appendix A)
// ============================================================================

/// Maximum datagram size (MTU) - typically 1200 bytes for QUIC (RFC 9000 Section 14)
pub const MAX_DATAGRAM_SIZE: u64 = 1200;

/// Initial congestion window (RFC 9002 Section 7.2)
/// 
/// RECOMMENDED: 10 * max_datagram_size, capped at 14,720 bytes
pub const INITIAL_WINDOW: u64 = core::cmp::min(10 * MAX_DATAGRAM_SIZE, 14720);

/// Minimum congestion window (RFC 9002 Section 7.2)
///
/// After persistent congestion, the window is reduced to this value.
pub const MINIMUM_WINDOW: u64 = 2 * MAX_DATAGRAM_SIZE;

/// Loss reduction factor (RFC 9002 Section 7.6)
///
/// On loss, the congestion window is multiplied by this factor.
/// RECOMMENDED: 0.5 (halve the window)
pub const LOSS_REDUCTION_FACTOR: f64 = 0.5;

/// Persistent congestion threshold (RFC 9002 Section 7.6.2)
///
/// If all packets sent within a period of PTO * PERSISTENT_CONGESTION_THRESHOLD
/// are lost, persistent congestion is declared.
/// 
/// Value: 3 (RECOMMENDED)
pub const PERSISTENT_CONGESTION_THRESHOLD: u32 = 3;

// ============================================================================
// NewReno Congestion Controller (RFC 9002 Appendix B)
// ============================================================================

/// NewReno Congestion Control Implementation
///
/// **State Variables**:
/// - `cwnd`: Congestion window (in bytes)
/// - `bytes_in_flight`: Number of bytes sent but not yet acknowledged
/// - `ssthresh`: Slow start threshold
/// - `recovery_start_time`: When the current recovery period started (None if not in recovery)
///
/// **Phases**:
/// 1. **Slow Start**: Exponential growth (cwnd doubles per RTT) until ssthresh
/// 2. **Congestion Avoidance**: Linear growth (cwnd increases by 1 MSS per RTT)
/// 3. **Recovery**: After loss, reduce cwnd and don't react to further losses until recovery ends
#[derive(Debug, Clone)]
pub struct NewRenoCongestionController {
    /// Current congestion window (bytes)
    cwnd: CongestionWindow,
    
    /// Bytes in flight (unacknowledged)
    bytes_in_flight: BytesInFlight,
    
    /// Slow start threshold (bytes)
    ssthresh: u64,
    
    /// Recovery start time (None if not in recovery)
    recovery_start_time: Option<Instant>,
    
    /// Maximum datagram size (MTU)
    max_datagram_size: u64,
}

impl NewRenoCongestionController {
    /// Create a new NewReno congestion controller
    ///
    /// **RFC 9002 Section 7.2**: Initial window is 10 * max_datagram_size
    pub const fn new() -> Self {
        Self {
            cwnd: INITIAL_WINDOW,
            bytes_in_flight: 0,
            ssthresh: u64::MAX, // Start in slow start
            recovery_start_time: None,
            max_datagram_size: MAX_DATAGRAM_SIZE,
        }
    }
    
    /// Check if in slow start phase
    fn in_slow_start(&self) -> bool {
        self.cwnd < self.ssthresh
    }
    
    /// Check if in recovery phase
    fn in_recovery(&self) -> bool {
        self.recovery_start_time.is_some()
    }
    
    /// Enter recovery phase
    fn enter_recovery(&mut self, time_now: Instant) {
        // RFC 9002 Section 7.6: Reduce cwnd and set ssthresh
        self.ssthresh = (self.cwnd as f64 * LOSS_REDUCTION_FACTOR) as u64;
        self.ssthresh = core::cmp::max(self.ssthresh, MINIMUM_WINDOW);
        
        self.cwnd = self.ssthresh;
        self.recovery_start_time = Some(time_now);
    }
    
    /// Exit recovery phase
    fn exit_recovery(&mut self) {
        self.recovery_start_time = None;
    }
}

impl Default for NewRenoCongestionController {
    fn default() -> Self {
        Self::new()
    }
}

impl CongestionController for NewRenoCongestionController {
    fn congestion_window(&self) -> CongestionWindow {
        self.cwnd
    }
    
    fn bytes_in_flight(&self) -> BytesInFlight {
        self.bytes_in_flight
    }
    
    fn on_packet_sent(&mut self, sent: &PacketSent) {
        if sent.in_flight {
            self.bytes_in_flight += sent.size as u64;
        }
    }
    
    fn on_packets_acked(&mut self, acked_bytes: u64, time_now: Instant, _rtt: Duration) {
        // Reduce bytes_in_flight
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(acked_bytes);
        
        // Exit recovery if we've acked packets sent after recovery started
        if let Some(recovery_start) = self.recovery_start_time {
            if time_now > recovery_start {
                self.exit_recovery();
            }
        }
        
        // Don't increase cwnd during recovery
        if self.in_recovery() {
            return;
        }
        
        // RFC 9002 Section 7.4: Increase cwnd based on phase
        if self.in_slow_start() {
            // Slow start: cwnd increases by acked_bytes (exponential growth)
            self.cwnd += acked_bytes;
        } else {
            // Congestion avoidance: cwnd increases by (max_datagram_size * acked_bytes) / cwnd
            // This gives linear growth of 1 MSS per RTT
            let increase = (self.max_datagram_size * acked_bytes) / self.cwnd;
            self.cwnd += increase;
        }
    }
    
    fn on_packets_lost(&mut self, lost_bytes: u64, time_now: Instant) {
        // Reduce bytes_in_flight
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);
        
        // RFC 9002 Section 7.6: Enter recovery if not already in recovery
        if !self.in_recovery() {
            self.enter_recovery(time_now);
        }
    }
    
    fn on_congestion_event(&mut self, time_now: Instant) {
        // RFC 9002 Section 7.5: Treat ECN-CE marks same as loss
        if !self.in_recovery() {
            self.enter_recovery(time_now);
        }
    }
}

// ============================================================================
// Future: Cubic Congestion Controller
// ============================================================================

/// Cubic Congestion Control (RFC 8312)
///
/// **Not yet implemented** - uses a cubic function for window growth
/// that is more aggressive than NewReno in high-bandwidth networks.
///
/// This is a placeholder for future implementation.
#[derive(Debug, Clone)]
pub struct CubicCongestionController {
    // TODO: Implement Cubic state variables
    _phantom: (),
}

// ============================================================================
// Future: BBR Congestion Controller
// ============================================================================

/// BBR (Bottleneck Bandwidth and RTT) Congestion Control
///
/// **Not yet implemented** - uses bandwidth and RTT measurements instead
/// of loss signals to determine sending rate.
///
/// This is a placeholder for future implementation.
#[derive(Debug, Clone)]
pub struct BbrCongestionController {
    // TODO: Implement BBR state variables
    _phantom: (),
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_initial_state() {
        let cc = NewRenoCongestionController::new();
        assert_eq!(cc.congestion_window(), INITIAL_WINDOW);
        assert_eq!(cc.bytes_in_flight(), 0);
        assert!(cc.can_send());
    }
    
    #[test]
    fn test_slow_start_growth() {
        let mut cc = NewRenoCongestionController::new();
        let initial_cwnd = cc.congestion_window();
        
        // Simulate acking 1200 bytes
        cc.on_packets_acked(1200, Instant::now(), Duration::from_millis(100));
        
        // In slow start, cwnd should increase by acked_bytes
        assert_eq!(cc.congestion_window(), initial_cwnd + 1200);
    }
}
