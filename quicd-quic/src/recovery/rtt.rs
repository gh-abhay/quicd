//! RTT Estimation (RFC 9002 Section 5)
//!
//! This module provides implementations for tracking Round-Trip Time (RTT)
//! and computing loss detection timeouts.
//!
//! The RTT estimator maintains:
//! - `min_rtt`: The minimum RTT observed (used for persistent congestion detection)
//! - `smoothed_rtt`: Exponentially weighted moving average of RTT samples
//! - `rttvar`: RTT variance, used to compute Probe Timeout (PTO)
//!
//! **Formula** (RFC 9002 Section 5.3):
//! ```text
//! rttvar = 3/4 * rttvar + 1/4 * abs(smoothed_rtt - adjusted_rtt)
//! smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt
//! ```

#![forbid(unsafe_code)]

use super::RttEstimator;
use core::time::{Duration, Instant};

/// Default RTT Estimator Implementation
///
/// Implements the RTT smoothing algorithm from RFC 9002 Section 5.
///
/// **State Variables**:
/// - `min_rtt`: Minimum RTT observed across all samples
/// - `smoothed_rtt`: Smoothed RTT (SRTT)
/// - `rttvar`: RTT variance
/// - `first_rtt_sample`: Timestamp of the first RTT measurement
#[derive(Debug, Clone)]
pub struct DefaultRttEstimator {
    pub min_rtt: Duration,
    pub smoothed_rtt: Duration,
    pub rttvar: Duration,
    pub first_rtt_sample: Option<Instant>,
}

impl DefaultRttEstimator {
    /// Create a new RTT estimator with initial values
    ///
    /// **RFC 9002 Appendix A.2**: Initial RTT is set to 333ms before any measurements.
    pub const fn new() -> Self {
        Self {
            min_rtt: Duration::from_secs(u64::MAX), // Sentinel value
            smoothed_rtt: super::INITIAL_RTT,
            rttvar: super::INITIAL_RTT / 2, // Half of initial RTT
            first_rtt_sample: None,
        }
    }
}

impl Default for DefaultRttEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl RttEstimator for DefaultRttEstimator {
    fn update_rtt(&mut self, latest_rtt: Duration, ack_delay: Duration, time_now: Instant) {
        // Record first RTT sample time
        if self.first_rtt_sample.is_none() {
            self.first_rtt_sample = Some(time_now);
            self.min_rtt = latest_rtt;
            self.smoothed_rtt = latest_rtt;
            self.rttvar = latest_rtt / 2;
            return;
        }
        
        // Update min_rtt
        if latest_rtt < self.min_rtt {
            self.min_rtt = latest_rtt;
        }
        
        // Adjust for ACK delay (RFC 9002 Section 5.3)
        // Only subtract ack_delay if it doesn't make the RTT smaller than min_rtt
        let adjusted_rtt = if latest_rtt > self.min_rtt + ack_delay {
            latest_rtt - ack_delay
        } else {
            latest_rtt
        };
        
        // Update rttvar: rttvar = 3/4 * rttvar + 1/4 * |smoothed_rtt - adjusted_rtt|
        let rtt_diff = if self.smoothed_rtt > adjusted_rtt {
            self.smoothed_rtt - adjusted_rtt
        } else {
            adjusted_rtt - self.smoothed_rtt
        };
        
        self.rttvar = (self.rttvar * 3 + rtt_diff) / 4;
        
        // Update smoothed_rtt: smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt
        self.smoothed_rtt = (self.smoothed_rtt * 7 + adjusted_rtt) / 8;
    }
    
    fn smoothed_rtt(&self) -> Duration {
        self.smoothed_rtt
    }
    
    fn min_rtt(&self) -> Duration {
        self.min_rtt
    }
    
    fn rttvar(&self) -> Duration {
        self.rttvar
    }
    
    fn pto(&self, max_ack_delay: Duration) -> Duration {
        // RFC 9002 Section 6.2:
        // PTO = smoothed_rtt + max(4 * rttvar, kGranularity) + max_ack_delay
        let variance_component = core::cmp::max(self.rttvar * 4, super::TIMER_GRANULARITY);
        self.smoothed_rtt + variance_component + max_ack_delay
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_initial_state() {
        let rtt = DefaultRttEstimator::new();
        assert_eq!(rtt.smoothed_rtt(), super::super::INITIAL_RTT);
    }
    
    #[test]
    fn test_first_sample() {
        let mut rtt = DefaultRttEstimator::new();
        let sample = Duration::from_millis(100);
        let now = Instant::now();
        
        rtt.update_rtt(sample, Duration::from_millis(0), now);
        
        assert_eq!(rtt.min_rtt(), sample);
        assert_eq!(rtt.smoothed_rtt(), sample);
        assert_eq!(rtt.rttvar(), sample / 2);
    }
}
