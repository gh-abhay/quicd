//! # RTT Estimation (RFC 9002 Section 5)
//!
//! Calculates smoothed RTT and RTT variance for timeout calculations.

#![forbid(unsafe_code)]

use crate::types::Instant;
use core::time::Duration;

/// RTT Estimator (RFC 9002 Section 5)
///
/// Tracks smoothed RTT (SRTT) and RTT variance (RTTVAR) using
/// exponentially weighted moving averages.
#[derive(Debug, Clone)]
pub struct RttEstimator {
    /// Smoothed RTT (SRTT)
    smoothed_rtt: Duration,

    /// RTT variance (RTTVAR)
    rtt_var: Duration,

    /// Minimum RTT observed
    min_rtt: Duration,

    /// Latest RTT sample
    latest_rtt: Duration,

    /// First RTT sample received
    first_sample_received: bool,
}

impl RttEstimator {
    /// Create a new RTT estimator with initial RTT estimate
    pub fn new(initial_rtt: Duration) -> Self {
        Self {
            smoothed_rtt: initial_rtt,
            rtt_var: initial_rtt / 2,
            min_rtt: initial_rtt,
            latest_rtt: initial_rtt,
            first_sample_received: false,
        }
    }

    /// Update RTT estimate with new sample (RFC 9002 Section 5.3)
    pub fn update(&mut self, rtt_sample: Duration) {
        self.latest_rtt = rtt_sample;

        if rtt_sample < self.min_rtt {
            self.min_rtt = rtt_sample;
        }

        if !self.first_sample_received {
            // First RTT sample (RFC 9002 Section 5.3)
            self.smoothed_rtt = rtt_sample;
            self.rtt_var = rtt_sample / 2;
            self.first_sample_received = true;
        } else {
            // Subsequent samples: exponentially weighted moving average
            let rttvar_sample = if self.smoothed_rtt > rtt_sample {
                self.smoothed_rtt - rtt_sample
            } else {
                rtt_sample - self.smoothed_rtt
            };

            self.rtt_var = (self.rtt_var * 3 + rttvar_sample) / 4;
            self.smoothed_rtt = (self.smoothed_rtt * 7 + rtt_sample) / 8;
        }
    }

    /// Get smoothed RTT
    pub fn smoothed_rtt(&self) -> Duration {
        self.smoothed_rtt
    }

    /// Get RTT variance
    pub fn rtt_var(&self) -> Duration {
        self.rtt_var
    }

    /// Get minimum RTT
    pub fn min_rtt(&self) -> Duration {
        self.min_rtt
    }

    /// Get latest RTT sample
    pub fn latest_rtt(&self) -> Duration {
        self.latest_rtt
    }

    /// Calculate PTO (Probe Timeout) duration (RFC 9002 Section 6.2)
    pub fn pto(&self, max_ack_delay: Duration, pto_count: u32) -> Duration {
        let pto = self.smoothed_rtt
            + Duration::max(4 * self.rtt_var, Duration::from_millis(1))
            + max_ack_delay;
        pto * (1 << pto_count)
    }
}

/// RTT Sample (sent time + ack time)
#[derive(Debug, Clone, Copy)]
pub struct RttSample {
    pub sent_time: Instant,
    pub ack_time: Instant,
}

impl RttSample {
    /// Calculate RTT from sample
    pub fn rtt(&self) -> Duration {
        self.ack_time
            .duration_since(self.sent_time)
            .unwrap_or(Duration::from_secs(0))
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // RttEstimator Tests (RFC 9002 Section 5)
    // ========================================================================

    mod rtt_estimator_tests {
        use super::*;

        #[test]
        fn test_rtt_estimator_new() {
            // RFC 9002 Section 5: Initial RTT is configurable (typically 333ms)
            let initial = Duration::from_millis(333);
            let estimator = RttEstimator::new(initial);

            assert_eq!(estimator.smoothed_rtt(), initial);
            assert_eq!(estimator.rtt_var(), initial / 2);
            assert_eq!(estimator.min_rtt(), initial);
            assert_eq!(estimator.latest_rtt(), initial);
        }

        #[test]
        fn test_first_rtt_sample() {
            // RFC 9002 Section 5.3: On first RTT sample
            // SRTT = rtt_sample
            // RTTVAR = rtt_sample / 2
            let mut estimator = RttEstimator::new(Duration::from_millis(333));
            let sample = Duration::from_millis(100);

            estimator.update(sample);

            assert_eq!(estimator.smoothed_rtt(), sample);
            assert_eq!(estimator.rtt_var(), sample / 2);
            assert_eq!(estimator.min_rtt(), sample);
            assert_eq!(estimator.latest_rtt(), sample);
        }

        #[test]
        fn test_subsequent_rtt_samples() {
            // RFC 9002 Section 5.3: After first sample, use EWMA
            // RTTVAR = (3/4) * RTTVAR + (1/4) * |SRTT - rtt_sample|
            // SRTT = (7/8) * SRTT + (1/8) * rtt_sample
            let mut estimator = RttEstimator::new(Duration::from_millis(333));

            // First sample
            estimator.update(Duration::from_millis(100));

            // Second sample: slightly higher
            let sample2 = Duration::from_millis(120);
            estimator.update(sample2);

            // SRTT should be between 100ms and 120ms (closer to 100)
            let srtt = estimator.smoothed_rtt();
            assert!(srtt > Duration::from_millis(100));
            assert!(srtt < Duration::from_millis(120));

            // Latest should be the last sample
            assert_eq!(estimator.latest_rtt(), sample2);

            // Min should still be the minimum observed
            assert_eq!(estimator.min_rtt(), Duration::from_millis(100));
        }

        #[test]
        fn test_min_rtt_tracking() {
            // min_rtt should track the minimum observed RTT
            let mut estimator = RttEstimator::new(Duration::from_millis(333));

            estimator.update(Duration::from_millis(100));
            assert_eq!(estimator.min_rtt(), Duration::from_millis(100));

            estimator.update(Duration::from_millis(50)); // New minimum
            assert_eq!(estimator.min_rtt(), Duration::from_millis(50));

            estimator.update(Duration::from_millis(80)); // Not a new minimum
            assert_eq!(estimator.min_rtt(), Duration::from_millis(50));
        }

        #[test]
        fn test_rtt_variance_calculation() {
            // RFC 9002: RTTVAR measures variance for timeout calculations
            let mut estimator = RttEstimator::new(Duration::from_millis(100));

            // First sample sets RTTVAR = sample / 2
            estimator.update(Duration::from_millis(100));
            assert_eq!(estimator.rtt_var(), Duration::from_millis(50));

            // Second sample with same RTT should reduce variance
            estimator.update(Duration::from_millis(100));
            // RTTVAR = (3/4) * 50 + (1/4) * |100 - 100| = 37.5ms (truncated to 37)
            let rtt_var = estimator.rtt_var();
            assert!(rtt_var < Duration::from_millis(50));
        }

        #[test]
        fn test_pto_calculation_basic() {
            // RFC 9002 Section 6.2: PTO = SRTT + max(4*RTTVAR, 1ms) + max_ack_delay
            let mut estimator = RttEstimator::new(Duration::from_millis(100));
            estimator.update(Duration::from_millis(100));
            // After first sample: SRTT=100ms, RTTVAR=50ms

            let max_ack_delay = Duration::from_millis(25);
            let pto = estimator.pto(max_ack_delay, 0);

            // PTO = 100 + max(200, 1) + 25 = 325ms
            assert_eq!(pto, Duration::from_millis(325));
        }

        #[test]
        fn test_pto_exponential_backoff() {
            // RFC 9002 Section 6.2: PTO doubles with each timeout (pto_count)
            let mut estimator = RttEstimator::new(Duration::from_millis(100));
            estimator.update(Duration::from_millis(100));

            let max_ack_delay = Duration::from_millis(25);

            let pto0 = estimator.pto(max_ack_delay, 0);
            let pto1 = estimator.pto(max_ack_delay, 1);
            let pto2 = estimator.pto(max_ack_delay, 2);

            // Each PTO should double
            assert_eq!(pto1, pto0 * 2);
            assert_eq!(pto2, pto0 * 4);
        }

        #[test]
        fn test_pto_minimum_rttvar() {
            // RFC 9002: Use at least 1ms for RTTVAR component
            let mut estimator = RttEstimator::new(Duration::from_nanos(100)); // Very small RTT
            estimator.update(Duration::from_nanos(100));
            // RTTVAR = 50ns, so 4*RTTVAR = 200ns < 1ms

            let pto = estimator.pto(Duration::ZERO, 0);

            // Should use 1ms minimum: PTO = 0.0001ms + 1ms + 0 = ~1ms
            assert!(pto >= Duration::from_millis(1));
        }

        #[test]
        fn test_rtt_decreasing_samples() {
            // Test behavior when RTT decreases (network improves)
            let mut estimator = RttEstimator::new(Duration::from_millis(333));

            estimator.update(Duration::from_millis(200));
            estimator.update(Duration::from_millis(150));
            estimator.update(Duration::from_millis(100));
            estimator.update(Duration::from_millis(80));

            // SRTT should trend toward 80ms but EWMA is slow (7/8 weight on old value)
            // After 4 samples, it won't be near 80ms yet
            let srtt = estimator.smoothed_rtt();
            assert!(srtt > Duration::from_millis(80));
            // EWMA is slow - just verify it's less than starting point
            assert!(srtt < Duration::from_millis(200));

            // Min should be 80ms
            assert_eq!(estimator.min_rtt(), Duration::from_millis(80));
        }

        #[test]
        fn test_rtt_spike() {
            // Test behavior during RTT spike (network congestion)
            let mut estimator = RttEstimator::new(Duration::from_millis(100));

            // Establish stable baseline
            for _ in 0..5 {
                estimator.update(Duration::from_millis(100));
            }

            // Spike to 500ms
            estimator.update(Duration::from_millis(500));

            // SRTT should increase but not jump to 500ms
            let srtt = estimator.smoothed_rtt();
            assert!(srtt > Duration::from_millis(100));
            assert!(srtt < Duration::from_millis(200));

            // RTTVAR should increase significantly
            let rtt_var = estimator.rtt_var();
            assert!(rtt_var > Duration::from_millis(50));
        }
    }

    // ========================================================================
    // RttSample Tests
    // ========================================================================

    mod rtt_sample_tests {
        use super::*;

        #[test]
        fn test_rtt_sample_calculation() {
            let sent = Instant::from_nanos(1_000_000_000);
            let ack = Instant::from_nanos(1_100_000_000); // 100ms later

            let sample = RttSample {
                sent_time: sent,
                ack_time: ack,
            };

            assert_eq!(sample.rtt(), Duration::from_millis(100));
        }

        #[test]
        fn test_rtt_sample_zero() {
            let time = Instant::from_nanos(1_000_000_000);

            let sample = RttSample {
                sent_time: time,
                ack_time: time, // Same time
            };

            assert_eq!(sample.rtt(), Duration::ZERO);
        }

        #[test]
        fn test_rtt_sample_out_of_order() {
            // Edge case: ack_time before sent_time (should return 0)
            let sent = Instant::from_nanos(2_000_000_000);
            let ack = Instant::from_nanos(1_000_000_000); // Before sent

            let sample = RttSample {
                sent_time: sent,
                ack_time: ack,
            };

            // Should handle gracefully, returning 0
            assert_eq!(sample.rtt(), Duration::ZERO);
        }

        #[test]
        fn test_rtt_sample_nanosecond_precision() {
            let sent = Instant::from_nanos(1_000_000_000);
            let ack = Instant::from_nanos(1_000_000_500); // 500ns later

            let sample = RttSample {
                sent_time: sent,
                ack_time: ack,
            };

            assert_eq!(sample.rtt(), Duration::from_nanos(500));
        }
    }
}
