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

    #[test]
    fn test_rtt_estimator_initial_values() {
        let initial_rtt = Duration::from_millis(100);
        let estimator = RttEstimator::new(initial_rtt);

        assert_eq!(estimator.smoothed_rtt(), initial_rtt);
        assert_eq!(estimator.rtt_var(), initial_rtt / 2);
        assert_eq!(estimator.min_rtt(), initial_rtt);
    }

    #[test]
    fn test_rtt_estimator_first_sample() {
        let mut estimator = RttEstimator::new(Duration::from_millis(100));

        let sample = Duration::from_millis(50);
        estimator.update(sample);

        // First sample: smoothed_rtt = sample, rtt_var = sample / 2
        assert_eq!(estimator.smoothed_rtt(), sample);
        assert_eq!(estimator.rtt_var(), sample / 2);
        assert_eq!(estimator.min_rtt(), sample);
        assert_eq!(estimator.latest_rtt(), sample);
    }

    #[test]
    fn test_rtt_estimator_subsequent_samples() {
        let mut estimator = RttEstimator::new(Duration::from_millis(100));

        // First sample
        estimator.update(Duration::from_millis(100));

        // Second sample (higher RTT)
        estimator.update(Duration::from_millis(120));

        // RFC 9002 Section 5.3:
        // rttvar_sample = abs(smoothed_rtt - rtt_sample) = abs(100 - 120) = 20
        // rtt_var = (rtt_var * 3 + rttvar_sample) / 4 = (50 * 3 + 20) / 4 = 42.5
        // smoothed_rtt = (smoothed_rtt * 7 + rtt_sample) / 8 = (100 * 7 + 120) / 8 = 102.5

        let expected_srtt = Duration::from_nanos(102_500_000); // 102.5 ms
        let expected_rttvar = Duration::from_nanos(42_500_000); // 42.5 ms

        assert_eq!(estimator.smoothed_rtt(), expected_srtt);
        assert_eq!(estimator.rtt_var(), expected_rttvar);
        assert_eq!(estimator.min_rtt(), Duration::from_millis(100));
    }

    #[test]
    fn test_rtt_estimator_min_rtt_tracking() {
        let mut estimator = RttEstimator::new(Duration::from_millis(100));

        estimator.update(Duration::from_millis(100));
        assert_eq!(estimator.min_rtt(), Duration::from_millis(100));

        estimator.update(Duration::from_millis(50));
        assert_eq!(estimator.min_rtt(), Duration::from_millis(50));

        estimator.update(Duration::from_millis(150));
        assert_eq!(estimator.min_rtt(), Duration::from_millis(50)); // Min doesn't increase
    }

    #[test]
    fn test_pto_calculation() {
        let mut estimator = RttEstimator::new(Duration::from_millis(100));
        estimator.update(Duration::from_millis(100));

        let max_ack_delay = Duration::from_millis(25);

        // RFC 9002 Section 6.2:
        // PTO = smoothed_rtt + max(4 * rtt_var, 1ms) + max_ack_delay
        // PTO = 100 + max(4 * 50, 1) + 25 = 100 + 200 + 25 = 325 ms
        let pto = estimator.pto(max_ack_delay, 0);
        assert_eq!(pto, Duration::from_millis(325));
    }

    #[test]
    fn test_pto_with_backoff() {
        let mut estimator = RttEstimator::new(Duration::from_millis(100));
        estimator.update(Duration::from_millis(100));

        let max_ack_delay = Duration::from_millis(25);

        // PTO count 0: 325 ms (from previous test)
        let pto0 = estimator.pto(max_ack_delay, 0);
        assert_eq!(pto0, Duration::from_millis(325));

        // PTO count 1: 325 * 2 = 650 ms
        let pto1 = estimator.pto(max_ack_delay, 1);
        assert_eq!(pto1, Duration::from_millis(650));

        // PTO count 2: 325 * 4 = 1300 ms
        let pto2 = estimator.pto(max_ack_delay, 2);
        assert_eq!(pto2, Duration::from_millis(1300));
    }

    #[test]
    fn test_pto_minimum_rtt_var() {
        let mut estimator = RttEstimator::new(Duration::from_millis(10));
        estimator.update(Duration::from_millis(10));
        estimator.update(Duration::from_millis(10)); // Very stable RTT

        let max_ack_delay = Duration::from_millis(0);

        // RFC 9002: max(4 * rtt_var, 1ms) ensures minimum variance
        // Even with rtt_var approaching 0, PTO should include at least 1ms
        let pto = estimator.pto(max_ack_delay, 0);
        assert!(pto >= Duration::from_millis(11)); // srtt + 1ms minimum
    }

    #[test]
    fn test_rtt_sample_calculation() {
        let sent_time = Instant::from_nanos(1_000_000_000); // 1 second
        let ack_time = Instant::from_nanos(1_050_000_000); // 1.05 seconds

        let sample = RttSample {
            sent_time,
            ack_time,
        };
        assert_eq!(sample.rtt(), Duration::from_millis(50));
    }

    #[test]
    fn test_rtt_estimator_stability() {
        let mut estimator = RttEstimator::new(Duration::from_millis(100));

        // Feed stable samples
        for _ in 0..10 {
            estimator.update(Duration::from_millis(100));
        }

        // Smoothed RTT should converge to sample value
        let srtt = estimator.smoothed_rtt();
        assert!(srtt >= Duration::from_millis(99) && srtt <= Duration::from_millis(101));

        // RTT variance should be low
        let rttvar = estimator.rtt_var();
        assert!(rttvar < Duration::from_millis(10));
    }

    #[test]
    fn test_rtt_estimator_variance_tracking() {
        let mut estimator = RttEstimator::new(Duration::from_millis(100));
        estimator.update(Duration::from_millis(100));

        // Add samples with high variance
        estimator.update(Duration::from_millis(50));
        estimator.update(Duration::from_millis(150));

        // RTT variance should reflect the variability
        let rttvar = estimator.rtt_var();
        assert!(rttvar > Duration::from_millis(20));
    }

    #[test]
    fn test_exponential_smoothing_weights() {
        let mut estimator = RttEstimator::new(Duration::from_millis(100));
        estimator.update(Duration::from_millis(100));

        // Add a very different sample
        estimator.update(Duration::from_millis(500));

        // RFC 9002: smoothed_rtt = (7 * old + 1 * new) / 8
        // smoothed_rtt = (7 * 100 + 500) / 8 = 1200 / 8 = 150
        assert_eq!(estimator.smoothed_rtt(), Duration::from_millis(150));
    }
}
