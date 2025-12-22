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
        let pto = self.smoothed_rtt + Duration::max(4 * self.rtt_var, Duration::from_millis(1))
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
        self.ack_time.duration_since(self.sent_time).unwrap_or(Duration::from_secs(0))
    }
}
