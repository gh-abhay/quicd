use std::time::Duration;

#[derive(Debug, Clone)]
pub struct RttEstimator {
    pub latest_rtt: Duration,
    pub min_rtt: Duration,
    pub smoothed_rtt: Duration,
    pub rttvar: Duration,
    first_sample: bool,
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self {
            latest_rtt: Duration::from_millis(0),
            min_rtt: Duration::from_millis(0),
            smoothed_rtt: Duration::from_millis(333), // Initial RTT (RFC 9002 Section 6.2.2)
            rttvar: Duration::from_millis(166), // Initial RTTVar = 333 / 2
            first_sample: true,
        }
    }
}

impl RttEstimator {
    pub fn update(&mut self, rtt: Duration, ack_delay: Duration) {
        self.latest_rtt = rtt;
        
        if self.first_sample {
            self.min_rtt = rtt;
            self.smoothed_rtt = rtt;
            self.rttvar = rtt / 2;
            self.first_sample = false;
            return;
        }
        
        // Update MinRTT
        if rtt < self.min_rtt || self.min_rtt.as_millis() == 0 {
            self.min_rtt = rtt;
        }
        
        // Adjust for ACK Delay
        let adjusted_rtt = if rtt > self.min_rtt + ack_delay {
            rtt - ack_delay
        } else {
            rtt
        };
        
        // Update RTTVar and SmoothedRTT
        // rttvar = 3/4 * rttvar + 1/4 * |smoothed_rtt - adjusted_rtt|
        let delta = if self.smoothed_rtt > adjusted_rtt {
            self.smoothed_rtt - adjusted_rtt
        } else {
            adjusted_rtt - self.smoothed_rtt
        };
        
        self.rttvar = self.rttvar.mul_f32(0.75) + delta.mul_f32(0.25);
        
        // smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt
        self.smoothed_rtt = self.smoothed_rtt.mul_f32(0.875) + adjusted_rtt.mul_f32(0.125);
    }
    
    pub fn pto_duration(&self, max_ack_delay: Duration) -> Duration {
        // PTO = smoothed_rtt + max(4*rttvar, granularity) + max_ack_delay
        // Granularity is usually 1ms.
        let rttvar_term = std::cmp::max(self.rttvar * 4, Duration::from_millis(1));
        self.smoothed_rtt + rttvar_term + max_ack_delay
    }
}
