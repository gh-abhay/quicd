use std::time::{Duration, Instant};

pub trait CongestionController: Send + Sync {
    fn on_packet_sent(&mut self, sent_bytes: u64);
    fn on_packet_acked(&mut self, acked_bytes: u64, rtt: Duration, now: Instant);
    fn on_packet_lost(&mut self, lost_bytes: u64, now: Instant);
    fn on_persistent_congestion(&mut self, min_window: u64); // RFC 9002 Section 7.6
    fn congestion_window(&self) -> u64;
    fn bytes_in_flight(&self) -> u64;
    fn is_congestion_limited(&self) -> bool;
}

#[derive(Debug)]
pub struct NewReno {
    cwnd: u64,
    bytes_in_flight: u64,
    ssthresh: u64,
    recovery_start_time: Option<Instant>,
    
    // Constants
    initial_window: u64,
    min_window: u64,
}

impl Default for NewReno {
    fn default() -> Self {
        // RFC 9002 Section 7.2: Initial CWND = min(10 * MSS, max(2 * MSS, 14720))
        // Assuming MSS = 1200 (safe default)
        let mss = 1200;
        let initial_window = std::cmp::min(10 * mss, std::cmp::max(2 * mss, 14720));
        
        Self {
            cwnd: initial_window,
            bytes_in_flight: 0,
            ssthresh: u64::MAX,
            recovery_start_time: None,
            initial_window,
            min_window: 2 * mss,
        }
    }
}

impl CongestionController for NewReno {
    fn on_packet_sent(&mut self, sent_bytes: u64) {
        self.bytes_in_flight += sent_bytes;
    }

    fn on_packet_acked(&mut self, acked_bytes: u64, _rtt: Duration, now: Instant) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(acked_bytes);
        
        if self.in_recovery(now) {
            return;
        }
        
        if self.cwnd < self.ssthresh {
            // Slow Start
            self.cwnd += acked_bytes;
        } else {
            // Congestion Avoidance
            // cwnd += MSS * acked_bytes / cwnd
            // Using 1200 as MSS for calculation
            let mss = 1200;
            self.cwnd += (mss * acked_bytes) / self.cwnd;
        }
    }

    fn on_packet_lost(&mut self, lost_bytes: u64, now: Instant) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);
        
        if self.in_recovery(now) {
            return;
        }
        
        // Congestion Event
        self.ssthresh = self.cwnd / 2;
        self.ssthresh = std::cmp::max(self.ssthresh, self.min_window);
        self.cwnd = self.ssthresh;
        self.recovery_start_time = Some(now);
    }
    
    fn on_persistent_congestion(&mut self, min_window: u64) {
        // RFC 9002 Section 7.6: Reset to minimum window on persistent congestion
        self.cwnd = min_window;
        self.ssthresh = min_window;
    }

    fn congestion_window(&self) -> u64 {
        self.cwnd
    }

    fn bytes_in_flight(&self) -> u64 {
        self.bytes_in_flight
    }

    fn is_congestion_limited(&self) -> bool {
        self.bytes_in_flight >= self.cwnd
    }
}

impl NewReno {
    fn in_recovery(&self, now: Instant) -> bool {
        match self.recovery_start_time {
            Some(start) => now <= start, // Simplified check, usually check against largest acked packet sent time
            None => false,
        }
    }
}
