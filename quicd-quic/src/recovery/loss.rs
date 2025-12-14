use crate::packet::{PacketNumber, PacketType};
use crate::frame::Frame;
use crate::recovery::{RttEstimator, CongestionController};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct SentPacket {
    pub packet_number: u64,
    pub time_sent: Instant,
    pub sent_bytes: u64,
    pub ack_eliciting: bool,
    pub in_flight: bool,
    pub packet_type: PacketType,
    pub frames: Vec<Frame>,
}

pub struct LossDetector {
    sent_packets: BTreeMap<u64, SentPacket>, // Map PN -> SentPacket
    pub lost_packets: Vec<SentPacket>,
    
    largest_acked_packet: Option<u64>,
    loss_time: Option<Instant>,
    
    // PTO state
    pub time_of_last_ack_eliciting_packet: Option<Instant>,
    pub pto_count: u32,
    
    // Persistent Congestion (RFC 9002 Section 7.6)
    persistent_congestion_start_time: Option<Instant>,
    
    // Constants
    k_packet_threshold: u64,
    k_time_threshold: f32,
    k_granularity: Duration,
    k_persistent_congestion_threshold: u32, // Default: 3
}

impl Default for LossDetector {
    fn default() -> Self {
        Self {
            sent_packets: BTreeMap::new(),
            lost_packets: Vec::new(),
            largest_acked_packet: None,
            loss_time: None,
            time_of_last_ack_eliciting_packet: None,
            pto_count: 0,
            persistent_congestion_start_time: None,
            k_packet_threshold: 3,
            k_time_threshold: 9.0 / 8.0,
            k_granularity: Duration::from_millis(1),
            k_persistent_congestion_threshold: 3,
        }
    }
}

impl LossDetector {
    pub fn on_packet_sent(&mut self, packet: SentPacket, cc: &mut dyn CongestionController) {
        if packet.in_flight {
            cc.on_packet_sent(packet.sent_bytes);
        }
        if packet.ack_eliciting {
            self.time_of_last_ack_eliciting_packet = Some(packet.time_sent);
        }
        self.sent_packets.insert(packet.packet_number, packet);
    }

    pub fn on_ack_received(
        &mut self,
        largest_acknowledged: u64,
        first_range: u64,
        ranges: &[(u64, u64)], // (gap, len)
        ack_delay: Duration,
        rtt_estimator: &mut RttEstimator,
        cc: &mut dyn CongestionController,
        now: Instant,
    ) {
        self.largest_acked_packet = Some(std::cmp::max(
            self.largest_acked_packet.unwrap_or(0),
            largest_acknowledged,
        ));

        // Decode ranges into absolute intervals [low, high]
        let mut intervals = Vec::new();
        let mut current_high = largest_acknowledged;
        let mut current_low = current_high.saturating_sub(first_range);
        intervals.push((current_low, current_high));
        
        for &(gap, len) in ranges {
            if current_low < gap + 2 {
                break; 
            }
            current_high = current_low - (gap + 2);
            current_low = current_high.saturating_sub(len);
            intervals.push((current_low, current_high));
        }
        
        let mut acked_pns = Vec::new();
        
        // Check sent_packets against intervals
        // Optimization: only check packets <= largest_acknowledged
        let pns_to_check: Vec<u64> = self.sent_packets.range(..=largest_acknowledged).map(|(&k, _)| k).collect();
        
        for pn in pns_to_check {
             for &(low, high) in &intervals {
                if pn >= low && pn <= high {
                    acked_pns.push(pn);
                    break;
                }
            }
        }
        
        if acked_pns.is_empty() {
            return;
        }
        
        // Update RTT if largest acked is newly acked
        if acked_pns.contains(&largest_acknowledged) {
            if let Some(packet) = self.sent_packets.get(&largest_acknowledged) {
                if packet.ack_eliciting {
                    let rtt = now.duration_since(packet.time_sent);
                    rtt_estimator.update(rtt, ack_delay);
                }
            }
        }
        
        // Process acked packets
        for pn in acked_pns {
            if let Some(packet) = self.sent_packets.remove(&pn) {
                if packet.in_flight {
                    cc.on_packet_acked(packet.sent_bytes, rtt_estimator.latest_rtt, now);
                }
            }
        }
        
        // Reset PTO count on new ack
        self.pto_count = 0;

        self.detect_loss(rtt_estimator, cc, now);
    }
    
    pub fn detect_loss(
        &mut self,
        rtt_estimator: &RttEstimator,
        cc: &mut dyn CongestionController,
        now: Instant,
    ) {
        self.loss_time = None;
        let loss_delay = rtt_estimator.latest_rtt.mul_f32(self.k_time_threshold);
        let loss_delay = std::cmp::max(loss_delay, self.k_granularity);
        
        let largest_acked = self.largest_acked_packet.unwrap_or(0);
        
        let mut lost_pns = Vec::new();
        
        for (&pn, packet) in self.sent_packets.iter() {
            if pn > largest_acked {
                continue;
            }
            
            let time_since_sent = now.duration_since(packet.time_sent);
            let packet_threshold_exceeded = largest_acked >= pn + self.k_packet_threshold;
            let time_threshold_exceeded = time_since_sent >= loss_delay;
            
            if packet_threshold_exceeded || time_threshold_exceeded {
                lost_pns.push(pn);
            } else {
                // Calculate loss time for timer
                let packet_loss_time = packet.time_sent + loss_delay;
                if self.loss_time.is_none() || packet_loss_time < self.loss_time.unwrap() {
                    self.loss_time = Some(packet_loss_time);
                }
            }
        }
        
        for pn in lost_pns {
            if let Some(packet) = self.sent_packets.remove(&pn) {
                if packet.in_flight {
                    cc.on_packet_lost(packet.sent_bytes, now);
                }
                self.lost_packets.push(packet);
            }
        }
        
        // Check for persistent congestion (RFC 9002 Section 7.6)
        self.detect_persistent_congestion(rtt_estimator, cc, now);
    }
    
    /// Detect persistent congestion (RFC 9002 Section 7.6)
    fn detect_persistent_congestion(
        &mut self,
        rtt_estimator: &RttEstimator,
        cc: &mut dyn CongestionController,
        now: Instant,
    ) {
        if self.lost_packets.len() < 2 {
            return;
        }
        
        // Find the period covered by recent losses
        if let (Some(first_lost), Some(last_lost)) = (
            self.lost_packets.first(),
            self.lost_packets.last(),
        ) {
            let period = last_lost.time_sent.duration_since(first_lost.time_sent);
            
            // Persistent congestion threshold = kPersistentCongestionThreshold * PTO
            let max_ack_delay = Duration::from_millis(25); // Conservative default
            let pto = rtt_estimator.pto_duration(max_ack_delay);
            let threshold = pto.mul_f32(self.k_persistent_congestion_threshold as f32);
            
            if period >= threshold {
                // Persistent congestion detected - reset to minimum window
                let min_window = 2 * 1200; // 2 * MSS
                cc.on_persistent_congestion(min_window);
                self.persistent_congestion_start_time = Some(now);
            }
        }
    }

    pub fn get_loss_detection_timer(&self, rtt_estimator: &RttEstimator, max_ack_delay: Duration) -> Option<Instant> {
        if !self.sent_packets.iter().any(|(_, p)| p.ack_eliciting && p.in_flight) {
            return None;
        }

        if let Some(loss_time) = self.loss_time {
            return Some(loss_time);
        }

        if let Some(last_ack_eliciting_time) = self.time_of_last_ack_eliciting_packet {
            let pto = rtt_estimator.pto_duration(max_ack_delay)
                .mul_f32(2.0_f32.powi(self.pto_count as i32));
            
            return Some(last_ack_eliciting_time + pto);
        }

        None
    }

    pub fn on_loss_detection_timeout(&mut self, rtt_estimator: &RttEstimator, cc: &mut dyn CongestionController, now: Instant) -> LossDetectionEvent {
        if let Some(loss_time) = self.loss_time {
            if now >= loss_time {
                self.detect_loss(rtt_estimator, cc, now);
                return LossDetectionEvent::LossDetected;
            }
        }

        self.pto_count += 1;
        LossDetectionEvent::PTO
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum LossDetectionEvent {
    None,
    LossDetected,
    PTO,
}
