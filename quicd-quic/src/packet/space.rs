//! Packet number space management (RFC 9002 Section 3)
//!
//! QUIC has three packet number spaces: Initial, Handshake, and Application Data.
//! Each space maintains independent state for:
//! - Packet number allocation
//! - Sent packet tracking
//! - Received packet tracking (for ACK generation)
//! - Loss detection timers

use crate::types::{PacketNumber, Instant, StreamId};
use crate::error::Result;
use core::time::Duration;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// Packet number space identifier (RFC 9002 Section 3)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketSpaceId {
    Initial,
    Handshake,
    ApplicationData,
}

/// Information about a sent packet (RFC 9002 Appendix A.1)
#[derive(Debug, Clone)]
pub struct SentPacketInfo {
    /// Packet number
    pub packet_number: PacketNumber,
    
    /// Time the packet was sent
    pub time_sent: Instant,
    
    /// Packet size in bytes
    pub size: usize,
    
    /// True if packet elicits an ACK (contains non-ACK/PADDING frames)
    pub ack_eliciting: bool,
    
    /// True if packet counts toward bytes in flight
    pub in_flight: bool,
    
    /// Frames included in this packet (for retransmission)
    pub frames: Vec<FrameType>,
    
    /// True if packet has been declared lost
    pub is_lost: bool,
}

/// Frame type identifier (for retransmission tracking)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Crypto { offset: u64, length: usize },
    Stream { stream_id: StreamId, offset: u64, length: usize, fin: bool },
    Ack,
    ResetStream { stream_id: StreamId },
    StopSending { stream_id: StreamId },
    MaxData,
    MaxStreamData { stream_id: StreamId },
    MaxStreams { bidirectional: bool },
    NewConnectionId,
    RetireConnectionId,
    PathChallenge,
    PathResponse,
    ConnectionClose,
    HandshakeDone,
    Ping,
    Padding,
}

/// Event emitted when processing ACKs
#[derive(Debug, Clone)]
pub enum AckEvent {
    /// Packet was acknowledged
    PacketAcked {
        packet_number: PacketNumber,
        time_sent: Instant,
        time_acked: Instant,
        size: usize,
        ack_eliciting: bool,
    },
    
    /// Packet was declared lost
    PacketLost {
        packet_number: PacketNumber,
        time_sent: Instant,
        time_lost: Instant,
        size: usize,
        frames: Vec<FrameType>,
    },
}

/// Range of received packet numbers for ACK generation
#[derive(Debug, Clone)]
pub struct AckRange {
    /// Smallest packet number in range (inclusive)
    pub smallest: PacketNumber,
    
    /// Largest packet number in range (inclusive)
    pub largest: PacketNumber,
}

/// Set of received packet number ranges (RFC 9000 Section 13.2.3)
///
/// **Design**: Efficiently tracks non-contiguous received packets for ACK generation.
/// Uses a sorted list of ranges to minimize memory and encode ACK frames efficiently.
#[derive(Debug, Clone)]
pub struct RangeSet {
    /// Sorted list of ranges (largest first)
    ranges: Vec<AckRange>,
    
    /// Largest packet number received
    largest: Option<PacketNumber>,
}

impl RangeSet {
    pub fn new() -> Self {
        Self {
            ranges: Vec::new(),
            largest: None,
        }
    }
    
    /// Insert a received packet number
    ///
    /// **RFC 9000 Section 13.2.3**: Merges adjacent ranges to minimize ACK frame size.
    pub fn insert(&mut self, packet_number: PacketNumber) -> bool;
    
    /// Get the largest received packet number
    pub fn largest(&self) -> Option<PacketNumber> {
        self.largest
    }
    
    /// Get all ranges for ACK frame generation (largest to smallest)
    pub fn ranges(&self) -> &[AckRange] {
        &self.ranges
    }
    
    /// Check if a packet number has been received
    pub fn contains(&self, packet_number: PacketNumber) -> bool;
}

/// RTT estimator (RFC 9002 Appendix A.3)
///
/// **Design**: Implements the EWMA algorithm for smoothed RTT calculation.
#[derive(Debug, Clone)]
pub struct RttEstimator {
    /// Smoothed RTT (SRTT)
    smoothed_rtt: Duration,
    
    /// RTT variation
    rtt_var: Duration,
    
    /// Minimum RTT observed (not adjusted for ack delay)
    min_rtt: Duration,
    
    /// Latest RTT sample
    latest_rtt: Duration,
    
    /// First RTT sample received
    first_sample_time: Option<Instant>,
}

impl RttEstimator {
    /// Initial RTT estimate (RFC 9002 Appendix A.2)
    pub const INITIAL_RTT: Duration = Duration::from_millis(333);
    
    /// Create a new RTT estimator with initial values
    pub fn new() -> Self {
        Self {
            smoothed_rtt: Self::INITIAL_RTT,
            rtt_var: Self::INITIAL_RTT / 2,
            min_rtt: Duration::MAX,
            latest_rtt: Duration::ZERO,
            first_sample_time: None,
        }
    }
    
    /// Update RTT estimate with new sample (RFC 9002 Section A.3)
    ///
    /// **Parameters**:
    /// - `ack_delay`: Delay peer reported in ACK frame (adjusted by ack_delay_exponent)
    /// - `rtt_sample`: Time between packet sent and ACK received
    pub fn update(&mut self, ack_delay: Duration, rtt_sample: Duration) {
        // Implementation follows RFC 9002 Appendix A.3 pseudocode
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
    
    /// Calculate PTO duration (RFC 9002 Section 6.2.1)
    pub fn pto_duration(&self, max_ack_delay: Duration) -> Duration {
        self.smoothed_rtt + 4.max(1) * self.rtt_var + max_ack_delay
    }
}

/// Packet number space state machine
///
/// **Design**: Each packet number space is completely independent. This struct
/// encapsulates all state needed for:
/// - Allocating packet numbers
/// - Tracking sent packets for loss detection
/// - Tracking received packets for ACK generation
/// - Managing loss detection timers
///
/// **RFC 9002 Section 3**: "Packet numbers in each space start at 0."
#[derive(Debug)]
pub struct PacketNumberSpace {
    /// Identifier for this space
    space_id: PacketSpaceId,
    
    // ===== Packet Number Management =====
    
    /// Next packet number to allocate
    next_packet_number: PacketNumber,
    
    /// Largest packet number sent
    largest_sent: Option<PacketNumber>,
    
    /// Largest packet number acknowledged by peer
    largest_acked: Option<PacketNumber>,
    
    // ===== Sent Packet Tracking =====
    
    /// Sent packets awaiting acknowledgment (ordered by packet number)
    sent_packets: VecDeque<SentPacketInfo>,
    
    /// Total bytes in flight (ack-eliciting packets not yet acked/lost)
    bytes_in_flight: usize,
    
    // ===== Received Packet Tracking =====
    
    /// Received packet numbers (for ACK generation)
    received_packets: RangeSet,
    
    /// Number of ack-eliciting packets received since last ACK sent
    ack_eliciting_since_last_ack: usize,
    
    /// True if we should send an ACK frame
    should_send_ack: bool,
    
    // ===== Loss Detection State (RFC 9002 Section 6) =====
    
    /// Time at which the earliest sent packet should be considered lost
    loss_time: Option<Instant>,
    
    /// Number of PTO expirations without receiving an ACK
    pto_count: u32,
    
    /// Time the most recent ack-eliciting packet was sent
    time_of_last_ack_eliciting_packet: Option<Instant>,
}

impl PacketNumberSpace {
    /// Create a new packet number space
    pub fn new(space_id: PacketSpaceId) -> Self {
        Self {
            space_id,
            next_packet_number: 0,
            largest_sent: None,
            largest_acked: None,
            sent_packets: VecDeque::new(),
            bytes_in_flight: 0,
            received_packets: RangeSet::new(),
            ack_eliciting_since_last_ack: 0,
            should_send_ack: false,
            loss_time: None,
            pto_count: 0,
            time_of_last_ack_eliciting_packet: None,
        }
    }
    
    // ===== Packet Number Allocation =====
    
    /// Allocate the next packet number
    pub fn next_packet_number(&mut self) -> PacketNumber {
        let pn = self.next_packet_number;
        self.next_packet_number += 1;
        self.largest_sent = Some(pn);
        pn
    }
    
    /// Get the largest packet number sent
    pub fn largest_sent(&self) -> Option<PacketNumber> {
        self.largest_sent
    }
    
    /// Get the largest packet number acknowledged
    pub fn largest_acked(&self) -> Option<PacketNumber> {
        self.largest_acked
    }
    
    // ===== Sent Packet Tracking =====
    
    /// Record a sent packet (RFC 9002 Appendix A.1)
    ///
    /// **Design**: Called after packet is written to socket. Stores metadata
    /// for loss detection and retransmission.
    pub fn on_packet_sent(&mut self, info: SentPacketInfo) {
        if info.ack_eliciting {
            self.time_of_last_ack_eliciting_packet = Some(info.time_sent);
        }
        
        if info.in_flight {
            self.bytes_in_flight += info.size;
        }
        
        self.sent_packets.push_back(info);
    }
    
    /// Get bytes in flight
    pub fn bytes_in_flight(&self) -> usize {
        self.bytes_in_flight
    }
    
    /// Check if there are any sent packets awaiting acknowledgment
    pub fn has_in_flight_packets(&self) -> bool {
        !self.sent_packets.is_empty()
    }
    
    // ===== Received Packet Tracking =====
    
    /// Mark a packet as received (RFC 9000 Section 13.2)
    ///
    /// **Returns**: `true` if this is a new packet (not a duplicate)
    pub fn on_packet_received(&mut self, packet_number: PacketNumber, ack_eliciting: bool) -> bool {
        let is_new = self.received_packets.insert(packet_number);
        
        if is_new && ack_eliciting {
            self.ack_eliciting_since_last_ack += 1;
            
            // RFC 9000 Section 13.2.1: Send ACK if 2+ ack-eliciting packets received
            if self.ack_eliciting_since_last_ack >= 2 {
                self.should_send_ack = true;
            }
        }
        
        is_new
    }
    
    /// Check if we should send an ACK frame
    pub fn should_send_ack(&self) -> bool {
        self.should_send_ack
    }
    
    /// Get ACK ranges for generating ACK frame
    pub fn ack_ranges(&self) -> &[AckRange] {
        self.received_packets.ranges()
    }
    
    /// Get largest received packet number
    pub fn largest_received(&self) -> Option<PacketNumber> {
        self.received_packets.largest()
    }
    
    /// Mark that we sent an ACK frame
    pub fn on_ack_sent(&mut self) {
        self.ack_eliciting_since_last_ack = 0;
        self.should_send_ack = false;
    }
    
    // ===== ACK Processing (RFC 9002 Section 6.1) =====
    
    /// Process ACK frame and detect lost packets
    ///
    /// **RFC 9002 Section 6.1**: When an ACK is received, newly acknowledged packets
    /// are processed first, then loss detection is performed.
    ///
    /// **Returns**: Vector of ack events (packets acked and lost)
    pub fn on_ack_received(
        &mut self,
        largest_acked: PacketNumber,
        ack_ranges: &[AckRange],
        ack_delay: Duration,
        now: Instant,
        rtt_estimator: &mut RttEstimator,
    ) -> Result<Vec<AckEvent>> {
        let mut events = Vec::new();
        
        // 1. Update largest_acked
        if let Some(prev_largest) = self.largest_acked {
            if largest_acked <= prev_largest {
                // Duplicate or out-of-order ACK, ignore
                return Ok(events);
            }
        }
        self.largest_acked = Some(largest_acked);
        
        // 2. Process newly acknowledged packets
        let mut newly_acked = Vec::new();
        self.sent_packets.retain(|pkt| {
            if self.is_acked(pkt.packet_number, largest_acked, ack_ranges) {
                newly_acked.push(pkt.clone());
                false  // Remove from sent_packets
            } else {
                true   // Keep in sent_packets
            }
        });
        
        // 3. Update RTT if largest packet is newly acked
        if let Some(largest_pkt) = newly_acked.iter()
            .find(|p| p.packet_number == largest_acked) 
        {
            if largest_pkt.ack_eliciting {
                let rtt_sample = now.duration_since(largest_pkt.time_sent);
                rtt_estimator.update(ack_delay, rtt_sample);
            }
        }
        
        // 4. Generate ack events and update bytes in flight
        for pkt in newly_acked {
            if pkt.in_flight {
                self.bytes_in_flight = self.bytes_in_flight.saturating_sub(pkt.size);
            }
            
            events.push(AckEvent::PacketAcked {
                packet_number: pkt.packet_number,
                time_sent: pkt.time_sent,
                time_acked: now,
                size: pkt.size,
                ack_eliciting: pkt.ack_eliciting,
            });
        }
        
        // 5. Detect lost packets (RFC 9002 Section 6.1.1)
        let lost_events = self.detect_lost_packets(now, rtt_estimator)?;
        events.extend(lost_events);
        
        // 6. Reset PTO count (RFC 9002 Section 6.2.1)
        self.pto_count = 0;
        
        // 7. Update loss time
        self.set_loss_detection_timer(now, rtt_estimator);
        
        Ok(events)
    }
    
    /// Check if a packet number is acknowledged
    fn is_acked(
        &self,
        packet_number: PacketNumber,
        largest_acked: PacketNumber,
        ranges: &[AckRange],
    ) -> bool {
        if packet_number > largest_acked {
            return false;
        }
        
        for range in ranges {
            if packet_number >= range.smallest && packet_number <= range.largest {
                return true;
            }
        }
        
        false
    }
    
    // ===== Loss Detection (RFC 9002 Section 6.1.1) =====
    
    /// Detect lost packets using time and packet thresholds
    ///
    /// **RFC 9002 Section 6.1.1**: A packet is declared lost if:
    /// 1. A packet at least 3 higher has been acknowledged (packet threshold), OR
    /// 2. Sent more than threshold time in the past (time threshold)
    fn detect_lost_packets(
        &mut self,
        now: Instant,
        rtt_estimator: &RttEstimator,
    ) -> Result<Vec<AckEvent>> {
        let mut events = Vec::new();
        
        let Some(largest_acked) = self.largest_acked else {
            return Ok(events);
        };
        
        // Packet threshold: 3 (RFC 9002 Section 6.1.1)
        let packet_threshold = 3;
        
        // Time threshold: max(smoothed_rtt + 4 * rtt_var, 1ms)
        let time_threshold = rtt_estimator.smoothed_rtt() 
            + 4 * rtt_estimator.rtt_var();
        let time_threshold = time_threshold.max(Duration::from_millis(1));
        
        let loss_deadline = now - time_threshold;
        
        // Check each sent packet for loss
        let mut i = 0;
        while i < self.sent_packets.len() {
            let pkt = &self.sent_packets[i];
            
            if pkt.packet_number > largest_acked {
                // Packet sent after largest acked, can't determine loss yet
                i += 1;
                continue;
            }
            
            let lost_by_packet_threshold = 
                pkt.packet_number + packet_threshold <= largest_acked;
            let lost_by_time_threshold = pkt.time_sent < loss_deadline;
            
            if lost_by_packet_threshold || lost_by_time_threshold {
                // Declare packet lost
                let pkt = self.sent_packets.remove(i).unwrap();
                
                if pkt.in_flight {
                    self.bytes_in_flight = self.bytes_in_flight.saturating_sub(pkt.size);
                }
                
                events.push(AckEvent::PacketLost {
                    packet_number: pkt.packet_number,
                    time_sent: pkt.time_sent,
                    time_lost: now,
                    size: pkt.size,
                    frames: pkt.frames,
                });
            } else {
                i += 1;
            }
        }
        
        Ok(events)
    }
    
    // ===== Timer Management (RFC 9002 Section 6.2) =====
    
    /// Calculate PTO deadline for this space
    ///
    /// **RFC 9002 Section 6.2.1**: PTO = smoothed_rtt + max(4*rtt_var, 1ms) + max_ack_delay
    pub fn pto_deadline(
        &self,
        rtt_estimator: &RttEstimator,
        max_ack_delay: Duration,
    ) -> Option<Instant> {
        let Some(last_sent) = self.time_of_last_ack_eliciting_packet else {
            return None;
        };
        
        let pto_duration = rtt_estimator.pto_duration(max_ack_delay);
        
        // Exponential backoff based on pto_count
        let backoff_duration = pto_duration * (1 << self.pto_count);
        
        last_sent.checked_add(backoff_duration)
    }
    
    /// Handle PTO timeout (RFC 9002 Section 6.2)
    ///
    /// **Design**: When PTO expires, send probe packets to elicit ACKs.
    pub fn on_pto_timeout(&mut self, now: Instant) {
        self.pto_count += 1;
        // Caller must send probe packets based on this space
    }
    
    /// Get loss detection timer deadline
    pub fn loss_detection_deadline(&self) -> Option<Instant> {
        self.loss_time
    }
    
    /// Set loss detection timer
    fn set_loss_detection_timer(&mut self, now: Instant, rtt_estimator: &RttEstimator) {
        // Find earliest time a packet could be declared lost
        if let Some(largest_acked) = self.largest_acked {
            let time_threshold = rtt_estimator.smoothed_rtt() 
                + 4 * rtt_estimator.rtt_var();
            
            let mut earliest_loss_time = None;
            for pkt in &self.sent_packets {
                if pkt.packet_number <= largest_acked {
                    if let Some(loss_time) = pkt.time_sent.checked_add(time_threshold) {
                        match earliest_loss_time {
                            None => earliest_loss_time = Some(loss_time),
                            Some(current) if loss_time < current => {
                                earliest_loss_time = Some(loss_time);
                            }
                            _ => {}
                        }
                    }
                }
            }
            
            self.loss_time = earliest_loss_time;
        }
    }
    
    /// Get PTO count (for exponential backoff)
    pub fn pto_count(&self) -> u32 {
        self.pto_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_packet_number_allocation() {
        let mut space = PacketNumberSpace::new(PacketSpaceId::ApplicationData);
        
        assert_eq!(space.next_packet_number(), 0);
        assert_eq!(space.next_packet_number(), 1);
        assert_eq!(space.next_packet_number(), 2);
        assert_eq!(space.largest_sent(), Some(2));
    }
    
    #[test]
    fn test_received_packet_tracking() {
        let mut space = PacketNumberSpace::new(PacketSpaceId::ApplicationData);
        
        // Receive packets 0, 1, 3, 4 (missing 2)
        assert!(space.on_packet_received(0, true));
        assert!(space.on_packet_received(1, true));
        assert!(space.on_packet_received(3, true));
        assert!(space.on_packet_received(4, true));
        
        // Should have ranges [0-1] and [3-4]
        let ranges = space.ack_ranges();
        assert_eq!(ranges.len(), 2);
        
        // Duplicate packet should return false
        assert!(!space.on_packet_received(1, true));
    }
}
