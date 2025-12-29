//! # Packet Number Space State (RFC 9000 Section 12.3, 13.1)
//!
//! Tracks state for each packet number space (Initial, Handshake, ApplicationData).
//! Each space maintains independent packet numbers, ACK tracking, and crypto state.

#![forbid(unsafe_code)]

use crate::types::{Instant, PacketNumber, PacketNumberSpace};
use core::time::Duration;
use std::collections::BTreeSet;

/// Tracks received packet numbers for ACK generation
/// Uses a compact representation for efficient storage
#[derive(Debug, Clone, Default)]
pub struct ReceivedPacketTracker {
    /// Set of received packet numbers (we use BTreeSet for ordered traversal)
    /// For production, this should use a more efficient range-based representation
    received: BTreeSet<PacketNumber>,
    /// Maximum number of packet numbers to track (to bound memory usage)
    max_tracked: usize,
}

impl ReceivedPacketTracker {
    pub fn new(max_tracked: usize) -> Self {
        Self {
            received: BTreeSet::new(),
            max_tracked,
        }
    }

    /// Record a received packet
    pub fn on_received(&mut self, pn: PacketNumber) {
        self.received.insert(pn);
        
        // If we exceed max, remove the smallest entries
        while self.received.len() > self.max_tracked {
            if let Some(&smallest) = self.received.iter().next() {
                self.received.remove(&smallest);
            }
        }
    }

    /// Get the largest received packet number
    pub fn largest(&self) -> Option<PacketNumber> {
        self.received.iter().next_back().copied()
    }

    /// Compute first_ack_range: number of contiguous packets preceding largest
    /// that have been received
    pub fn first_ack_range(&self) -> u64 {
        let largest = match self.largest() {
            Some(l) => l,
            None => return 0,
        };

        // Count backwards from largest to find the first gap
        let mut count = 0u64;
        for pn in (0..=largest).rev() {
            if self.received.contains(&pn) {
                count += 1;
            } else {
                break;
            }
        }
        // first_ack_range is the count minus 1 (since it's packets PRECEDING largest)
        // Actually, first_ack_range = number of packets in range, minus 1
        // If only largest is received, first_ack_range = 0
        // If largest and largest-1 are received, first_ack_range = 1
        count.saturating_sub(1)
    }

    /// Clear packets up to and including the given packet number
    /// (called after we've sent an ACK and confirmed the peer received it)
    pub fn clear_up_to(&mut self, pn: PacketNumber) {
        self.received.retain(|&p| p > pn);
    }
}

/// Packet Number Space State
///
/// Maintains per-space state for:
/// - Next packet number to send
/// - Largest received packet number
/// - ACK tracking (which packets need acknowledgment)
/// - Crypto level completion
///
/// **RFC 9000 Section 12.3**: Each packet number space has independent
/// packet numbering. Endpoints MUST maintain separate packet number spaces.
#[derive(Debug, Clone)]
pub struct PacketNumberSpaceState {
    /// The packet number space this state belongs to
    pub space: PacketNumberSpace,

    /// Next packet number to assign for outgoing packets
    pub next_pn: PacketNumber,

    /// Largest packet number received and successfully processed
    pub largest_pn_received: Option<PacketNumber>,

    /// Time when largest packet number was received
    pub largest_pn_received_time: Option<Instant>,

    /// Largest acknowledged packet number (from peer's ACK frames)
    pub largest_acked: Option<PacketNumber>,

    /// Largest packet number we've acknowledged in an ACK frame we sent
    /// Used to determine when we need to send new ACKs
    pub largest_pn_acked_by_us: Option<PacketNumber>,

    /// Whether this packet number space has been discarded
    /// (RFC 9000 Section 4.9.1: Initial and Handshake spaces are discarded)
    pub is_discarded: bool,

    /// Number of ACK-eliciting packets received since last ACK sent
    pub ack_eliciting_received: usize,

    /// Time when we should send an ACK (or None if no ACK pending)
    pub ack_deadline: Option<Instant>,
    
    /// Tracker for received packet numbers (for proper ACK generation)
    pub received_tracker: ReceivedPacketTracker,
}

impl PacketNumberSpaceState {
    /// Create a new packet number space state
    pub fn new(space: PacketNumberSpace) -> Self {
        Self {
            space,
            next_pn: 0,
            largest_pn_received: None,
            largest_pn_received_time: None,
            largest_acked: None,
            largest_pn_acked_by_us: None,
            is_discarded: false,
            ack_eliciting_received: 0,
            ack_deadline: None,
            received_tracker: ReceivedPacketTracker::new(1024), // Track up to 1024 packets
        }
    }

    /// Allocate the next packet number
    ///
    /// Returns the packet number and increments internal counter.
    pub fn next_packet_number(&mut self) -> PacketNumber {
        let pn = self.next_pn;
        self.next_pn += 1;
        pn
    }

    /// Record receipt of a packet
    ///
    /// Updates largest received packet number and timestamp.
    pub fn on_packet_received(&mut self, pn: PacketNumber, now: Instant, is_ack_eliciting: bool) {
        // Track this packet for ACK generation
        self.received_tracker.on_received(pn);
        
        if let Some(largest) = self.largest_pn_received {
            if pn > largest {
                self.largest_pn_received = Some(pn);
                self.largest_pn_received_time = Some(now);
            }
        } else {
            self.largest_pn_received = Some(pn);
            self.largest_pn_received_time = Some(now);
        }

        if is_ack_eliciting {
            self.ack_eliciting_received += 1;
            self.update_ack_deadline(now);
        }
    }

    /// Record ACK of sent packets
    ///
    /// Updates largest acknowledged packet number.
    pub fn on_ack_received(&mut self, largest_acked: PacketNumber) {
        if let Some(current_largest) = self.largest_acked {
            if largest_acked > current_largest {
                self.largest_acked = Some(largest_acked);
            }
        } else {
            self.largest_acked = Some(largest_acked);
        }
    }

    /// Discard this packet number space (RFC 9000 Section 4.9.1)
    ///
    /// Called when:
    /// - Initial keys are discarded after Handshake keys are available
    /// - Handshake keys are discarded after handshake completes
    pub fn discard(&mut self) {
        self.is_discarded = true;
    }

    /// Check if an ACK should be sent
    ///
    /// Returns true if:
    /// - We've received ACK-eliciting packets
    /// - ACK deadline has passed
    pub fn should_send_ack(&self, now: Instant) -> bool {
        if self.is_discarded {
            return false;
        }

        if let Some(deadline) = self.ack_deadline {
            now >= deadline
        } else {
            false
        }
    }

    /// Check if we have new packets to acknowledge
    ///
    /// Returns true if we've received packets that we haven't yet ACKed
    pub fn has_pending_acks(&self) -> bool {
        if self.is_discarded {
            return false;
        }
        match (self.largest_pn_received, self.largest_pn_acked_by_us) {
            (Some(received), Some(acked)) => received > acked,
            (Some(_), None) => true, // Received packets but never sent ACK
            (None, _) => false,      // No packets received
        }
    }

    /// Reset ACK state after sending an ACK frame
    ///
    /// # Arguments
    /// - `largest_acked`: The largest packet number included in the ACK we sent
    pub fn on_ack_sent(&mut self, largest_acked: PacketNumber) {
        self.ack_eliciting_received = 0;
        self.ack_deadline = None;
        // Track largest PN we've acknowledged
        if let Some(current) = self.largest_pn_acked_by_us {
            if largest_acked > current {
                self.largest_pn_acked_by_us = Some(largest_acked);
            }
        } else {
            self.largest_pn_acked_by_us = Some(largest_acked);
        }
    }

    /// Update ACK deadline based on received packets
    ///
    /// RFC 9000 Section 13.2.1: Send ACK within max_ack_delay
    fn update_ack_deadline(&mut self, now: Instant) {
        // Immediate ACK after receiving 2+ ACK-eliciting packets
        if self.ack_eliciting_received >= 2 {
            self.ack_deadline = Some(now);
            return;
        }

        // Otherwise schedule ACK for later (default max_ack_delay is 25ms)
        let max_ack_delay = Duration::from_millis(25);
        if let Some(deadline) = now.checked_add(max_ack_delay) {
            self.ack_deadline = Some(deadline);
        }
    }
}

/// Packet Number Space Manager
///
/// Manages all three packet number spaces for a connection.
pub struct PacketNumberSpaceManager {
    pub initial: PacketNumberSpaceState,
    pub handshake: PacketNumberSpaceState,
    pub application_data: PacketNumberSpaceState,
}

impl PacketNumberSpaceManager {
    /// Create a new manager with all three spaces
    pub fn new() -> Self {
        Self {
            initial: PacketNumberSpaceState::new(PacketNumberSpace::Initial),
            handshake: PacketNumberSpaceState::new(PacketNumberSpace::Handshake),
            application_data: PacketNumberSpaceState::new(PacketNumberSpace::ApplicationData),
        }
    }

    /// Get mutable reference to a specific space
    pub fn get_mut(&mut self, space: PacketNumberSpace) -> &mut PacketNumberSpaceState {
        match space {
            PacketNumberSpace::Initial => &mut self.initial,
            PacketNumberSpace::Handshake => &mut self.handshake,
            PacketNumberSpace::ApplicationData => &mut self.application_data,
        }
    }

    /// Get immutable reference to a specific space
    pub fn get(&self, space: PacketNumberSpace) -> &PacketNumberSpaceState {
        match space {
            PacketNumberSpace::Initial => &self.initial,
            PacketNumberSpace::Handshake => &self.handshake,
            PacketNumberSpace::ApplicationData => &self.application_data,
        }
    }

    /// Discard Initial packet number space (RFC 9000 Section 4.9.1)
    pub fn discard_initial(&mut self) {
        self.initial.discard();
    }

    /// Discard Handshake packet number space (RFC 9000 Section 4.9.1)
    pub fn discard_handshake(&mut self) {
        self.handshake.discard();
    }
}

impl Default for PacketNumberSpaceManager {
    fn default() -> Self {
        Self::new()
    }
}
