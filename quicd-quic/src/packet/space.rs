//! # Packet Number Space State (RFC 9000 Section 12.3, 13.1)
//!
//! Tracks state for each packet number space (Initial, Handshake, ApplicationData).
//! Each space maintains independent packet numbers, ACK tracking, and crypto state.

#![forbid(unsafe_code)]

use crate::error::{Error, Result};
use crate::types::{Instant, PacketNumber, PacketNumberSpace};
use core::time::Duration;

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

    /// Whether this packet number space has been discarded
    /// (RFC 9000 Section 4.9.1: Initial and Handshake spaces are discarded)
    pub is_discarded: bool,

    /// Number of ACK-eliciting packets received since last ACK sent
    pub ack_eliciting_received: usize,

    /// Time when we should send an ACK (or None if no ACK pending)
    pub ack_deadline: Option<Instant>,
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
            is_discarded: false,
            ack_eliciting_received: 0,
            ack_deadline: None,
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
    pub fn on_packet_received(
        &mut self,
        pn: PacketNumber,
        now: Instant,
        is_ack_eliciting: bool,
    ) {
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

    /// Reset ACK state after sending an ACK frame
    pub fn on_ack_sent(&mut self) {
        self.ack_eliciting_received = 0;
        self.ack_deadline = None;
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
            application_data: PacketNumberSpaceState::new(
                PacketNumberSpace::ApplicationData,
            ),
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
