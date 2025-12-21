//! # Packet Number Space Management (RFC 9000 Section 12.3, RFC 9002)
//!
//! This module provides utilities for managing packet number spaces, including
//! tracking sent and received packets for ACK generation and loss detection.
//!
//! ## Responsibilities
//!
//! - Track the next packet number to allocate in each space
//! - Maintain sent packet metadata for loss detection
//! - Track received packets for ACK frame generation
//! - Detect gaps in received packet numbers

#![forbid(unsafe_code)]

// This module is currently a placeholder for packet number space management.
// Full implementation will include:
// - SentPacketTracker: Tracks metadata about sent packets for loss detection
// - ReceivedPacketTracker: Tracks received packets for ACK generation
// - PacketNumberAllocator: Allocates monotonically increasing packet numbers

