//! Connection ID generator with eBPF routing cookie support.
//!
//! This module provides a CID generator that embeds routing cookies for
//! connection affinity, using the eBPF-based routing system.

use quicd_quic::cid::{ConnectionId, ConnectionIdGenerator, MAX_CID_LENGTH};
use super::router;
use std::sync::atomic::{AtomicU8, Ordering};

/// CID generator that embeds eBPF routing cookies.
///
/// This generator creates 20-byte Connection IDs with embedded routing
/// cookies to ensure packets for a connection are consistently routed
/// to the same worker thread via eBPF.
///
/// # Format
///
/// - Bytes 0-5: Random prefix (6 bytes)
/// - Bytes 6-7: Routing cookie (u16 big-endian)
/// - Bytes 8-18: Random entropy (11 bytes)
/// - Byte 19: Protection byte (SipHash-1-3 LSB over bytes 0-18)
pub struct RoutingConnectionIdGenerator {
    /// Worker index for routing cookie generation
    worker_idx: u8,
    /// Current generation counter (shared across all workers)
    generation: AtomicU8,
}

impl RoutingConnectionIdGenerator {
    /// Create a new routing CID generator for a specific worker.
    ///
    /// # Arguments
    ///
    /// * `worker_idx` - Worker/socket index (0-255)
    /// * `generation` - Initial generation counter (0-31)
    pub fn new(worker_idx: u8, generation: u8) -> Self {
        Self {
            worker_idx,
            generation: AtomicU8::new(generation),
        }
    }

    /// Update the generation counter (e.g., during rotation).
    pub fn set_generation(&self, generation: u8) {
        self.generation.store(generation, Ordering::Relaxed);
    }

    /// Get the current generation counter.
    pub fn generation(&self) -> u8 {
        self.generation.load(Ordering::Relaxed)
    }
}

impl ConnectionIdGenerator for RoutingConnectionIdGenerator {
    fn generate(&self, requested_len: usize) -> ConnectionId {
        // Use router::CID_LENGTH (20 bytes) regardless of requested length
        // The router requires a fixed-length CID with embedded routing cookie
        let length = router::CID_LENGTH;
        
        let generation = self.generation.load(Ordering::Relaxed);
        
        // Generate entropy for the CID (6 + 11 = 17 bytes)
        let mut entropy = [0u8; 17];
        if let Err(e) = getrandom::getrandom(&mut entropy) {
            // Fallback to deterministic generation if randomness fails
            // (should never happen in production)
            tracing::warn!("Failed to get random bytes for CID: {:?}", e);
            for (i, byte) in entropy.iter_mut().enumerate() {
                *byte = (i as u8).wrapping_mul(137);
            }
        }

        // Use router's CID generation with embedded cookie
        let cid_bytes = router::ConnectionId::generate_with_entropy(
            generation,
            self.worker_idx,
            entropy,
        );

        // Convert to ConnectionId - should always succeed for 20-byte CID
        ConnectionId::from_slice(&cid_bytes)
            .expect("Failed to create ConnectionId from 20-byte buffer - this should never happen")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_routing_generator() {
        let generator = RoutingConnectionIdGenerator::new(42, 0);
        
        let cid1 = generator.generate(router::CID_LENGTH);
        let cid2 = generator.generate(router::CID_LENGTH);
        
        assert_eq!(cid1.len(), router::CID_LENGTH);
        assert_eq!(cid2.len(), router::CID_LENGTH);
        
        // Verify CIDs are valid (have correct protection byte)
        assert!(router::ConnectionId::verify_protection(cid1.as_bytes()));
        assert!(router::ConnectionId::verify_protection(cid2.as_bytes()));
        
        // Extract and verify worker index
        assert_eq!(
            router::ConnectionId::get_worker_idx(cid1.as_bytes()),
            Some(42)
        );
        assert_eq!(
            router::ConnectionId::get_worker_idx(cid2.as_bytes()),
            Some(42)
        );
    }

    #[test]
    fn test_generation_update() {
        let generator = RoutingConnectionIdGenerator::new(10, 0);
        assert_eq!(generator.generation(), 0);
        
        generator.set_generation(5);
        assert_eq!(generator.generation(), 5);
        
        let cid = generator.generate(router::CID_LENGTH);
        let cookie = router::ConnectionId::extract_cookie(cid.as_bytes());
        
        // Cookie should embed generation=5, worker=10
        let expected_cookie = router::Cookie::generate(5, 10);
        assert_eq!(cookie, Some(expected_cookie));
    }
}
