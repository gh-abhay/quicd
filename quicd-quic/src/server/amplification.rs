//! # Anti-Amplification Limits (RFC 9000 Section 8)
//!
//! Prevents servers from being used in amplification attacks by limiting
//! bytes sent to unvalidated addresses.

#![forbid(unsafe_code)]

extern crate alloc;
use crate::types::Instant;
use alloc::collections::BTreeMap as HashMap;
use alloc::vec::Vec;

/// Address identifier (simplified - real impl would use SocketAddr)
pub type AddressKey = [u8; 16];

/// Anti-amplification tracker for address validation
///
/// **RFC 9000 Section 8.1**: Server MUST NOT send more than 3x the bytes
/// received from an unvalidated address.
#[derive(Debug)]
pub struct AmplificationLimiter {
    /// Per-address byte counters
    limits: HashMap<AddressKey, AddressLimit>,

    /// Cleanup interval
    cleanup_interval: core::time::Duration,

    /// Last cleanup time
    last_cleanup: Option<Instant>,
}

/// Byte limits for a single address
#[derive(Debug, Clone)]
struct AddressLimit {
    /// Bytes received from this address
    bytes_received: usize,

    /// Bytes sent to this address  
    bytes_sent: usize,

    /// Address validated (can send unlimited)
    validated: bool,

    /// Last activity time (for cleanup)
    last_activity: Instant,
}

impl AmplificationLimiter {
    /// Create new limiter
    pub fn new() -> Self {
        Self {
            limits: HashMap::new(),
            cleanup_interval: core::time::Duration::from_secs(60),
            last_cleanup: None,
        }
    }

    /// Record bytes received from address
    pub fn record_received(&mut self, addr: &AddressKey, bytes: usize, now: Instant) {
        let limit = self.limits.entry(*addr).or_insert_with(|| AddressLimit {
            bytes_received: 0,
            bytes_sent: 0,
            validated: false,
            last_activity: now,
        });

        limit.bytes_received = limit.bytes_received.saturating_add(bytes);
        limit.last_activity = now;
    }

    /// Record bytes sent to address
    pub fn record_sent(&mut self, addr: &AddressKey, bytes: usize, now: Instant) {
        if let Some(limit) = self.limits.get_mut(addr) {
            limit.bytes_sent = limit.bytes_sent.saturating_add(bytes);
            limit.last_activity = now;
        }
    }

    /// Check if sending would exceed amplification limit
    ///
    /// Returns Ok(()) if allowed, Err with available budget otherwise.
    pub fn check_send(&self, addr: &AddressKey, bytes: usize) -> Result<(), usize> {
        let limit = match self.limits.get(addr) {
            Some(l) => l,
            None => return Ok(()), // No limits yet
        };

        // Validated addresses have no limit
        if limit.validated {
            return Ok(());
        }

        // RFC 9000 Section 8.1: 3x amplification limit
        let max_allowed = limit.bytes_received.saturating_mul(3);
        let available = max_allowed.saturating_sub(limit.bytes_sent);

        if bytes <= available {
            Ok(())
        } else {
            Err(available)
        }
    }

    /// Mark address as validated (removes limits)
    ///
    /// **RFC 9000 Section 8.1**: After address validation (handshake complete
    /// or Retry/PATH_CHALLENGE validated), remove sending limits.
    pub fn mark_validated(&mut self, addr: &AddressKey) {
        if let Some(limit) = self.limits.get_mut(addr) {
            limit.validated = true;
        }
    }

    /// Periodic cleanup of old address entries
    pub fn cleanup(&mut self, now: Instant) {
        if let Some(last) = self.last_cleanup {
            let elapsed = now.duration_since(last);
            if elapsed.is_some() && elapsed.unwrap() < self.cleanup_interval {
                return;
            }
        }

        // Remove entries older than 5 minutes
        let cutoff = now.checked_sub(core::time::Duration::from_secs(300));
        if let Some(cutoff) = cutoff {
            self.limits.retain(|_, limit| limit.last_activity >= cutoff);
        }

        self.last_cleanup = Some(now);
    }

    /// Get current statistics for address
    pub fn get_stats(&self, addr: &AddressKey) -> Option<(usize, usize, bool)> {
        self.limits
            .get(addr)
            .map(|l| (l.bytes_received, l.bytes_sent, l.validated))
    }
}

impl Default for AmplificationLimiter {
    fn default() -> Self {
        Self::new()
    }
}

