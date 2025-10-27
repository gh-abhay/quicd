//! Hierarchical Timer Wheel for High-Performance QUIC Connection Management
//!
//! Implements a two-level timer wheel optimized for millions of concurrent QUIC connections.
//! Based on the Linux kernel timer wheel design but adapted for QUIC-specific timeout handling.
//!
//! ## Design
//!
//! - **Inner Wheel**: 256 slots, 50ms granularity (covers ~12.8 seconds)
//! - **Outer Wheel**: 256 slots, 12.8s granularity (covers ~54 minutes)
//! - **Overflow**: Separate handling for timers > 54 minutes
//! - **Timer Types**: Connection idle, PTO, handshake, custom timers
//!
//! ## Performance
//!
//! - O(1) timer insertion and removal
//! - Efficient batch processing of expired timers
//! - Excellent cache locality for high connection counts
//! - Minimal memory overhead per timer

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

/// Timer types for QUIC connections
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimerType {
    /// Connection idle timeout (typically 30 seconds)
    IdleTimeout,
    /// Path PTO timer
    PathPto,
    /// Handshake timeout
    Handshake,
    /// Custom application timer
    Custom(u32),
}

/// Timer entry stored in the wheel
#[derive(Debug, Clone)]
pub struct TimerEntry {
    /// Connection DCID this timer belongs to
    pub dcid: Vec<u8>,
    /// Type of timer
    pub timer_type: TimerType,
    /// When this timer was scheduled (for debugging)
    pub scheduled_at: Instant,
}

/// Hierarchical timer wheel for efficient timeout management
#[derive(Debug)]
pub struct TimerWheel {
    /// Inner wheel: 256 slots, 50ms granularity
    inner_wheel: Vec<Vec<TimerEntry>>,
    /// Outer wheel: 256 slots, 12.8s granularity (256 * 50ms)
    outer_wheel: Vec<Vec<TimerEntry>>,
    /// Overflow timers for durations > 54 minutes
    overflow_timers: VecDeque<(TimerEntry, Instant)>,
    /// Current inner wheel position (0-255)
    inner_pos: usize,
    /// Current outer wheel position (0-255)
    outer_pos: usize,
    /// Base time for wheel calculations
    base_time: Instant,
    /// Active timer count for monitoring
    active_timers: usize,
}

impl TimerWheel {
    /// Create a new timer wheel
    pub fn new() -> Self {
        Self {
            inner_wheel: (0..256).map(|_| Vec::new()).collect(),
            outer_wheel: (0..256).map(|_| Vec::new()).collect(),
            overflow_timers: VecDeque::new(),
            inner_pos: 0,
            outer_pos: 0,
            base_time: Instant::now(),
            active_timers: 0,
        }
    }

    /// Add a timer to the wheel
    ///
    /// # Arguments
    /// * `dcid` - The connection DCID this timer belongs to
    /// * `timer_type` - Type of timer
    /// * `duration` - How long until the timer expires
    pub fn add_timer(&mut self, dcid: Vec<u8>, timer_type: TimerType, duration: Duration) {
        let expiration_time = self.base_time + duration;
        let now = Instant::now();

        // Calculate which slot this timer goes in
        let ticks_from_now = if expiration_time > now {
            ((expiration_time - now).as_millis() as u64 + 49) / 50 // Round up to next tick
        } else {
            0 // Expire immediately
        };

        let entry = TimerEntry {
            dcid,
            timer_type,
            scheduled_at: now,
        };

        if ticks_from_now < 256 {
            // Inner wheel
            let slot = (self.inner_pos + ticks_from_now as usize) % 256;
            self.inner_wheel[slot].push(entry);
        } else if ticks_from_now < 256 * 256 {
            // Outer wheel
            let outer_ticks = ticks_from_now / 256;
            let slot = (self.outer_pos + outer_ticks as usize) % 256;
            self.outer_wheel[slot].push(entry);
        } else {
            // Overflow - store with absolute expiration time
            self.overflow_timers.push_back((entry, expiration_time));
        }

        self.active_timers += 1;
    }

    /// Remove all timers for a specific connection
    ///
    /// # Arguments
    /// * `dcid` - The connection DCID to remove timers for
    ///
    /// # Returns
    /// Number of timers removed
    pub fn remove_connection_timers(&mut self, dcid: &[u8]) -> usize {
        let mut removed = 0;

        // Remove from inner wheel
        for slot in &mut self.inner_wheel {
            slot.retain(|entry| {
                if entry.dcid == dcid {
                    removed += 1;
                    false
                } else {
                    true
                }
            });
        }

        // Remove from outer wheel
        for slot in &mut self.outer_wheel {
            slot.retain(|entry| {
                if entry.dcid == dcid {
                    removed += 1;
                    false
                } else {
                    true
                }
            });
        }

        // Remove from overflow
        self.overflow_timers.retain(|(entry, _)| {
            if entry.dcid == dcid {
                removed += 1;
                false
            } else {
                true
            }
        });

        self.active_timers = self.active_timers.saturating_sub(removed);
        removed
    }

    /// Process expired timers and advance the wheel
    ///
    /// # Returns
    /// Vector of expired timer entries
    pub fn process_expired_timers(&mut self) -> Vec<TimerEntry> {
        self.process_expired_timers_at(Instant::now())
    }

    /// Process expired timers at a specific time (for testing)
    ///
    /// # Arguments
    /// * `current_time` - The current time to use for expiration checks
    ///
    /// # Returns
    /// Vector of expired timer entries
    pub fn process_expired_timers_at(&mut self, current_time: Instant) -> Vec<TimerEntry> {
        let mut expired = Vec::new();
        let now = current_time;

        // Calculate how many ticks have elapsed since last processing
        let elapsed = now.duration_since(self.base_time);
        let ticks_elapsed = (elapsed.as_millis() as u64) / 50; // 50ms per tick

        if ticks_elapsed == 0 {
            // Not enough time has passed for any ticks
            // Still check overflow timers
            while let Some((_entry, expiration)) = self.overflow_timers.front() {
                if *expiration <= now {
                    let entry = self.overflow_timers.pop_front().unwrap().0;
                    expired.push(entry);
                } else {
                    break;
                }
            }
            self.active_timers = self.active_timers.saturating_sub(expired.len());
            return expired;
        }

        // Advance the wheel by the number of ticks that have elapsed
        for _ in 0..ticks_elapsed.min(256 * 256) {
            // Prevent infinite loops
            // Process current inner wheel slot
            expired.extend(self.inner_wheel[self.inner_pos].drain(..));

            // Check if we need to advance outer wheel
            if self.inner_pos == 0 {
                // Process current outer wheel slot
                expired.extend(self.outer_wheel[self.outer_pos].drain(..));

                // Advance outer wheel
                self.outer_pos = (self.outer_pos + 1) % 256;
            }

            // Advance inner wheel
            self.inner_pos = (self.inner_pos + 1) % 256;
        }

        // Update base time for next processing
        self.base_time = now;

        // Process overflow timers
        while let Some((_entry, expiration)) = self.overflow_timers.front() {
            if *expiration <= now {
                let entry = self.overflow_timers.pop_front().unwrap().0;
                expired.push(entry);
            } else {
                break;
            }
        }

        // Update active timer count
        self.active_timers = self.active_timers.saturating_sub(expired.len());

        expired
    }

    /// Get the number of active timers
    pub fn active_timer_count(&self) -> usize {
        self.active_timers
    }

    /// Get wheel statistics for monitoring
    pub fn stats(&self) -> TimerWheelStats {
        let mut inner_slots_used = 0;
        let mut outer_slots_used = 0;
        let mut max_inner_slot = 0;
        let mut max_outer_slot = 0;

        for (_i, slot) in self.inner_wheel.iter().enumerate() {
            if !slot.is_empty() {
                inner_slots_used += 1;
                max_inner_slot = max_inner_slot.max(slot.len());
            }
        }

        for (_i, slot) in self.outer_wheel.iter().enumerate() {
            if !slot.is_empty() {
                outer_slots_used += 1;
                max_outer_slot = max_outer_slot.max(slot.len());
            }
        }

        TimerWheelStats {
            active_timers: self.active_timers,
            inner_slots_used,
            outer_slots_used,
            max_inner_slot,
            max_outer_slot,
            overflow_count: self.overflow_timers.len(),
            inner_pos: self.inner_pos,
            outer_pos: self.outer_pos,
        }
    }
}

/// Statistics for monitoring timer wheel performance
#[derive(Debug, Clone)]
pub struct TimerWheelStats {
    /// Total active timers
    pub active_timers: usize,
    /// Number of inner wheel slots with timers
    pub inner_slots_used: usize,
    /// Number of outer wheel slots with timers
    pub outer_slots_used: usize,
    /// Maximum timers in any inner slot
    pub max_inner_slot: usize,
    /// Maximum timers in any outer slot
    pub max_outer_slot: usize,
    /// Number of overflow timers
    pub overflow_count: usize,
    /// Current inner wheel position
    pub inner_pos: usize,
    /// Current outer wheel position
    pub outer_pos: usize,
}

impl Default for TimerWheel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_timer_wheel_basic() {
        let mut wheel = TimerWheel::new();

        // Add a timer that expires in 100ms
        wheel.add_timer(vec![1], TimerType::IdleTimeout, Duration::from_millis(100));

        assert_eq!(wheel.active_timer_count(), 1);

        // Process timers (should not expire yet)
        let expired = wheel.process_expired_timers();
        assert_eq!(expired.len(), 0);
        assert_eq!(wheel.active_timer_count(), 1);

        // Wait for expiration
        thread::sleep(Duration::from_millis(150));

        // Process timers (should expire now)
        let expired = wheel.process_expired_timers();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].dcid, vec![1]);
        assert_eq!(wheel.active_timer_count(), 0);
    }

    #[test]
    fn test_timer_wheel_remove_connection() {
        let mut wheel = TimerWheel::new();

        wheel.add_timer(vec![1], TimerType::IdleTimeout, Duration::from_secs(1));
        wheel.add_timer(vec![1], TimerType::PathPto, Duration::from_secs(2));
        wheel.add_timer(vec![2], TimerType::IdleTimeout, Duration::from_secs(1));

        assert_eq!(wheel.active_timer_count(), 3);

        let removed = wheel.remove_connection_timers(&[1]);
        assert_eq!(removed, 2);
        assert_eq!(wheel.active_timer_count(), 1);
    }

    #[test]
    fn test_timer_wheel_overflow() {
        let mut wheel = TimerWheel::new();

        // Add a timer that exceeds wheel capacity (> 54 minutes)
        // 256 * 256 * 50ms = 3276800ms = 3276.8 seconds = ~54.6 minutes
        wheel.add_timer(vec![1], TimerType::IdleTimeout, Duration::from_secs(3300)); // 55 minutes

        assert_eq!(wheel.active_timer_count(), 1);

        // Check that it's in overflow
        assert_eq!(wheel.overflow_timers.len(), 1);

        // Process timers at a time far in the future - should expire
        let future_time = Instant::now() + Duration::from_secs(3301);
        let expired = wheel.process_expired_timers_at(future_time);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].dcid, vec![1]);
        assert_eq!(wheel.active_timer_count(), 0);
        assert_eq!(wheel.overflow_timers.len(), 0);
    }
}
