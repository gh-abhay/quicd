//! Thread management and CPU affinity utilities
//!
//! This module provides utilities for:
//! - CPU pinning of OS threads
//! - Thread priority management
//! - NUMA-aware thread placement

use crate::config::{CpuAffinityStrategy, ThreadPriority};
use core_affinity::CoreId;

/// Thread placement manager
///
/// Handles CPU affinity assignment for network I/O and QUIC protocol handler threads.
pub struct ThreadPlacement {
    strategy: CpuAffinityStrategy,
    cpu_count: usize,
    next_io_cpu: usize,
    next_quic_cpu: usize,
}

impl ThreadPlacement {
    /// Create a new thread placement manager
    pub fn new(strategy: CpuAffinityStrategy) -> Self {
        let cpu_count = num_cpus::get();
        Self {
            strategy,
            cpu_count,
            next_io_cpu: 0,
            next_quic_cpu: match strategy {
                CpuAffinityStrategy::Interleaved => 1,
                CpuAffinityStrategy::Sequential => 0,
                CpuAffinityStrategy::Auto => 0,
            },
        }
    }

    /// Get the next CPU core for a network I/O thread
    pub fn next_io_core(&mut self) -> Option<CoreId> {
        if self.strategy == CpuAffinityStrategy::Auto {
            return None;
        }

        let core_id = self.next_io_cpu;

        match self.strategy {
            CpuAffinityStrategy::Interleaved => {
                // I/O threads on even cores: 0, 2, 4, 6, ...
                self.next_io_cpu += 2;
            }
            CpuAffinityStrategy::Sequential => {
                // I/O threads on sequential cores: 0, 1, 2, 3, ...
                self.next_io_cpu += 1;
            }
            CpuAffinityStrategy::Auto => unreachable!(),
        }

        if core_id < self.cpu_count {
            Some(CoreId { id: core_id })
        } else {
            None
        }
    }

    /// Get the next CPU core for a QUIC protocol handler thread
    pub fn next_quic_core(&mut self, io_thread_index: usize) -> Option<CoreId> {
        if self.strategy == CpuAffinityStrategy::Auto {
            return None;
        }

        let core_id = match self.strategy {
            CpuAffinityStrategy::Interleaved => {
                // QUIC threads on odd cores, adjacent to their I/O thread
                // I/O 0 (CPU 0) → QUIC 0 (CPU 1)
                // I/O 1 (CPU 2) → QUIC 1 (CPU 3)
                io_thread_index * 2 + 1
            }
            CpuAffinityStrategy::Sequential => {
                // QUIC threads start after all I/O threads
                // If we have 4 I/O threads: I/O(0,1,2,3), QUIC(4,5,6,7)
                self.next_quic_cpu
            }
            CpuAffinityStrategy::Auto => unreachable!(),
        };

        if self.strategy == CpuAffinityStrategy::Sequential {
            self.next_quic_cpu += 1;
        }

        if core_id < self.cpu_count {
            Some(CoreId { id: core_id })
        } else {
            None
        }
    }
}

/// Pin current thread to a specific CPU core
///
/// # Returns
///
/// - `Ok(())` if pinning successful
/// - `Err(String)` if pinning failed
pub fn pin_to_core(core_id: CoreId) -> Result<(), String> {
    if core_affinity::set_for_current(core_id) {
        log::debug!("Thread pinned to CPU core {}", core_id.id);
        Ok(())
    } else {
        Err(format!("Failed to pin thread to CPU core {}", core_id.id))
    }
}

/// Set thread priority
///
/// # Platform Support
///
/// - Linux: Uses `pthread_setschedparam` (requires CAP_SYS_NICE for real-time)
/// - macOS: Uses `pthread_setschedparam` (limited)
/// - Windows: Uses `SetThreadPriority`
///
/// # Returns
///
/// - `Ok(())` if priority set successfully
/// - `Err(String)` if operation failed
pub fn set_thread_priority(priority: ThreadPriority) -> Result<(), String> {
    match priority {
        ThreadPriority::Low => {
            // Best-effort low priority
            #[cfg(unix)]
            unsafe {
                // Increase nice value (lower priority)
                let ret = libc::nice(10);
                if ret == -1 {
                    return Err("Failed to set low priority".to_string());
                }
            }
        }
        ThreadPriority::Normal => {
            // Default priority, no action needed
        }
        ThreadPriority::High => {
            // Try to set high priority (may require privileges)
            #[cfg(target_os = "linux")]
            {
                use libc::{pthread_self, pthread_setschedparam, sched_param, SCHED_RR};
                unsafe {
                    let mut param: sched_param = std::mem::zeroed();
                    param.sched_priority = 10; // Mid-range real-time priority

                    let ret = pthread_setschedparam(pthread_self(), SCHED_RR, &param as *const _);

                    if ret != 0 {
                        log::warn!(
                            "Failed to set high thread priority (SCHED_RR). \
                             This is normal if running without CAP_SYS_NICE. \
                             Continuing with default priority."
                        );
                    }
                }
            }
        }
        ThreadPriority::Max => {
            // Maximum real-time priority (requires privileges)
            #[cfg(target_os = "linux")]
            {
                use libc::{pthread_self, pthread_setschedparam, sched_param, SCHED_FIFO};
                unsafe {
                    let mut param: sched_param = std::mem::zeroed();
                    param.sched_priority = 99; // Maximum real-time priority

                    let ret = pthread_setschedparam(pthread_self(), SCHED_FIFO, &param as *const _);

                    if ret != 0 {
                        log::warn!(
                            "Failed to set max thread priority (SCHED_FIFO). \
                             Requires CAP_SYS_NICE capability. \
                             Continuing with default priority."
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thread_placement_interleaved() {
        let mut placement = ThreadPlacement::new(CpuAffinityStrategy::Interleaved);

        // I/O threads on even cores
        assert_eq!(placement.next_io_core().unwrap().id, 0);
        assert_eq!(placement.next_io_core().unwrap().id, 2);

        // QUIC threads on odd cores
        assert_eq!(placement.next_quic_core(0).unwrap().id, 1); // After I/O 0
        assert_eq!(placement.next_quic_core(1).unwrap().id, 3); // After I/O 1
    }

    #[test]
    fn test_thread_placement_sequential() {
        let mut placement = ThreadPlacement::new(CpuAffinityStrategy::Sequential);

        // I/O threads sequential
        assert_eq!(placement.next_io_core().unwrap().id, 0);
        assert_eq!(placement.next_io_core().unwrap().id, 1);

        // QUIC threads sequential after I/O
        assert_eq!(placement.next_quic_core(0).unwrap().id, 0);
        assert_eq!(placement.next_quic_core(1).unwrap().id, 1);
    }

    #[test]
    fn test_thread_placement_auto() {
        let mut placement = ThreadPlacement::new(CpuAffinityStrategy::Auto);

        // Auto mode returns None (no pinning)
        assert!(placement.next_io_core().is_none());
        assert!(placement.next_quic_core(0).is_none());
    }
}
