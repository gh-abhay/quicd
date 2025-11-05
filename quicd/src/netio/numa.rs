//! NUMA (Non-Uniform Memory Access) awareness for buffer allocation.
//!
//! On multi-socket servers, memory access latency depends on which NUMA node
//! the memory is allocated from:
//! - Local memory (same socket as CPU): ~100ns latency
//! - Remote memory (different socket): ~200-300ns latency
//!
//! This module provides NUMA-aware buffer allocation by:
//! 1. Detecting which NUMA node the worker thread runs on
//! 2. Using memory policy to prefer local allocations
//! 3. Falling back gracefully on non-NUMA systems
//!
//! # Architecture
//!
//! - Called once per worker during initialization
//! - Sets memory policy for the current thread
//! - All subsequent allocations prefer local NUMA node
//! - Zero overhead after initialization (policy is per-thread)
//!
//! # Linux Syscalls Used
//!
//! - `get_mempolicy()`: Query current NUMA node
//! - `set_mempolicy()`: Set NUMA allocation policy (MPOL_PREFERRED)
//! - Falls back to standard allocation if syscalls fail or NUMA not available

use std::io;
use tracing::{debug, info, warn};

/// NUMA memory policy modes (from linux/mempolicy.h)
#[allow(dead_code)]
mod mpol {
    pub const MPOL_DEFAULT: i32 = 0;     // Default policy
    pub const MPOL_PREFERRED: i32 = 1;   // Prefer specific node, fall back allowed
    pub const MPOL_BIND: i32 = 2;        // Strict binding to nodes
    pub const MPOL_INTERLEAVE: i32 = 3;  // Interleave across nodes
    pub const MPOL_LOCAL: i32 = 4;       // Prefer local node
}

/// Maximum number of NUMA nodes supported (typical servers have 2-8)
const MAX_NUMA_NODES: usize = 64;

/// Check if NUMA is available on this system.
///
/// Returns true if the system has multiple NUMA nodes, false otherwise.
/// On non-NUMA systems (single socket), this returns false.
fn is_numa_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        // Check /sys/devices/system/node to see if NUMA nodes exist
        if let Ok(entries) = std::fs::read_dir("/sys/devices/system/node") {
            let node_count = entries
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.file_name()
                        .to_str()
                        .map(|s| s.starts_with("node"))
                        .unwrap_or(false)
                })
                .count();
            return node_count > 1;
        }
    }
    false
}

/// Get the NUMA node ID for the current CPU.
///
/// Returns the NUMA node that the current thread is running on.
/// Returns None if NUMA is not available or detection fails.
#[cfg(target_os = "linux")]
fn get_current_numa_node() -> Option<u32> {
    use std::mem::MaybeUninit;
    
    // Use getcpu() syscall to get current CPU and NUMA node
    // This is faster than reading /proc or /sys
    let mut cpu: u32 = 0;
    let mut node: u32 = 0;
    
    unsafe {
        // syscall(__NR_getcpu, &cpu, &node, NULL)
        // getcpu returns current CPU and NUMA node
        let ret = libc::syscall(
            libc::SYS_getcpu,
            &mut cpu as *mut u32,
            &mut node as *mut u32,
            std::ptr::null_mut::<libc::c_void>(),
        );
        
        if ret == 0 {
            Some(node)
        } else {
            None
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn get_current_numa_node() -> Option<u32> {
    None
}

/// Set NUMA memory policy to prefer the specified node.
///
/// This affects all future memory allocations in the current thread.
/// Uses MPOL_PREFERRED policy which prefers the specified node but
/// allows fallback to other nodes if necessary.
///
/// # Arguments
///
/// * `node` - NUMA node ID to prefer for allocations
///
/// # Returns
///
/// Ok(()) if policy was set successfully, Err otherwise.
#[cfg(target_os = "linux")]
fn set_numa_preferred_node(node: u32) -> io::Result<()> {
    if node >= MAX_NUMA_NODES as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("NUMA node {} exceeds maximum {}", node, MAX_NUMA_NODES),
        ));
    }

    // Create node mask with only the preferred node set
    let mut nodemask: [libc::c_ulong; (MAX_NUMA_NODES + 63) / 64] = [0; (MAX_NUMA_NODES + 63) / 64];
    let word_idx = (node as usize) / 64;
    let bit_idx = (node as usize) % 64;
    nodemask[word_idx] = 1u64 << bit_idx;

    unsafe {
        // set_mempolicy(MPOL_PREFERRED, &nodemask, maxnode)
        let ret = libc::syscall(
            libc::SYS_set_mempolicy,
            mpol::MPOL_PREFERRED,
            nodemask.as_ptr(),
            MAX_NUMA_NODES,
        );

        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn set_numa_preferred_node(_node: u32) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "NUMA not supported on this platform",
    ))
}

/// Configure NUMA-aware allocation for the current worker thread.
///
/// This should be called once during worker initialization, after
/// CPU affinity has been set. It will:
///
/// 1. Check if NUMA is available on the system
/// 2. Detect which NUMA node the thread is running on
/// 3. Set memory policy to prefer local NUMA node
/// 4. Log the configuration for debugging
///
/// If NUMA is not available or any step fails, this function logs
/// a warning and returns without error. The system will fall back
/// to standard allocation.
///
/// # Arguments
///
/// * `worker_id` - Worker ID for logging purposes
///
/// # Returns
///
/// Ok(()) if NUMA was configured successfully (or not needed)
/// Returns without error even if NUMA setup fails (graceful fallback)
pub fn configure_numa_for_worker(worker_id: usize) -> io::Result<()> {
    // Check if NUMA is available
    if !is_numa_available() {
        debug!(
            worker_id,
            "NUMA not available on this system (single socket or NUMA disabled)"
        );
        return Ok(());
    }

    // Get current NUMA node
    let node = match get_current_numa_node() {
        Some(n) => n,
        None => {
            warn!(
                worker_id,
                "Failed to detect current NUMA node, using default allocation policy"
            );
            return Ok(());
        }
    };

    // Set NUMA policy to prefer local node
    match set_numa_preferred_node(node) {
        Ok(()) => {
            info!(
                worker_id,
                numa_node = node,
                "NUMA-aware allocation configured (prefer local node)"
            );
            Ok(())
        }
        Err(e) => {
            warn!(
                worker_id,
                numa_node = node,
                error = ?e,
                "Failed to set NUMA memory policy, using default allocation"
            );
            Ok(()) // Return Ok to not fail worker initialization
        }
    }
}

/// Reset NUMA memory policy to system default.
///
/// This should be called during worker shutdown to restore default policy.
/// Useful for cleanup, though not strictly necessary since the thread will exit.
#[allow(dead_code)]
pub fn reset_numa_policy() -> io::Result<()> {
    #[cfg(target_os = "linux")]
    unsafe {
        let ret = libc::syscall(
            libc::SYS_set_mempolicy,
            mpol::MPOL_DEFAULT,
            std::ptr::null::<libc::c_ulong>(),
            0,
        );

        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(not(target_os = "linux"))]
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_numa_detection() {
        // Just check that it doesn't panic
        let available = is_numa_available();
        println!("NUMA available: {}", available);
    }

    #[test]
    fn test_get_numa_node() {
        // Just check that it doesn't panic
        if let Some(node) = get_current_numa_node() {
            println!("Current NUMA node: {}", node);
        } else {
            println!("Could not detect NUMA node");
        }
    }
}
