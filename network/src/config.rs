//! Network configuration

use serde::{Deserialize, Serialize};

/// Thread priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThreadPriority {
    /// Low priority (nice +10)
    Low,
    /// Normal priority (default)
    Normal,
    /// High priority (SCHED_RR if available)
    High,
    /// Maximum priority (SCHED_FIFO, requires CAP_SYS_NICE)
    Max,
}

impl Default for ThreadPriority {
    fn default() -> Self {
        Self::Normal
    }
}

/// CPU affinity strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CpuAffinityStrategy {
    /// No pinning, let OS scheduler decide
    Auto,
    /// Interleaved: I/O on even cores (0,2,4), QUIC on odd cores (1,3,5)
    Interleaved,
    /// Sequential: I/O on first N cores, QUIC on next N cores
    Sequential,
}

impl Default for CpuAffinityStrategy {
    fn default() -> Self {
        Self::Interleaved
    }
}

/// Network I/O layer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Number of dedicated network I/O threads
    pub threads: usize,

    /// Enable CPU pinning for network I/O threads
    pub enable_cpu_pinning: bool,

    /// Enable NUMA-aware thread placement
    pub enable_numa_awareness: bool,

    /// Thread priority
    pub thread_priority: ThreadPriority,

    /// CPU affinity strategy
    pub cpu_affinity_strategy: CpuAffinityStrategy,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self::auto_detect()
    }
}

impl NetworkConfig {
    /// Create configuration with auto-detected settings
    pub fn auto_detect() -> Self {
        let cpu_count = num_cpus::get();
        let threads = Self::calculate_threads(cpu_count);

        Self {
            threads,
            enable_cpu_pinning: true,
            enable_numa_awareness: true,
            thread_priority: ThreadPriority::Normal,
            cpu_affinity_strategy: CpuAffinityStrategy::Interleaved,
        }
    }

    /// Calculate optimal thread count based on CPU count
    ///
    /// Formula: `min(max(cpu_count / 4, 1), 8)`
    fn calculate_threads(cpu_count: usize) -> usize {
        match cpu_count {
            1 => 1,
            2..=4 => 1,
            5..=8 => 2,
            9..=16 => 4,
            17..=32 => 8,
            _ => 8, // Cap at 8 threads
        }
    }
}
