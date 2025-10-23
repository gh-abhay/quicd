/// CPU affinity utilities for optimal thread pinning
/// Implements interleaved pinning strategy for network and protocol layers

use core_affinity::CoreId;
use tracing::{info, warn};

/// CPU pinning strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinningStrategy {
    /// No CPU pinning
    None,
    /// Sequential pinning (0, 1, 2, 3, ...)
    Sequential,
    /// Interleaved pinning for network and protocol threads
    /// Network threads on even cores, protocol threads on odd cores
    Interleaved,
}

#[derive(Debug, Clone)]
pub struct CpuAffinityManager {
    core_ids: Vec<CoreId>,
    strategy: PinningStrategy,
}

impl CpuAffinityManager {
    pub fn new(strategy: PinningStrategy) -> Option<Self> {
        let core_ids = core_affinity::get_core_ids()?;
        
        info!(
            "CPU affinity manager initialized with {} cores, strategy: {:?}",
            core_ids.len(),
            strategy
        );
        
        Some(Self { core_ids, strategy })
    }

    /// Pin current thread to a CPU core based on thread type and index
    pub fn pin_thread(&self, thread_type: ThreadType, index: usize) -> bool {
        if self.strategy == PinningStrategy::None {
            return false;
        }

        let core_id = self.get_core_for_thread(thread_type, index);
        
        match core_id {
            Some(core) => {
                if core_affinity::set_for_current(core) {
                    info!(
                        "Thread {:?}[{}] pinned to core {:?}",
                        thread_type, index, core
                    );
                    true
                } else {
                    warn!(
                        "Failed to pin thread {:?}[{}] to core {:?}",
                        thread_type, index, core
                    );
                    false
                }
            }
            None => {
                warn!(
                    "No core available for thread {:?}[{}]",
                    thread_type, index
                );
                false
            }
        }
    }

    fn get_core_for_thread(&self, thread_type: ThreadType, index: usize) -> Option<CoreId> {
        match self.strategy {
            PinningStrategy::None => None,
            PinningStrategy::Sequential => {
                self.core_ids.get(index % self.core_ids.len()).copied()
            }
            PinningStrategy::Interleaved => {
                // Interleaved strategy:
                // Network threads: 0, 2, 4, 6, ...
                // Protocol threads: 1, 3, 5, 7, ...
                // App threads: Use remaining cores or share
                match thread_type {
                    ThreadType::Network => {
                        let core_index = index * 2;
                        self.core_ids.get(core_index % self.core_ids.len()).copied()
                    }
                    ThreadType::Protocol => {
                        let core_index = index * 2 + 1;
                        self.core_ids.get(core_index % self.core_ids.len()).copied()
                    }
                    ThreadType::Application => {
                        // App threads can use any remaining cores
                        // or share with network/protocol threads
                        self.core_ids.get(index % self.core_ids.len()).copied()
                    }
                }
            }
        }
    }

    pub fn num_cores(&self) -> usize {
        self.core_ids.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadType {
    Network,
    Protocol,
    Application,
}
