//! Network I/O utilities module.
//!
//! This module provides pure network functionality:
//! - Buffer pool management for zero-copy operations
//! - Socket creation and configuration
//! - Network I/O configuration
//! - NUMA-aware memory allocation
//!
//! For worker thread orchestration, see the `worker` module.

pub mod buffer;
pub mod config;
pub mod numa;
pub(crate) mod socket;

#[cfg(test)]
mod tests;

#[allow(unused_imports)]
pub use buffer::{create_worker_pool, ConsumeBuffer, Reuse, WorkerBufPool, WorkerBuffer};
pub use config::NetIoConfig;
pub use numa::configure_numa_for_worker;
#[allow(unused_imports)]
pub(crate) use socket::create_udp_socket;
