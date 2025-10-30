//! Network I/O utilities module.
//!
//! This module provides pure network functionality:
//! - Buffer pool management for zero-copy operations
//! - Socket creation and configuration
//! - Network I/O configuration
//!
//! For worker thread orchestration, see the `worker` module.

pub mod buffer;
pub mod config;
pub(crate) mod socket;

pub use buffer::{create_worker_pool, WorkerBufPool, WorkerBuffer};
pub use config::NetIoConfig;
pub(crate) use socket::create_udp_socket;
