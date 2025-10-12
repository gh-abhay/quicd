//! Task management module
//!
//! Provides structured, modular tasks for the daemon's operation.

pub mod network_io;
pub mod request_processing;
pub mod service_handling;
pub mod monitoring;

pub use network_io::NetworkIoTask;
pub use request_processing::RequestProcessingTask;
pub use service_handling::ServiceHandlingTask;
pub use monitoring::{run_metrics_logging, run_connection_cleanup};
