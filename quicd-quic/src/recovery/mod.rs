//! # Loss Detection and Congestion Control (RFC 9002)
//!
//! Modular architecture for pluggable congestion control algorithms.

pub mod congestion;
pub mod rtt;
pub mod traits;

pub use congestion::{CongestionController, CongestionControllerFactory, CongestionEvent};
pub use rtt::{RttEstimator, RttSample};
pub use traits::{LossDetector, PacketSentInfo, RecoveryState};
