//! # Loss Detection and Congestion Control (RFC 9002)
//!
//! Modular architecture for pluggable congestion control algorithms.

pub mod congestion;
pub mod loss;
pub mod rtt;
pub mod traits;

pub use congestion::{CongestionController, CongestionControllerFactory, CongestionEvent};
pub use loss::{
    DefaultLossDetector, LossDetectionAction, LossDetectionConfig,
    PacketNumberSpaceLossState, SentPacketInfo, SentPacketTracker,
};
// Re-export the actual LossDetector trait from loss module
pub use loss::LossDetector;
pub use rtt::{RttEstimator, RttSample};
pub use traits::{PacketSentInfo, RecoveryState};


