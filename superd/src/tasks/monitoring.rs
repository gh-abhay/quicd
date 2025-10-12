//! Monitoring tasks
//!
//! Background tasks for metrics logging and connection cleanup.

use std::sync::Arc;
use std::time::Duration;
use tokio::time;
use quic::QuicEngine;
use crate::{Metrics, Result};

/// Metrics logging task
///
/// Periodically logs performance statistics for monitoring.
pub async fn run_metrics_logging(
    metrics: Arc<Metrics>,
    interval: Duration,
) -> Result<()> {
    log::info!("Metrics logging task started (interval: {:?})", interval);
    
    let mut ticker = time::interval(interval);
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    
    loop {
        ticker.tick().await;
        metrics.log_stats();
    }
}

/// Connection cleanup task
///
/// Periodically removes closed connections to prevent memory leaks.
/// Essential for long-running production deployments.
pub async fn run_connection_cleanup(
    quic_engine: Arc<tokio::sync::Mutex<QuicEngine>>,
    interval: Duration,
) -> Result<()> {
    log::info!("Connection cleanup task started (interval: {:?})", interval);
    
    let mut ticker = time::interval(interval);
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    
    loop {
        ticker.tick().await;
        
        let mut engine = quic_engine.lock().await;
        let before = engine.active_connections();
        engine.cleanup_closed_connections();
        let after = engine.active_connections();
        
        if before != after {
            log::debug!("Cleaned up {} closed connections ({} -> {})", 
                before - after, before, after);
        }
    }
}
