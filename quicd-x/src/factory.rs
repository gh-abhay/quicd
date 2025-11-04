use std::future::Future;

use async_trait::async_trait;
use futures_core::Stream;

use crate::{AppEvent, ConnectionError, ConnectionHandle, TransportControls};

/// Trait implemented by pluggable QUIC applications.
#[async_trait]
pub trait QuicAppFactory: Send + Sync + 'static {
    /// Returns true when this factory can serve the supplied ALPN.
    fn accepts_alpn(&self, alpn: &str) -> bool;

    /// Spawns the application task(s) for a connection.
    async fn spawn_app<S, F>(
        &self,
        alpn: String,
        handle: ConnectionHandle,
        events: S,
        transport: TransportControls,
        shutdown: F,
    ) -> Result<(), ConnectionError>
    where
        S: Stream<Item = AppEvent> + Unpin + Send + 'static,
        F: Future<Output = ()> + Send + 'static;
}
