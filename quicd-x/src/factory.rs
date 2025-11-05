use std::future::Future;
use std::pin::Pin;

use async_trait::async_trait;

use crate::{AppEvent, ConnectionError, ConnectionHandle, TransportControls};

/// Boxed stream of application events.
pub type AppEventStream = Pin<Box<dyn futures_core::Stream<Item = AppEvent> + Send + 'static>>;

/// Boxed future for shutdown signal.
pub type ShutdownFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Trait implemented by pluggable QUIC applications.
#[async_trait]
pub trait QuicAppFactory: Send + Sync + 'static {
    /// Returns true when this factory can serve the supplied ALPN.
    fn accepts_alpn(&self, alpn: &str) -> bool;

    /// Spawns the application task(s) for a connection.
    async fn spawn_app(
        &self,
        alpn: String,
        handle: ConnectionHandle,
        events: AppEventStream,
        transport: TransportControls,
        shutdown: ShutdownFuture,
    ) -> Result<(), ConnectionError>;
}
