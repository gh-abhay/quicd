use std::future::Future;
use std::pin::Pin;

use async_trait::async_trait;

use crate::{AppEvent, ConnectionError, ConnectionHandle, TransportControls};

/// Boxed stream of application events.
pub type AppEventStream = Pin<Box<dyn futures_core::Stream<Item = AppEvent> + Send + 'static>>;

/// Boxed future for shutdown signal.
///
/// This future completes when:
/// - The connection is closing (ConnectionClosing event received)
/// - A global shutdown was initiated
/// - A timeout is reached (typically 30 seconds)
///
/// Applications should monitor this future and gracefully wind down when it completes.
/// The shutdown signal provides a grace period for cleanup before the connection is
/// forcefully closed.
///
/// # Timeout Behavior
///
/// If the application does not complete within the timeout after the shutdown future
/// resolves, the worker may forcefully terminate the connection. Applications should:
/// - Listen for ConnectionClosing events
/// - Monitor the shutdown future
/// - Complete cleanup within a reasonable time (< 30s recommended)
pub type ShutdownFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Trait implemented by pluggable QUIC applications.
///
/// # Shutdown Handling
///
/// Applications must handle graceful shutdown properly:
///
/// 1. **Listen for ConnectionClosing**: When this event arrives, the connection
///    is terminating. The app should stop sending new data and prepare to exit.
///
/// 2. **Monitor shutdown future**: The `shutdown` parameter will complete when
///    a graceful shutdown is initiated. This provides a signal independent of
///    connection events.
///
/// 3. **Cleanup timeout**: Applications have up to 30 seconds (configurable)
///    after ConnectionClosing to complete cleanup. After this timeout, the
///    worker may forcefully close the connection.
///
/// # Example Shutdown Pattern
///
/// ```rust,ignore
/// use tokio::select;
///
/// async fn spawn_app(
///     // ... parameters
///     mut events: AppEventStream,
///     shutdown: ShutdownFuture,
/// ) -> Result<(), ConnectionError> {
///     loop {
///         select! {
///             Some(event) = events.next() => {
///                 match event {
///                     AppEvent::ConnectionClosing { .. } => {
///                         // Graceful cleanup: flush buffers, save state, etc.
///                         cleanup().await;
///                         break;
///                     }
///                     _ => { /* handle other events */ }
///                 }
///             }
///             _ = &mut shutdown => {
///                 // Global shutdown initiated
///                 cleanup().await;
///                 break;
///             }
///         }
///     }
///     Ok(())
/// }
/// ```
#[async_trait]
pub trait QuicAppFactory: Send + Sync + 'static {
    /// Returns true when this factory can serve the supplied ALPN.
    fn accepts_alpn(&self, alpn: &str) -> bool;

    /// Spawns the application task(s) for a connection.
    ///
    /// # Parameters
    ///
    /// - `alpn`: The negotiated ALPN string (e.g., "h3", "h3-29")
    /// - `handle`: Connection handle for sending operations
    /// - `events`: Stream of events from the worker (connection lifecycle, streams, etc.)
    /// - `transport`: Transport configuration (e.g., datagram support)
    /// - `shutdown`: Future that completes when graceful shutdown should begin
    ///
    /// # Shutdown Contract
    ///
    /// When `shutdown` completes or `ConnectionClosing` event arrives:
    /// - Stop accepting new work
    /// - Flush any pending writes
    /// - Clean up resources
    /// - Return from this function within 30 seconds
    ///
    /// Failure to complete within the timeout may result in forceful termination.
    async fn spawn_app(
        &self,
        alpn: String,
        handle: ConnectionHandle,
        events: AppEventStream,
        transport: TransportControls,
        shutdown: ShutdownFuture,
    ) -> Result<(), ConnectionError>;
}
