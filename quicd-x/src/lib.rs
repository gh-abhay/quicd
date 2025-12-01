//! Common interfaces shared between the `quicd` core and pluggable QUIC applications.
//!
//! # Architecture
//!
//! This crate defines the contract between the QUIC server core (`quicd`) and pluggable
//! applications (like HTTP/3, MOQ, DOQ, etc.) that run on top of it.
//!
//! ## Design Philosophy
//!
//! ### Event-Driven, Non-Blocking
//! The entire interface is designed around async events and channels to ensure:
//! - **Worker threads NEVER block** on application tasks
//! - **Zero-copy data transfer** using `bytes::Bytes`
//! - **Backpressure handling** via bounded channels
//! - **Fair resource allocation** across millions of connections
//!
//! ### Separation of Concerns
//! - **Worker threads** (sync): Handle network I/O, QUIC protocol, timeouts
//! - **App tasks** (async): Implement application logic on Tokio runtime
//! - **Channels**: Bidirectional communication without blocking
//!
//! ## Key Concepts
//!
//! ### Connection Lifecycle
//! - **Application Registration**: Apps implement `QuicAppFactory` and register via `ALPN`.
//! - **Connection Handshake**: Worker threads negotiate QUIC handshakes and determine ALPN.
//! - **App Task Spawning**: Once handshake completes, a single `Tokio` task is spawned per
//!   connection on a shared runtime, implementing the app's protocol logic.
//! - **Connection Cleanup**: App task ends when connection closes.
//!
//! ### Data Flow (Ingress: Server → App)
//! - **Connection Events**: `AppEvent::HandshakeCompleted`, `AppEvent::ConnectionClosing`
//! - **Stream Events**: `AppEvent::NewStream` when peer opens a stream
//! - **Stream Data**: Via `RecvStream::read()` (zero-copy `Bytes`)
//! - **Stream Readable**: `AppEvent::StreamReadable` for efficient backpressure signaling
//! - **Datagrams**: `AppEvent::Datagram` for unreliable packets
//! - **Command Responses**: `AppEvent::StreamOpened`, `AppEvent::DatagramSent`, etc.
//!
//! ### Data Flow (Egress: App → Server)
//! - **Stream Operations**: Via `ConnectionHandle::open_bi()`, `open_uni()`
//! - **Stream Writes**: Via `SendStream::write()` (zero-copy `Bytes`)
//! - **Fluent API**: Use `send_data().with_fin(true).send()` for ergonomic patterns
//! - **Datagrams**: Via `ConnectionHandle::send_datagram()`
//! - **Stream Control**: Via `ConnectionHandle::reset_stream()`, `close()`
//! - **Stats**: Via `ConnectionHandle::stats()`
//!
//! ## Event-Driven, Non-Blocking Design
//!
//! The entire interface is designed to be non-blocking and event-driven:
//! - **Worker Thread**: Never blocked by app tasks; handles ingress/egress for all connections
//! - **App Task**: Driven by events from `AppEventStream`; uses channels for all I/O
//! - **Channel Backpressure**: If ingress channel fills, worker will block (but other connections unaffected)
//! - **Zero-Copy**: Uses `bytes::Bytes` throughout to avoid unnecessary allocations
//!
//! ## API Refinements (v0.2)
//!
//! ### Backpressure Signaling
//! - **`AppEvent::StreamReadable`**: Edge-triggered notification when buffered data is available
//! - Helps apps implement efficient polling without constant `read()` calls
//! - Enables better flow control and resource management
//!
//! ### Ergonomic Builders
//! - **`SendStream::send_data()`**: Fluent builder for HTTP/3 patterns
//! - Example: `send_stream.send_data(body).with_fin(true).send().await`
//! - Keeps the API ergonomic without added complexity
//!
//! ### Enhanced Error Handling
//! - **`ConnectionError::QuicError`**: RFC 9000 compliant error codes
//! - **`ConnectionError::TlsFail`**: Specific TLS handshake failures
//! - Better error propagation for protocol-aware applications
//!
//! ### Graceful Shutdown
//! - **30-second timeout**: Apps have grace period after `ConnectionClosing`
//! - **`ShutdownFuture`**: Global shutdown signal independent of connection events
//! - Prevents zombie tasks and ensures clean resource cleanup
//!
//! # Example
//!
//! ```rust,no_run
//! use quicd_x::{QuicAppFactory, AppEvent, ConnectionHandle, StreamData};
//! use async_trait::async_trait;
//! use futures::StreamExt;
//!
//! struct MyAppFactory;
//!
//! #[async_trait]
//! impl QuicAppFactory for MyAppFactory {
//!     fn accepts_alpn(&self, alpn: &str) -> bool {
//!         alpn == "myapp"
//!     }
//!
//!     async fn spawn_app(
//!         &self,
//!         alpn: String,
//!         handle: ConnectionHandle,
//!         mut events: quicd_x::AppEventStream,
//!         _transport: quicd_x::TransportControls,
//!         mut shutdown: quicd_x::ShutdownFuture,
//!     ) -> Result<(), quicd_x::ConnectionError> {
//!         loop {
//!             tokio::select! {
//!                 Some(event) = events.next() => {
//!                     match event {
//!                         AppEvent::HandshakeCompleted { .. } => {
//!                             // Connection established
//!                         }
//!                         AppEvent::NewStream { stream_id, mut recv_stream, send_stream, .. } => {
//!                             if let Some(send) = send_stream {
//!                                 // Echo using fluent API
//!                                 while let Ok(Some(StreamData::Data(data))) = recv_stream.read().await {
//!                                     send.send_data(data).with_fin(false).send().await?;
//!                                 }
//!                                 send.finish().await?;
//!                             }
//!                         }
//!                         AppEvent::StreamReadable { stream_id } => {
//!                             // Stream has buffered data - can read without blocking
//!                         }
//!                         AppEvent::ConnectionClosing { .. } => {
//!                             // Graceful cleanup
//!                             break;
//!                         }
//!                         _ => {}
//!                     }
//!                 }
//!                 _ = &mut shutdown => {
//!                     // Global shutdown - cleanup and exit
//!                     break;
//!                 }
//!             }
//!         }
//!         Ok(())
//!     }
//! }
//! ```

mod error;
mod events;
mod factory;
mod handle;
mod server;

pub mod config;
pub mod system_resources;

pub use crate::config::QuicAppConfig;
pub use crate::config::QuicTransportConfig;
pub use crate::config::{CongestionControl, DEFAULT_MAX_IDLE_TIMEOUT_MS, DEFAULT_INITIAL_RTT_MS, DEFAULT_MAX_STREAMS_BIDI, DEFAULT_MAX_STREAMS_UNI, DEFAULT_MAX_UDP_PAYLOAD_SIZE, DEFAULT_RECV_WINDOW, DEFAULT_STREAM_RECV_WINDOW, DEFAULT_MAX_CONNECTIONS_PER_WORKER};
pub use crate::error::ConnectionError;
pub use crate::events::{AppEvent, TransportEvent};
pub use crate::factory::{AppEventStream, QuicAppFactory, ShutdownFuture};
pub use crate::handle::{
    ConnectionHandle, ConnectionId, ConnectionStats, RecvStream, SendDataBuilder, SendStream,
    StreamData, StreamId, TransportControls,
};
pub use crate::server::{
    new_connection_handle, new_recv_stream, new_send_stream, ConnectionState, EgressCommand,
    StreamWriteCmd,
};

/// Macro to export a QUIC application factory from a dynamic library.
///
/// This macro generates the necessary C-ABI entry point for the `quicd` server
/// to load and instantiate the application factory.
///
/// # Requirements
///
/// - The factory type must implement `Default`
/// - The factory type must implement `QuicAppFactory`
/// - The library must be compiled as a `cdylib` (set in Cargo.toml)
/// - The `quicd-x` version must match the server's version
///
/// # Example
///
/// ```rust
/// use quicd_x::{QuicAppFactory, export_quic_app};
/// use async_trait::async_trait;
///
/// #[derive(Default)]
/// struct MyAppFactory;
///
/// #[async_trait]
/// impl QuicAppFactory for MyAppFactory {
///     fn accepts_alpn(&self, alpn: &str) -> bool {
///         alpn == "my-proto"
///     }
///     // ... implement other required methods
/// }
///
/// export_quic_app!(MyAppFactory);
/// ```
///
/// # Cargo.toml Configuration
///
/// ```toml
/// [lib]
/// crate-type = ["cdylib"]
///
/// [dependencies]
/// quicd-x = "0.1"  # Must match server version
/// ```
#[macro_export]
macro_rules! export_quic_app {
    ($factory_type:ty) => {
        #[no_mangle]
        pub extern "C" fn _quicd_create_factory() -> *mut std::ffi::c_void {
            let factory: Box<dyn $crate::QuicAppFactory> = Box::new(<$factory_type>::default());
            // Double-box to convert fat pointer (trait object) to thin pointer
            let wrapper: Box<Box<dyn $crate::QuicAppFactory>> = Box::new(factory);
            Box::into_raw(wrapper) as *mut std::ffi::c_void
        }
    };
}

