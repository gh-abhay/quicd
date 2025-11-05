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
//! - **Datagrams**: `AppEvent::Datagram` for unreliable packets
//! - **Command Responses**: `AppEvent::StreamOpened`, `AppEvent::DatagramSent`, etc.
//!
//! ### Data Flow (Egress: App → Server)
//! - **Stream Operations**: Via `ConnectionHandle::open_bi()`, `open_uni()`
//! - **Stream Writes**: Via `SendStream::write()` (zero-copy `Bytes`)
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
//!         _shutdown: quicd_x::ShutdownFuture,
//!     ) -> Result<(), quicd_x::ConnectionError> {
//!         while let Some(event) = events.next().await {
//!             match event {
//!                 AppEvent::HandshakeCompleted { .. } => {
//!                     // Connection established
//!                 }
//!                 AppEvent::NewStream { stream_id, mut recv_stream, send_stream, .. } => {
//!                     if let Some(send) = send_stream {
//!                         // Handle bidirectional stream
//!                         while let Ok(Some(StreamData::Data(data))) = recv_stream.read().await {
//!                             send.write(data, false).await?;
//!                         }
//!                     }
//!                 }
//!                 AppEvent::ConnectionClosing { .. } => break,
//!                 _ => {}
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

pub use crate::error::ConnectionError;
pub use crate::events::{AppEvent, TransportEvent};
pub use crate::factory::{AppEventStream, QuicAppFactory, ShutdownFuture};
pub use crate::handle::{
    ConnectionHandle, ConnectionId, ConnectionStats, RecvStream, SendStream, StreamData, StreamId,
    TransportControls,
};
pub use crate::server::{
    new_connection_handle, new_recv_stream, new_send_stream, EgressCommand, StreamWriteCmd,
};
