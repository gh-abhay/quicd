//! HTTP/3 implementation for quicd server.
//!
//! This crate provides an HTTP/3 application that runs on top of the quicd QUIC server.
//! It implements the H3ServerSession trait and related types for building HTTP/3 applications.

mod quic_impl;
mod session;

pub use session::{H3Factory, H3Session, DefaultH3HandlerFactory};

use std::pin::Pin;
use std::sync::Arc;
use async_trait::async_trait;
use bytes::Bytes;
use futures::Stream;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri};
use quicd_x::{StreamId, TransportEvent};

/// HTTP/3-specific errors.
#[derive(Debug, thiserror::Error)]
pub enum H3Error {
    #[error("Frame unexpected in stream phase")]
    PhaseError,
    #[error("QPACK decode failure")]
    CompressionError,
    #[error("QUIC transport: {0}")]
    Transport(#[from] quicd_x::ConnectionError),
    #[error("HTTP/3 protocol error: {0}")]
    Protocol(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Events from the H3 session to the app.
pub enum H3Event {
    /// Incoming request: Headers + optional body stream.
    Request {
        req: Request<()>,
        #[allow(dead_code)] // TODO: implement
        body: Pin<Box<dyn Stream<Item = Result<Bytes, H3Error>> + Send>>,
        stream_id: StreamId,
        /// Channel to send the response back
        response_tx: tokio::sync::mpsc::Sender<H3ResponseBuilder>,
    },
    /// Peer promised a push (client-initiated; app can cancel or handle).
    PushPromise {
        push_uri: Uri,
        promised_id: u64,
        headers: HeaderMap,
    },
    /// Priority update from peer.
    PriorityUpdate {
        element_id: u64,
        priority: H3Priority,
    },
    /// Datagram received.
    Datagram { payload: Bytes },
    /// Session closing.
    Closing { reason: Option<H3Error> },
    /// Transport event bubbled up.
    Transport(TransportEvent),
}

/// Priority struct (RFC 9218).
#[derive(Debug, Clone, Copy)]
pub struct H3Priority {
    pub urgency: u8,
    pub incremental: bool,
}

/// Fluent response builder.
#[derive(Debug)]
pub struct H3ResponseBuilder {
    inner: Response<()>,
    priority: Option<H3Priority>,
    trailers: Option<HeaderMap>,
    response_tx: Option<tokio::sync::mpsc::Sender<H3ResponseBuilder>>,
}

impl H3ResponseBuilder {
    pub fn new(status: StatusCode) -> Self {
        Self {
            inner: Response::builder().status(status).body(()).unwrap(),
            priority: None,
            trailers: None,
            response_tx: None,
        }
    }

    /// Internal method to set the response sender
    pub(crate) fn with_sender(mut self, tx: tokio::sync::mpsc::Sender<H3ResponseBuilder>) -> Self {
        self.response_tx = Some(tx);
        self
    }

    pub fn status(mut self, status: StatusCode) -> Self {
        *self.inner.status_mut() = status;
        self
    }

    pub fn header<K: AsRef<str>, V: AsRef<[u8]>>(mut self, key: K, value: V) -> Self {
        self.inner.headers_mut().insert(
            HeaderName::from_bytes(key.as_ref().as_bytes()).unwrap(),
            HeaderValue::from_bytes(value.as_ref()).unwrap(),
        );
        self
    }

    pub fn with_priority(mut self, prio: H3Priority) -> Self {
        self.priority = Some(prio);
        self
    }

    pub fn trailers(mut self, trailers: HeaderMap) -> Self {
        self.trailers = Some(trailers);
        self
    }

    pub async fn body<St>(mut self, _body: St) -> Result<(), H3Error>
    where
        St: Stream<Item = Result<Bytes, H3Error>> + Send + Unpin + 'static,
    {
        // Send the response back to the session
        if let Some(tx) = self.response_tx.take() {
            let _ = tx.send(self).await;
        }
        // TODO: In a full implementation, we'd wait for confirmation that the response was sent
        Ok(())
    }
}

/// Core trait for H3 session handle.
#[async_trait]
pub trait H3ServerSession: Send + Sync {
    /// Async stream of incoming H3 events.
    fn events(&self) -> Pin<Box<dyn Stream<Item = H3Event> + Send>>;

    /// Send response to an incoming request.
    async fn send_response(&self, stream_id: StreamId, builder: H3ResponseBuilder) -> Result<(), H3Error>;

    /// Initiate server push.
    async fn push(&self, method: Method, uri: Uri, headers: HeaderMap) -> Result<H3ResponseBuilder, H3Error>;

    /// Update priority for a stream/push.
    async fn update_priority(&self, element_id: u64, prio: H3Priority) -> Result<(), H3Error>;

    /// Send unreliable datagram.
    async fn send_datagram(&self, data: Bytes) -> Result<usize, H3Error>;

    /// Graceful close with GOAWAY.
    async fn goaway(&self, last_id: u64, reason: Option<H3Error>) -> Result<(), H3Error>;

    /// Session stats.
    fn stats(&self) -> H3Stats;

    /// Raw QUIC stream access.
    async fn open_raw_bidir(&self) -> Result<(quicd_x::SendStream, quicd_x::RecvStream), H3Error>;
}

/// Stats struct.
#[derive(Debug, Clone)]
pub struct H3Stats {
    pub active_requests: usize,
    pub qpack_table_size: usize,
    pub push_promises: usize,
}

/// App handler trait.
#[async_trait]
pub trait H3Handler: Send + 'static {
    /// Init and return the handler.
    async fn init(&mut self, session: Arc<dyn H3ServerSession>) -> Result<(), H3Error>;

    /// Handle events.
    async fn handle(&mut self, event: H3Event) -> Result<(), H3Error>;

    /// Shutdown hook.
    async fn shutdown(&mut self, reason: Option<H3Error>);
}

/// Factory for runtime loading.
#[async_trait]
pub trait H3HandlerFactory: Send + Sync + 'static {
    fn accepts(&self, config: &str) -> bool;

    async fn create(&self, session: Arc<dyn H3ServerSession + Send + Sync>, config: Bytes) -> Result<Box<dyn H3Handler + Send + 'static>, H3Error>;
}
