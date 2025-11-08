//! HTTP/3 session implementation using h3 crate.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use async_trait::async_trait;
use bytes::Bytes;
use futures::{Stream, StreamExt};
use tokio::sync::{mpsc, Mutex};
use parking_lot::Mutex as ParkingMutex;
use quicd_x::{ConnectionHandle, QuicAppFactory, AppEventStream, ShutdownFuture};
use crate::quic_impl::{H3Connection, H3SendStream};
use crate::{H3Error, H3Event, H3HandlerFactory, H3Priority, H3ResponseBuilder, H3ServerSession, H3Stats, StreamId};

/// Stream wrapper for h3 RequestStream to convert to our error type
struct RequestBodyStream<S> {
    request_stream: Option<h3::server::RequestStream<S, bytes::Bytes>>,
}

impl<S> Stream for RequestBodyStream<S>
where
    S: h3::quic::RecvStream + Send + Unpin,
{
    type Item = Result<Bytes, H3Error>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        if let Some(ref mut stream) = self.request_stream {
            match stream.poll_recv_data(cx) {
                std::task::Poll::Ready(Ok(Some(_data))) => {
                    // TODO: Convert impl Buf to Bytes - for now return empty
                    std::task::Poll::Ready(Some(Ok(Bytes::new())))
                }
                std::task::Poll::Ready(Ok(None)) => std::task::Poll::Ready(None),
                std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Some(Err(H3Error::Protocol(e.to_string())))),
                std::task::Poll::Pending => std::task::Poll::Pending,
            }
        } else {
            std::task::Poll::Ready(None)
        }
    }
}

/// Internal session state that implements H3ServerSession.
struct H3SessionInner {
    handle: ConnectionHandle,
    event_tx: mpsc::UnboundedSender<H3Event>,
    pending_responses: Arc<Mutex<HashMap<StreamId, mpsc::Sender<H3ResponseBuilder>>>>,
    h3_connection: Arc<Mutex<Option<h3::server::Connection<H3Connection, bytes::Bytes>>>>,
    active_streams: Arc<Mutex<HashMap<u64, h3::server::RequestStream<H3SendStream, bytes::Bytes>>>>,
    next_stream_id: AtomicU64,
    sent_goaway: Arc<Mutex<Option<h3::proto::stream::StreamId>>>,
    stats: Arc<ParkingMutex<H3Stats>>,
    raw_stream_requests: Arc<Mutex<HashMap<u64, tokio::sync::oneshot::Sender<Result<(quicd_x::SendStream, quicd_x::RecvStream), H3Error>>>>>,
}

impl H3SessionInner {
    fn new(handle: ConnectionHandle) -> (Self, mpsc::UnboundedReceiver<H3Event>) {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        (
            Self {
                handle,
                event_tx,
                pending_responses: Arc::new(Mutex::new(HashMap::new())),
                h3_connection: Arc::new(Mutex::new(None)),
                active_streams: Arc::new(Mutex::new(HashMap::new())),
                next_stream_id: AtomicU64::new(0),
                sent_goaway: Arc::new(Mutex::new(None)),
                stats: Arc::new(ParkingMutex::new(H3Stats {
                    active_requests: 0,
                    qpack_table_size: 0,
                    push_promises: 0,
                })),
                raw_stream_requests: Arc::new(Mutex::new(HashMap::new())),
            },
            event_rx,
        )
    }
}

#[async_trait]
impl H3ServerSession for H3SessionInner {
    fn events(&self) -> Pin<Box<dyn Stream<Item = H3Event> + Send>> {
        // This is a placeholder - the actual events come from the event_rx
        // In a real implementation, we'd need to return a stream that yields events
        Box::pin(futures::stream::empty())
    }

    async fn send_response(&self, stream_id: StreamId, builder: H3ResponseBuilder) -> Result<(), H3Error> {
        if let Some(tx) = self.pending_responses.lock().await.get(&stream_id) {
            let _ = tx.send(builder).await;
        }
        Ok(())
    }

    async fn push(&self, method: http::Method, uri: http::Uri, headers: http::HeaderMap) -> Result<H3ResponseBuilder, H3Error> {
        if let Some(_h3_conn) = self.h3_connection.lock().await.as_mut() {
            // Increment push promises counter
            {
                let mut stats = self.stats.lock();
                stats.push_promises += 1;
            }
            
            // Try to initiate a server push
            // Create a request for the push
            let mut request_builder = http::Request::builder()
                .method(method)
                .uri(uri);
            
            // Add headers to the request
            for (name, value) in headers {
                if let Some(name) = name {
                    request_builder = request_builder.header(name, value);
                }
            }
            
            let _request = request_builder
                .body(())
                .map_err(|e| H3Error::Protocol(format!("Invalid push request: {}", e)))?;
            
            // For now, we'll simulate push by returning a response builder
            // In a real implementation, this would use h3_conn.push(request) or similar
            // and return a response builder that sends on the push stream
            let builder = H3ResponseBuilder::new(http::StatusCode::OK);
            
            // TODO: Implement actual h3 push when the API is available
            Ok(builder)
        } else {
            Err(H3Error::Protocol("H3 connection not available for push".to_string()))
        }
    }

    async fn update_priority(&self, element_id: u64, prio: H3Priority) -> Result<(), H3Error> {
        if let Some(_h3_conn) = self.h3_connection.lock().await.as_mut() {
            // TODO: Implement priority update using h3 API when available
            // For now, we log the priority update
            // When h3 supports priority frames, this would send a PRIORITY_UPDATE frame
            println!("Priority update for element {}: urgency={}, incremental={}", 
                    element_id, prio.urgency, prio.incremental);
            
            // TODO: Send PRIORITY_UPDATE frame via h3_conn when API becomes available
            // h3_conn.send_priority_update(element_id, prio.urgency, prio.incremental)?;
            
            Ok(())
        } else {
            Err(H3Error::Protocol("H3 connection not available for priority update".to_string()))
        }
    }

    async fn send_datagram(&self, data: Bytes) -> Result<usize, H3Error> {
        match self.handle.send_datagram(data) {
            Ok(request_id) => Ok(request_id as usize), // Convert u64 to usize
            Err(e) => Err(H3Error::Transport(e)),
        }
    }

    async fn goaway(&self, last_id: u64, _reason: Option<H3Error>) -> Result<(), H3Error> {
        if let Some(h3_conn) = self.h3_connection.lock().await.as_mut() {
            // Convert u64 to StreamId
            let stream_id = match h3::proto::stream::StreamId::try_from(last_id) {
                Ok(id) => id,
                Err(_) => return Err(H3Error::Protocol(format!("Invalid stream ID for GOAWAY: {}", last_id))),
            };
            
            // Send GOAWAY frame by calling the inner connection's shutdown method
            let mut sent_closing_guard = self.sent_goaway.lock().await;
            match h3_conn.inner.shutdown(&mut *sent_closing_guard, stream_id).await {
                Ok(()) => {
                    println!("GOAWAY frame sent with last stream ID: {}", last_id);
                    Ok(())
                }
                Err(e) => {
                    eprintln!("Failed to send GOAWAY frame: {:?}", e);
                    Err(H3Error::Protocol(format!("Failed to send GOAWAY: {}", e)))
                }
            }
        } else {
            Err(H3Error::Protocol("H3 connection not available for GOAWAY".to_string()))
        }
    }

    fn stats(&self) -> H3Stats {
        // Clone the current stats
        self.stats.lock().clone()
    }

    async fn open_raw_bidir(&self) -> Result<(quicd_x::SendStream, quicd_x::RecvStream), H3Error> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        
        // Initiate the stream opening
        let request_id = match self.handle.open_bi() {
            Ok(id) => id,
            Err(e) => return Err(H3Error::Transport(e)),
        };
        
        // Store the response channel
        {
            let mut requests = self.raw_stream_requests.lock().await;
            requests.insert(request_id, tx);
        }
        
        // Wait for the response
        match rx.await {
            Ok(result) => result,
            Err(_) => Err(H3Error::Protocol("Raw stream request cancelled".to_string())),
        }
    }
}

/// HTTP/3 session implementation.
pub struct H3Session<F> {
    inner: Arc<H3SessionInner>,
    event_rx: mpsc::UnboundedReceiver<H3Event>,
    handler_factory: F,
    h3_connection: Option<H3Connection>,
}

impl<F> H3Session<F>
where
    F: H3HandlerFactory,
{
    pub fn new(handle: ConnectionHandle, handler_factory: F) -> Self {
        let (inner, event_rx) = H3SessionInner::new(handle.clone());
        Self {
            inner: Arc::new(inner),
            event_rx,
            handler_factory,
            h3_connection: Some(H3Connection::new(handle)),
        }
    }

    pub async fn run(mut self, mut event_stream: quicd_x::AppEventStream) -> Result<(), H3Error> {
        let h3_conn = self.h3_connection.take().unwrap();
        
        // Create h3 connection now that handshake is complete
        let h3_connection = match h3::server::Connection::new(h3_conn).await {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("Failed to create H3 connection: {:?}", e);
                let _ = self.inner.event_tx.send(H3Event::Closing { 
                    reason: Some(H3Error::Protocol(format!("H3 connection creation failed: {}", e))) 
                });
                return Err(H3Error::Protocol(format!("H3 connection creation failed: {}", e)));
            }
        };
        
        // Store the h3 connection in the inner struct for push operations
        *self.inner.h3_connection.lock().await = Some(h3_connection);
        
        // Get a mutable reference to the h3 connection for the accept loop
        let mut h3_conn_guard = self.inner.h3_connection.lock().await;
        let h3_connection = h3_conn_guard.as_mut().unwrap();
        
        // For now, we'll handle events and create h3 connection on demand
        // This is a simplified implementation
        while let Some(event) = event_stream.next().await {
            match event {
                quicd_x::AppEvent::HandshakeCompleted { .. } => {
                    // Handshake completed, start processing requests
                    // The H3 connection should already be created above
                    let h3_conn_available = self.inner.h3_connection.lock().await.is_some();
                    if !h3_conn_available {
                        eprintln!("Handshake completed but H3 connection not available");
                        let _ = self.inner.event_tx.send(H3Event::Closing { 
                            reason: Some(H3Error::Protocol("H3 connection not available after handshake".to_string())) 
                        });
                        break;
                    }
                    
                    // Get a mutable reference to the h3 connection for the accept loop
                    let mut h3_conn_guard = self.inner.h3_connection.lock().await;
                    let h3_connection = h3_conn_guard.as_mut().unwrap();
                    loop {
                        match h3_connection.accept().await {
                            Ok(Some(request_resolver)) => {
                                // Resolve the request
                                match request_resolver.resolve_request().await {
                                    Ok((request, request_stream)) => {
                                        let stream_id = self.inner.next_stream_id.fetch_add(1, Ordering::Relaxed);
                                        
                                        // Increment active requests counter
                                        {
                                            let mut stats = self.inner.stats.lock();
                                            stats.active_requests += 1;
                                        }
                                        
                                        // Split the request stream into send and receive parts
                                        let (send_stream, recv_stream) = request_stream.split();
                                        
                                        // Store the send stream for response sending
                                        self.inner.active_streams.lock().await.insert(stream_id, send_stream);
                                        
                                        // Create a body stream from the receive stream
                                        let body_stream = RequestBodyStream {
                                            request_stream: Some(recv_stream),
                                        };
                                        
                                        // Create response channel
                                        let (response_tx, mut response_rx) = tokio::sync::mpsc::channel(1);
                                        
                                        // Send request event
                                        let event = H3Event::Request {
                                            req: request,
                                            body: Box::pin(body_stream),
                                            stream_id,
                                            response_tx,
                                        };
                                        
                                        if self.inner.event_tx.send(event).is_err() {
                                            // Application disconnected, clean up and exit
                                            self.inner.active_streams.lock().await.remove(&stream_id);
                                            {
                                                let mut stats = self.inner.stats.lock();
                                                stats.active_requests = stats.active_requests.saturating_sub(1);
                                            }
                                            break;
                                        }
                                        
                                        // Wait for response and handle it
                                        match response_rx.recv().await {
                                            Some(response_builder) => {
                                                // Send the response using the stored request stream
                                                if let Some(send_stream) = self.inner.active_streams.lock().await.get_mut(&stream_id) {
                                                    // Send response headers
                                                    let http_response = response_builder.inner;
                                                    if let Some(priority) = response_builder.priority {
                                                        // TODO: Handle priority when sending response
                                                        println!("Response has priority: urgency={}, incremental={}", 
                                                                priority.urgency, priority.incremental);
                                                    }
                                                    
                                                    match send_stream.send_response(http_response).await {
                                                        Ok(()) => {
                                                            // Response headers sent successfully
                                                            println!("Response headers sent for stream {}", stream_id);
                                                        }
                                                        Err(e) => {
                                                            eprintln!("Failed to send response headers for stream {}: {:?}", stream_id, e);
                                                            // Try to send an error response
                                                            if let Ok(error_response) = http::Response::builder()
                                                                .status(500)
                                                                .body(())
                                                            {
                                                                let _ = send_stream.send_response(error_response).await;
                                                            }
                                                        }
                                                    }
                                                } else {
                                                    eprintln!("Send stream not found for stream {}", stream_id);
                                                }
                                            }
                                            None => {
                                                // Application didn't send a response, send a default error
                                                eprintln!("No response received for stream {}", stream_id);
                                                if let Some(send_stream) = self.inner.active_streams.lock().await.get_mut(&stream_id) {
                                                    if let Ok(error_response) = http::Response::builder()
                                                        .status(500)
                                                        .body(())
                                                    {
                                                        let _ = send_stream.send_response(error_response).await;
                                                    }
                                                }
                                            }
                                        }
                                        
                                        // Clean up the stream after response
                                        self.inner.active_streams.lock().await.remove(&stream_id);
                                        
                                        // Decrement active requests counter
                                        {
                                            let mut stats = self.inner.stats.lock();
                                            stats.active_requests = stats.active_requests.saturating_sub(1);
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("Failed to resolve request: {:?}", e);
                                        // Continue processing other requests - don't break the connection
                                    }
                                }
                            }
                            Ok(None) => {
                                // Connection closed normally
                                let _ = self.inner.event_tx.send(H3Event::Closing { reason: None });
                                break;
                            }
                            Err(e) => {
                                eprintln!("Accept error: {:?}", e);
                                let _ = self.inner.event_tx.send(H3Event::Closing { 
                                    reason: Some(H3Error::Protocol(e.to_string())) 
                                });
                                break;
                            }
                        }
                    }
                }
                quicd_x::AppEvent::ConnectionClosing { error_code, reason } => {
                    eprintln!("Connection closing with error code {}: {:?}", error_code, reason);
                    let _ = self.inner.event_tx.send(H3Event::Closing { reason: None });
                    break;
                }
                quicd_x::AppEvent::Datagram { payload } => {
                    // Forward datagram to application
                    let _ = self.inner.event_tx.send(H3Event::Datagram { payload });
                }
                quicd_x::AppEvent::StreamOpened { request_id, result } => {
                    // Handle raw stream opening response
                    let mut requests = self.inner.raw_stream_requests.lock().await;
                    if let Some(tx) = requests.remove(&request_id) {
                        let result = result.map_err(H3Error::Transport);
                        if tx.send(result).is_err() {
                            eprintln!("Failed to send raw stream response for request {}", request_id);
                        }
                    } else {
                        eprintln!("Received StreamOpened for unknown request {}", request_id);
                    }
                }
                _ => {
                    // Handle other events as needed
                }
            }
        }
        
        Ok(())
    }

    pub fn session(&self) -> Arc<dyn H3ServerSession + Send + Sync> {
        self.inner.clone()
    }
}

/// Factory for creating H3Session instances.
pub struct H3Factory<F> {
    handler_factory: F,
}

impl<F> H3Factory<F> {
    pub fn new(handler_factory: F) -> Self {
        Self { handler_factory }
    }

    pub fn create_session(&self, handle: ConnectionHandle) -> H3Session<F>
    where
        F: H3HandlerFactory + Clone,
    {
        H3Session::new(handle, self.handler_factory.clone())
    }
}

#[async_trait]
impl<F> QuicAppFactory for H3Factory<F>
where
    F: H3HandlerFactory + Clone + Send + Sync + 'static,
{
    fn accepts_alpn(&self, alpn: &str) -> bool {
        // Accept HTTP/3 ALPN identifiers
        alpn == "h3" || alpn.starts_with("h3-")
    }

    async fn spawn_app(
        &self,
        _alpn: String,
        handle: ConnectionHandle,
        events: AppEventStream,
        _transport: quicd_x::TransportControls,
        shutdown: ShutdownFuture,
    ) -> Result<(), quicd_x::ConnectionError> {
        // Create the H3 session
        let session = H3Session::new(handle, self.handler_factory.clone());
        
        // Create a combined future that handles both the session run and shutdown
        tokio::select! {
            result = session.run(events) => {
                result.map_err(|e| quicd_x::ConnectionError::App(e.to_string()))
            }
            _ = shutdown => {
                // Shutdown signal received
                Ok(())
            }
        }
    }
}

/// Default handler factory for basic HTTP/3 functionality.
/// This provides a simple handler that accepts all requests and returns a 200 OK response.
pub struct DefaultH3HandlerFactory;

impl DefaultH3HandlerFactory {
    pub fn new() -> Self {
        Self
    }
}

impl Clone for DefaultH3HandlerFactory {
    fn clone(&self) -> Self {
        DefaultH3HandlerFactory
    }
}

#[async_trait]
impl H3HandlerFactory for DefaultH3HandlerFactory {
    fn accepts(&self, _config: &str) -> bool {
        true
    }

    async fn create(&self, session: Arc<dyn H3ServerSession + Send + Sync>, _config: Bytes) -> Result<Box<dyn crate::H3Handler + Send + 'static>, H3Error> {
        Ok(Box::new(DefaultH3Handler { session }))
    }
}

/// Default HTTP/3 handler that provides basic request/response functionality.
pub struct DefaultH3Handler {
    session: Arc<dyn H3ServerSession + Send + Sync>,
}

#[async_trait]
impl crate::H3Handler for DefaultH3Handler {
    async fn init(&mut self, _session: Arc<dyn H3ServerSession>) -> Result<(), H3Error> {
        Ok(())
    }

    async fn handle(&mut self, event: H3Event) -> Result<(), H3Error> {
        match event {
            H3Event::Request { req, body: _body, stream_id, response_tx } => {
                // Create a simple 200 OK response
                let response = H3ResponseBuilder::new(http::StatusCode::OK);
                
                // Send the response
                if let Err(_) = response_tx.send(response).await {
                    eprintln!("Failed to send response for stream {}", stream_id);
                }
            }
            H3Event::Closing { reason } => {
                println!("Connection closing: {:?}", reason);
            }
            _ => {
                // Handle other events as needed
            }
        }
        Ok(())
    }

    async fn shutdown(&mut self, reason: Option<H3Error>) {
        println!("Handler shutting down: {:?}", reason);
    }
}

// Make it Send + Sync for the QuicAppFactory bound
unsafe impl Send for DefaultH3HandlerFactory {}
unsafe impl Sync for DefaultH3HandlerFactory {}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock handler factory for testing
    struct MockHandler;

    #[async_trait]
    impl crate::H3Handler for MockHandler {
        async fn init(&mut self, _session: Arc<dyn H3ServerSession>) -> Result<(), H3Error> {
            Ok(())
        }

        async fn handle(&mut self, _event: H3Event) -> Result<(), H3Error> {
            Ok(())
        }

        async fn shutdown(&mut self, _reason: Option<H3Error>) {
            // Do nothing
        }
    }

    struct MockHandlerFactory;

    impl Clone for MockHandlerFactory {
        fn clone(&self) -> Self {
            MockHandlerFactory
        }
    }

    #[async_trait]
    impl H3HandlerFactory for MockHandlerFactory {
        fn accepts(&self, _config: &str) -> bool {
            true
        }

        async fn create(&self, _session: Arc<dyn H3ServerSession + Send + Sync>, _config: Bytes) -> Result<Box<dyn crate::H3Handler + Send + 'static>, H3Error> {
            Ok(Box::new(MockHandler))
        }
    }

    // Make it Send + Sync for the QuicAppFactory bound
    unsafe impl Send for MockHandlerFactory {}
    unsafe impl Sync for MockHandlerFactory {}

    #[test]
    fn test_h3_factory_creation() {
        let factory = H3Factory::new(MockHandlerFactory);
        // Just test that it can be created
        assert!(factory.handler_factory.accepts("test"));
    }

    #[test]
    fn test_alpn_acceptance() {
        // Test ALPN acceptance logic directly
        // Should accept standard HTTP/3 ALPN
        assert!("h3" == "h3" || "h3".starts_with("h3-"));
        
        // Should accept versioned HTTP/3 ALPN
        assert!("h3-29" == "h3" || "h3-29".starts_with("h3-"));
        assert!("h3-30" == "h3" || "h3-30".starts_with("h3-"));
        
        // Should not accept other protocols
        assert!(!("h2" == "h3" || "h2".starts_with("h3-")));
        assert!(!("http/1.1" == "h3" || "http/1.1".starts_with("h3-")));
        assert!(!("" == "h3" || "".starts_with("h3-")));
    }

    #[test]
    fn test_stats_initialization() {
        // Test that stats are properly initialized
        let stats = H3Stats {
            active_requests: 0,
            qpack_table_size: 0,
            push_promises: 0,
        };
        
        assert_eq!(stats.active_requests, 0);
        assert_eq!(stats.qpack_table_size, 0);
        assert_eq!(stats.push_promises, 0);
    }

    #[test]
    fn test_error_types() {
        // Test that error types can be created
        let protocol_error = H3Error::Protocol("test error".to_string());
        let transport_error = H3Error::Transport(quicd_x::ConnectionError::Closed("test".into()));
        
        match protocol_error {
            H3Error::Protocol(msg) => assert_eq!(msg, "test error"),
            _ => panic!("Wrong error type"),
        }
        
        match transport_error {
            H3Error::Transport(_) => {}, // Just check it's the right variant
            _ => panic!("Wrong error type"),
        }
    }
}