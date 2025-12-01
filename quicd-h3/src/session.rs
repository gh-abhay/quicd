use async_trait::async_trait;
use bytes::Bytes;
use http::{Method, Uri};

use crate::error::H3Error;
use crate::push::{PushManager, validate_push_promise_headers};

/// Represents an HTTP/3 request received from the client.
#[derive(Debug)]
pub struct H3Request {
    pub method: Method,
    pub uri: Uri,
    pub headers: Vec<(String, String)>, // Simplified, use Vec instead of HeaderMap
    pub body: Option<Bytes>, // For small bodies, or stream for large
}

/// Handle for sending HTTP/3 responses on a specific stream.
pub struct H3ResponseSender {
    pub(crate) send_stream: quicd_x::SendStream,
    pub(crate) qpack_encoder: std::sync::Arc<tokio::sync::Mutex<quicd_qpack::AsyncEncoder>>,
    pub(crate) push_manager: Option<std::sync::Arc<tokio::sync::Mutex<PushManager>>>,
    pub(crate) connection_handle: Option<quicd_x::ConnectionHandle>,
    pub(crate) stream_id: u64, // The request stream ID for push promises
    pub(crate) encoder_send_stream: std::sync::Arc<tokio::sync::Mutex<Option<quicd_x::SendStream>>>,
    // QPACK blocking and references are handled internally by quicd-qpack
}

impl H3ResponseSender {
    /// Send an HTTP/3 response.
    pub async fn send_response(&mut self, status: u16, headers: Vec<(String, String)>, body: Bytes) -> Result<(), H3Error> {
        // Encode headers
        let status_str = status.to_string();
        let mut all_headers = vec![
            (b":status".as_slice(), status_str.as_bytes()),
        ];
        for (name, value) in &headers {
            all_headers.push((name.as_bytes(), value.as_bytes()));
        }

        // Encode headers with QPACK
        let mut encoder_guard = self.qpack_encoder.lock().await;
        let encoded_headers = encoder_guard.encoder_mut().encode(self.stream_id, &all_headers)
            .map_err(|_| H3Error::Qpack("encoding failed".into()))?;

        // PERF #3: Batch encoder instructions into single write with pre-allocation
        let mut batched_instructions = bytes::BytesMut::with_capacity(256);
        while let Some(inst) = encoder_guard.encoder_mut().poll_encoder_stream() {
            batched_instructions.extend_from_slice(&inst);
        }
        
        // Release encoder lock before stream write (reduces lock contention)
        drop(encoder_guard);
        
        if !batched_instructions.is_empty() {
            if let Some(encoder_stream) = self.encoder_send_stream.lock().await.as_mut() {
                let _ = encoder_stream.write(batched_instructions.freeze(), false).await;
            }
        }

        // Send HEADERS frame
        let headers_frame = crate::frames::H3Frame::Headers { encoded_headers };
        let frame_data = headers_frame.encode();
        self.send_stream.write(frame_data, false).await
            .map_err(|e| H3Error::Stream(format!("write failed: {:?}", e)))?;

        // Send DATA frame
        let data_frame = crate::frames::H3Frame::Data { data: body };
        let data_frame_data = data_frame.encode();
        self.send_stream.write(data_frame_data, true).await
            .map_err(|e| H3Error::Stream(format!("write failed: {:?}", e)))?; // FIN

        Ok(())
    }

    /// Send an interim (1xx) response.
    /// 
    /// RFC 9114 Section 4.1: An HTTP request/response exchange can include multiple
    /// informational (1xx) responses before the final response. These interim responses
    /// convey status without ending the request.
    /// 
    /// Interim responses MUST NOT contain:
    /// - content-length, content-type, content-encoding headers
    /// - A message body (no DATA frames)
    pub async fn send_interim_response(&mut self, status: u16, headers: Vec<(String, String)>) -> Result<(), H3Error> {
        // Validate that status is 1xx
        if status < 100 || status >= 200 {
            return Err(H3Error::Http(format!("status {} is not an interim response (1xx)", status)));
        }
        
        // Build headers with :status pseudo-header
        let status_str = status.to_string();
        let mut all_headers = vec![
            (b":status".as_slice(), status_str.as_bytes()),
        ];
        for (name, value) in &headers {
            all_headers.push((name.as_bytes(), value.as_bytes()));
        }
        
        // RFC 9114 Section 4.1: Validate interim response headers
        crate::validation::validate_interim_response_headers(&all_headers.iter().map(|(n, v)| (String::from_utf8_lossy(n).to_string(), String::from_utf8_lossy(v).to_string())).collect::<Vec<_>>())?;
        
        // Encode headers with QPACK
        let mut encoder_guard = self.qpack_encoder.lock().await;
        let encoded_headers = encoder_guard.encoder_mut().encode(self.stream_id, &all_headers)
            .map_err(|_| H3Error::Qpack("encoding failed".into()))?;

        // PERF #3: Batch encoder instructions into single write
        let mut batched_instructions = bytes::BytesMut::new();
        while let Some(inst) = encoder_guard.encoder_mut().poll_encoder_stream() {
            batched_instructions.extend_from_slice(&inst);
        }
        
        if !batched_instructions.is_empty() {
            if let Some(encoder_stream) = self.encoder_send_stream.lock().await.as_mut() {
                let _ = encoder_stream.write(batched_instructions.freeze(), false).await;
            }
        }

        // Send HEADERS frame (no FIN - more data may follow)
        let headers_frame = crate::frames::H3Frame::Headers { encoded_headers };
        let frame_data = headers_frame.encode();
        self.send_stream.write(frame_data, false).await
            .map_err(|e| H3Error::Stream(format!("write failed: {:?}", e)))?;

        Ok(())
    }

    /// Send a PUSH_PROMISE frame to initiate server push.
    ///
    /// Per RFC 9114 Section 4.6: Server push allows a server to send responses
    /// for requests that the client has not yet made.
    ///
    /// # Arguments
    /// - `headers`: The request headers being promised (must include all pseudo-headers)
    ///
    /// # Returns
    /// The push ID assigned to this push
    pub async fn send_push_promise(&mut self, headers: Vec<(String, String)>) -> Result<u64, H3Error> {
        // Validate push promise headers
        validate_push_promise_headers(&headers)?;

        let push_manager = self.push_manager.as_ref()
            .ok_or_else(|| H3Error::Http("server push not available".into()))?;
        
        let mut manager = push_manager.lock().await;
        
        // GAP FIX #4: RFC 9114 Section 7.2.7: Validate push_id against client's MAX_PUSH_ID
        // Note: We need access to max_push_id from H3Session, which isn't available here
        // This should be checked in H3Session when allocating the push
        
        // Allocate a new push ID
        let push_id = manager.allocate_push_id()?;
        
        // Register the push promise
        manager.register_promise(push_id, headers.clone())?;
        
        // Encode headers for PUSH_PROMISE frame
        let headers_bytes: Vec<(&[u8], &[u8])> = headers.iter()
            .map(|(n, v)| (n.as_bytes(), v.as_bytes()))
            .collect();
        
        let mut encoder_guard = self.qpack_encoder.lock().await;
        let encoded_headers = encoder_guard.encoder_mut().encode(self.stream_id, &headers_bytes)
            .map_err(|_| H3Error::Qpack("encoding failed".into()))?;

        // PERF #3: Batch encoder instructions into single write
        let mut batched_instructions = bytes::BytesMut::new();
        while let Some(inst) = encoder_guard.encoder_mut().poll_encoder_stream() {
            batched_instructions.extend_from_slice(&inst);
        }
        
        if !batched_instructions.is_empty() {
            if let Some(encoder_stream) = self.encoder_send_stream.lock().await.as_mut() {
                let _ = encoder_stream.write(batched_instructions.freeze(), false).await;
            }
        }
        
        drop(manager); // Release lock before async operation
        
        // Send PUSH_PROMISE frame on the request stream
        let push_promise = crate::frames::H3Frame::PushPromise {
            push_id,
            encoded_headers,
        };
        let frame_data = push_promise.encode();
        self.send_stream.write(frame_data, false).await
            .map_err(|e| H3Error::Stream(format!("write failed: {:?}", e)))?;
        
        Ok(push_id)
    }
    
    /// Send a response on a push stream.
    ///
    /// Per RFC 9114 Section 4.6: After sending PUSH_PROMISE, the server opens
    /// a unidirectional push stream to send the response.
    ///
    /// # Arguments
    /// - `push_id`: The push ID from send_push_promise()
    /// - `status`: HTTP status code
    /// - `headers`: Response headers
    /// - `body`: Response body
    pub async fn send_push_response(
        &mut self,
        push_id: u64,
        status: u16,
        headers: Vec<(String, String)>,
        body: Bytes,
    ) -> Result<(), H3Error> {
        use crate::push::PushResponse;
        
        let push_manager = self.push_manager.as_ref()
            .ok_or_else(|| H3Error::Http("server push not available".into()))?;
        
        let handle = self.connection_handle.as_ref()
            .ok_or_else(|| H3Error::Http("connection handle not available".into()))?;
        
        // Check if push is cancelled and store response
        {
            let mut manager = push_manager.lock().await;
            if let Some(promise) = manager.get_promise_mut(push_id) {
                if promise.is_cancelled() {
                    return Err(H3Error::Http("push was cancelled".into()));
                }
                // Store the response data for when the stream opens
                promise.set_response(PushResponse {
                    status,
                    headers,
                    body,
                });
            } else {
                return Err(H3Error::Http(format!("push ID {} not found", push_id)));
            }
        }
        
        // Open a unidirectional stream for the push
        let request_id = handle.open_uni()
            .map_err(|e| H3Error::Connection(format!("failed to open push stream: {:?}", e)))?;
        
        // Register the pending stream
        {
            let mut manager = push_manager.lock().await;
            manager.register_pending_stream(request_id, push_id)
                .map_err(|e| H3Error::Connection(format!("failed to register push stream: {:?}", e)))?;
        }
        
        // Note: The actual stream writing happens in h3_session when UniStreamOpened event is received
        Ok(())
    }

    /// Cancel the current request stream with an application error code.
    ///
    /// Per RFC 9114 Section 4.1.1: Either endpoint can abruptly terminate a stream
    /// by sending a RESET_STREAM frame. This immediately terminates sending on the stream.
    ///
    /// # Arguments
    /// - `error_code`: Application-specific error code (H3_NO_ERROR = 0x100, H3_REQUEST_CANCELLED = 0x10C, etc.)
    pub async fn cancel(&mut self, error_code: u64) -> Result<(), H3Error> {
        let handle = self.connection_handle.as_ref()
            .ok_or_else(|| H3Error::Http("connection handle not available".into()))?;
        
        // Send RESET_STREAM to peer
        let _request_id = handle.reset_stream(self.stream_id, error_code)
            .map_err(|e| H3Error::Connection(format!("Failed to reset stream: {:?}", e)))?;
        
        Ok(())
    }

}

/// Trait that applications implement to handle HTTP/3 requests.
///
/// This trait provides the interface for handling incoming HTTP/3 requests
/// and sending responses. It's designed to be simple and ergonomic.
#[async_trait]
pub trait H3Handler: Send + Sync + 'static {
    /// Handles an incoming HTTP/3 request.
    ///
    /// # Arguments
    /// - `request`: The parsed HTTP request
    /// - `sender`: Handle to send the response
    ///
    /// # Returns
    /// Result indicating success or error
    async fn handle_request(&self, request: H3Request, sender: &mut H3ResponseSender) -> Result<(), H3Error>;
    
    /// Handle an HTTP/3 datagram (RFC 9297).
    ///
    /// This method is called when an HTTP/3 datagram is received on the connection.
    /// Datagrams are unreliable, unordered messages that can be sent over HTTP/3
    /// for use cases like WebRTC, gaming, or real-time applications.
    ///
    /// Default implementation ignores datagrams. Override to handle them.
    ///
    /// # Arguments
    /// * `flow_id` - Quarter stream ID identifying the datagram flow
    /// * `payload` - Datagram payload bytes
    ///
    /// # Returns
    /// Ok(()) if handled successfully, Err for connection errors
    async fn handle_datagram(&self, _flow_id: u64, _payload: Bytes) -> Result<(), H3Error> {
        // Default: ignore datagrams
        Ok(())
    }
}

/// Default HTTP/3 handler that returns a simple 404 Not Found response.
///
/// This is a basic implementation for testing and development purposes.
#[derive(Clone)]
pub struct DefaultH3Handler;

#[async_trait]
impl H3Handler for DefaultH3Handler {
    async fn handle_request(&self, request: H3Request, sender: &mut H3ResponseSender) -> Result<(), H3Error> {
        if request.method == Method::GET && request.uri.path() == "/" {
            let body = Bytes::from("Hello World");
            sender.send_response(200, vec![("content-type".to_string(), "text/plain".to_string())], body).await
        } else {
            let body = Bytes::from("404 Not Found");
            sender.send_response(404, vec![("content-type".to_string(), "text/plain".to_string())], body).await
        }
    }
    
    async fn handle_datagram(&self, _flow_id: u64, _payload: Bytes) -> Result<(), H3Error> {
        Ok(())
    }
}
