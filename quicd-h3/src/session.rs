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
    pub(crate) qpack: std::sync::Arc<tokio::sync::Mutex<crate::qpack::QpackCodec>>,
    pub(crate) push_manager: Option<std::sync::Arc<tokio::sync::Mutex<PushManager>>>,
    pub(crate) connection_handle: Option<quicd_x::ConnectionHandle>,
    pub(crate) stream_id: u64, // The request stream ID for push promises
    pub(crate) encoder_send_stream: std::sync::Arc<tokio::sync::Mutex<Option<quicd_x::SendStream>>>,
}

impl H3ResponseSender {
    /// Send an HTTP/3 response.
    pub async fn send_response(&mut self, status: u16, headers: Vec<(String, String)>, body: Bytes) -> Result<(), H3Error> {
        // Encode headers
        let mut all_headers = vec![
            (":status".to_string(), status.to_string()),
        ];
        all_headers.extend(headers);

        let (encoded_headers, encoder_instructions, _referenced_entries) = {
            let mut qpack = self.qpack.lock().await;
            let result = qpack.encode_headers(&all_headers)
                .map_err(|_| H3Error::Qpack("encoding failed".into()))?;
            // RFC 9204 Section 2.1.2: Add references (will be released when stream completes)
            for index in &result.2 {
                qpack.add_reference(*index);
            }
            result
        };

        // Send encoder instructions to encoder stream if any
        // PERF #29: Batch all instructions into a single write
        if !encoder_instructions.is_empty() {
            let mut encoder_stream_guard = self.encoder_send_stream.lock().await;
            if let Some(encoder_stream) = encoder_stream_guard.as_mut() {
                // Combine all instructions into a single buffer
                let total_size: usize = encoder_instructions.iter().map(|b| b.len()).sum();
                let mut combined = bytes::BytesMut::with_capacity(total_size);
                
                for instruction in encoder_instructions {
                    combined.extend_from_slice(&instruction);
                }
                
                // Single write for all instructions - reduces system calls
                encoder_stream.write(combined.freeze(), false).await
                    .map_err(|e| H3Error::Stream(format!("failed to write encoder instructions: {:?}", e)))?;
            }
            // If encoder stream not available, we skip (during initialization)
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
        
        // Allocate a new push ID
        let push_id = manager.allocate_push_id()?;
        
        // Register the push promise
        manager.register_promise(push_id, headers.clone())?;
        
        // Encode headers for PUSH_PROMISE frame
        let (encoded_headers, encoder_instructions, _referenced_entries) = {
            let mut qpack = self.qpack.lock().await;
            let result = qpack.encode_headers(&headers)
                .map_err(|_| H3Error::Qpack("encoding failed".into()))?;
            // RFC 9204 Section 2.1.2: Add references
            for index in &result.2 {
                qpack.add_reference(*index);
            }
            result
        };
        
        // Send encoder instructions to encoder stream if any
        if !encoder_instructions.is_empty() {
            let mut encoder_stream_guard = self.encoder_send_stream.lock().await;
            if let Some(encoder_stream) = encoder_stream_guard.as_mut() {
                for instruction in encoder_instructions {
                    encoder_stream.write(instruction, false).await
                        .map_err(|e| H3Error::Stream(format!("failed to write encoder instruction: {:?}", e)))?;
                }
            }
            // If encoder stream not available, we skip (during initialization)
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
            manager.register_pending_stream(request_id, push_id);
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
}

/// Default HTTP/3 handler that returns a simple 404 Not Found response.
///
/// This is a basic implementation for testing and development purposes.
#[derive(Clone)]
pub struct DefaultH3Handler;

#[async_trait]
impl H3Handler for DefaultH3Handler {
    async fn handle_request(&self, _request: H3Request, sender: &mut H3ResponseSender) -> Result<(), H3Error> {
        let body = Bytes::from("404 Not Found");
        sender.send_response(404, vec![("content-type".to_string(), "text/plain".to_string())], body).await
    }
}
