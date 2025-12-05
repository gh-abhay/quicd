use bytes::Bytes;
use http::{Method, Uri};

use crate::error::H3Error;
use crate::push::{validate_push_promise_headers, PushManager};

/// Represents an HTTP/3 request received from the client.
#[derive(Debug)]
pub struct H3Request {
    pub method: Method,
    pub uri: Uri,
    pub headers: Vec<(String, String)>, // Simplified, use Vec instead of HeaderMap
    pub body: Option<Bytes>,            // For small bodies, or stream for large
}

/// Handle for sending HTTP/3 responses on a specific stream.
pub struct H3ResponseSender<'a> {
    pub(crate) send_stream: quicd_x::SendStream,
    pub(crate) qpack_encoder: &'a std::cell::RefCell<quicd_qpack::Encoder>,
    pub(crate) push_manager: Option<&'a std::cell::RefCell<PushManager>>,
    pub(crate) connection_handle: Option<quicd_x::ConnectionHandle>,
    pub(crate) stream_id: u64, // The request stream ID for push promises
    pub(crate) encoder_send_stream: &'a std::cell::RefCell<Option<quicd_x::SendStream>>,
    // QPACK blocking and references are handled internally by quicd-qpack
}

impl<'a> H3ResponseSender<'a> {
    /// Send an HTTP/3 response.
    pub fn send_response(
        &mut self,
        status: u16,
        headers: Vec<(String, String)>,
        body: Bytes,
    ) -> Result<(), H3Error> {
        // Encode headers
        let status_str = status.to_string();
        let mut all_headers = vec![(b":status".as_slice(), status_str.as_bytes())];
        for (name, value) in &headers {
            all_headers.push((name.as_bytes(), value.as_bytes()));
        }

        // Encode headers with QPACK
        let mut encoder_guard = self.qpack_encoder.borrow_mut();
        let encoded_headers = encoder_guard
            .encode(self.stream_id, &all_headers)
            .map_err(|_| H3Error::Qpack("encoding failed".into()))?;

        // PERF #3: Batch encoder instructions into single write with pre-allocation
        let mut batched_instructions = bytes::BytesMut::with_capacity(256);
        while let Some(inst) = encoder_guard.poll_encoder_stream() {
            batched_instructions.extend_from_slice(inst.as_ref());
        }

        // Release encoder borrow before stream write
        drop(encoder_guard);

        if !batched_instructions.is_empty() {
            if let Some(encoder_stream) = self.encoder_send_stream.borrow_mut().as_mut() {
                let _ = encoder_stream.try_write(batched_instructions.freeze(), false);
            }
        }

        // Send HEADERS frame
        let headers_frame = crate::frames::H3Frame::Headers { encoded_headers };
        let frame_data = headers_frame.encode();
        self.send_stream
            .try_write(frame_data, false)
            .map_err(|e| H3Error::Stream(format!("write failed: {:?}", e)))?;

        // Send DATA frame
        let data_frame = crate::frames::H3Frame::Data { data: body };
        let data_frame_data = data_frame.encode();
        self.send_stream
            .try_write(data_frame_data, true)
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
    pub fn send_interim_response(
        &mut self,
        status: u16,
        headers: Vec<(String, String)>,
    ) -> Result<(), H3Error> {
        // Validate that status is 1xx
        if status < 100 || status >= 200 {
            return Err(H3Error::Http(format!(
                "status {} is not an interim response (1xx)",
                status
            )));
        }

        // Build headers with :status pseudo-header
        let status_str = status.to_string();
        let mut all_headers = vec![(b":status".as_slice(), status_str.as_bytes())];
        for (name, value) in &headers {
            all_headers.push((name.as_bytes(), value.as_bytes()));
        }

        // RFC 9114 Section 4.1: Validate interim response headers
        crate::validation::validate_interim_response_headers(
            &all_headers
                .iter()
                .map(|(n, v)| {
                    (
                        String::from_utf8_lossy(n).to_string(),
                        String::from_utf8_lossy(v).to_string(),
                    )
                })
                .collect::<Vec<_>>(),
        )?;

        // Encode headers with QPACK
        let mut encoder_guard = self.qpack_encoder.borrow_mut();
        let encoded_headers = encoder_guard
            .encode(self.stream_id, &all_headers)
            .map_err(|_| H3Error::Qpack("encoding failed".into()))?;

        // PERF #3: Batch encoder instructions into single write
        let mut batched_instructions = bytes::BytesMut::new();
        while let Some(inst) = encoder_guard.poll_encoder_stream() {
            batched_instructions.extend_from_slice(inst.as_ref());
        }

        if !batched_instructions.is_empty() {
            if let Some(encoder_stream) = self.encoder_send_stream.borrow_mut().as_mut() {
                let _ = encoder_stream.try_write(batched_instructions.freeze(), false);
            }
        }

        // Send HEADERS frame (no FIN - more data may follow)
        let headers_frame = crate::frames::H3Frame::Headers { encoded_headers };
        let frame_data = headers_frame.encode();
        self.send_stream
            .try_write(frame_data, false)
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
    pub fn send_push_promise(
        &mut self,
        headers: Vec<(String, String)>,
    ) -> Result<u64, H3Error> {
        // Validate push promise headers
        validate_push_promise_headers(&headers)?;

        let push_manager = self
            .push_manager
            .as_ref()
            .ok_or_else(|| H3Error::Http("server push not available".into()))?;

        let mut manager = push_manager.borrow_mut();

        // GAP FIX #4: RFC 9114 Section 7.2.7: Validate push_id against client's MAX_PUSH_ID
        // Note: We need access to max_push_id from H3Session, which isn't available here
        // This should be checked in H3Session when allocating the push

        // Allocate a new push ID
        let push_id = manager.allocate_push_id()?;

        // Register the push promise
        manager.register_promise(push_id, headers.clone())?;

        // Encode headers for PUSH_PROMISE frame
        let headers_bytes: Vec<(&[u8], &[u8])> = headers
            .iter()
            .map(|(n, v)| (n.as_bytes(), v.as_bytes()))
            .collect();

        let mut encoder_guard = self.qpack_encoder.borrow_mut();
        let encoded_headers = encoder_guard
            .encode(self.stream_id, &headers_bytes)
            .map_err(|_| H3Error::Qpack("encoding failed".into()))?;

        // PERF #3: Batch encoder instructions into single write
        let mut batched_instructions = bytes::BytesMut::new();
        while let Some(inst) = encoder_guard.poll_encoder_stream() {
            batched_instructions.extend_from_slice(inst.as_ref());
        }

        if !batched_instructions.is_empty() {
            if let Some(encoder_stream) = self.encoder_send_stream.borrow_mut().as_mut() {
                let _ = encoder_stream.try_write(batched_instructions.freeze(), false);
            }
        }

        // Send PUSH_PROMISE frame on the request stream
        let push_promise = crate::frames::H3Frame::PushPromise {
            push_id,
            encoded_headers,
        };
        let frame_data = push_promise.encode();
        self.send_stream
            .try_write(frame_data, false)
            .map_err(|e| H3Error::Stream(format!("write failed: {:?}", e)))?;

        Ok(push_id)
    }

    /// Send an HTTP/3 datagram.
    ///
    /// Per RFC 9297: Datagrams carry a flow identifier and payload.
    /// They are unreliable and may be lost or reordered.
    ///
    /// # Arguments
    /// * `flow_id` - The Quarter Stream ID identifying the datagram flow
    /// * `payload` - The datagram payload bytes
    ///
    /// # Errors
    /// Returns error if H3_DATAGRAM is not enabled
    pub fn send_datagram(&mut self, flow_id: u64, payload: Bytes) -> Result<(), H3Error> {
        let handle = self
            .connection_handle
            .as_ref()
            .ok_or_else(|| H3Error::Http("connection handle not available".into()))?;

        // Encode flow ID as varint prefix
        let flow_id_bytes = crate::frames::H3Frame::encode_varint_to_bytes(flow_id);
        let mut datagram_data =
            bytes::BytesMut::with_capacity(flow_id_bytes.len() + payload.len());
        datagram_data.extend_from_slice(&flow_id_bytes);
        datagram_data.extend_from_slice(&payload);

        // Send datagram
        let _request_id = handle
            .send_datagram(datagram_data.freeze())
            .map_err(|e| H3Error::Connection(format!("failed to send datagram: {:?}", e)))?;

        Ok(())
    }
}

/// Trait that applications implement to handle HTTP/3 requests.
///
/// This trait provides the interface for handling incoming HTTP/3 requests
/// and sending responses. It's designed to be simple and ergonomic.
pub trait H3Handler: Send + Sync + 'static {
    /// Handles an incoming HTTP/3 request.
    ///
    /// # Arguments
    /// - `request`: The parsed HTTP request
    /// - `sender`: Handle to send the response
    ///
    /// # Returns
    /// Result indicating success or error
    fn handle_request(
        &self,
        request: H3Request,
        sender: &mut H3ResponseSender,
    ) -> Result<(), H3Error>;

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
    fn handle_datagram(&self, _flow_id: u64, _payload: Bytes) -> Result<(), H3Error> {
        // Default: ignore datagrams
        Ok(())
    }
}

/// Default HTTP/3 handler that returns a simple 404 Not Found response.
///
/// This is a basic implementation for testing and development purposes.
#[derive(Clone)]
pub struct DefaultH3Handler;

impl H3Handler for DefaultH3Handler {
    fn handle_request(
        &self,
        request: H3Request,
        sender: &mut H3ResponseSender,
    ) -> Result<(), H3Error> {
        if request.method == Method::GET && request.uri.path() == "/" {
            let body = Bytes::from("Hello World");
            sender.send_response(
                200,
                vec![("content-type".to_string(), "text/plain".to_string())],
                body,
            )
        } else {
            let body = Bytes::from("404 Not Found");
            sender.send_response(
                404,
                vec![("content-type".to_string(), "text/plain".to_string())],
                body,
            )
        }
    }

    fn handle_datagram(&self, _flow_id: u64, _payload: Bytes) -> Result<(), H3Error> {
        Ok(())
    }
}
