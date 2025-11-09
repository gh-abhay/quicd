use async_trait::async_trait;
use bytes::Bytes;
use http::{Method, Uri};

use crate::error::H3Error;

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
    pub(crate) qpack: std::sync::Arc<crate::qpack::QpackCodec>,
}

impl H3ResponseSender {
    /// Send an HTTP/3 response.
    pub async fn send_response(&mut self, status: u16, headers: Vec<(String, String)>, body: Bytes) -> Result<(), H3Error> {
        // Encode headers
        let mut all_headers = vec![
            (":status".to_string(), status.to_string()),
        ];
        all_headers.extend(headers);

        let encoded_headers = self.qpack.encode_headers(&all_headers)
            .map_err(|_| H3Error::Qpack("encoding failed".into()))?;

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
    /// Returns the push ID that was assigned to this push.
    pub async fn send_push_promise(&mut self, _headers: Vec<(String, String)>) -> Result<u64, H3Error> {
        // TODO: This needs access to the session to get the next push ID
        // For now, return an error indicating this is not implemented
        Err(H3Error::Http("PUSH_PROMISE not yet implemented".into()))
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