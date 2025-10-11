use crate::{Service, ServiceRequest, ServiceResponse, Result};
use bytes::Bytes;
use serde_json::json;

/// HTTP/3 service - returns hello world JSON for any path
pub struct Http3Service;

impl Http3Service {
    pub fn new() -> Self {
        Self
    }
}

impl Service for Http3Service {
    fn handle_request(&mut self, req: ServiceRequest) -> Result<Option<ServiceResponse>> {
        // For simplicity, assume the request is HTTP/3
        // In reality, parse HTTP/3 headers
        let response_body = json!({
            "message": "Hello World",
            "path": "any", // In real impl, parse from request
            "timestamp": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        });

        let response_data = serde_json::to_vec(&response_body).unwrap();
        let response = ServiceResponse {
            conn_id: req.conn_id,
            stream_id: Some(req.stream_id),
            data: Bytes::from(response_data),
            fin: true,
            is_datagram: false, // HTTP/3 uses streams
        };
        Ok(Some(response))
    }
}