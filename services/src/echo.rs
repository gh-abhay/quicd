use crate::{Service, ServiceRequest, ServiceResponse, Result};

/// Echo service - echoes back received data
pub struct EchoService;

impl EchoService {
    pub fn new() -> Self {
        Self
    }
}

impl Service for EchoService {
    fn handle_request(&mut self, req: ServiceRequest) -> Result<Option<ServiceResponse>> {
        // Echo back the data
        let response = ServiceResponse {
            conn_id: req.conn_id,
            stream_id: Some(req.stream_id),
            data: req.data,
            fin: true, // Close the stream after echo
            is_datagram: req.is_datagram,
        };
        Ok(Some(response))
    }
}