use bytes::Bytes;
use std::collections::HashMap;
use thiserror::Error;

pub mod echo;
pub mod http3;

#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("Service error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, ServiceError>;

/// Service request
#[derive(Debug)]
pub struct ServiceRequest {
    pub conn_id: u64,
    pub stream_id: u64,
    pub data: Bytes,
    pub is_datagram: bool,
}

/// Service response
#[derive(Debug)]
pub struct ServiceResponse {
    pub conn_id: u64,
    pub stream_id: Option<u64>, // None for datagrams
    pub data: Bytes,
    pub fin: bool,
    pub is_datagram: bool,
}

/// Service trait
pub trait Service {
    fn handle_request(&mut self, req: ServiceRequest) -> Result<Option<ServiceResponse>>;
}

/// Service registry
pub struct ServiceRegistry {
    services: HashMap<String, Box<dyn Service + Send + Sync>>,
}

impl ServiceRegistry {
    pub fn new() -> Self {
        Self {
            services: HashMap::new(),
        }
    }

    pub fn register(&mut self, name: String, service: Box<dyn Service + Send + Sync>) {
        self.services.insert(name, service);
    }

    pub fn handle_request(&mut self, service_name: &str, req: ServiceRequest) -> Result<Option<ServiceResponse>> {
        if let Some(service) = self.services.get_mut(service_name) {
            service.handle_request(req)
        } else {
            Err(ServiceError::Other(format!("Service {} not found", service_name)))
        }
    }
}