//! Server push support per RFC 9114 Section 4.6.
//!
//! This module implements HTTP/3 server push, allowing servers to send
//! responses proactively before the client requests them.

use crate::error::H3Error;
use std::collections::HashMap;

/// State of a server push.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushState {
    /// Push promised but push stream not yet opened
    Promised,
    /// Push stream opened, sending response
    Sending,
    /// Push completed successfully
    Completed,
    /// Push cancelled by client
    Cancelled,
}

/// Response data for a server push.
#[derive(Debug, Clone)]
pub struct PushResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: bytes::Bytes,
}

/// Manages a single server push operation.
pub struct PushPromise {
    /// The push ID assigned to this push
    push_id: u64,
    /// Current state of the push
    state: PushState,
    /// Stream ID of the push stream (once opened)
    push_stream_id: Option<u64>,
    /// The request stream this push was promised on
    promised_on_stream: u64,
    /// Promised request headers
    headers: Vec<(String, String)>,
    /// Response data to send when stream opens
    response: Option<PushResponse>,
}

impl PushPromise {
    /// Create a new push promise.
    pub fn new(push_id: u64, promised_on_stream: u64, headers: Vec<(String, String)>) -> Self {
        Self {
            push_id,
            state: PushState::Promised,
            push_stream_id: None,
            promised_on_stream,
            headers,
            response: None,
        }
    }

    /// Set the response data for this push.
    pub fn set_response(&mut self, response: PushResponse) {
        self.response = Some(response);
    }

    /// Get the response data if set.
    pub fn response(&self) -> Option<&PushResponse> {
        self.response.as_ref()
    }

    /// Get the push ID.
    pub fn push_id(&self) -> u64 {
        self.push_id
    }

    /// Get the current state.
    pub fn state(&self) -> PushState {
        self.state
    }

    /// Get the push stream ID if opened.
    pub fn push_stream_id(&self) -> Option<u64> {
        self.push_stream_id
    }

    /// Mark the push stream as opened.
    pub fn set_push_stream_id(&mut self, stream_id: u64) {
        self.push_stream_id = Some(stream_id);
        self.state = PushState::Sending;
    }

    /// Mark the push as completed.
    pub fn mark_completed(&mut self) {
        self.state = PushState::Completed;
    }

    /// Mark the push as cancelled.
    pub fn mark_cancelled(&mut self) {
        self.state = PushState::Cancelled;
    }

    /// Check if the push is cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.state == PushState::Cancelled
    }

    /// Get the promised headers.
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }
}

/// Manager for server push operations.
///
/// Per RFC 9114 Section 4.6:
/// - Server can send PUSH_PROMISE on request streams
/// - Each push has a unique push ID
/// - Push responses sent on unidirectional push streams
/// - Client can cancel pushes with CANCEL_PUSH
/// - Server advertises MAX_PUSH_ID limit
pub struct PushManager {
    /// Next push ID to allocate
    next_push_id: u64,
    /// Maximum push ID we can use (from client's MAX_PUSH_ID)
    max_push_id: u64,
    /// Active push promises by push ID
    promises: HashMap<u64, PushPromise>,
    /// Pending push stream open requests (request_id -> push_id)
    pending_push_streams: HashMap<u64, u64>,
}

impl PushManager {
    /// Create a new push manager.
    pub fn new() -> Self {
        Self {
            next_push_id: 0,
            max_push_id: 0,
            promises: HashMap::new(),
            pending_push_streams: HashMap::new(),
        }
    }

    /// Update the maximum push ID from client's MAX_PUSH_ID frame.
    ///
    /// Per RFC 9114 Section 7.2.7: Server MUST NOT send PUSH_PROMISE
    /// with push ID greater than the limit set by client.
    pub fn update_max_push_id(&mut self, max_push_id: u64) {
        self.max_push_id = max_push_id;
    }

    /// Get the current max push ID.
    pub fn max_push_id(&self) -> u64 {
        self.max_push_id
    }

    /// Allocate a new push ID.
    ///
    /// Returns error if we've exceeded MAX_PUSH_ID.
    pub fn allocate_push_id(&mut self) -> Result<u64, H3Error> {
        if self.next_push_id > self.max_push_id {
            return Err(H3Error::Http(format!(
                "exceeded MAX_PUSH_ID: next={}, max={}",
                self.next_push_id, self.max_push_id
            )));
        }

        let push_id = self.next_push_id;
        self.next_push_id += 1;
        Ok(push_id)
    }

    /// Register a push promise.
    pub fn register_promise(
        &mut self,
        push_id: u64,
        stream_id: u64,
        headers: Vec<(String, String)>,
    ) -> Result<(), H3Error> {
        if self.promises.contains_key(&push_id) {
            return Err(H3Error::Http(format!(
                "push ID {} already in use",
                push_id
            )));
        }

        self.promises.insert(
            push_id,
            PushPromise::new(push_id, stream_id, headers),
        );
        Ok(())
    }

    /// Get a push promise by ID.
    pub fn get_promise(&self, push_id: u64) -> Option<&PushPromise> {
        self.promises.get(&push_id)
    }

    /// Get a mutable push promise by ID.
    pub fn get_promise_mut(&mut self, push_id: u64) -> Option<&mut PushPromise> {
        self.promises.get_mut(&push_id)
    }

    /// Cancel a push.
    ///
    /// Per RFC 9114 Section 7.2.5: Client sends CANCEL_PUSH to indicate
    /// it doesn't want the push.
    pub fn cancel_push(&mut self, push_id: u64) -> Result<(), H3Error> {
        if let Some(promise) = self.promises.get_mut(&push_id) {
            promise.mark_cancelled();
            Ok(())
        } else {
            // Per RFC 9114: CANCEL_PUSH for unknown push ID is not an error
            Ok(())
        }
    }

    /// Register a pending push stream open request.
    pub fn register_pending_stream(&mut self, request_id: u64, push_id: u64) {
        self.pending_push_streams.insert(request_id, push_id);
    }

    /// Handle a push stream being opened.
    pub fn handle_stream_opened(&mut self, request_id: u64, stream_id: u64) -> Result<(), H3Error> {
        if let Some(push_id) = self.pending_push_streams.remove(&request_id) {
            if let Some(promise) = self.promises.get_mut(&push_id) {
                promise.set_push_stream_id(stream_id);
                Ok(())
            } else {
                Err(H3Error::Http(format!("push ID {} not found", push_id)))
            }
        } else {
            // Not a push stream open request
            Ok(())
        }
    }

    /// Remove completed or cancelled pushes.
    pub fn cleanup(&mut self) {
        self.promises.retain(|_, promise| {
            !matches!(promise.state(), PushState::Completed | PushState::Cancelled)
        });
    }

    /// Get the number of active pushes.
    pub fn active_push_count(&self) -> usize {
        self.promises.len()
    }
}

impl Default for PushManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate push promise headers.
///
/// Per RFC 9114 Section 4.6: PUSH_PROMISE must contain request headers
/// that the server is promising to respond to.
pub fn validate_push_promise_headers(headers: &[(String, String)]) -> Result<(), H3Error> {
    let mut has_method = false;
    let mut has_scheme = false;
    let mut has_authority = false;
    let mut has_path = false;

    for (name, _) in headers {
        if name.starts_with(':') {
            match name.as_str() {
                ":method" => has_method = true,
                ":scheme" => has_scheme = true,
                ":authority" => has_authority = true,
                ":path" => has_path = true,
                _ => {
                    return Err(H3Error::Http(format!(
                        "invalid pseudo-header in PUSH_PROMISE: {}",
                        name
                    )));
                }
            }
        }
    }

    // All four pseudo-headers are required for PUSH_PROMISE
    if !has_method || !has_scheme || !has_authority || !has_path {
        return Err(H3Error::Http(
            "PUSH_PROMISE missing required pseudo-headers".into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_push_manager_allocation() {
        let mut manager = PushManager::new();
        manager.update_max_push_id(10);

        // Should be able to allocate up to max_push_id
        for i in 0..=10 {
            assert_eq!(manager.allocate_push_id().unwrap(), i);
        }

        // Exceeding max should fail
        assert!(manager.allocate_push_id().is_err());
    }

    #[test]
    fn test_push_promise_lifecycle() {
        let mut manager = PushManager::new();
        manager.update_max_push_id(100);

        let push_id = manager.allocate_push_id().unwrap();
        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.com".to_string()),
            (":path".to_string(), "/style.css".to_string()),
        ];

        manager.register_promise(push_id, 4, headers).unwrap();

        let promise = manager.get_promise(push_id).unwrap();
        assert_eq!(promise.state(), PushState::Promised);
        assert_eq!(promise.push_id(), push_id);
    }

    #[test]
    fn test_push_cancellation() {
        let mut manager = PushManager::new();
        manager.update_max_push_id(100);

        let push_id = manager.allocate_push_id().unwrap();
        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.com".to_string()),
            (":path".to_string(), "/style.css".to_string()),
        ];

        manager.register_promise(push_id, 4, headers).unwrap();
        manager.cancel_push(push_id).unwrap();

        let promise = manager.get_promise(push_id).unwrap();
        assert_eq!(promise.state(), PushState::Cancelled);
        assert!(promise.is_cancelled());
    }

    #[test]
    fn test_push_stream_opening() {
        let mut manager = PushManager::new();
        manager.update_max_push_id(100);

        let push_id = manager.allocate_push_id().unwrap();
        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.com".to_string()),
            (":path".to_string(), "/style.css".to_string()),
        ];

        manager.register_promise(push_id, 4, headers).unwrap();

        // Simulate opening push stream
        let request_id = 1234;
        manager.register_pending_stream(request_id, push_id);
        manager.handle_stream_opened(request_id, 7).unwrap();

        let promise = manager.get_promise(push_id).unwrap();
        assert_eq!(promise.state(), PushState::Sending);
        assert_eq!(promise.push_stream_id(), Some(7));
    }

    #[test]
    fn test_validate_push_promise_headers() {
        // Valid headers
        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.com".to_string()),
            (":path".to_string(), "/resource".to_string()),
        ];
        assert!(validate_push_promise_headers(&headers).is_ok());

        // Missing :method
        let headers = vec![
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.com".to_string()),
            (":path".to_string(), "/resource".to_string()),
        ];
        assert!(validate_push_promise_headers(&headers).is_err());

        // Invalid pseudo-header
        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.com".to_string()),
            (":path".to_string(), "/resource".to_string()),
            (":invalid".to_string(), "value".to_string()),
        ];
        assert!(validate_push_promise_headers(&headers).is_err());
    }

    #[test]
    fn test_duplicate_push_id() {
        let mut manager = PushManager::new();
        manager.update_max_push_id(100);

        let push_id = manager.allocate_push_id().unwrap();
        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.com".to_string()),
            (":path".to_string(), "/style.css".to_string()),
        ];

        manager.register_promise(push_id, 4, headers.clone()).unwrap();

        // Duplicate should fail
        assert!(manager.register_promise(push_id, 4, headers).is_err());
    }

    #[test]
    fn test_cleanup() {
        let mut manager = PushManager::new();
        manager.update_max_push_id(100);

        let push_id1 = manager.allocate_push_id().unwrap();
        let push_id2 = manager.allocate_push_id().unwrap();
        let push_id3 = manager.allocate_push_id().unwrap();

        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.com".to_string()),
            (":path".to_string(), "/style.css".to_string()),
        ];

        manager.register_promise(push_id1, 4, headers.clone()).unwrap();
        manager.register_promise(push_id2, 4, headers.clone()).unwrap();
        manager.register_promise(push_id3, 4, headers).unwrap();

        manager.get_promise_mut(push_id1).unwrap().mark_completed();
        manager.get_promise_mut(push_id2).unwrap().mark_cancelled();

        assert_eq!(manager.active_push_count(), 3);
        manager.cleanup();
        assert_eq!(manager.active_push_count(), 1);

        assert!(manager.get_promise(push_id3).is_some());
    }
}
