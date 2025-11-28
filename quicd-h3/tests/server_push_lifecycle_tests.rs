/// Tests for server push lifecycle including cancellation, cleanup, and error handling
/// Per RFC 9114 Section 4.6 (Server Push)
use quicd_h3::push::{PushManager, PushResponse, PushState};

#[test]
fn test_push_allocation_respects_max_push_id() {
    let mut manager = PushManager::new();
    
    // Set MAX_PUSH_ID to 5
    manager.update_max_push_id(5);
    
    // Allocate push IDs up to the limit
    assert_eq!(manager.allocate_push_id().unwrap(), 0);
    assert_eq!(manager.allocate_push_id().unwrap(), 1);
    assert_eq!(manager.allocate_push_id().unwrap(), 2);
    assert_eq!(manager.allocate_push_id().unwrap(), 3);
    assert_eq!(manager.allocate_push_id().unwrap(), 4);
    assert_eq!(manager.allocate_push_id().unwrap(), 5);
    
    // Next allocation should fail
    assert!(manager.allocate_push_id().is_err());
}

#[test]
fn test_push_cancellation_before_stream_opens() {
    let mut manager = PushManager::new();
    manager.update_max_push_id(10);
    
    let push_id = manager.allocate_push_id().unwrap();
    let headers = vec![
        (":method".to_string(), "GET".to_string()),
        (":scheme".to_string(), "https".to_string()),
        (":authority".to_string(), "example.com".to_string()),
        (":path".to_string(), "/style.css".to_string()),
    ];
    
    manager.register_promise(push_id, headers).unwrap();
    
    // Set response after registration
    let response = PushResponse {
        status: 200,
        headers: vec![("content-type".to_string(), "text/css".to_string())],
        body: bytes::Bytes::from("body { color: red; }"),
    };
    manager.get_promise_mut(push_id).unwrap().set_response(response);
    
    // Cancel the push before stream opens
    assert!(manager.cancel_push(push_id).is_ok());
    
    // Verify push is cancelled
    assert!(manager.get_promise(push_id).unwrap().is_cancelled());
}

#[test]
fn test_push_cancellation_after_stream_opens() {
    let mut manager = PushManager::new();
    manager.update_max_push_id(10);
    
    let push_id = manager.allocate_push_id().unwrap();
    let headers = vec![
        (":method".to_string(), "GET".to_string()),
        (":scheme".to_string(), "https".to_string()),
        (":authority".to_string(), "example.com".to_string()),
        (":path".to_string(), "/script.js".to_string()),
    ];
    
    manager.register_promise(push_id, headers).unwrap();
    
    // Set response
    let response = PushResponse {
        status: 200,
        headers: vec![("content-type".to_string(), "application/javascript".to_string())],
        body: bytes::Bytes::from("console.log('test');"),
    };
    manager.get_promise_mut(push_id).unwrap().set_response(response);
    
    // Register pending stream and open it
    let request_id = 1;
    manager.register_pending_stream(request_id, push_id);
    let stream_id = 100;
    manager.handle_stream_opened(request_id, stream_id).unwrap();
    
    // Verify stream is tracked
    assert_eq!(manager.get_promise(push_id).unwrap().push_stream_id(), Some(stream_id));
    assert_eq!(manager.get_promise(push_id).unwrap().state(), PushState::Sending);
    
    // Cancel the push after stream opened
    assert!(manager.cancel_push(push_id).is_ok());
    
    // Verify push is cancelled
    assert!(manager.get_promise(push_id).unwrap().is_cancelled());
    
    // Stream ID should still be tracked
    assert_eq!(manager.get_promise(push_id).unwrap().push_stream_id(), Some(stream_id));
}

#[test]
fn test_push_lifecycle_complete_flow() {
    let mut manager = PushManager::new();
    manager.update_max_push_id(10);
    
    // 1. Allocate push ID
    let push_id = manager.allocate_push_id().unwrap();
    
    // 2. Register promise
    let headers = vec![
        (":method".to_string(), "GET".to_string()),
        (":scheme".to_string(), "https".to_string()),
        (":authority".to_string(), "example.com".to_string()),
        (":path".to_string(), "/resource.json".to_string()),
    ];
    manager.register_promise(push_id, headers).unwrap();
    
    // 3. Set response
    let response = PushResponse {
        status: 200,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: bytes::Bytes::from(r#"{"key": "value"}"#),
    };
    manager.get_promise_mut(push_id).unwrap().set_response(response);
    
    // 4. Verify promise is in Promised state
    assert_eq!(manager.get_promise(push_id).unwrap().state(), PushState::Promised);
    
    // 5. Register pending stream and open it
    let request_id = 1;
    manager.register_pending_stream(request_id, push_id);
    let stream_id = 200;
    manager.handle_stream_opened(request_id, stream_id).unwrap();
    
    // 6. Verify now in Sending state (set_push_stream_id transitions to Sending)
    assert_eq!(manager.get_promise(push_id).unwrap().state(), PushState::Sending);
    
    // 7. Mark as completed
    manager.get_promise_mut(push_id).unwrap().mark_completed();
    assert_eq!(manager.get_promise(push_id).unwrap().state(), PushState::Completed);
    
    // 8. Cleanup removes completed push
    manager.cleanup();
    assert!(manager.get_promise(push_id).is_none());
}

#[test]
fn test_cleanup_removes_cancelled_pushes() {
    let mut manager = PushManager::new();
    manager.update_max_push_id(10);
    
    // Create and cancel a push
    let push_id = manager.allocate_push_id().unwrap();
    let headers = vec![
        (":method".to_string(), "GET".to_string()),
        (":scheme".to_string(), "https".to_string()),
        (":authority".to_string(), "example.com".to_string()),
        (":path".to_string(), "/cancelled.html".to_string()),
    ];
    
    manager.register_promise(push_id, headers).unwrap();
    manager.cancel_push(push_id).unwrap();
    
    // Verify cancelled
    assert!(manager.get_promise(push_id).unwrap().is_cancelled());
    
    // Cleanup should remove it
    manager.cleanup();
    assert!(manager.get_promise(push_id).is_none());
}

#[test]
fn test_cleanup_preserves_active_pushes() {
    let mut manager = PushManager::new();
    manager.update_max_push_id(10);
    
    // Create an active push (stays in Promised state)
    let push_id1 = manager.allocate_push_id().unwrap();
    let headers1 = vec![
        (":method".to_string(), "GET".to_string()),
        (":scheme".to_string(), "https".to_string()),
        (":authority".to_string(), "example.com".to_string()),
        (":path".to_string(), "/active.html".to_string()),
    ];
    manager.register_promise(push_id1, headers1).unwrap();
    
    // Create and complete a push
    let push_id2 = manager.allocate_push_id().unwrap();
    let headers2 = vec![
        (":method".to_string(), "GET".to_string()),
        (":scheme".to_string(), "https".to_string()),
        (":authority".to_string(), "example.com".to_string()),
        (":path".to_string(), "/completed.html".to_string()),
    ];
    manager.register_promise(push_id2, headers2).unwrap();
    manager.get_promise_mut(push_id2).unwrap().mark_completed();
    
    // Cleanup should only remove completed
    manager.cleanup();
    
    assert!(manager.get_promise(push_id1).is_some()); // Active preserved
    assert!(manager.get_promise(push_id2).is_none()); // Completed removed
}

#[test]
fn test_max_push_id_getter() {
    let mut manager = PushManager::new();
    
    // Initial value
    assert_eq!(manager.max_push_id(), 0);
    
    // Set to 10
    manager.update_max_push_id(10);
    assert_eq!(manager.max_push_id(), 10);
    
    // Update to 20
    manager.update_max_push_id(20);
    assert_eq!(manager.max_push_id(), 20);
}

#[test]
fn test_multiple_pushes_lifecycle() {
    let mut manager = PushManager::new();
    manager.update_max_push_id(100);
    
    // Create multiple pushes
    let mut push_ids = vec![];
    for i in 0..5 {
        let push_id = manager.allocate_push_id().unwrap();
        push_ids.push(push_id);
        
        let headers = vec![
            (":method".to_string(), "GET".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":authority".to_string(), "example.com".to_string()),
            (":path".to_string(), format!("/resource{}.css", i)),
        ];
        
        manager.register_promise(push_id, headers).unwrap();
    }
    
    // Complete some, cancel others
    manager.get_promise_mut(push_ids[0]).unwrap().mark_completed();
    manager.cancel_push(push_ids[1]).unwrap();
    manager.get_promise_mut(push_ids[2]).unwrap().mark_completed();
    // push_ids[3] and push_ids[4] remain in Promised state
    
    // Before cleanup - all should exist
    assert_eq!(manager.active_push_count(), 5);
    
    // After cleanup - only active ones remain
    manager.cleanup();
    assert_eq!(manager.active_push_count(), 2); // Only [3] and [4]
    assert!(manager.get_promise(push_ids[3]).is_some());
    assert!(manager.get_promise(push_ids[4]).is_some());
}

#[test]
fn test_push_without_response_data() {
    let mut manager = PushManager::new();
    manager.update_max_push_id(10);
    
    let push_id = manager.allocate_push_id().unwrap();
    let headers = vec![
        (":method".to_string(), "GET".to_string()),
        (":scheme".to_string(), "https".to_string()),
        (":authority".to_string(), "example.com".to_string()),
        (":path".to_string(), "/no-data.html".to_string()),
    ];
    
    // Register promise without setting response data
    manager.register_promise(push_id, headers).unwrap();
    
    // Get promise and verify no response
    let promise = manager.get_promise(push_id).unwrap();
    assert!(promise.response().is_none());
    
    // In real scenario, this would trigger CANCEL_PUSH when we try to send
}

#[test]
fn test_pending_stream_tracking() {
    let mut manager = PushManager::new();
    manager.update_max_push_id(10);
    
    let push_id = manager.allocate_push_id().unwrap();
    let headers = vec![
        (":method".to_string(), "GET".to_string()),
        (":scheme".to_string(), "https".to_string()),
        (":authority".to_string(), "example.com".to_string()),
        (":path".to_string(), "/test.html".to_string()),
    ];
    
    manager.register_promise(push_id, headers).unwrap();
    
    // Initially no stream opened
    assert_eq!(manager.get_promise(push_id).unwrap().push_stream_id(), None);
    assert_eq!(manager.get_promise(push_id).unwrap().state(), PushState::Promised);
    
    // Register pending stream and open it
    let request_id = 42;
    manager.register_pending_stream(request_id, push_id);
    let stream_id = 200;
    manager.handle_stream_opened(request_id, stream_id).unwrap();
    
    // Now stream should be tracked and state transitioned to Sending
    assert_eq!(manager.get_promise(push_id).unwrap().push_stream_id(), Some(stream_id));
    assert_eq!(manager.get_promise(push_id).unwrap().state(), PushState::Sending);
}

#[test]
fn test_cancel_unknown_push_id() {
    let mut manager = PushManager::new();
    manager.update_max_push_id(10);
    
    // Per RFC 9114: Cancelling unknown push ID should not error
    assert!(manager.cancel_push(999).is_ok());
}

#[test]
fn test_duplicate_push_id_rejected() {
    let mut manager = PushManager::new();
    manager.update_max_push_id(10);
    
    let push_id = manager.allocate_push_id().unwrap();
    let headers = vec![
        (":method".to_string(), "GET".to_string()),
        (":scheme".to_string(), "https".to_string()),
        (":authority".to_string(), "example.com".to_string()),
        (":path".to_string(), "/test.html".to_string()),
    ];
    
    // First registration succeeds
    assert!(manager.register_promise(push_id, headers.clone()).is_ok());
    
    // Duplicate should fail
    assert!(manager.register_promise(push_id, headers).is_err());
}
