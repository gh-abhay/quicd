//! GAP #8: RFC 9218 Extensible Priority Scheme comprehensive tests

use quicd_h3::priority::{PriorityTree, PriorityNode};

#[test]
fn test_rfc9218_weight_calculation() {
    // RFC 9218 Section 4: Weight = 2^(7 - urgency)
    let mut tree = PriorityTree::new();
    
    // Test all urgency levels
    let test_cases = vec![
        (0, 128), // 2^7 = 128
        (1, 64),  // 2^6 = 64
        (2, 32),  // 2^5 = 32
        (3, 16),  // 2^4 = 16
        (4, 8),   // 2^3 = 8
        (5, 4),   // 2^2 = 4
        (6, 2),   // 2^1 = 2
        (7, 1),   // 2^0 = 1
    ];
    
    for (urgency, expected_weight) in test_cases {
        tree.insert(PriorityNode {
            element_id: urgency as u64,
            element_type: 0,
            urgency,
            incremental: false,
            parent_id: None,
            children: vec![],
            weight: 0,  // Will be calculated
            bytes_sent: 0,
            active: false,
        });
        
        let node = tree.get(urgency as u64).unwrap();
        assert_eq!(node.weight, expected_weight,
            "Urgency {} should have weight {}, got {}", urgency, expected_weight, node.weight);
    }
}

#[test]
fn test_rfc9218_priority_selection() {
    // RFC 9218: Lower urgency (0) has higher priority than higher urgency (7)
    let mut tree = PriorityTree::new();
    
    // Add stream with urgency 7 (lowest priority)
    tree.insert(PriorityNode {
        element_id: 1,
        element_type: 0,
        urgency: 7,
        incremental: false,
        parent_id: None,
        children: vec![],
        weight: 0,
        bytes_sent: 0,
        active: true,
    });
    
    // Add stream with urgency 0 (highest priority)
    tree.insert(PriorityNode {
        element_id: 2,
        element_type: 0,
        urgency: 0,
        incremental: false,
        parent_id: None,
        children: vec![],
        weight: 0,
        bytes_sent: 0,
        active: true,
    });
    
    // Urgency 0 stream should be selected first
    let (selected_id, selected_urgency, selected_weight) = tree.get_next_priority().unwrap();
    assert_eq!(selected_id, 2);
    assert_eq!(selected_urgency, 0);
    assert_eq!(selected_weight, 128);
}

#[test]
fn test_rfc9218_same_urgency_round_robin() {
    // RFC 9218 Section 4: Streams with same urgency share bandwidth fairly
    let mut tree = PriorityTree::new();
    
    // Add three streams with same urgency
    for i in 1..=3 {
        tree.insert(PriorityNode {
            element_id: i,
            element_type: 0,
            urgency: 3,
            incremental: false,
            parent_id: None,
            children: vec![],
            weight: 0,
            bytes_sent: 0,
            active: true,
        });
    }
    
    // Should round-robin among them
    let mut selected_ids = vec![];
    for _ in 0..6 {
        if let Some((id, _, _)) = tree.get_next_priority() {
            selected_ids.push(id);
        }
    }
    
    // All three should be selected at least once in 6 iterations
    assert!(selected_ids.contains(&1));
    assert!(selected_ids.contains(&2));
    assert!(selected_ids.contains(&3));
}

#[test]
fn test_rfc9218_active_inactive_streams() {
    // Only active streams should be scheduled
    let mut tree = PriorityTree::new();
    
    // Add active stream
    tree.insert(PriorityNode {
        element_id: 1,
        element_type: 0,
        urgency: 0,
        incremental: false,
        parent_id: None,
        children: vec![],
        weight: 0,
        bytes_sent: 0,
        active: true,
    });
    
    // Add inactive stream (even though it has same priority)
    tree.insert(PriorityNode {
        element_id: 2,
        element_type: 0,
        urgency: 0,
        incremental: false,
        parent_id: None,
        children: vec![],
        weight: 0,
        bytes_sent: 0,
        active: false,
    });
    
    // Only active stream should be returned
    let (selected_id, _, _) = tree.get_next_priority().unwrap();
    assert_eq!(selected_id, 1);
}

#[test]
fn test_rfc9218_mark_active_inactive() {
    let mut tree = PriorityTree::new();
    
    tree.insert(PriorityNode {
        element_id: 1,
        element_type: 0,
        urgency: 3,
        incremental: false,
        parent_id: None,
        children: vec![],
        weight: 0,
        bytes_sent: 0,
        active: true,
    });
    
    // Should be selectable when active
    assert!(tree.get_next_priority().is_some());
    
    // Mark as inactive
    tree.mark_active(1, false);
    
    // Should not be selectable when inactive
    assert!(tree.get_next_priority().is_none());
    
    // Mark as active again
    tree.mark_active(1, true);
    
    // Should be selectable again
    assert!(tree.get_next_priority().is_some());
}

#[test]
fn test_rfc9218_bandwidth_tracking() {
    let mut tree = PriorityTree::new();
    
    tree.insert(PriorityNode {
        element_id: 1,
        element_type: 0,
        urgency: 3,
        incremental: false,
        parent_id: None,
        children: vec![],
        weight: 0,
        bytes_sent: 0,
        active: true,
    });
    
    // Record bytes sent
    tree.record_bytes_sent(1, 1024);
    tree.record_bytes_sent(1, 2048);
    
    // Should accumulate
    let node = tree.get(1).unwrap();
    assert_eq!(node.bytes_sent, 3072);
}

#[test]
fn test_rfc9218_incremental_flag() {
    // RFC 9218: Incremental flag affects how responses are delivered
    // Incremental=true means send in chunks, incremental=false means buffer until complete
    let mut tree = PriorityTree::new();
    
    tree.insert(PriorityNode {
        element_id: 1,
        element_type: 0,
        urgency: 3,
        incremental: true,  // Send incrementally
        parent_id: None,
        children: vec![],
        weight: 0,
        bytes_sent: 0,
        active: true,
    });
    
    let node = tree.get(1).unwrap();
    assert!(node.incremental);
}

#[test]
fn test_rfc9218_no_active_streams() {
    let mut tree = PriorityTree::new();
    
    // Add only inactive streams
    tree.insert(PriorityNode {
        element_id: 1,
        element_type: 0,
        urgency: 3,
        incremental: false,
        parent_id: None,
        children: vec![],
        weight: 0,
        bytes_sent: 0,
        active: false,
    });
    
    // Should return None when no active streams
    assert!(tree.get_next_priority().is_none());
}

#[test]
fn test_rfc9218_get_active_at_urgency() {
    let mut tree = PriorityTree::new();
    
    // Add streams at different urgency levels
    for urgency in 0..4 {
        tree.insert(PriorityNode {
            element_id: urgency as u64,
            element_type: 0,
            urgency,
            incremental: false,
            parent_id: None,
            children: vec![],
            weight: 0,
            bytes_sent: 0,
            active: urgency < 2, // Only 0 and 1 are active
        });
    }
    
    // Get active at urgency 0
    let active_at_0 = tree.get_active_at_urgency(0);
    assert_eq!(active_at_0.len(), 1);
    assert!(active_at_0.contains(&0));
    
    // Get active at urgency 2 (inactive)
    let active_at_2 = tree.get_active_at_urgency(2);
    assert_eq!(active_at_2.len(), 0);
}

#[test]
fn test_rfc9218_priority_update_reordering() {
    // Test that priority updates affect scheduling order
    let mut tree = PriorityTree::new();
    
    // Add stream with low priority
    tree.insert(PriorityNode {
        element_id: 1,
        element_type: 0,
        urgency: 7,  // Lowest priority
        incremental: false,
        parent_id: None,
        children: vec![],
        weight: 0,
        bytes_sent: 0,
        active: true,
    });
    
    // Add stream with medium priority
    tree.insert(PriorityNode {
        element_id: 2,
        element_type: 0,
        urgency: 3,  // Medium priority
        incremental: false,
        parent_id: None,
        children: vec![],
        weight: 0,
        bytes_sent: 0,
        active: true,
    });
    
    // Medium priority should be selected
    let (selected_id, _, _) = tree.get_next_priority().unwrap();
    assert_eq!(selected_id, 2);
    
    // Update stream 1 to highest priority
    tree.insert(PriorityNode {
        element_id: 1,
        element_type: 0,
        urgency: 0,  // Highest priority now
        incremental: false,
        parent_id: None,
        children: vec![],
        weight: 0,
        bytes_sent: 0,
        active: true,
    });
    
    // Now stream 1 should be selected due to higher priority
    let (selected_id, _, _) = tree.get_next_priority().unwrap();
    assert_eq!(selected_id, 1);
}
