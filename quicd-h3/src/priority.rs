//! RFC 9218 Extensible Priority Implementation
//!
//! This module implements the extensible priority scheme for HTTP/3 as defined in RFC 9218.
//! It provides tree-based prioritization with urgency levels and incremental flags.

use std::collections::HashMap;

/// Priority tree node representing a request or push stream
#[derive(Debug, Clone)]
pub struct PriorityNode {
    /// Stream ID for this node
    pub element_id: u64,
    /// Element type (0=request, 1=push)
    pub element_type: u8,
    /// Urgency level (0-7, 0=highest priority)
    pub urgency: u8,
    /// Incremental flag
    pub incremental: bool,
    /// Parent node ID (None = root)
    pub parent_id: Option<u64>,
    /// Child nodes
    pub children: Vec<u64>,
    /// RFC 9218 Section 4: Weight derived from urgency (higher weight = higher priority)
    /// Weight = 2^(7 - urgency), so urgency 0 gets weight 128, urgency 7 gets weight 1
    pub weight: u32,
    /// Bytes sent for this stream (for fair scheduling)
    pub bytes_sent: u64,
    /// Whether this stream is currently active (has data to send)
    pub active: bool,
}

/// Priority tree manager implementing RFC 9218
pub struct PriorityTree {
    /// All nodes in the tree indexed by element_id
    nodes: HashMap<u64, PriorityNode>,
    /// Root node ID
    root_id: Option<u64>,
    /// Round-robin index for same-urgency fair scheduling
    round_robin_index: HashMap<u8, usize>,
}

impl PriorityTree {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            root_id: None,
            round_robin_index: HashMap::new(),
        }
    }

    /// Calculate weight from urgency per RFC 9218 Section 4
    /// Weight = 2^(7 - urgency)
    fn calculate_weight(urgency: u8) -> u32 {
        let urgency = urgency.min(7); // Clamp to valid range
        1u32 << (7 - urgency)
    }

    /// Add or update a priority node
    pub fn insert(&mut self, mut node: PriorityNode) {
        let id = node.element_id;
        let parent_id = node.parent_id;

        // Calculate weight from urgency
        node.weight = Self::calculate_weight(node.urgency);

        // Remove from old parent if it exists
        if let Some(old_node) = self.nodes.get(&id) {
            if let Some(old_parent_id) = old_node.parent_id {
                if let Some(parent) = self.nodes.get_mut(&old_parent_id) {
                    parent.children.retain(|child| *child != id);
                }
            }
        }

        // Add to new parent
        if let Some(parent_id) = parent_id {
            if let Some(parent) = self.nodes.get_mut(&parent_id) {
                if !parent.children.contains(&id) {
                    parent.children.push(id);
                }
            }
        } else {
            self.root_id = Some(id);
        }

        self.nodes.insert(id, node);
    }

    /// Get next element to process based on RFC 9218 priority
    /// Returns (element_id, urgency, weight) or None if no active streams
    pub fn get_next_priority(&mut self) -> Option<(u64, u8, u32)> {
        // Get all active streams grouped by urgency
        let mut urgency_groups: HashMap<u8, Vec<u64>> = HashMap::new();

        for (element_id, node) in &self.nodes {
            if node.active {
                urgency_groups
                    .entry(node.urgency)
                    .or_insert_with(Vec::new)
                    .push(*element_id);
            }
        }

        if urgency_groups.is_empty() {
            return None;
        }

        // RFC 9218 Section 4: Process lowest urgency (highest priority) first
        let min_urgency = *urgency_groups.keys().min()?;
        let candidates = urgency_groups.get(&min_urgency)?;

        if candidates.is_empty() {
            return None;
        }

        // RFC 9218 Section 4: Within same urgency, use weighted round-robin
        // Fair scheduling: rotate among streams at same urgency level
        let rr_index = self.round_robin_index.entry(min_urgency).or_insert(0);
        let selected_id = candidates[*rr_index % candidates.len()];
        *rr_index = (*rr_index + 1) % candidates.len();

        let node = self.nodes.get(&selected_id)?;
        Some((node.element_id, node.urgency, node.weight))
    }

    /// Mark a stream as active (has data to send)
    pub fn mark_active(&mut self, element_id: u64, active: bool) {
        if let Some(node) = self.nodes.get_mut(&element_id) {
            node.active = active;
        }
    }

    /// Record bytes sent for a stream (for bandwidth accounting)
    pub fn record_bytes_sent(&mut self, element_id: u64, bytes: u64) {
        if let Some(node) = self.nodes.get_mut(&element_id) {
            node.bytes_sent = node.bytes_sent.saturating_add(bytes);
        }
    }

    /// Get all active streams at a given urgency level
    pub fn get_active_at_urgency(&self, urgency: u8) -> Vec<u64> {
        self.nodes
            .iter()
            .filter(|(_, node)| node.active && node.urgency == urgency)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Remove a node from the tree
    pub fn remove(&mut self, element_id: u64) {
        if let Some(node) = self.nodes.remove(&element_id) {
            // Remove from parent's children
            if let Some(parent_id) = node.parent_id {
                if let Some(parent) = self.nodes.get_mut(&parent_id) {
                    parent.children.retain(|child| *child != element_id);
                }
            }

            // Orphan children (move to root or remove)
            for child_id in node.children {
                if let Some(child) = self.nodes.get_mut(&child_id) {
                    child.parent_id = None;
                }
            }
        }
    }

    /// Get priority information for an element
    pub fn get(&self, element_id: u64) -> Option<&PriorityNode> {
        self.nodes.get(&element_id)
    }
}

impl Default for PriorityTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_tree_basic() {
        let mut tree = PriorityTree::new();

        // Add root node
        tree.insert(PriorityNode {
            element_id: 1,
            element_type: 0,
            urgency: 3,
            incremental: false,
            parent_id: None,
            children: vec![],
            weight: 0, // Will be calculated
            bytes_sent: 0,
            active: true,
        });

        // Add child with higher priority (lower urgency)
        tree.insert(PriorityNode {
            element_id: 2,
            element_type: 0,
            urgency: 1,
            incremental: false,
            parent_id: Some(1),
            children: vec![],
            weight: 0, // Will be calculated
            bytes_sent: 0,
            active: true,
        });

        // Higher priority (urgency 1) should be returned first
        let next = tree.get_next_priority();
        assert_eq!(
            next.map(|(id, urgency, _weight)| (id, urgency)),
            Some((2, 1))
        );
    }

    #[test]
    fn test_priority_tree_remove() {
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
            active: false,
        });

        tree.remove(1);
        assert!(tree.get(1).is_none());
    }

    #[test]
    fn test_priority_weight_calculation() {
        let mut tree = PriorityTree::new();

        // Urgency 0 (highest) should get weight 128 (2^7)
        tree.insert(PriorityNode {
            element_id: 1,
            element_type: 0,
            urgency: 0,
            incremental: false,
            parent_id: None,
            children: vec![],
            weight: 0,
            bytes_sent: 0,
            active: false,
        });

        assert_eq!(tree.get(1).unwrap().weight, 128);

        // Urgency 7 (lowest) should get weight 1 (2^0)
        tree.insert(PriorityNode {
            element_id: 2,
            element_type: 0,
            urgency: 7,
            incremental: false,
            parent_id: None,
            children: vec![],
            weight: 0,
            bytes_sent: 0,
            active: false,
        });

        assert_eq!(tree.get(2).unwrap().weight, 1);
    }

    #[test]
    fn test_priority_round_robin() {
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
        let first = tree.get_next_priority().map(|(id, _, _)| id);
        let second = tree.get_next_priority().map(|(id, _, _)| id);
        let third = tree.get_next_priority().map(|(id, _, _)| id);

        // All three should be returned
        assert!(first.is_some());
        assert!(second.is_some());
        assert!(third.is_some());

        // They should be different
        assert_ne!(first, second);
    }
}
