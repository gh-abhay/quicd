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
}

/// Priority tree manager implementing RFC 9218
pub struct PriorityTree {
    /// All nodes in the tree indexed by element_id
    nodes: HashMap<u64, PriorityNode>,
    /// Root node ID
    root_id: Option<u64>,
}

impl PriorityTree {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            root_id: None,
        }
    }

    /// Add or update a priority node
    pub fn insert(&mut self, node: PriorityNode) {
        let id = node.element_id;
        let parent_id = node.parent_id;
        
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

    /// Get next element to process based on priority
    /// Returns (element_id, urgency) or None if tree is empty
    pub fn get_next_priority(&self) -> Option<(u64, u8)> {
        // Start from root
        let root_id = self.root_id?;
        
        // Traverse tree to find highest priority leaf
        self.find_highest_priority_leaf(root_id)
    }

    fn find_highest_priority_leaf(&self, node_id: u64) -> Option<(u64, u8)> {
        let node = self.nodes.get(&node_id)?;
        
        if node.children.is_empty() {
            // Leaf node
            return Some((node.element_id, node.urgency));
        }
        
        // Find child with highest priority (lowest urgency)
        let mut best: Option<(u64, u8)> = None;
        
        for child_id in &node.children {
            if let Some(child_priority) = self.find_highest_priority_leaf(*child_id) {
                if let Some((_, current_urgency)) = best {
                    if child_priority.1 < current_urgency {
                        best = Some(child_priority);
                    }
                } else {
                    best = Some(child_priority);
                }
            }
        }
        
        best
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
        });
        
        // Add child with higher priority
        tree.insert(PriorityNode {
            element_id: 2,
            element_type: 0,
            urgency: 1,
            incremental: false,
            parent_id: Some(1),
            children: vec![],
        });
        
        // Higher priority should be returned first
        let next = tree.get_next_priority();
        assert_eq!(next, Some((2, 1)));
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
        });
        
        tree.remove(1);
        assert!(tree.get(1).is_none());
    }
}
