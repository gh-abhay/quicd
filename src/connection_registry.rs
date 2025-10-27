//! Shared Connection Registry
//!
//! Provides a global, thread-safe connection registry using DashMap to enable
//! shared connection state across all protocol tasks. This allows any protocol
//! task to send data to any connection, enabling advanced load balancing and
//! routing scenarios.

use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::Arc,
    time::Instant,
};

use dashmap::DashMap;
use quiche::Connection as QuicheConnection;

use crate::timer_wheel::{TimerWheel, TimerType, TimerEntry};

/// Unique connection identifier across the entire system
pub type GlobalConnectionId = u64;

/// Connection state stored in the shared registry
pub struct SharedConnectionState {
    /// Unique connection ID
    pub conn_id: GlobalConnectionId,
    /// Quiche connection object (not Debug)
    pub conn: QuicheConnection,
    /// Peer address
    pub peer: SocketAddr,
    /// Next timeout deadline
    pub next_timeout: Option<Instant>,
    /// Whether NewConnection message has been sent
    pub sent_new_connection: bool,
    /// Active streams on this connection
    pub active_streams: HashSet<u64>,
    /// Connection aliases (different DCIDs that map to this connection)
    pub aliases: Vec<Vec<u8>>,
}

/// Entry in the shared connection registry
pub struct ConnectionEntry {
    /// The connection state
    pub state: SharedConnectionState,
    /// Which protocol task currently "owns" this connection for timer processing
    /// This is used for load balancing timer operations
    pub owning_task_id: usize,
}

/// Shared connection registry using DashMap for concurrent access
pub struct ConnectionRegistry {
    /// Core storage: DCID -> ConnectionEntry
    connections: Arc<DashMap<Vec<u8>, ConnectionEntry>>,
    /// Alias mapping: DCID alias -> canonical DCID
    aliases: Arc<DashMap<Vec<u8>, Vec<u8>>>,
    /// Global connection ID generator
    next_conn_id: Arc<std::sync::atomic::AtomicU64>,
    /// Hierarchical timer wheel for efficient timeout management
    timer_wheel: Arc<parking_lot::Mutex<TimerWheel>>,
}

impl ConnectionRegistry {
    /// Create a new empty connection registry
    pub fn new() -> Self {
        Self {
            connections: Arc::new(DashMap::new()),
            aliases: Arc::new(DashMap::new()),
            next_conn_id: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            timer_wheel: Arc::new(parking_lot::Mutex::new(TimerWheel::new())),
        }
    }

    /// Generate a new unique connection ID
    pub fn next_connection_id(&self) -> GlobalConnectionId {
        self.next_conn_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Insert a new connection into the registry
    pub fn insert_connection(&self, canonical_dcid: Vec<u8>, entry: ConnectionEntry) {
        // Insert aliases first
        for alias in &entry.state.aliases {
            self.aliases.insert(alias.clone(), canonical_dcid.clone());
        }
        // Insert the main connection
        self.connections.insert(canonical_dcid, entry);
    }

    /// Get a connection by DCID (checking both canonical and aliases)
    pub fn get_connection(&self, dcid: &[u8]) -> Option<dashmap::mapref::one::Ref<'_, Vec<u8>, ConnectionEntry>> {
        // Try direct lookup first
        if let Some(entry) = self.connections.get(dcid) {
            return Some(entry);
        }

        // Try alias lookup
        if let Some(canonical_ref) = self.aliases.get(dcid) {
            let canonical = canonical_ref.clone();
            if let Some(entry) = self.connections.get(&canonical) {
                return Some(entry);
            }
        }

        None
    }

    /// Remove a connection from the registry
    pub fn remove_connection(&self, dcid: &[u8]) -> Option<(Vec<u8>, ConnectionEntry)> {
        // Try direct removal first
        if let Some((canonical, entry)) = self.connections.remove(dcid) {
            // Remove all aliases
            for alias in &entry.state.aliases {
                self.aliases.remove(alias);
            }
            return Some((canonical, entry));
        }

        // Try alias removal
        if let Some(canonical_ref) = self.aliases.remove(dcid) {
            let canonical = canonical_ref.0; // Extract the key from the removed entry
            if let Some((canonical_key, entry)) = self.connections.remove(&canonical) {
                // Remove all aliases
                for alias in &entry.state.aliases {
                    self.aliases.remove(alias);
                }
                return Some((canonical_key, entry));
            }
        }

        None
    }

    /// Update a connection in the registry
    pub fn update_connection<F>(&self, dcid: &[u8], updater: F) -> bool
    where
        F: FnOnce(&mut ConnectionEntry) -> (),
    {
        // Try direct update first
        if let Some(mut entry) = self.connections.get_mut(dcid) {
            updater(&mut entry);
            return true;
        }

        // Try alias update
        if let Some(canonical_ref) = self.aliases.get(dcid) {
            let canonical = canonical_ref.clone();
            if let Some(mut entry) = self.connections.get_mut(&canonical) {
                updater(&mut entry);
                return true;
            }
        }

        false
    }

    /// Get all connection DCIDs (for timer processing)
    pub fn get_all_dcids(&self) -> Vec<Vec<u8>> {
        self.connections.iter().map(|entry| entry.key().clone()).collect()
    }

    /// Get connections owned by a specific task (for timer processing)
    pub fn get_connections_for_task(&self, task_id: usize) -> Vec<(Vec<u8>, ConnectionEntry)> {
        self.connections
            .iter()
            .filter(|entry| entry.value().owning_task_id == task_id)
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    /// Get the total number of active connections
    pub fn active_connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Check if a connection exists
    pub fn connection_exists(&self, dcid: &[u8]) -> bool {
        self.connections.contains_key(dcid) || self.aliases.contains_key(dcid)
    }

    /// Schedule a timer for a connection
    pub fn schedule_timer(&self, dcid: Vec<u8>, timer_type: TimerType, duration: std::time::Duration) {
        self.timer_wheel.lock().add_timer(dcid, timer_type, duration);
    }

    /// Remove all timers for a connection
    pub fn remove_connection_timers(&self, dcid: &[u8]) -> usize {
        self.timer_wheel.lock().remove_connection_timers(dcid)
    }

    /// Process expired timers and return the expired timer entries
    pub fn process_expired_timers(&self) -> Vec<TimerEntry> {
        self.timer_wheel.lock().process_expired_timers()
    }

    /// Get timer wheel statistics
    pub fn timer_stats(&self) -> crate::timer_wheel::TimerWheelStats {
        self.timer_wheel.lock().stats()
    }
}

impl Default for ConnectionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedConnectionState {
    /// Create a new connection state
    pub fn new(conn_id: GlobalConnectionId, conn: QuicheConnection, peer: SocketAddr) -> Self {
        let mut state = Self {
            conn_id,
            conn,
            peer,
            next_timeout: None,
            sent_new_connection: false,
            active_streams: HashSet::new(),
            aliases: Vec::new(),
        };
        state.refresh_timeout();
        state
    }

    /// Refresh the timeout based on the connection's timeout
    pub fn refresh_timeout(&mut self) {
        self.next_timeout = self
            .conn
            .timeout()
            .map(|duration| Instant::now() + duration);
    }

    /// Check if the connection has timed out
    pub fn is_timed_out(&self) -> bool {
        self.next_timeout
            .map(|deadline| deadline <= Instant::now())
            .unwrap_or(false)
    }
}

impl Clone for ConnectionEntry {
    fn clone(&self) -> Self {
        // Quiche connections are not cloneable, so we panic if this is attempted
        // In practice, this should not be called as we return references instead
        panic!("ConnectionEntry cannot be cloned due to non-cloneable Quiche connection")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    // Mock connection state for testing (since QuicheConnection is not cloneable)
    fn create_mock_connection_entry(conn_id: GlobalConnectionId, task_id: usize) -> ConnectionEntry {
        // Create a minimal mock - in real tests we'd need to mock QuicheConnection
        // For now, we'll create a basic structure that tests the registry logic
        ConnectionEntry {
            state: SharedConnectionState {
                conn_id,
                conn: unsafe { std::mem::zeroed() }, // This is unsafe but for testing only
                peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443),
                next_timeout: None,
                sent_new_connection: false,
                active_streams: HashSet::new(),
                aliases: Vec::new(),
            },
            owning_task_id: task_id,
        }
    }

    #[test]
    fn test_connection_registry_basic_operations() {
        let registry = ConnectionRegistry::new();

        // Test empty registry
        assert_eq!(registry.active_connection_count(), 0);
        assert!(!registry.connection_exists(b"test"));
        assert!(registry.get_connection(b"test").is_none());

        // Test connection ID generation
        let id1 = registry.next_connection_id();
        let id2 = registry.next_connection_id();
        assert_eq!(id1, 0);
        assert_eq!(id2, 1);
    }

    #[test]
    fn test_connection_insertion_and_retrieval() {
        let registry = ConnectionRegistry::new();

        let dcid = b"connection1".to_vec();
        let entry = create_mock_connection_entry(1, 0);

        // Insert connection
        registry.insert_connection(dcid.clone(), entry);

        // Verify insertion
        assert_eq!(registry.active_connection_count(), 1);
        assert!(registry.connection_exists(&dcid));

        // Test retrieval
        let retrieved = registry.get_connection(&dcid);
        assert!(retrieved.is_some());
        let retrieved_entry = retrieved.unwrap();
        assert_eq!(retrieved_entry.state.conn_id, 1);
        assert_eq!(retrieved_entry.owning_task_id, 0);
    }

    #[test]
    fn test_connection_aliases() {
        let registry = ConnectionRegistry::new();

        let canonical_dcid = b"canonical".to_vec();
        let alias_dcid = b"alias".to_vec();

        let mut entry = create_mock_connection_entry(1, 0);
        entry.state.aliases.push(alias_dcid.clone());

        // Insert connection with alias
        registry.insert_connection(canonical_dcid.clone(), entry);

        // Test canonical lookup
        assert!(registry.connection_exists(&canonical_dcid));
        let canonical_entry = registry.get_connection(&canonical_dcid);
        assert!(canonical_entry.is_some());

        // Test alias lookup
        assert!(registry.connection_exists(&alias_dcid));
        let alias_entry = registry.get_connection(&alias_dcid);
        assert!(alias_entry.is_some());

        // Verify they point to the same connection
        assert_eq!(canonical_entry.unwrap().state.conn_id, alias_entry.unwrap().state.conn_id);
    }

    #[test]
    fn test_connection_removal() {
        let registry = ConnectionRegistry::new();

        let dcid = b"connection1".to_vec();
        let entry = create_mock_connection_entry(1, 0);
        registry.insert_connection(dcid.clone(), entry);

        assert_eq!(registry.active_connection_count(), 1);

        // Remove by canonical DCID
        let removed = registry.remove_connection(&dcid);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().0, dcid);
        assert_eq!(registry.active_connection_count(), 0);
        assert!(!registry.connection_exists(&dcid));
    }

    #[test]
    fn test_connection_removal_by_alias() {
        let registry = ConnectionRegistry::new();

        let canonical_dcid = b"canonical".to_vec();
        let alias_dcid = b"alias".to_vec();

        let mut entry = create_mock_connection_entry(1, 0);
        entry.state.aliases.push(alias_dcid.clone());
        registry.insert_connection(canonical_dcid.clone(), entry);

        // Remove by alias
        let removed = registry.remove_connection(&alias_dcid);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().0, canonical_dcid);
        assert_eq!(registry.active_connection_count(), 0);
        assert!(!registry.connection_exists(&canonical_dcid));
        assert!(!registry.connection_exists(&alias_dcid));
    }

    #[test]
    fn test_connection_update() {
        let registry = ConnectionRegistry::new();

        let dcid = b"connection1".to_vec();
        let entry = create_mock_connection_entry(1, 0);
        registry.insert_connection(dcid.clone(), entry);

        // Update connection
        let updated = registry.update_connection(&dcid, |entry| {
            entry.owning_task_id = 5;
        });
        assert!(updated);

        // Verify update
        let retrieved = registry.get_connection(&dcid).unwrap();
        assert_eq!(retrieved.owning_task_id, 5);
    }

    #[test]
    fn test_connection_update_by_alias() {
        let registry = ConnectionRegistry::new();

        let canonical_dcid = b"canonical".to_vec();
        let alias_dcid = b"alias".to_vec();

        let mut entry = create_mock_connection_entry(1, 0);
        entry.state.aliases.push(alias_dcid.clone());
        registry.insert_connection(canonical_dcid.clone(), entry);

        // Update by alias
        let updated = registry.update_connection(&alias_dcid, |entry| {
            entry.owning_task_id = 7;
        });
        assert!(updated);

        // Verify update accessible by both canonical and alias
        let canonical_retrieved = registry.get_connection(&canonical_dcid).unwrap();
        let alias_retrieved = registry.get_connection(&alias_dcid).unwrap();
        assert_eq!(canonical_retrieved.owning_task_id, 7);
        assert_eq!(alias_retrieved.owning_task_id, 7);
    }

    #[test]
    fn test_get_connections_for_task() {
        let registry = ConnectionRegistry::new();

        // Add connections for different tasks
        let dcid1 = b"conn_task0".to_vec();
        let dcid2 = b"conn_task1".to_vec();
        let dcid3 = b"conn_task0_2".to_vec();

        registry.insert_connection(dcid1.clone(), create_mock_connection_entry(1, 0));
        registry.insert_connection(dcid2.clone(), create_mock_connection_entry(2, 1));
        registry.insert_connection(dcid3.clone(), create_mock_connection_entry(3, 0));

        // Get connections for task 0
        let task0_connections = registry.get_connections_for_task(0);
        assert_eq!(task0_connections.len(), 2);

        let dcids: Vec<_> = task0_connections.iter().map(|(dcid, _)| dcid.clone()).collect();
        assert!(dcids.contains(&dcid1));
        assert!(dcids.contains(&dcid3));
        assert!(!dcids.contains(&dcid2));

        // Get connections for task 1
        let task1_connections = registry.get_connections_for_task(1);
        assert_eq!(task1_connections.len(), 1);
        assert_eq!(task1_connections[0].0, dcid2);
    }

    #[test]
    fn test_get_all_dcids() {
        let registry = ConnectionRegistry::new();

        let dcid1 = b"conn1".to_vec();
        let dcid2 = b"conn2".to_vec();

        registry.insert_connection(dcid1.clone(), create_mock_connection_entry(1, 0));
        registry.insert_connection(dcid2.clone(), create_mock_connection_entry(2, 1));

        let all_dcids = registry.get_all_dcids();
        assert_eq!(all_dcids.len(), 2);
        assert!(all_dcids.contains(&dcid1));
        assert!(all_dcids.contains(&dcid2));
    }

    #[test]
    fn test_timer_operations() {
        let registry = ConnectionRegistry::new();

        let dcid = b"timed_conn".to_vec();
        registry.insert_connection(dcid.clone(), create_mock_connection_entry(1, 0));

        // Schedule a timer
        registry.schedule_timer(dcid.clone(), TimerType::IdleTimeout, Duration::from_secs(30));

        // Check timer stats
        let stats = registry.timer_stats();
        assert_eq!(stats.active_timers, 1);

        // Remove connection timers
        let removed_count = registry.remove_connection_timers(&dcid);
        assert_eq!(removed_count, 1);

        let stats_after = registry.timer_stats();
        assert_eq!(stats_after.active_timers, 0);
    }

    #[test]
    fn test_shared_connection_state_timeout() {
        use std::time::Instant;

        // Test timeout logic (without actual QuicheConnection)
        let mut state = SharedConnectionState {
            conn_id: 1,
            conn: unsafe { std::mem::zeroed() },
            peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443),
            next_timeout: Some(Instant::now() - Duration::from_secs(1)), // Already expired
            sent_new_connection: false,
            active_streams: HashSet::new(),
            aliases: Vec::new(),
        };

        assert!(state.is_timed_out());

        // Test with future timeout
        state.next_timeout = Some(Instant::now() + Duration::from_secs(30));
        assert!(!state.is_timed_out());

        // Test with no timeout
        state.next_timeout = None;
        assert!(!state.is_timed_out());
    }

    #[test]
    fn test_connection_registry_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let registry = Arc::new(ConnectionRegistry::new());
        let mut handles = vec![];

        // Spawn multiple threads to test concurrent access
        for i in 0..10 {
            let registry_clone = Arc::clone(&registry);
            let handle = thread::spawn(move || {
                let dcid = format!("conn_{}", i).into_bytes();
                let entry = create_mock_connection_entry(i as u64, (i % 3) as usize);
                registry_clone.insert_connection(dcid.clone(), entry);

                // Verify we can read it back
                let retrieved = registry_clone.get_connection(&dcid);
                assert!(retrieved.is_some());
                assert_eq!(retrieved.unwrap().state.conn_id, i as u64);
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(registry.active_connection_count(), 10);
    }
}