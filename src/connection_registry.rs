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

use crate::error::Result;

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
}

impl ConnectionRegistry {
    /// Create a new empty connection registry
    pub fn new() -> Self {
        Self {
            connections: Arc::new(DashMap::new()),
            aliases: Arc::new(DashMap::new()),
            next_conn_id: Arc::new(std::sync::atomic::AtomicU64::new(0)),
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
    pub fn get_connection(&self, dcid: &[u8]) -> Option<dashmap::mapref::one::Ref<Vec<u8>, ConnectionEntry>> {
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