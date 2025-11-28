//! Settings storage for 0-RTT support per RFC 9114 Section 7.2.4.2.
//!
//! This module provides mechanisms to persist and retrieve HTTP/3 SETTINGS frames
//! between connections, enabling proper 0-RTT validation. The storage is keyed by
//! connection origin (scheme + host + port) to ensure settings are only reused for
//! connections to the same server.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use crate::settings::SettingId;

/// Maximum age of remembered settings before expiration (24 hours).
///
/// RFC 9114 Section 7.2.4.2: "Clients SHOULD remember settings for some time"
/// but doesn't specify duration. We use 24 hours as a reasonable default to
/// balance security (settings don't persist indefinitely) and utility (settings
/// persist across typical usage patterns).
const DEFAULT_SETTINGS_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Origin identifier for settings storage.
///
/// Settings are stored per-origin to ensure they're only reused for connections
/// to the same server. This prevents security issues where settings from one
/// server are incorrectly applied to another.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Origin {
    /// Scheme (e.g., "https")
    pub scheme: String,
    /// Host (e.g., "example.com")
    pub host: String,
    /// Port (e.g., 443)
    pub port: u16,
}

impl Origin {
    /// Create a new origin identifier.
    pub fn new(scheme: String, host: String, port: u16) -> Self {
        Self { scheme, host, port }
    }

    /// Parse from authority string (host:port).
    pub fn from_authority(scheme: String, authority: &str) -> Result<Self, String> {
        if let Some((host, port_str)) = authority.rsplit_once(':') {
            let port = port_str.parse::<u16>()
                .map_err(|_| format!("invalid port: {}", port_str))?;
            Ok(Self::new(scheme, host.to_string(), port))
        } else {
            // No explicit port, use default for scheme
            let port = match scheme.as_str() {
                "https" => 443,
                "http" => 80,
                _ => return Err(format!("unknown scheme: {}", scheme)),
            };
            Ok(Self::new(scheme, authority.to_string(), port))
        }
    }

    /// Format as string for display.
    pub fn to_string(&self) -> String {
        format!("{}://{}:{}", self.scheme, self.host, self.port)
    }
}

/// Entry in settings storage with timestamp.
#[derive(Debug, Clone)]
struct SettingsEntry {
    /// Settings map
    settings: HashMap<SettingId, u64>,
    /// When these settings were stored
    stored_at: SystemTime,
    /// TTL for these settings
    ttl: Duration,
}

impl SettingsEntry {
    /// Check if this entry has expired.
    fn is_expired(&self) -> bool {
        SystemTime::now()
            .duration_since(self.stored_at)
            .map(|age| age > self.ttl)
            .unwrap_or(true) // Treat time errors as expired
    }
}

/// In-memory settings storage.
///
/// This is the simplest implementation that stores settings in memory for the
/// lifetime of the process. For production deployments that need persistence
/// across process restarts, consider implementing a file-based or database-backed
/// storage.
#[derive(Debug, Clone)]
pub struct InMemorySettingsStorage {
    /// Storage map protected by RwLock for concurrent access
    storage: Arc<RwLock<HashMap<Origin, SettingsEntry>>>,
    /// Default TTL for stored settings
    default_ttl: Duration,
}

impl InMemorySettingsStorage {
    /// Create a new in-memory settings storage with default TTL.
    pub fn new() -> Self {
        Self {
            storage: Arc::new(RwLock::new(HashMap::new())),
            default_ttl: DEFAULT_SETTINGS_TTL,
        }
    }

    /// Create a new in-memory settings storage with custom TTL.
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            storage: Arc::new(RwLock::new(HashMap::new())),
            default_ttl: ttl,
        }
    }

    /// Store settings for an origin.
    ///
    /// This should be called when receiving a SETTINGS frame from a peer to
    /// remember the settings for future 0-RTT connections.
    pub fn store(&self, origin: Origin, settings: HashMap<SettingId, u64>) {
        let entry = SettingsEntry {
            settings,
            stored_at: SystemTime::now(),
            ttl: self.default_ttl,
        };

        if let Ok(mut storage) = self.storage.write() {
            storage.insert(origin, entry);
        }
    }

    /// Retrieve settings for an origin.
    ///
    /// Returns None if:
    /// - No settings are stored for this origin
    /// - The stored settings have expired (> TTL)
    ///
    /// This should be called when establishing a 0-RTT connection to retrieve
    /// the remembered settings for validation.
    pub fn retrieve(&self, origin: &Origin) -> Option<HashMap<SettingId, u64>> {
        if let Ok(mut storage) = self.storage.write() {
            if let Some(entry) = storage.get(origin) {
                if entry.is_expired() {
                    // Remove expired entry
                    storage.remove(origin);
                    None
                } else {
                    Some(entry.settings.clone())
                }
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Clear all stored settings.
    ///
    /// Useful for testing or for user-initiated "clear browsing data" actions.
    pub fn clear(&self) {
        if let Ok(mut storage) = self.storage.write() {
            storage.clear();
        }
    }

    /// Clear expired entries.
    ///
    /// This can be called periodically to prevent unbounded memory growth.
    pub fn clear_expired(&self) {
        if let Ok(mut storage) = self.storage.write() {
            storage.retain(|_, entry| !entry.is_expired());
        }
    }

    /// Get the number of stored origins.
    pub fn len(&self) -> usize {
        self.storage.read()
            .map(|storage| storage.len())
            .unwrap_or(0)
    }

    /// Check if storage is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for InMemorySettingsStorage {
    fn default() -> Self {
        Self::new()
    }
}

/// Trait for settings storage backends.
///
/// Implement this trait to provide custom storage backends (e.g., file-based,
/// database-backed, or distributed cache).
pub trait SettingsStorage: Send + Sync {
    /// Store settings for an origin.
    fn store(&self, origin: Origin, settings: HashMap<SettingId, u64>);

    /// Retrieve settings for an origin.
    fn retrieve(&self, origin: &Origin) -> Option<HashMap<SettingId, u64>>;

    /// Clear all stored settings.
    fn clear(&self);
}

impl SettingsStorage for InMemorySettingsStorage {
    fn store(&self, origin: Origin, settings: HashMap<SettingId, u64>) {
        self.store(origin, settings);
    }

    fn retrieve(&self, origin: &Origin) -> Option<HashMap<SettingId, u64>> {
        self.retrieve(origin)
    }

    fn clear(&self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_origin_from_authority() {
        let origin = Origin::from_authority("https".to_string(), "example.com:8443").unwrap();
        assert_eq!(origin.scheme, "https");
        assert_eq!(origin.host, "example.com");
        assert_eq!(origin.port, 8443);
    }

    #[test]
    fn test_origin_from_authority_default_port() {
        let origin = Origin::from_authority("https".to_string(), "example.com").unwrap();
        assert_eq!(origin.scheme, "https");
        assert_eq!(origin.host, "example.com");
        assert_eq!(origin.port, 443);
    }

    #[test]
    fn test_origin_to_string() {
        let origin = Origin::new("https".to_string(), "example.com".to_string(), 443);
        assert_eq!(origin.to_string(), "https://example.com:443");
    }

    #[test]
    fn test_store_and_retrieve() {
        let storage = InMemorySettingsStorage::new();
        let origin = Origin::new("https".to_string(), "example.com".to_string(), 443);

        let mut settings = HashMap::new();
        settings.insert(0x01, 4096);
        settings.insert(0x06, 8192);

        storage.store(origin.clone(), settings.clone());
        
        let retrieved = storage.retrieve(&origin).unwrap();
        assert_eq!(retrieved.get(&0x01), Some(&4096));
        assert_eq!(retrieved.get(&0x06), Some(&8192));
    }

    #[test]
    fn test_retrieve_nonexistent() {
        let storage = InMemorySettingsStorage::new();
        let origin = Origin::new("https".to_string(), "example.com".to_string(), 443);

        assert!(storage.retrieve(&origin).is_none());
    }

    #[test]
    fn test_clear() {
        let storage = InMemorySettingsStorage::new();
        let origin = Origin::new("https".to_string(), "example.com".to_string(), 443);

        let mut settings = HashMap::new();
        settings.insert(0x01, 4096);
        storage.store(origin.clone(), settings);

        storage.clear();
        assert!(storage.retrieve(&origin).is_none());
        assert!(storage.is_empty());
    }

    #[test]
    fn test_expiration() {
        let storage = InMemorySettingsStorage::with_ttl(Duration::from_millis(100));
        let origin = Origin::new("https".to_string(), "example.com".to_string(), 443);

        let mut settings = HashMap::new();
        settings.insert(0x01, 4096);
        storage.store(origin.clone(), settings);

        // Should be retrievable immediately
        assert!(storage.retrieve(&origin).is_some());

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(150));

        // Should be expired now
        assert!(storage.retrieve(&origin).is_none());
    }

    #[test]
    fn test_clear_expired() {
        let storage = InMemorySettingsStorage::with_ttl(Duration::from_millis(100));
        
        let origin1 = Origin::new("https".to_string(), "example.com".to_string(), 443);
        let origin2 = Origin::new("https".to_string(), "other.com".to_string(), 443);

        let mut settings = HashMap::new();
        settings.insert(0x01, 4096);

        storage.store(origin1.clone(), settings.clone());
        
        // Wait a bit
        std::thread::sleep(Duration::from_millis(150));
        
        // Store a fresh entry
        storage.store(origin2.clone(), settings.clone());

        assert_eq!(storage.len(), 2); // Both entries present

        storage.clear_expired();

        assert_eq!(storage.len(), 1); // Only fresh entry remains
        assert!(storage.retrieve(&origin1).is_none());
        assert!(storage.retrieve(&origin2).is_some());
    }

    #[test]
    fn test_multiple_origins() {
        let storage = InMemorySettingsStorage::new();
        
        let origin1 = Origin::new("https".to_string(), "example.com".to_string(), 443);
        let origin2 = Origin::new("https".to_string(), "other.com".to_string(), 443);
        let origin3 = Origin::new("https".to_string(), "example.com".to_string(), 8443);

        let mut settings1 = HashMap::new();
        settings1.insert(0x01, 1111);

        let mut settings2 = HashMap::new();
        settings2.insert(0x01, 2222);

        let mut settings3 = HashMap::new();
        settings3.insert(0x01, 3333);

        storage.store(origin1.clone(), settings1);
        storage.store(origin2.clone(), settings2);
        storage.store(origin3.clone(), settings3);

        assert_eq!(storage.retrieve(&origin1).unwrap().get(&0x01), Some(&1111));
        assert_eq!(storage.retrieve(&origin2).unwrap().get(&0x01), Some(&2222));
        assert_eq!(storage.retrieve(&origin3).unwrap().get(&0x01), Some(&3333));
    }

    #[test]
    fn test_overwrite_existing() {
        let storage = InMemorySettingsStorage::new();
        let origin = Origin::new("https".to_string(), "example.com".to_string(), 443);

        let mut settings1 = HashMap::new();
        settings1.insert(0x01, 1111);
        storage.store(origin.clone(), settings1);

        let mut settings2 = HashMap::new();
        settings2.insert(0x01, 2222);
        storage.store(origin.clone(), settings2);

        assert_eq!(storage.retrieve(&origin).unwrap().get(&0x01), Some(&2222));
    }
}
