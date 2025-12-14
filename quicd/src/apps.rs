//! Application layer integration for QUIC.
//!
//! This module manages the registry of QUIC applications (protocols) that can run
//! on top of the QUIC transport. Applications are identified by their ALPN
//! (Application-Layer Protocol Negotiation) identifier during the TLS handshake.
//!
//! # Architecture
//!
//! - Applications implement the `QuicAppFactory` trait from quicd-x
//! - Each application is registered with one or more ALPN strings (e.g., "h3", "h3-29")
//! - During connection handshake, the negotiated ALPN determines which app handles the connection
//! - One application task is spawned per connection on the shared Tokio runtime
//! - The worker thread communicates with app tasks via channels (quicd-x interface)
//!
//! # Registration
//!
//! Applications are registered in `main.rs` before workers start:
//! ```rust,ignore
//! let registry = AppRegistry::new();
//! registry.register("h3", Box::new(H3Factory::new()));
//! ```

use anyhow::Context;
use libloading::{Library, Symbol};
use quicd_x::QuicAppFactory;
use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::Arc;

/// Registry of QUIC application factories indexed by ALPN.
///
/// This is shared across all worker threads (read-only after initialization).
/// Each worker uses this to look up the appropriate factory when a connection
/// completes its handshake with a specific ALPN.
#[derive(Clone)]
pub struct AppRegistry {
    /// Map from ALPN string to application factory
    factories: Arc<HashMap<String, Arc<dyn QuicAppFactory>>>,
}

impl AppRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            factories: Arc::new(HashMap::new()),
        }
    }

    /// Create a registry with initial factories
    #[allow(dead_code)]
    pub fn with_factories(factories: HashMap<String, Arc<dyn QuicAppFactory>>) -> Self {
        Self {
            factories: Arc::new(factories),
        }
    }

    /// Register an application factory for a specific ALPN
    ///
    /// Note: This creates a new registry with the added factory.
    /// For efficiency, use `with_factories` to register all factories at once.
    pub fn register(self, alpn: impl Into<String>, factory: Arc<dyn QuicAppFactory>) -> Self {
        let mut factories = (*self.factories).clone();
        factories.insert(alpn.into(), factory);
        Self {
            factories: Arc::new(factories),
        }
    }

    /// Look up a factory by ALPN
    ///
    /// Returns None if no factory is registered for this ALPN.
    pub fn get(&self, alpn: &str) -> Option<Arc<dyn QuicAppFactory>> {
        self.factories.get(alpn).cloned()
    }

    /// Check if an ALPN is supported
    #[allow(dead_code)]
    pub fn supports(&self, alpn: &str) -> bool {
        self.factories.contains_key(alpn)
    }

    /// Get list of all registered ALPN protocols
    pub fn alpn_list(&self) -> Vec<String> {
        self.factories.keys().cloned().collect()
    }

    /// Get all registered ALPNs
    pub fn alpns(&self) -> Vec<String> {
        self.factories.keys().cloned().collect()
    }

    /// Get the number of registered applications
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.factories.len()
    }

    /// Check if the registry is empty
    pub fn is_empty(&self) -> bool {
        self.factories.is_empty()
    }
}

impl Default for AppRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for AppRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppRegistry")
            .field("alpns", &self.alpns())
            .finish()
    }
}

/// Load an application factory from a dynamic library.
///
/// # Safety Requirements
///
/// The plugin library must:
/// - Be compiled with the same Rust compiler version as the server
/// - Link against the same `quicd-x` version
/// - Export `_quicd_create_factory` function (use `export_quic_app!` macro)
/// - Be compiled for the same target architecture
///
/// Violating these requirements leads to undefined behavior.
///
/// # Arguments
///
/// * `path` - Path to the dynamic library file (.so/.dylib/.dll)
///
/// # Errors
///
/// Returns an error if:
/// - The library file cannot be loaded
/// - The required symbol is not found
/// - The factory function returns null
pub fn load_plugin(path: &str) -> anyhow::Result<Arc<dyn QuicAppFactory>> {
    unsafe {
        let lib = Library::new(path)
            .with_context(|| format!("Failed to load plugin library: {}", path))?;
        // Leak the library to keep it loaded for the lifetime of the process
        let lib = Box::leak(Box::new(lib));

        let func: Symbol<unsafe extern "C" fn() -> *mut c_void> = lib.get(b"_quicd_create_factory")
            .with_context(|| format!("Plugin {} does not export '_quicd_create_factory' symbol. Did you use the export_quic_app! macro?", path))?;

        let raw_ptr = func();
        if raw_ptr.is_null() {
            anyhow::bail!("Plugin {} returned null factory pointer", path);
        }

        // Reconstruct the double-boxed factory
        // Note: This assumes the plugin was compiled with the same Rust compiler version
        // and quicd-x version as the server.
        let wrapper: Box<Box<dyn QuicAppFactory>> =
            Box::from_raw(raw_ptr as *mut Box<dyn QuicAppFactory>);
        let factory: Box<dyn QuicAppFactory> = *wrapper;

        Ok(Arc::from(factory))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_registry() {
        let registry = AppRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
        assert!(!registry.supports("h3"));
    }

    #[test]
    fn test_registry_alpns() {
        let registry = AppRegistry::new();
        let alpns = registry.alpns();
        assert_eq!(alpns.len(), 0);
    }
}
