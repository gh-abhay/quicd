//! Application registry and lifecycle management.
//!
//! This module manages the registration and initialization of application
//! protocols (HTTP/3, custom protocols, etc.) for the QUIC server.

use anyhow::{Context, Result};
use quicd_x::QuicdApplication;
use std::collections::HashMap;
use std::sync::Arc;

use crate::config::application::{ApplicationConfig, ApplicationType, ApplicationTypeConfig};

/// Factory function type for creating application instances.
pub type AppFactory = Arc<dyn Fn() -> Arc<dyn QuicdApplication> + Send + Sync>;

/// Application registry mapping ALPN to application factories.
///
/// The registry is built during server initialization based on
/// configuration and is used to route connections to the appropriate
/// application based on ALPN negotiation.
pub struct AppRegistry {
    factories: HashMap<String, AppFactory>,
}

impl AppRegistry {
    /// Create a new empty application registry.
    pub fn new() -> Self {
        Self {
            factories: HashMap::new(),
        }
    }

    /// Register an application factory for a given ALPN.
    ///
    /// Returns an error if the ALPN is already registered.
    pub fn register(
        mut self,
        alpn: impl Into<String>,
        factory: AppFactory,
    ) -> Result<Self> {
        let alpn = alpn.into();
        if self.factories.contains_key(&alpn) {
            anyhow::bail!("ALPN '{}' is already registered", alpn);
        }
        self.factories.insert(alpn, factory);
        Ok(self)
    }

    /// Get the application factory for a given ALPN.
    pub fn get(&self, alpn: &str) -> Option<&AppFactory> {
        self.factories.get(alpn)
    }

    /// List all registered ALPNs.
    pub fn alpns(&self) -> Vec<&str> {
        self.factories.keys().map(|s| s.as_str()).collect()
    }

    /// Get the number of registered applications.
    pub fn len(&self) -> usize {
        self.factories.len()
    }

    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.factories.is_empty()
    }
}

impl Default for AppRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Build application registry from configuration.
///
/// This function processes the application configurations and creates
/// the appropriate application instances (HTTP/3, plugins, etc.).
pub fn build_registry(app_configs: &[ApplicationConfig]) -> Result<AppRegistry> {
    let mut registry = AppRegistry::new();

    for app_config in app_configs {
        // Validate configuration
        app_config
            .validate()
            .map_err(|errs| anyhow::anyhow!("Invalid config for ALPN '{}': {}", app_config.alpn, errs.join("; ")))?;

        match app_config.app_type {
            ApplicationType::Http3 => {
                let h3_config = match &app_config.config {
                    ApplicationTypeConfig::Http3(cfg) => cfg.clone(),
                    _ => anyhow::bail!("Type mismatch: expected Http3 config"),
                };

                if !h3_config.enabled {
                    tracing::info!("HTTP/3 application disabled for ALPN '{}'", app_config.alpn);
                    continue;
                }

                // Create H3 application factory
                let factory: AppFactory = Arc::new(move || {
                    Arc::new(quicd_h3::H3Application::new(h3_config.h3.clone()))
                });

                registry = registry.register(&app_config.alpn, factory)
                    .with_context(|| format!("Failed to register HTTP/3 for ALPN '{}'", app_config.alpn))?;

                tracing::info!("Registered HTTP/3 application for ALPN '{}'", app_config.alpn);
            }

            ApplicationType::Plugin => {
                // Plugin loading would be implemented here
                // For now, we'll skip it as it requires dynamic library loading
                tracing::warn!(
                    "Plugin loading not yet implemented for ALPN '{}', skipping",
                    app_config.alpn
                );
            }
        }
    }

    if registry.is_empty() {
        tracing::warn!("No applications registered - server will reject all connections");
    }

    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_basic() {
        let mut registry = AppRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);

        let factory: AppFactory = Arc::new(|| {
            Arc::new(quicd_h3::H3Application::new(quicd_h3::H3Config::default()))
        });

        registry = registry.register("h3", factory).unwrap();
        assert_eq!(registry.len(), 1);
        assert!(!registry.is_empty());
        assert!(registry.get("h3").is_some());
        assert!(registry.get("unknown").is_none());
    }

    #[test]
    fn test_registry_duplicate_alpn() {
        let registry = AppRegistry::new();
        let factory: AppFactory = Arc::new(|| {
            Arc::new(quicd_h3::H3Application::new(quicd_h3::H3Config::default()))
        });

        let registry = registry.register("h3", factory.clone()).unwrap();
        let result = registry.register("h3", factory);
        assert!(result.is_err());
    }
}
