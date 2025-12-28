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
/// 
/// Uses Vec to maintain ALPN order for deterministic TLS negotiation.
pub struct AppRegistry {
    factories: Vec<(String, AppFactory)>,
}

impl AppRegistry {
    /// Create a new empty application registry.
    pub fn new() -> Self {
        Self {
            factories: Vec::new(),
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
        if self.factories.iter().any(|(a, _)| a == &alpn) {
            anyhow::bail!("ALPN '{}' is already registered", alpn);
        }
        self.factories.push((alpn, factory));
        Ok(self)
    }

    /// Get the application factory for a given ALPN.
    pub fn get(&self, alpn: &str) -> Option<&AppFactory> {
        self.factories.iter().find(|(a, _)| a == alpn).map(|(_, f)| f)
    }

    /// List all registered ALPNs.
    pub fn alpns(&self) -> Vec<&str> {
        self.factories.iter().map(|(s, _)| s.as_str()).collect()
    }

    /// Get all registered ALPN protocols as owned Strings (for TLS configuration).
    /// Maintains insertion order for deterministic ALPN negotiation.
    pub fn get_all_alpn_protocols(&self) -> Vec<String> {
        self.factories.iter().map(|(s, _)| s.clone()).collect()
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
/// 
/// Each application can register multiple ALPN identifiers.
/// 
/// Applications are sorted to ensure HTTP/3 ALPNs are registered before
/// hq-interop for proper ALPN negotiation priority.
pub fn build_registry(app_configs: &HashMap<String, ApplicationConfig>) -> Result<AppRegistry> {
    let mut registry = AppRegistry::new();

    // Sort applications to ensure predictable ALPN order: http3 before hq-interop
    let mut sorted_apps: Vec<_> = app_configs.iter().collect();
    sorted_apps.sort_by_key(|(name, config)| {
        // Priority order: http3 (0), hq-interop (1), others (2)
        let priority = if config.app_type == "builtin:http3" {
            0
        } else if config.app_type == "builtin:hq-interop" {
            1
        } else {
            2
        };
        (priority, *name)
    });

    for (app_name, app_config) in sorted_apps {
        // Skip disabled applications
        if !app_config.enabled {
            tracing::info!("Application '{}' is disabled, skipping", app_name);
            continue;
        }

        // Validate configuration
        app_config
            .validate()
            .map_err(|errs| anyhow::anyhow!("Invalid config for application '{}': {}", app_name, errs.join("; ")))?;

        // Parse application type
        let app_type = app_config.parse_type()
            .map_err(|e| anyhow::anyhow!("Failed to parse type for application '{}': {}", app_name, e))?;

        match app_type {
            ApplicationType::Http3 => {
                let h3_config = match &app_config.config {
                    ApplicationTypeConfig::Http3(cfg) => cfg.clone(),
                    _ => anyhow::bail!("Type mismatch: expected Http3 config for application '{}'", app_name),
                };

                // Register all ALPN identifiers for this application
                for alpn in &app_config.alpn {
                    // Create H3 application factory for each ALPN
                    let factory: AppFactory = {
                        let h3_cfg = h3_config.clone();
                        Arc::new(move || {
                            // Convert our config to quicd-h3 config
                            let h3_lib_config = quicd_h3::H3Config {
                                qpack: quicd_h3::QpackConfig {
                                    max_table_capacity: h3_cfg.qpack.max_table_capacity as u64,
                                    blocked_streams: h3_cfg.qpack.blocked_streams as u64,
                                },
                                push: quicd_h3::PushConfig {
                                    enabled: h3_cfg.push.enabled,
                                    max_concurrent: h3_cfg.push.max_concurrent as u64,
                                    max_push_id: 1000, // Default from quicd-h3
                                },
                                handler: quicd_h3::HandlerConfig {
                                    file_serving_enabled: h3_cfg.handler.file_serving_enabled,
                                    file_root: h3_cfg.handler.file_root.clone().into(),
                                    directory_listing: h3_cfg.handler.directory_listing,
                                    compression_enabled: h3_cfg.handler.compression_enabled,
                                    compression_algorithms: h3_cfg.handler.compression_algorithms.clone(),
                                    index_files: h3_cfg.handler.index_files.clone(),
                                },
                                limits: quicd_h3::LimitsConfig {
                                    max_field_section_size: h3_cfg.limits.max_field_section_size as u64,
                                    max_concurrent_streams: h3_cfg.limits.max_concurrent_streams as u64,
                                    idle_timeout_secs: h3_cfg.limits.idle_timeout_secs,
                                },
                            };
                            Arc::new(quicd_h3::H3Application::new(h3_lib_config))
                        })
                    };

                    registry = registry.register(alpn, factory)
                        .with_context(|| format!("Failed to register HTTP/3 for ALPN '{}' in application '{}'", alpn, app_name))?;

                    tracing::info!("Registered HTTP/3 application '{}' for ALPN '{}'", app_name, alpn);
                }
            }

            ApplicationType::HqInterop => {
                let hq_config = match &app_config.config {
                    ApplicationTypeConfig::HqInterop(cfg) => cfg.clone(),
                    _ => anyhow::bail!("Type mismatch: expected HqInterop config for application '{}'", app_name),
                };

                // Register all ALPN identifiers for this application
                for alpn in &app_config.alpn {
                    // Create HqInterop application factory for each ALPN
                    let factory: AppFactory = {
                        let hq_cfg = hq_config.clone();
                        Arc::new(move || {
                            // Convert our config to quicd-hq-interop config
                            let hq_lib_config = quicd_hq_interop::HqInteropConfig {
                                handler: quicd_hq_interop::HandlerConfig {
                                    file_root: hq_cfg.handler.file_root.clone().into(),
                                    index_files: hq_cfg.handler.index_files.clone(),
                                },
                            };
                            Arc::new(quicd_hq_interop::HqInteropApplication::new(hq_lib_config))
                        })
                    };

                    registry = registry.register(alpn, factory)
                        .with_context(|| format!("Failed to register HQ-Interop for ALPN '{}' in application '{}'", alpn, app_name))?;

                    tracing::info!("Registered HQ-Interop application '{}' for ALPN '{}'", app_name, alpn);
                }
            }

            ApplicationType::Moq => {
                tracing::warn!(
                    "MOQ application type not yet implemented for application '{}', skipping",
                    app_name
                );
            }

            ApplicationType::Plugin => {
                // Plugin loading would be implemented here
                // For now, we'll skip it as it requires dynamic library loading
                tracing::warn!(
                    "Plugin loading not yet implemented for application '{}', skipping",
                    app_name
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
    use crate::config::application::{ApplicationTypeConfig, Http3Config};

    #[test]
    fn test_registry_basic() {
        let registry = AppRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);

        let factory: AppFactory = Arc::new(|| {
            Arc::new(quicd_h3::H3Application::new(quicd_h3::H3Config::default()))
        });

        let registry = registry.register("h3", factory).unwrap();
        assert_eq!(registry.len(), 1);
        assert!(!registry.is_empty());
        assert!(registry.get("h3").is_some());
        assert!(registry.get("unknown").is_none());
    }

    #[test]
    fn test_build_registry_multiple_alpns() {
        let mut apps = HashMap::new();
        apps.insert(
            "http3".to_string(),
            ApplicationConfig {
                alpn: vec!["h3".to_string(), "h3-29".to_string()],
                app_type: "builtin:http3".to_string(),
                enabled: true,
                config: ApplicationTypeConfig::Http3(Http3Config::default()),
            },
        );

        let registry = build_registry(&apps).unwrap();
        assert_eq!(registry.len(), 2);
        assert!(registry.get("h3").is_some());
        assert!(registry.get("h3-29").is_some());
    }

    #[test]
    fn test_build_registry_disabled_app() {
        let mut apps = HashMap::new();
        apps.insert(
            "http3".to_string(),
            ApplicationConfig {
                alpn: vec!["h3".to_string()],
                app_type: "builtin:http3".to_string(),
                enabled: false,
                config: ApplicationTypeConfig::Http3(Http3Config::default()),
            },
        );

        let registry = build_registry(&apps).unwrap();
        assert!(registry.is_empty());
    }
}
