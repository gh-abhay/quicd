//! Comprehensive tests for configuration module.
//!
//! Tests cover:
//! - Configuration validation
//! - Default values
//! - Edge cases and boundary conditions
//! - RFC compliance for ALPN and protocol settings

#[cfg(test)]
mod global_config_tests {
    use crate::config::global::{GlobalConfig, LogLevel, LoggingConfig, NetworkConfig, RuntimeConfig, TlsConfig};

    #[test]
    fn test_network_config_default() {
        let config = NetworkConfig::default();
        assert_eq!(config.host, "0.0.0.0");
        assert_eq!(config.port, 443);
        assert!(config.reuse_addr);
    }

    #[test]
    fn test_network_config_valid_ipv4() {
        let config = NetworkConfig {
            host: "127.0.0.1".to_string(),
            port: 8443,
            reuse_addr: true,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_network_config_valid_ipv6() {
        let config = NetworkConfig {
            host: "::".to_string(),
            port: 443,
            reuse_addr: true,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_network_config_invalid_host() {
        let config = NetworkConfig {
            host: "not-an-ip-address".to_string(),
            port: 443,
            reuse_addr: true,
        };
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("Invalid host address")));
    }

    #[test]
    fn test_runtime_config_default() {
        let config = RuntimeConfig::default();
        assert!(config.worker_threads > 0);
        assert_eq!(config.max_blocking_threads, 512);
        assert_eq!(config.thread_name, "quicd-worker");
        assert_eq!(config.thread_stack_size, 2 * 1024 * 1024);
    }

    #[test]
    fn test_runtime_config_zero_workers() {
        let config = RuntimeConfig {
            worker_threads: 0,
            ..RuntimeConfig::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("worker_threads must be > 0")));
    }

    #[test]
    fn test_runtime_config_excessive_workers() {
        let config = RuntimeConfig {
            worker_threads: 2000,
            ..RuntimeConfig::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("unreasonably high")));
    }

    #[test]
    fn test_runtime_config_stack_too_small() {
        let config = RuntimeConfig {
            thread_stack_size: 64 * 1024, // 64KB, less than minimum
            ..RuntimeConfig::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("thread_stack_size too small")));
    }

    #[test]
    fn test_runtime_config_stack_too_large() {
        let config = RuntimeConfig {
            thread_stack_size: 128 * 1024 * 1024, // 128MB, more than max
            ..RuntimeConfig::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("thread_stack_size too large")));
    }

    #[test]
    fn test_log_level_parsing() {
        assert_eq!("trace".parse::<LogLevel>().unwrap(), LogLevel::Trace);
        assert_eq!("debug".parse::<LogLevel>().unwrap(), LogLevel::Debug);
        assert_eq!("info".parse::<LogLevel>().unwrap(), LogLevel::Info);
        assert_eq!("warn".parse::<LogLevel>().unwrap(), LogLevel::Warn);
        assert_eq!("warning".parse::<LogLevel>().unwrap(), LogLevel::Warn);
        assert_eq!("error".parse::<LogLevel>().unwrap(), LogLevel::Error);
        // Case insensitive
        assert_eq!("DEBUG".parse::<LogLevel>().unwrap(), LogLevel::Debug);
        assert_eq!("INFO".parse::<LogLevel>().unwrap(), LogLevel::Info);
    }

    #[test]
    fn test_log_level_parsing_invalid() {
        assert!("invalid".parse::<LogLevel>().is_err());
        assert!("".parse::<LogLevel>().is_err());
    }

    #[test]
    fn test_log_level_display() {
        assert_eq!(LogLevel::Trace.to_string(), "trace");
        assert_eq!(LogLevel::Debug.to_string(), "debug");
        assert_eq!(LogLevel::Info.to_string(), "info");
        assert_eq!(LogLevel::Warn.to_string(), "warn");
        assert_eq!(LogLevel::Error.to_string(), "error");
    }

    #[test]
    fn test_logging_config_default() {
        let config = LoggingConfig::default();
        assert_eq!(config.level, LogLevel::Info);
        assert!(!config.json_format);
        assert!(config.enable_colors);
        assert!(!config.include_file_line);
    }

    #[test]
    fn test_tls_config_missing_cert() {
        let config = TlsConfig {
            cert_path: None,
            key_path: Some("/path/to/key.pem".into()),
            ..TlsConfig::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("cert_path is required")));
    }

    #[test]
    fn test_tls_config_missing_key() {
        let config = TlsConfig {
            cert_path: Some("/path/to/cert.pem".into()),
            key_path: None,
            ..TlsConfig::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("key_path is required")));
    }

    #[test]
    fn test_tls_config_both_missing() {
        let config = TlsConfig::default();
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.len() >= 2); // Both cert and key are missing
    }

    #[test]
    fn test_global_config_default() {
        let config = GlobalConfig::default();
        assert_eq!(config.network.host, "0.0.0.0");
        assert_eq!(config.network.port, 443);
    }
}

#[cfg(test)]
mod application_config_tests {
    use crate::config::application::{
        ApplicationConfig, ApplicationType, ApplicationTypeConfig, 
        HandlerConfig, Http3Config, HqInteropConfig, LimitsConfig,
        MoqConfig, PluginConfig, PluginSettings, PushConfig, QpackConfig,
    };

    #[test]
    fn test_application_config_empty_alpn() {
        let config = ApplicationConfig {
            alpn: vec![],
            app_type: "builtin:http3".to_string(),
            enabled: true,
            config: ApplicationTypeConfig::Http3(Http3Config::default()),
        };
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("At least one ALPN")));
    }

    #[test]
    fn test_application_config_empty_alpn_string() {
        let config = ApplicationConfig {
            alpn: vec!["".to_string()],
            app_type: "builtin:http3".to_string(),
            enabled: true,
            config: ApplicationTypeConfig::Http3(Http3Config::default()),
        };
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("cannot be empty")));
    }

    /// RFC 7301 specifies ALPN identifiers are length-prefixed with a single byte,
    /// meaning max length is 255 bytes.
    #[test]
    fn test_application_config_alpn_max_length() {
        let long_alpn = "a".repeat(256);
        let config = ApplicationConfig {
            alpn: vec![long_alpn],
            app_type: "builtin:http3".to_string(),
            enabled: true,
            config: ApplicationTypeConfig::Http3(Http3Config::default()),
        };
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("too long")));
    }

    #[test]
    fn test_application_config_alpn_exactly_255_bytes() {
        let max_alpn = "a".repeat(255);
        let config = ApplicationConfig {
            alpn: vec![max_alpn],
            app_type: "builtin:http3".to_string(),
            enabled: true,
            config: ApplicationTypeConfig::Http3(Http3Config::default()),
        };
        // Should be valid (255 is the max, not 254)
        let result = config.validate();
        assert!(result.is_ok());
    }

    #[test]
    fn test_application_type_parsing_http3() {
        let config = ApplicationConfig {
            alpn: vec!["h3".to_string()],
            app_type: "builtin:http3".to_string(),
            enabled: true,
            config: ApplicationTypeConfig::Http3(Http3Config::default()),
        };
        assert_eq!(config.parse_type().unwrap(), ApplicationType::Http3);
    }

    #[test]
    fn test_application_type_parsing_hq_interop() {
        let config = ApplicationConfig {
            alpn: vec!["hq-interop".to_string()],
            app_type: "builtin:hq-interop".to_string(),
            enabled: true,
            config: ApplicationTypeConfig::HqInterop(HqInteropConfig::default()),
        };
        assert_eq!(config.parse_type().unwrap(), ApplicationType::HqInterop);
    }

    #[test]
    fn test_application_type_parsing_moq() {
        let config = ApplicationConfig {
            alpn: vec!["moq".to_string()],
            app_type: "builtin:moq".to_string(),
            enabled: true,
            config: ApplicationTypeConfig::Moq(MoqConfig::default()),
        };
        assert_eq!(config.parse_type().unwrap(), ApplicationType::Moq);
    }

    #[test]
    fn test_application_type_parsing_plugin() {
        let config = ApplicationConfig {
            alpn: vec!["custom".to_string()],
            app_type: "plugin".to_string(),
            enabled: true,
            config: ApplicationTypeConfig::Plugin(PluginConfig::default()),
        };
        assert_eq!(config.parse_type().unwrap(), ApplicationType::Plugin);
    }

    #[test]
    fn test_application_type_parsing_unknown_builtin() {
        let config = ApplicationConfig {
            alpn: vec!["unknown".to_string()],
            app_type: "builtin:unknown".to_string(),
            enabled: true,
            config: ApplicationTypeConfig::Http3(Http3Config::default()),
        };
        let result = config.parse_type();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown builtin"));
    }

    #[test]
    fn test_application_type_parsing_invalid_format() {
        let config = ApplicationConfig {
            alpn: vec!["test".to_string()],
            app_type: "invalid-format".to_string(),
            enabled: true,
            config: ApplicationTypeConfig::Http3(Http3Config::default()),
        };
        let result = config.parse_type();
        assert!(result.is_err());
    }

    #[test]
    fn test_http3_config_default() {
        let config = Http3Config::default();
        assert_eq!(config.qpack.max_table_capacity, 4096);
        assert_eq!(config.qpack.blocked_streams, 100);
        assert!(!config.push.enabled);
        assert!(config.handler.file_serving_enabled);
        assert_eq!(config.limits.max_field_section_size, 16384);
        assert_eq!(config.limits.max_concurrent_streams, 100);
        assert_eq!(config.limits.idle_timeout_secs, 30);
    }

    #[test]
    fn test_http3_config_zero_table_capacity() {
        let config = Http3Config {
            qpack: QpackConfig {
                max_table_capacity: 0,
                ..QpackConfig::default()
            },
            ..Http3Config::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("max_table_capacity"));
    }

    #[test]
    fn test_http3_config_push_enabled_zero_concurrent() {
        let config = Http3Config {
            push: PushConfig {
                enabled: true,
                max_concurrent: 0,
            },
            ..Http3Config::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("max_concurrent"));
    }

    #[test]
    fn test_http3_config_file_serving_empty_root() {
        let config = Http3Config {
            handler: HandlerConfig {
                file_serving_enabled: true,
                file_root: "".to_string(),
                ..HandlerConfig::default()
            },
            ..Http3Config::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("file_root"));
    }

    #[test]
    fn test_http3_config_zero_field_section_size() {
        let config = Http3Config {
            limits: LimitsConfig {
                max_field_section_size: 0,
                ..LimitsConfig::default()
            },
            ..Http3Config::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("max_field_section_size"));
    }

    #[test]
    fn test_http3_config_zero_concurrent_streams() {
        let config = Http3Config {
            limits: LimitsConfig {
                max_concurrent_streams: 0,
                ..LimitsConfig::default()
            },
            ..Http3Config::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("max_concurrent_streams"));
    }

    #[test]
    fn test_moq_config_default() {
        let config = MoqConfig::default();
        assert_eq!(config.max_streams, 50);
        assert!(config.track_sources);
    }

    #[test]
    fn test_moq_config_zero_streams() {
        let config = MoqConfig {
            max_streams: 0,
            ..MoqConfig::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("max_streams"));
    }

    #[test]
    fn test_hq_interop_config_default() {
        let config = HqInteropConfig::default();
        assert_eq!(config.handler.file_root, "/www");
    }

    #[test]
    fn test_hq_interop_config_empty_file_root() {
        let config = HqInteropConfig {
            handler: crate::config::application::HqInteropHandlerConfig {
                file_root: "".to_string(),
                ..Default::default()
            },
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("file_root"));
    }
}

#[cfg(test)]
mod server_config_tests {
    use crate::config::{ServerConfig, ApplicationConfig};
    use crate::config::application::{ApplicationTypeConfig, Http3Config};
    use std::collections::HashMap;

    fn make_valid_app_config(alpn: &str) -> ApplicationConfig {
        ApplicationConfig {
            alpn: vec![alpn.to_string()],
            app_type: "builtin:http3".to_string(),
            enabled: true,
            config: ApplicationTypeConfig::Http3(Http3Config::default()),
        }
    }

    #[test]
    fn test_server_config_default() {
        let config = ServerConfig::default();
        assert!(config.applications.is_empty());
    }

    #[test]
    fn test_server_config_find_app_by_alpn() {
        let mut config = ServerConfig::default();
        config.applications.insert("http3".to_string(), make_valid_app_config("h3"));
        
        let found = config.find_app_by_alpn("h3");
        assert!(found.is_some());
        assert_eq!(found.unwrap().0, "http3");

        let not_found = config.find_app_by_alpn("h3-29");
        assert!(not_found.is_none());
    }

    #[test]
    fn test_server_config_supported_alpns() {
        let mut config = ServerConfig::default();
        config.applications.insert("http3".to_string(), ApplicationConfig {
            alpn: vec!["h3".to_string(), "h3-29".to_string()],
            app_type: "builtin:http3".to_string(),
            enabled: true,
            config: ApplicationTypeConfig::Http3(Http3Config::default()),
        });
        
        let alpns = config.supported_alpns();
        assert!(alpns.contains(&"h3"));
        assert!(alpns.contains(&"h3-29"));
    }

    #[test]
    fn test_server_config_disabled_app_not_in_supported() {
        let mut config = ServerConfig::default();
        config.applications.insert("http3".to_string(), ApplicationConfig {
            alpn: vec!["h3".to_string()],
            app_type: "builtin:http3".to_string(),
            enabled: false, // Disabled
            config: ApplicationTypeConfig::Http3(Http3Config::default()),
        });
        
        let alpns = config.supported_alpns();
        assert!(alpns.is_empty());
    }

    #[test]
    fn test_server_config_duplicate_alpn_detection() {
        let mut config = ServerConfig::default();
        // Setting up TLS config to avoid validation failures there
        config.global.tls.cert_path = Some("/tmp/cert.pem".into());
        config.global.tls.key_path = Some("/tmp/key.pem".into());
        
        config.applications.insert("app1".to_string(), make_valid_app_config("h3"));
        config.applications.insert("app2".to_string(), make_valid_app_config("h3")); // Duplicate!
        
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("Duplicate ALPN")));
    }

    #[test]
    fn test_server_config_no_enabled_apps() {
        let mut config = ServerConfig::default();
        // Setting up TLS config to avoid validation failures there
        config.global.tls.cert_path = Some("/tmp/cert.pem".into());
        config.global.tls.key_path = Some("/tmp/key.pem".into());
        
        config.applications.insert("http3".to_string(), ApplicationConfig {
            alpn: vec!["h3".to_string()],
            app_type: "builtin:http3".to_string(),
            enabled: false, // All disabled
            config: ApplicationTypeConfig::Http3(Http3Config::default()),
        });
        
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("No enabled applications")));
    }
}

#[cfg(test)]
mod channel_config_tests {
    use crate::channel_config::ChannelConfig;

    #[test]
    fn test_channel_config_default() {
        let config = ChannelConfig::default();
        // These should match the serde default functions
        assert_eq!(config.worker_egress_capacity, 2048);
        assert_eq!(config.connection_ingress_capacity, 1024);
        assert_eq!(config.stream_ingress_capacity, 256);
        assert_eq!(config.stream_egress_capacity, 256);
    }

    #[test]
    fn test_channel_config_validate_too_small_egress() {
        let config = ChannelConfig {
            worker_egress_capacity: 32, // Below minimum of 64
            ..ChannelConfig::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("worker_egress_capacity"));
    }

    #[test]
    fn test_channel_config_validate_too_small_connection_ingress() {
        let config = ChannelConfig {
            connection_ingress_capacity: 16, // Below minimum of 32
            ..ChannelConfig::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("connection_ingress_capacity"));
    }

    #[test]
    fn test_channel_config_validate_too_small_stream_ingress() {
        let config = ChannelConfig {
            stream_ingress_capacity: 8, // Below minimum of 16
            ..ChannelConfig::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("stream_ingress_capacity"));
    }

    #[test]
    fn test_channel_config_validate_too_small_stream_egress() {
        let config = ChannelConfig {
            stream_egress_capacity: 8, // Below minimum of 16
            ..ChannelConfig::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("stream_egress_capacity"));
    }

    #[test]
    fn test_channel_config_validate_at_minimum() {
        let config = ChannelConfig {
            worker_egress_capacity: 64,
            connection_ingress_capacity: 32,
            stream_ingress_capacity: 16,
            stream_egress_capacity: 16,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_channel_config_memory_estimate() {
        let config = ChannelConfig::default();
        let estimate = config.estimate_memory_per_connection(10);
        // Should be positive and reasonable
        assert!(estimate > 0);
        // Connection ingress: 1024 * 100 = 102,400
        // Stream channels: 10 * (256 + 256) * 100 = 512,000
        // Total: ~614,400
        assert!(estimate > 500_000);
        assert!(estimate < 1_000_000);
    }

    #[test]
    fn test_channel_config_memory_estimate_zero_streams() {
        let config = ChannelConfig::default();
        let estimate = config.estimate_memory_per_connection(0);
        // Only connection ingress channel: 1024 * 100 = 102,400
        assert!(estimate > 50_000);
        assert!(estimate < 200_000);
    }
}

#[cfg(test)]
mod app_registry_tests {
    use crate::apps::{AppRegistry, AppFactory};
    use std::sync::Arc;
    
    fn mock_factory() -> AppFactory {
        Arc::new(|| {
            Arc::new(quicd_h3::H3Application::new(quicd_h3::H3Config::default()))
        })
    }

    #[test]
    fn test_registry_new_empty() {
        let registry = AppRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_registry_register_single() {
        let registry = AppRegistry::new()
            .register("h3", mock_factory())
            .unwrap();
        
        assert_eq!(registry.len(), 1);
        assert!(!registry.is_empty());
        assert!(registry.get("h3").is_some());
    }

    #[test]
    fn test_registry_register_multiple() {
        let registry = AppRegistry::new()
            .register("h3", mock_factory()).unwrap()
            .register("h3-29", mock_factory()).unwrap()
            .register("hq-interop", mock_factory()).unwrap();
        
        assert_eq!(registry.len(), 3);
        assert!(registry.get("h3").is_some());
        assert!(registry.get("h3-29").is_some());
        assert!(registry.get("hq-interop").is_some());
    }

    #[test]
    fn test_registry_duplicate_alpn_error() {
        let result = AppRegistry::new()
            .register("h3", mock_factory()).unwrap()
            .register("h3", mock_factory()); // Duplicate!
        
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.to_string().contains("already registered"));
    }

    #[test]
    fn test_registry_get_nonexistent() {
        let registry = AppRegistry::new()
            .register("h3", mock_factory()).unwrap();
        
        assert!(registry.get("unknown").is_none());
    }

    #[test]
    fn test_registry_alpns_list() {
        let registry = AppRegistry::new()
            .register("h3", mock_factory()).unwrap()
            .register("h3-29", mock_factory()).unwrap();
        
        let alpns = registry.alpns();
        assert_eq!(alpns.len(), 2);
        // Order should be preserved (insertion order)
        assert_eq!(alpns[0], "h3");
        assert_eq!(alpns[1], "h3-29");
    }

    #[test]
    fn test_registry_get_all_alpn_protocols() {
        let registry = AppRegistry::new()
            .register("h3", mock_factory()).unwrap()
            .register("h3-29", mock_factory()).unwrap();
        
        let protocols = registry.get_all_alpn_protocols();
        assert_eq!(protocols.len(), 2);
        assert_eq!(protocols[0], "h3");
        assert_eq!(protocols[1], "h3-29");
    }

    #[test]
    fn test_registry_default() {
        let registry = AppRegistry::default();
        assert!(registry.is_empty());
    }
}

#[cfg(test)]
mod telemetry_tests {
    use crate::telemetry::config::TelemetryConfig;
    use crate::telemetry::metrics::{MetricsEvent, MetricsTimer};

    #[test]
    fn test_telemetry_config_default() {
        let config = TelemetryConfig::default();
        assert_eq!(config.otlp_endpoint, "http://localhost:4317");
        assert_eq!(config.service_name, "quicd");
        assert!(config.enable_metrics);
        assert!(!config.enable_tracing);
        assert_eq!(config.export_interval_secs, 60);
    }

    #[test]
    fn test_metrics_event_packet_received() {
        let event = MetricsEvent::PacketReceived { bytes: 1200 };
        match event {
            MetricsEvent::PacketReceived { bytes } => assert_eq!(bytes, 1200),
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_metrics_event_packet_sent() {
        let event = MetricsEvent::PacketSent { bytes: 1500 };
        match event {
            MetricsEvent::PacketSent { bytes } => assert_eq!(bytes, 1500),
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_metrics_event_connection_closed() {
        let event = MetricsEvent::ConnectionClosed { duration_ms: 30000 };
        match event {
            MetricsEvent::ConnectionClosed { duration_ms } => assert_eq!(duration_ms, 30000),
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_metrics_event_http_request() {
        let event = MetricsEvent::HttpRequest {
            method: "GET".to_string(),
            status: 200,
            duration_ms: 50,
        };
        match event {
            MetricsEvent::HttpRequest { method, status, duration_ms } => {
                assert_eq!(method, "GET");
                assert_eq!(status, 200);
                assert_eq!(duration_ms, 50);
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_metrics_timer_start() {
        let timer = MetricsTimer::start();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let elapsed = timer.elapsed_ms();
        assert!(elapsed >= 10);
        assert!(elapsed < 100); // Should not take more than 100ms
    }

    #[test]
    fn test_metrics_timer_elapsed_us() {
        let timer = MetricsTimer::start();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let elapsed_us = timer.elapsed_us();
        assert!(elapsed_us >= 1000); // At least 1000 microseconds (1ms)
    }

    #[test]
    fn test_metrics_event_clone() {
        let event = MetricsEvent::PacketReceived { bytes: 1200 };
        let cloned = event.clone();
        match cloned {
            MetricsEvent::PacketReceived { bytes } => assert_eq!(bytes, 1200),
            _ => panic!("Clone failed"),
        }
    }
}

#[cfg(test)]
mod runtime_tests {
    use crate::config::RuntimeConfig;
    use crate::runtime::create_runtime;

    #[test]
    fn test_create_runtime_basic() {
        let config = RuntimeConfig {
            worker_threads: 2,
            max_blocking_threads: 10,
            thread_name: "test-worker".to_string(),
            thread_stack_size: 2 * 1024 * 1024,
            enable_thread_stats: false,
        };
        
        let runtime = create_runtime(&config);
        assert!(runtime.is_ok());
    }

    #[test]
    fn test_create_runtime_single_thread() {
        let config = RuntimeConfig {
            worker_threads: 1,
            max_blocking_threads: 10,
            thread_name: "single".to_string(),
            thread_stack_size: 2 * 1024 * 1024,
            enable_thread_stats: false,
        };
        
        let runtime = create_runtime(&config);
        assert!(runtime.is_ok());
    }
}

#[cfg(test)]
mod validation_tests {
    use crate::config::{ServerConfig, ApplicationConfig};
    use crate::config::application::{ApplicationTypeConfig, Http3Config};
    use crate::config::validation::validate_resource_limits;

    #[test]
    fn test_validate_resource_limits_low_egress_capacity() {
        let mut config = ServerConfig::default();
        config.global.netio.workers = 8;
        config.global.channels.worker_egress_capacity = 100; // Too low for 8 workers
        
        // This should produce warnings but not errors
        let result = validate_resource_limits(&config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_resource_limits_runtime_less_than_netio() {
        let mut config = ServerConfig::default();
        config.global.netio.workers = 8;
        config.global.runtime.worker_threads = 4; // Less than netio workers
        
        // This should produce warnings but not errors
        let result = validate_resource_limits(&config);
        assert!(result.is_ok());
    }
}

#[cfg(test)]
mod edge_case_tests {
    use crate::config::application::{ApplicationConfig, ApplicationTypeConfig, Http3Config};

    /// Test that multiple ALPNs can be registered to a single application
    #[test]
    fn test_multiple_alpns_per_application() {
        let config = ApplicationConfig {
            alpn: vec!["h3".to_string(), "h3-29".to_string(), "h3-28".to_string()],
            app_type: "builtin:http3".to_string(),
            enabled: true,
            config: ApplicationTypeConfig::Http3(Http3Config::default()),
        };
        assert!(config.validate().is_ok());
        assert_eq!(config.alpn.len(), 3);
    }

    /// Test ALPN with special characters (should be valid per RFC)
    #[test]
    fn test_alpn_with_dashes_and_numbers() {
        let config = ApplicationConfig {
            alpn: vec!["my-proto-v1.0".to_string()],
            app_type: "builtin:http3".to_string(),
            enabled: true,
            config: ApplicationTypeConfig::Http3(Http3Config::default()),
        };
        assert!(config.validate().is_ok());
    }

    /// Test application with empty type
    #[test]
    fn test_empty_app_type() {
        let config = ApplicationConfig {
            alpn: vec!["h3".to_string()],
            app_type: "".to_string(), // Empty!
            enabled: true,
            config: ApplicationTypeConfig::Http3(Http3Config::default()),
        };
        let result = config.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("cannot be empty")));
    }
}
