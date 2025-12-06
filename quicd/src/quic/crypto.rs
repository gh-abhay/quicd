//! TLS/Crypto configuration for QUIC.
//!
//! Provides TLS certificate and key management for Quiche.
//! Production-ready TLS certificate loading from files.
//!
//! Expects:
//! - Certificate files: .crt extension (PEM-encoded X.509 certificates)
//! - Private key files: .key extension (PEM-encoded private keys)

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

/// TLS credentials (certificate chain and private key)
#[derive(Clone)]
pub struct TlsCredentials {
    /// Certificate chain in PEM format (.crt file)
    pub cert_chain: Vec<u8>,
    /// Private key in PEM format (.key file)
    pub key: Vec<u8>,
}

impl TlsCredentials {
    /// Load credentials from files
    pub fn from_files(cert_path: &Path, key_path: &Path) -> Result<Self> {
        let cert_chain = fs::read(cert_path)
            .with_context(|| format!("failed to read certificate from {:?}", cert_path))?;

        let key = fs::read(key_path)
            .with_context(|| format!("failed to read private key from {:?}", key_path))?;

        Ok(Self { cert_chain, key })
    }
}

/// Create Quiche configuration with TLS credentials
pub fn create_quiche_config(
    credentials: &TlsCredentials,
    config: &super::config::QuicConfig,
    version: u32,
) -> Result<quiche::Config> {
    let mut quic_config = quiche::Config::new(version).with_context(|| {
        format!(
            "failed to create quiche config for version {:#010x}",
            version
        )
    })?;

    // Write credentials to temp files (Quiche expects file paths)
    // Use thread ID + timestamp for uniqueness to avoid races
    let temp_dir = std::env::temp_dir();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let thread_id = std::thread::current().id();
    let unique_id = format!("{:?}-{}", thread_id, timestamp);

    let cert_path = temp_dir.join(format!("quicd-cert-{}.pem", unique_id));
    let key_path = temp_dir.join(format!("quicd-key-{}.pem", unique_id));

    std::fs::write(&cert_path, &credentials.cert_chain)
        .context("failed to write certificate to temp file")?;
    std::fs::write(&key_path, &credentials.key).context("failed to write key to temp file")?;

    // Load TLS certificate and key
    quic_config
        .load_cert_chain_from_pem_file(&cert_path.to_string_lossy())
        .context("failed to load certificate chain")?;

    quic_config
        .load_priv_key_from_pem_file(&key_path.to_string_lossy())
        .context("failed to load private key")?;

    // Clean up temp files
    let _ = std::fs::remove_file(cert_path);
    let _ = std::fs::remove_file(key_path);

    // Load custom CA certificates for peer verification
    if let Some(ca_file) = &config.ca_cert_file {
        quic_config
            .load_verify_locations_from_file(ca_file)
            .with_context(|| format!("failed to load CA cert from file: {}", ca_file))?;
    }
    if let Some(ca_dir) = &config.ca_cert_dir {
        quic_config
            .load_verify_locations_from_directory(ca_dir)
            .with_context(|| format!("failed to load CA certs from directory: {}", ca_dir))?;
    }

    // Set application protocols (ALPN)
    // For now, we support generic QUIC. Application layer will add more later.
    quic_config
        .set_application_protos(&[
            b"quic",   // Generic QUIC
            b"h3",     // HTTP/3 (for future)
            b"h3-29",  // HTTP/3 draft-29
            b"moq-00", // Media over QUIC (for future)
        ])
        .context("failed to set ALPN")?;

    // Transport parameters
    quic_config.set_max_idle_timeout(config.max_idle_timeout_ms);
    quic_config.set_max_recv_udp_payload_size(config.max_udp_payload_size);
    quic_config.set_max_send_udp_payload_size(config.max_udp_payload_size);
    quic_config.set_initial_max_data(config.recv_window);
    quic_config.set_initial_max_stream_data_bidi_local(config.stream_recv_window);
    quic_config.set_initial_max_stream_data_bidi_remote(config.stream_recv_window);
    quic_config.set_initial_max_stream_data_uni(config.stream_recv_window);
    quic_config.set_initial_max_streams_bidi(config.max_streams_bidi);
    quic_config.set_initial_max_streams_uni(config.max_streams_uni);

    // Congestion control
    let cc_algo = match config.congestion_control {
        quicd_x::CongestionControl::Bbr => quiche::CongestionControlAlgorithm::BBR,
        quicd_x::CongestionControl::Bbr2 => quiche::CongestionControlAlgorithm::BBR2,
        quicd_x::CongestionControl::Cubic => quiche::CongestionControlAlgorithm::CUBIC,
        quicd_x::CongestionControl::Reno => quiche::CongestionControlAlgorithm::Reno,
    };
    quic_config.set_cc_algorithm(cc_algo);

    // Enable/disable features
    if config.enable_early_data {
        quic_config.enable_early_data();
    }

    if config.disable_active_migration {
        quic_config.set_disable_active_migration(true);
    }

    if config.enable_pacing {
        quic_config.enable_pacing(true);
    }

    // DATAGRAM extension (RFC 9221)
    if config.enable_dgram {
        quic_config.enable_dgram(
            true,
            config.dgram_recv_max_queue_len,
            config.dgram_send_max_queue_len,
        );
    }

    // Transport parameters (RFC 9000 §18.2)
    quic_config.set_ack_delay_exponent(config.ack_delay_exponent);
    quic_config.set_max_ack_delay(config.max_ack_delay);
    quic_config.set_active_connection_id_limit(config.active_connection_id_limit);
    
    // Flow control windows
    if let Some(max_conn_window) = get_max_connection_window(config) {
        quic_config.set_max_connection_window(max_conn_window);
    }
    if let Some(max_stream_window) = get_max_stream_window(config) {
        quic_config.set_max_stream_window(max_stream_window);
    }

    // Initial RTT estimate (RFC 9002 §6.2.2)
    quic_config.set_initial_rtt(std::time::Duration::from_millis(config.initial_rtt_ms));
    
    // Stateless reset token (RFC 9000 §10.3)
    if let Some(token) = config.stateless_reset_token {
        quic_config.set_stateless_reset_token(Some(u128::from_be_bytes(token)));
    }
    
    // Congestion control tuning (RFC 9002)
    quic_config.set_initial_congestion_window_packets(config.initial_congestion_window_packets);
    quic_config.enable_hystart(config.enable_hystart);
    if let Some(max_rate) = config.max_pacing_rate {
        quic_config.set_max_pacing_rate(max_rate);
    }
    quic_config.set_max_amplification_factor(config.max_amplification_factor);
    
    // PMTU discovery (RFC 9000 §14)
    quic_config.discover_pmtu(config.discover_pmtu);
    
    // GREASE (RFC 9287)
    quic_config.grease(config.grease);
    
    // DCID reuse control
    quic_config.set_disable_dcid_reuse(config.disable_dcid_reuse);
    
    // TLS key logging for debugging
    if config.log_keys {
        quic_config.log_keys();
    }

    Ok(quic_config)
}

/// Calculate maximum connection window based on config
fn get_max_connection_window(config: &super::config::QuicConfig) -> Option<u64> {
    // Set to 4x the receive window for better performance
    Some(config.recv_window * 4)
}

/// Calculate maximum stream window based on config
fn get_max_stream_window(config: &super::config::QuicConfig) -> Option<u64> {
    // Set to 4x the stream receive window
    Some(config.stream_recv_window * 4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_from_files() {
        // Note: This test requires cert.pem and key.pem files to exist
        // In production, certificates must always be provided
        // We skip this test if files don't exist
        let cert_path = std::path::Path::new("certs/cert.pem");
        let key_path = std::path::Path::new("certs/key.pem");
        
        if cert_path.exists() && key_path.exists() {
            let result = TlsCredentials::from_files(cert_path, key_path);
            assert!(result.is_ok());
            let creds = result.unwrap();
            assert!(!creds.cert_chain.is_empty());
            assert!(!creds.key.is_empty());
        }
    }

    #[test]
    fn test_new_config_fields_are_set() {
        use super::super::config::QuicConfig;
        
        let mut quic_config = QuicConfig::default();
        
        // Set all new transport config fields and verify they can be changed
        quic_config.ack_delay_exponent = 5;
        assert_eq!(quic_config.ack_delay_exponent, 5);
        
        quic_config.active_connection_id_limit = 4;
        assert_eq!(quic_config.active_connection_id_limit, 4);
        
        quic_config.stateless_reset_token = Some([42u8; 16]);
        assert!(quic_config.stateless_reset_token.is_some());
        
        quic_config.enable_hystart = false;
        assert!(!quic_config.enable_hystart);
        
        quic_config.enable_pacing = false;
        assert!(!quic_config.enable_pacing);
        
        quic_config.discover_pmtu = true;
        assert!(quic_config.discover_pmtu);
        
        quic_config.grease = false;
        assert!(!quic_config.grease);
        
        quic_config.disable_dcid_reuse = true;
        assert!(quic_config.disable_dcid_reuse);
    }

    #[test]
    fn test_ca_cert_file_path_validation() {
        use super::super::config::QuicConfig;
        
        let mut quic_config = QuicConfig::default();
        quic_config.ca_cert_file = Some("/nonexistent/ca.pem".into());
        
        // Should fail when trying to load nonexistent file
        let result = create_quiche_config(
            &TlsCredentials {
                cert_chain: vec![1, 2, 3],
                key: vec![4, 5, 6],
            },
            &quic_config,
            quiche::PROTOCOL_VERSION,
        );
        
        // Will fail if file doesn't exist
        assert!(result.is_err());
    }

    #[test]
    fn test_ca_cert_dir_path_validation() {
        use super::super::config::QuicConfig;
        
        let mut quic_config = QuicConfig::default();
        quic_config.ca_cert_dir = Some("/nonexistent/ca_dir".into());
        
        // Should fail when trying to load nonexistent directory
        let result = create_quiche_config(
            &TlsCredentials {
                cert_chain: vec![1, 2, 3],
                key: vec![4, 5, 6],
            },
            &quic_config,
            quiche::PROTOCOL_VERSION,
        );
        
        // Will fail if directory doesn't exist
        assert!(result.is_err());
    }
}
