//! TLS/Crypto configuration for QUIC.
//!
//! Provides TLS certificate and key management for Quiche.
//! Supports both file-based certificates and self-signed certificates.

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

/// TLS credentials (certificate chain and private key)
#[derive(Clone)]
pub struct TlsCredentials {
    /// Certificate chain in PEM format
    pub cert_chain: Vec<u8>,
    /// Private key in PEM format
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

    /// Generate self-signed certificate for testing/development
    ///
    /// **WARNING**: This should NOT be used in production!
    /// Self-signed certificates are insecure and should only be used for:
    /// - Local development
    /// - Testing
    /// - Internal networks where trust is already established
    pub fn self_signed() -> Result<Self> {
        // Use rcgen to generate self-signed certificate
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .context("failed to generate self-signed certificate")?;

        let cert_chain = cert.cert.pem().into_bytes();
        let key = cert.key_pair.serialize_pem().into_bytes();

        Ok(Self { cert_chain, key })
    }
}

/// Create Quiche configuration with TLS credentials
pub fn create_quiche_config(
    credentials: &TlsCredentials,
    config: &super::config::QuicConfig,
) -> Result<quiche::Config> {
    let mut quic_config =
        quiche::Config::new(quiche::PROTOCOL_VERSION).context("failed to create quiche config")?;

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
    quic_config.set_cc_algorithm(config.congestion_control.into());

    // Enable/disable features
    quic_config.enable_early_data();
    if config.enable_early_data {
        quic_config.enable_early_data();
    }

    if config.disable_active_migration {
        quic_config.set_disable_active_migration(true);
    }

    if config.enable_pacing {
        quic_config.enable_pacing(true);
    }

    // DATAGRAM extension
    if config.enable_dgram {
        quic_config.enable_dgram(true, config.max_dgram_size, config.max_dgram_size);
    }

    // Additional optimizations
    quic_config.set_ack_delay_exponent(3); // Default is 3
    quic_config.set_max_ack_delay(25); // 25ms max ack delay

    // Set initial RTT estimate
    // This helps with initial congestion window sizing
    // Note: Quiche doesn't expose set_initial_rtt, it uses internal defaults

    Ok(quic_config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_self_signed_cert() {
        let creds = TlsCredentials::self_signed().expect("failed to generate cert");
        assert!(!creds.cert_chain.is_empty());
        assert!(!creds.key.is_empty());
    }

    #[test]
    fn test_create_quiche_config() {
        let creds = TlsCredentials::self_signed().expect("failed to generate cert");
        let quic_config = super::super::config::QuicConfig::default();
        let config = create_quiche_config(&creds, &quic_config);
        assert!(config.is_ok());
    }
}
