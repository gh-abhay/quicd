//! Simple HTTP/3 file server example using quicd-h3.
//!
//! This example demonstrates how to configure and run an HTTP/3 server
//! that serves static files from a directory.
//!
//! # Usage
//!
//! ```bash
//! # Create a directory with some test files
//! mkdir -p www
//! echo "<html><body>Hello, HTTP/3!</body></html>" > www/index.html
//!
//! # Run the server
//! cargo run --package quicd-h3 --example file_server
//!
//! # Test with curl (requires HTTP/3 support)
//! curl --http3 https://localhost:4433/index.html
//! ```

use quicd_h3::{H3Application, H3Config};
use std::path::PathBuf;

fn main() {
    // Configure the HTTP/3 application
    let mut config = H3Config::default();

    // File serving configuration
    config.handler.file_root = PathBuf::from("./www");
    config.handler.file_serving_enabled = true;
    config.handler.directory_listing = false; // Security: disable directory listing
    config.handler.compression_enabled = true;
    config.handler.compression_algorithms = vec!["gzip".to_string(), "br".to_string()];
    config.handler.index_files = vec!["index.html".to_string(), "index.htm".to_string()];

    // QPACK configuration
    config.qpack.max_table_capacity = 4096;
    config.qpack.blocked_streams = 100;

    // Connection limits
    config.limits.max_field_section_size = 16384;
    config.limits.max_concurrent_streams = 100;
    config.limits.idle_timeout_secs = 30;

    // Server push (optional)
    config.push.enabled = false;

    // Validate configuration
    let errors = config.validate();
    if !errors.is_empty() {
        eprintln!("Configuration errors:");
        for error in errors {
            eprintln!("  - {}", error);
        }
        std::process::exit(1);
    }

    // Create the application
    let app = H3Application::new(config);

    println!("HTTP/3 file server configured");
    println!("  Serving files from: {:?}", app.config().handler.file_root);
    println!(
        "  QPACK table capacity: {} bytes",
        app.config().qpack.max_table_capacity
    );
    println!(
        "  Max concurrent streams: {}",
        app.config().limits.max_concurrent_streams
    );
    println!();
    println!("To use this application, register it with quicd:");
    println!("  1. Add to quicd.toml:");
    println!("     [[applications]]");
    println!("     alpn = \"h3\"");
    println!("     type = \"http3\"");
    println!("  2. Run: sudo quicd --config quicd.toml");
}
