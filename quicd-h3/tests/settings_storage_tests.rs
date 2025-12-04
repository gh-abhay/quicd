//! Integration tests for 0-RTT settings storage and validation.
//!
//! Tests the complete flow of storing settings after receiving them from a peer,
//! retrieving them on a subsequent connection, and validating compatibility.

use quicd_h3::settings::{known, SettingsValidator};
use quicd_h3::settings_storage::{InMemorySettingsStorage, Origin, SettingsStorage};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

#[test]
fn test_settings_storage_basic_flow() {
    let storage = InMemorySettingsStorage::new();
    let origin = Origin::new("https".to_string(), "example.com".to_string(), 443);

    // Initial connection - no remembered settings
    assert!(storage.retrieve(&origin).is_none());

    // Receive settings from server
    let mut settings = HashMap::new();
    settings.insert(known::MAX_FIELD_SECTION_SIZE, 8192);
    settings.insert(known::QPACK_MAX_TABLE_CAPACITY, 4096);
    settings.insert(known::ENABLE_CONNECT_PROTOCOL, 1);

    // Store for future use
    storage.store(origin.clone(), settings.clone());

    // Next connection - retrieve remembered settings
    let remembered = storage.retrieve(&origin).unwrap();
    assert_eq!(remembered.get(&known::MAX_FIELD_SECTION_SIZE), Some(&8192));
    assert_eq!(
        remembered.get(&known::QPACK_MAX_TABLE_CAPACITY),
        Some(&4096)
    );
    assert_eq!(remembered.get(&known::ENABLE_CONNECT_PROTOCOL), Some(&1));
}

#[test]
fn test_settings_validation_with_storage() {
    let storage = Arc::new(InMemorySettingsStorage::new());
    let origin = Origin::new("https".to_string(), "example.com".to_string(), 443);

    // First connection: receive and store settings
    let mut first_settings = HashMap::new();
    first_settings.insert(known::MAX_FIELD_SECTION_SIZE, 8192);
    first_settings.insert(known::QPACK_MAX_TABLE_CAPACITY, 4096);
    first_settings.insert(known::QPACK_BLOCKED_STREAMS, 100);

    storage.store(origin.clone(), first_settings.clone());

    // Second connection with 0-RTT: retrieve remembered settings
    let remembered = storage.retrieve(&origin).unwrap();
    let validator = SettingsValidator::with_remembered_settings(remembered);

    // New settings from server - compatible (same or increased)
    let mut second_settings = HashMap::new();
    second_settings.insert(known::MAX_FIELD_SECTION_SIZE, 16384); // Increased - OK
    second_settings.insert(known::QPACK_MAX_TABLE_CAPACITY, 4096); // Same - OK
    second_settings.insert(known::QPACK_BLOCKED_STREAMS, 200); // Increased - OK

    assert!(validator
        .validate_0rtt_compatibility(&second_settings)
        .is_ok());
}

#[test]
fn test_settings_validation_rejects_reduced_limits() {
    let storage = Arc::new(InMemorySettingsStorage::new());
    let origin = Origin::new("https".to_string(), "example.com".to_string(), 443);

    // First connection
    let mut first_settings = HashMap::new();
    first_settings.insert(known::MAX_FIELD_SECTION_SIZE, 16384);
    storage.store(origin.clone(), first_settings);

    // Second connection with 0-RTT
    let remembered = storage.retrieve(&origin).unwrap();
    let validator = SettingsValidator::with_remembered_settings(remembered);

    // New settings reduce the limit - MUST be rejected
    let mut second_settings = HashMap::new();
    second_settings.insert(known::MAX_FIELD_SECTION_SIZE, 8192); // Reduced!

    assert!(validator
        .validate_0rtt_compatibility(&second_settings)
        .is_err());
}

#[test]
fn test_settings_expiration() {
    let storage = InMemorySettingsStorage::with_ttl(Duration::from_millis(50));
    let origin = Origin::new("https".to_string(), "example.com".to_string(), 443);

    let mut settings = HashMap::new();
    settings.insert(known::MAX_FIELD_SECTION_SIZE, 8192);
    storage.store(origin.clone(), settings);

    // Should be retrievable immediately
    assert!(storage.retrieve(&origin).is_some());

    // Wait for expiration
    std::thread::sleep(Duration::from_millis(100));

    // Should be expired and auto-removed
    assert!(storage.retrieve(&origin).is_none());
}

#[test]
fn test_multiple_origins_isolated() {
    let storage = InMemorySettingsStorage::new();

    let origin1 = Origin::new("https".to_string(), "example.com".to_string(), 443);
    let origin2 = Origin::new("https".to_string(), "other.com".to_string(), 443);

    let mut settings1 = HashMap::new();
    settings1.insert(known::MAX_FIELD_SECTION_SIZE, 8192);

    let mut settings2 = HashMap::new();
    settings2.insert(known::MAX_FIELD_SECTION_SIZE, 16384);

    storage.store(origin1.clone(), settings1);
    storage.store(origin2.clone(), settings2);

    // Each origin should have its own settings
    assert_eq!(
        storage
            .retrieve(&origin1)
            .unwrap()
            .get(&known::MAX_FIELD_SECTION_SIZE),
        Some(&8192)
    );
    assert_eq!(
        storage
            .retrieve(&origin2)
            .unwrap()
            .get(&known::MAX_FIELD_SECTION_SIZE),
        Some(&16384)
    );
}

#[test]
fn test_0rtt_settings_validation_complete_flow() {
    // Simulate the complete 0-RTT flow:
    // 1. Initial connection receives settings
    // 2. Settings are stored
    // 3. New connection with 0-RTT retrieves settings
    // 4. New connection validates received settings against remembered ones

    let storage = Arc::new(InMemorySettingsStorage::new());
    let origin = Origin::new("https".to_string(), "cdn.example.com".to_string(), 443);

    // === FIRST CONNECTION ===
    let mut first_validator = SettingsValidator::new();

    // Receive SETTINGS frame
    let mut received_settings = HashMap::new();
    received_settings.insert(known::MAX_FIELD_SECTION_SIZE, 65536);
    received_settings.insert(known::QPACK_MAX_TABLE_CAPACITY, 8192);
    received_settings.insert(known::QPACK_BLOCKED_STREAMS, 100);
    received_settings.insert(known::ENABLE_CONNECT_PROTOCOL, 1);

    // Validate and remember
    assert!(first_validator
        .validate_settings(received_settings.clone())
        .is_ok());
    first_validator.remember_settings();

    // Store persistently
    storage.store(origin.clone(), received_settings);

    // === SECOND CONNECTION (0-RTT) ===

    // Retrieve remembered settings
    let remembered = storage
        .retrieve(&origin)
        .expect("should have remembered settings");

    // Create validator with remembered settings for 0-RTT validation
    let mut second_validator = SettingsValidator::with_remembered_settings(remembered);

    // Server sends new SETTINGS frame
    let mut new_settings = HashMap::new();
    new_settings.insert(known::MAX_FIELD_SECTION_SIZE, 65536); // Same - OK
    new_settings.insert(known::QPACK_MAX_TABLE_CAPACITY, 16384); // Increased - OK
    new_settings.insert(known::QPACK_BLOCKED_STREAMS, 100); // Same - OK
    new_settings.insert(known::ENABLE_CONNECT_PROTOCOL, 1); // Still enabled - OK

    // Validate 0-RTT compatibility BEFORE processing settings
    assert!(second_validator
        .validate_0rtt_compatibility(&new_settings)
        .is_ok());

    // Then validate and process the settings normally
    assert!(second_validator
        .validate_settings(new_settings.clone())
        .is_ok());

    // Remember for next time
    second_validator.remember_settings();
    storage.store(origin.clone(), new_settings);
}

#[test]
fn test_0rtt_validation_rejects_disabled_feature() {
    let storage = Arc::new(InMemorySettingsStorage::new());
    let origin = Origin::new("https".to_string(), "example.com".to_string(), 443);

    // First connection: extended CONNECT enabled
    let mut first_settings = HashMap::new();
    first_settings.insert(known::ENABLE_CONNECT_PROTOCOL, 1);
    storage.store(origin.clone(), first_settings);

    // Second connection with 0-RTT
    let remembered = storage.retrieve(&origin).unwrap();
    let validator = SettingsValidator::with_remembered_settings(remembered);

    // Server tries to disable extended CONNECT - MUST be rejected
    let mut second_settings = HashMap::new();
    second_settings.insert(known::ENABLE_CONNECT_PROTOCOL, 0); // Disabled!

    assert!(validator
        .validate_0rtt_compatibility(&second_settings)
        .is_err());
}

#[test]
fn test_0rtt_validation_rejects_omitted_non_default() {
    let storage = Arc::new(InMemorySettingsStorage::new());
    let origin = Origin::new("https".to_string(), "example.com".to_string(), 443);

    // First connection: non-default value
    let mut first_settings = HashMap::new();
    first_settings.insert(known::MAX_FIELD_SECTION_SIZE, 8192);
    storage.store(origin.clone(), first_settings);

    // Second connection with 0-RTT
    let remembered = storage.retrieve(&origin).unwrap();
    let validator = SettingsValidator::with_remembered_settings(remembered);

    // Server omits the setting entirely - MUST be rejected
    let second_settings = HashMap::new(); // Empty!

    assert!(validator
        .validate_0rtt_compatibility(&second_settings)
        .is_err());
}

#[test]
fn test_clear_expired_maintains_fresh_entries() {
    let storage = InMemorySettingsStorage::with_ttl(Duration::from_millis(100));

    let origin1 = Origin::new("https".to_string(), "old.example.com".to_string(), 443);
    let origin2 = Origin::new("https".to_string(), "new.example.com".to_string(), 443);

    let mut settings = HashMap::new();
    settings.insert(known::MAX_FIELD_SECTION_SIZE, 8192);

    // Store first entry
    storage.store(origin1.clone(), settings.clone());

    // Wait for it to become stale
    std::thread::sleep(Duration::from_millis(150));

    // Store second entry (fresh)
    storage.store(origin2.clone(), settings.clone());

    assert_eq!(storage.len(), 2);

    // Clear expired
    storage.clear_expired();

    // Only fresh entry should remain
    assert_eq!(storage.len(), 1);
    assert!(storage.retrieve(&origin1).is_none());
    assert!(storage.retrieve(&origin2).is_some());
}

#[test]
fn test_origin_parsing_with_port() {
    let origin = Origin::from_authority("https".to_string(), "example.com:8443").unwrap();
    assert_eq!(origin.scheme, "https");
    assert_eq!(origin.host, "example.com");
    assert_eq!(origin.port, 8443);
}

#[test]
fn test_origin_parsing_without_port() {
    let origin = Origin::from_authority("https".to_string(), "example.com").unwrap();
    assert_eq!(origin.scheme, "https");
    assert_eq!(origin.host, "example.com");
    assert_eq!(origin.port, 443); // Default HTTPS port
}

#[test]
fn test_origin_equality() {
    let origin1 = Origin::new("https".to_string(), "example.com".to_string(), 443);
    let origin2 = Origin::new("https".to_string(), "example.com".to_string(), 443);
    let origin3 = Origin::new("https".to_string(), "example.com".to_string(), 8443);

    assert_eq!(origin1, origin2);
    assert_ne!(origin1, origin3);
}
