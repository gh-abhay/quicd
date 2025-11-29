//! SETTINGS frame validation and enforcement per RFC 9114 Section 7.2.4.
//!
//! Manages settings received from peer and validates their usage.

use crate::error::H3Error;
use std::collections::HashMap;

/// Settings identifier type.
pub type SettingId = u64;

/// Well-known settings from RFC 9114.
pub mod known {
    use super::SettingId;

    /// Maximum field section size (RFC 9114 Section 7.2.4.1)
    pub const QPACK_MAX_TABLE_CAPACITY: SettingId = 0x01;
    
    /// Reserved settings that MUST be rejected (RFC 9114 Section 7.2.4.1)
    pub const RESERVED_0X02: SettingId = 0x02;
    pub const RESERVED_0X03: SettingId = 0x03;
    pub const RESERVED_0X04: SettingId = 0x04;
    pub const RESERVED_0X05: SettingId = 0x05;
    
    /// Maximum field section size
    pub const MAX_FIELD_SECTION_SIZE: SettingId = 0x06;
    
    /// QPACK blocked streams
    pub const QPACK_BLOCKED_STREAMS: SettingId = 0x07;
    
    /// Enable CONNECT protocol (extended CONNECT)
    pub const ENABLE_CONNECT_PROTOCOL: SettingId = 0x08;
    
    /// Enable WebTransport
    pub const H3_DATAGRAM: SettingId = 0x33;
    
    /// Enable WebTransport drafts
    pub const ENABLE_WEBTRANSPORT: SettingId = 0x2b603742;

    /// Check if a setting ID is reserved.
    pub fn is_reserved(id: SettingId) -> bool {
        matches!(id, RESERVED_0X02 | RESERVED_0X03 | RESERVED_0X04 | RESERVED_0X05)
    }
}

/// State of settings on a control stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsState {
    /// No SETTINGS frame received yet
    AwaitingSettings,
    /// SETTINGS frame received
    Received,
}

/// Validator for SETTINGS frames on control stream.
pub struct SettingsValidator {
    state: SettingsState,
    settings: HashMap<SettingId, u64>,
    /// Settings from previous session for 0-RTT validation (RFC 9114 Section 7.2.4.2)
    remembered_settings: Option<HashMap<SettingId, u64>>,
}

impl SettingsValidator {
    /// Create a new settings validator.
    pub fn new() -> Self {
        Self {
            state: SettingsState::AwaitingSettings,
            settings: HashMap::new(),
            remembered_settings: None,
        }
    }

    /// Create a settings validator with remembered settings from a previous session.
    ///
    /// Used for 0-RTT connections per RFC 9114 Section 7.2.4.2.
    pub fn with_remembered_settings(remembered_settings: HashMap<SettingId, u64>) -> Self {
        Self {
            state: SettingsState::AwaitingSettings,
            settings: HashMap::new(),
            remembered_settings: Some(remembered_settings),
        }
    }

    /// Validate and process a SETTINGS frame.
    ///
    /// Per RFC 9114 Section 7.2.4:
    /// - SETTINGS MUST be first frame on control stream
    /// - Reserved settings (0x02-0x05) MUST cause H3_SETTINGS_ERROR
    /// - Reserved greasing settings (0x1f * N + 0x21) MUST be ignored
    /// - Duplicate SETTINGS causes H3_FRAME_UNEXPECTED
    pub fn validate_settings(
        &mut self,
        settings: HashMap<SettingId, u64>,
    ) -> Result<(), H3Error> {
        // Check for duplicate SETTINGS
        if self.state == SettingsState::Received {
            return Err(H3Error::FrameUnexpected);
        }

        // Validate and filter settings
        let mut validated_settings = HashMap::new();
        for (&id, &value) in &settings {
            // RFC 9114 Section 7.2.4.1: Reserved HTTP/2 settings MUST cause error
            if known::is_reserved(id) {
                return Err(H3Error::SettingsError);
            }
            
            // RFC 9114 Section 7.2.4.1: Reserved greasing settings MUST be ignored
            if crate::frames::H3Frame::is_reserved_setting(id) {
                // Ignore reserved settings for greasing
                continue;
            }
            
            validated_settings.insert(id, value);
        }

        self.settings = validated_settings;
        self.state = SettingsState::Received;
        Ok(())
    }

    /// Validate that SETTINGS was the first frame.
    ///
    /// Call this when receiving any non-SETTINGS frame on control stream.
    pub fn validate_first_frame(&self) -> Result<(), H3Error> {
        if self.state == SettingsState::AwaitingSettings {
            return Err(H3Error::MissingSettings);
        }
        Ok(())
    }

    /// Get a setting value.
    pub fn get(&self, id: SettingId) -> Option<u64> {
        self.settings.get(&id).copied()
    }

    /// Get maximum field section size (default: unlimited).
    pub fn max_field_section_size(&self) -> Option<usize> {
        self.get(known::MAX_FIELD_SECTION_SIZE).map(|v| v as usize)
    }

    /// Check if extended CONNECT is enabled.
    pub fn enable_connect_protocol(&self) -> bool {
        self.get(known::ENABLE_CONNECT_PROTOCOL).unwrap_or(0) == 1
    }

    /// Get QPACK max table capacity.
    pub fn qpack_max_table_capacity(&self) -> u64 {
        self.get(known::QPACK_MAX_TABLE_CAPACITY).unwrap_or(0)
    }

    /// Get QPACK blocked streams.
    pub fn qpack_blocked_streams(&self) -> u64 {
        self.get(known::QPACK_BLOCKED_STREAMS).unwrap_or(0)
    }

    /// Check if settings have been received.
    pub fn is_received(&self) -> bool {
        self.state == SettingsState::Received
    }

    /// Validate 0-RTT settings compatibility per RFC 9114 Section 7.2.4.2.
    ///
    /// When a server accepts 0-RTT data, its SETTINGS frame MUST NOT reduce any limits
    /// or alter any values that might be violated by the client with its 0-RTT data.
    ///
    /// This method checks that new settings are compatible with remembered settings:
    /// - Limits (max values) cannot be reduced
    /// - Boolean flags cannot be disabled if previously enabled
    ///
    /// Returns Err(H3Error::SettingsError) if incompatible.
    pub fn validate_0rtt_compatibility(
        &self,
        new_settings: &HashMap<SettingId, u64>,
    ) -> Result<(), H3Error> {
        let Some(remembered) = &self.remembered_settings else {
            // No remembered settings, 0-RTT validation not applicable
            return Ok(());
        };

        // Check each setting from previous session
        for (&setting_id, &remembered_value) in remembered.iter() {
            let new_value = new_settings.get(&setting_id).copied();

            // RFC 9114 Section 7.2.4.2: If a server accepts 0-RTT but then sends settings
            // that are not compatible with the previously specified settings, this MUST be
            // treated as a connection error of type H3_SETTINGS_ERROR.
            match setting_id {
                // Limit settings: new value must not be less than remembered value
                known::MAX_FIELD_SECTION_SIZE
                | known::QPACK_MAX_TABLE_CAPACITY
                | known::QPACK_BLOCKED_STREAMS => {
                    if let Some(new_val) = new_value {
                        if new_val < remembered_value {
                            return Err(H3Error::SettingsError);
                        }
                    } else if remembered_value > 0 {
                        // Omitted setting that was previously non-default
                        // RFC 9114: "The server MUST include all settings that differ from their default values"
                        return Err(H3Error::SettingsError);
                    }
                }
                // Boolean settings: cannot be disabled if previously enabled
                known::ENABLE_CONNECT_PROTOCOL => {
                    if remembered_value == 1 {
                        if new_value.unwrap_or(0) != 1 {
                            return Err(H3Error::SettingsError);
                        }
                    }
                }
                // Other settings: validate they haven't changed in incompatible ways
                _ => {
                    // For unknown/extension settings, require exact match if non-default
                    if let Some(new_val) = new_value {
                        if new_val != remembered_value {
                            // Value changed - potentially incompatible
                            return Err(H3Error::SettingsError);
                        }
                    } else if remembered_value != 0 {
                        // Omitted setting that was previously non-default
                        return Err(H3Error::SettingsError);
                    }
                }
            }
        }

        Ok(())
    }

    /// Remember settings for future 0-RTT connections.
    ///
    /// Call this when receiving settings from a peer to store them for potential
    /// 0-RTT use in future connections.
    pub fn remember_settings(&mut self) {
        self.remembered_settings = Some(self.settings.clone());
    }

    /// Get the remembered settings from a previous session.
    pub fn get_remembered_settings(&self) -> Option<&HashMap<SettingId, u64>> {
        self.remembered_settings.as_ref()
    }
}

impl Default for SettingsValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for settings to send.
pub struct SettingsBuilder {
    settings: HashMap<SettingId, u64>,
}

impl SettingsBuilder {
    /// Create a new settings builder with defaults.
    pub fn new() -> Self {
        Self {
            settings: HashMap::new(),
        }
    }

    /// Set QPACK max table capacity.
    pub fn qpack_max_table_capacity(mut self, value: u64) -> Self {
        self.settings.insert(known::QPACK_MAX_TABLE_CAPACITY, value);
        self
    }

    /// Set max field section size.
    pub fn max_field_section_size(mut self, value: u64) -> Self {
        self.settings.insert(known::MAX_FIELD_SECTION_SIZE, value);
        self
    }

    /// Set QPACK blocked streams.
    pub fn qpack_blocked_streams(mut self, value: u64) -> Self {
        self.settings.insert(known::QPACK_BLOCKED_STREAMS, value);
        self
    }

    /// Enable extended CONNECT protocol.
    pub fn enable_connect_protocol(mut self) -> Self {
        self.settings.insert(known::ENABLE_CONNECT_PROTOCOL, 1);
        self
    }

    /// Build the settings map.
    pub fn build(self) -> HashMap<SettingId, u64> {
        self.settings
    }
}

impl Default for SettingsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_settings_first_frame_validation() {
        let mut validator = SettingsValidator::new();
        
        // Should fail if non-SETTINGS frame received first
        assert!(validator.validate_first_frame().is_err());
        
        // Process SETTINGS
        let settings = HashMap::new();
        assert!(validator.validate_settings(settings).is_ok());
        
        // Now should succeed
        assert!(validator.validate_first_frame().is_ok());
    }

    #[test]
    fn test_duplicate_settings_rejected() {
        let mut validator = SettingsValidator::new();
        
        let settings = HashMap::new();
        assert!(validator.validate_settings(settings.clone()).is_ok());
        
        // Second SETTINGS should fail
        assert!(validator.validate_settings(settings).is_err());
    }

    #[test]
    fn test_reserved_settings_rejected() {
        let mut validator = SettingsValidator::new();
        
        let mut settings = HashMap::new();
        settings.insert(known::RESERVED_0X02, 123);
        
        assert!(matches!(
            validator.validate_settings(settings),
            Err(H3Error::SettingsError)
        ));
    }

    #[test]
    fn test_settings_getters() {
        let mut validator = SettingsValidator::new();
        
        let mut settings = HashMap::new();
        settings.insert(known::MAX_FIELD_SECTION_SIZE, 8192);
        settings.insert(known::ENABLE_CONNECT_PROTOCOL, 1);
        settings.insert(known::QPACK_MAX_TABLE_CAPACITY, 4096);
        settings.insert(known::QPACK_BLOCKED_STREAMS, 100);
        
        validator.validate_settings(settings).unwrap();
        
        assert_eq!(validator.max_field_section_size(), Some(8192));
        assert!(validator.enable_connect_protocol());
        assert_eq!(validator.qpack_max_table_capacity(), 4096);
        assert_eq!(validator.qpack_blocked_streams(), 100);
    }

    #[test]
    fn test_settings_builder() {
        let settings = SettingsBuilder::new()
            .max_field_section_size(16384)
            .enable_connect_protocol()
            .qpack_max_table_capacity(4096)
            .qpack_blocked_streams(50)
            .build();
        
        assert_eq!(settings.get(&known::MAX_FIELD_SECTION_SIZE), Some(&16384));
        assert_eq!(settings.get(&known::ENABLE_CONNECT_PROTOCOL), Some(&1));
        assert_eq!(settings.get(&known::QPACK_MAX_TABLE_CAPACITY), Some(&4096));
        assert_eq!(settings.get(&known::QPACK_BLOCKED_STREAMS), Some(&50));
    }

    #[test]
    fn test_0rtt_settings_validation_no_remembered_settings() {
        // RFC 9114 Section 7.2.4.2: No validation if no remembered settings
        let validator = SettingsValidator::new();
        
        let mut new_settings = HashMap::new();
        new_settings.insert(known::MAX_FIELD_SECTION_SIZE, 8192);
        
        // Should succeed since there are no remembered settings to validate against
        assert!(validator.validate_0rtt_compatibility(&new_settings).is_ok());
    }

    #[test]
    fn test_0rtt_settings_validation_compatible_limits() {
        // RFC 9114 Section 7.2.4.2: New settings must not reduce limits
        let mut remembered = HashMap::new();
        remembered.insert(known::MAX_FIELD_SECTION_SIZE, 8192);
        remembered.insert(known::QPACK_MAX_TABLE_CAPACITY, 4096);
        remembered.insert(known::QPACK_BLOCKED_STREAMS, 100);
        
        let validator = SettingsValidator::with_remembered_settings(remembered);
        
        let mut new_settings = HashMap::new();
        new_settings.insert(known::MAX_FIELD_SECTION_SIZE, 16384); // Increased - OK
        new_settings.insert(known::QPACK_MAX_TABLE_CAPACITY, 4096); // Same - OK
        new_settings.insert(known::QPACK_BLOCKED_STREAMS, 200); // Increased - OK
        
        assert!(validator.validate_0rtt_compatibility(&new_settings).is_ok());
    }

    #[test]
    fn test_0rtt_settings_validation_reduced_limit_rejected() {
        // RFC 9114 Section 7.2.4.2: Reducing limits violates 0-RTT compatibility
        let mut remembered = HashMap::new();
        remembered.insert(known::MAX_FIELD_SECTION_SIZE, 16384);
        
        let validator = SettingsValidator::with_remembered_settings(remembered);
        
        let mut new_settings = HashMap::new();
        new_settings.insert(known::MAX_FIELD_SECTION_SIZE, 8192); // Reduced - ERROR
        
        assert!(matches!(
            validator.validate_0rtt_compatibility(&new_settings),
            Err(H3Error::SettingsError)
        ));
    }

    #[test]
    fn test_0rtt_settings_validation_omitted_non_default_rejected() {
        // RFC 9114 Section 7.2.4.2: Server MUST include all non-default settings
        let mut remembered = HashMap::new();
        remembered.insert(known::MAX_FIELD_SECTION_SIZE, 8192); // Non-default value
        
        let validator = SettingsValidator::with_remembered_settings(remembered);
        
        let new_settings = HashMap::new(); // Omitted the setting - ERROR
        
        assert!(matches!(
            validator.validate_0rtt_compatibility(&new_settings),
            Err(H3Error::SettingsError)
        ));
    }

    #[test]
    fn test_0rtt_settings_validation_boolean_flag_cannot_disable() {
        // RFC 9114 Section 7.2.4.2: Cannot disable a previously enabled flag
        let mut remembered = HashMap::new();
        remembered.insert(known::ENABLE_CONNECT_PROTOCOL, 1); // Enabled
        
        let validator = SettingsValidator::with_remembered_settings(remembered);
        
        let mut new_settings = HashMap::new();
        new_settings.insert(known::ENABLE_CONNECT_PROTOCOL, 0); // Disabled - ERROR
        
        assert!(matches!(
            validator.validate_0rtt_compatibility(&new_settings),
            Err(H3Error::SettingsError)
        ));
    }

    #[test]
    fn test_0rtt_settings_validation_boolean_flag_stays_enabled() {
        // RFC 9114 Section 7.2.4.2: Flag can stay enabled
        let mut remembered = HashMap::new();
        remembered.insert(known::ENABLE_CONNECT_PROTOCOL, 1);
        
        let validator = SettingsValidator::with_remembered_settings(remembered);
        
        let mut new_settings = HashMap::new();
        new_settings.insert(known::ENABLE_CONNECT_PROTOCOL, 1); // Still enabled - OK
        
        assert!(validator.validate_0rtt_compatibility(&new_settings).is_ok());
    }

    #[test]
    fn test_0rtt_remember_settings() {
        let mut validator = SettingsValidator::new();
        
        let mut settings = HashMap::new();
        settings.insert(known::MAX_FIELD_SECTION_SIZE, 8192);
        settings.insert(known::ENABLE_CONNECT_PROTOCOL, 1);
        
        validator.validate_settings(settings.clone()).unwrap();
        validator.remember_settings();
        
        let remembered = validator.get_remembered_settings().unwrap();
        assert_eq!(remembered.get(&known::MAX_FIELD_SECTION_SIZE), Some(&8192));
        assert_eq!(remembered.get(&known::ENABLE_CONNECT_PROTOCOL), Some(&1));
    }

    #[test]
    fn test_0rtt_validation_with_all_settings() {
        // Test comprehensive scenario with multiple settings
        let mut remembered = HashMap::new();
        remembered.insert(known::MAX_FIELD_SECTION_SIZE, 8192);
        remembered.insert(known::QPACK_MAX_TABLE_CAPACITY, 4096);
        remembered.insert(known::QPACK_BLOCKED_STREAMS, 100);
        remembered.insert(known::ENABLE_CONNECT_PROTOCOL, 1);
        
        let validator = SettingsValidator::with_remembered_settings(remembered);
        
        let mut new_settings = HashMap::new();
        new_settings.insert(known::MAX_FIELD_SECTION_SIZE, 16384); // Increased
        new_settings.insert(known::QPACK_MAX_TABLE_CAPACITY, 8192); // Increased
        new_settings.insert(known::QPACK_BLOCKED_STREAMS, 150); // Increased
        new_settings.insert(known::ENABLE_CONNECT_PROTOCOL, 1); // Same
        
        assert!(validator.validate_0rtt_compatibility(&new_settings).is_ok());
    }
}
