//! Configuration for hq-interop protocol.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Configuration for hq-interop application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HqInteropConfig {
    /// File serving configuration.
    #[serde(default)]
    pub handler: HandlerConfig,
}

impl Default for HqInteropConfig {
    fn default() -> Self {
        Self {
            handler: HandlerConfig::default(),
        }
    }
}

impl HqInteropConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Vec<String> {
        self.handler.validate()
    }
}

/// Handler configuration for file serving.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandlerConfig {
    /// Root directory for file serving.
    #[serde(default = "default_file_root")]
    pub file_root: PathBuf,

    /// Index file names to try for directory requests.
    #[serde(default = "default_index_files")]
    pub index_files: Vec<String>,
}

impl Default for HandlerConfig {
    fn default() -> Self {
        Self {
            file_root: default_file_root(),
            index_files: default_index_files(),
        }
    }
}

impl HandlerConfig {
    fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();

        if !self.file_root.exists() {
            errors.push(format!(
                "File serving root directory does not exist: {}",
                self.file_root.display()
            ));
        } else if !self.file_root.is_dir() {
            errors.push(format!(
                "File serving root is not a directory: {}",
                self.file_root.display()
            ));
        }

        errors
    }
}

fn default_file_root() -> PathBuf {
    PathBuf::from("./www")
}

fn default_index_files() -> Vec<String> {
    vec!["index.html".to_string(), "index.htm".to_string()]
}
