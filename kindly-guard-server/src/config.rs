//! Configuration for KindlyGuard

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Server configuration
    pub server: ServerConfig,
    
    /// Security scanning configuration
    pub scanner: ScannerConfig,
    
    /// Shield display configuration
    pub shield: ShieldConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Port to listen on (for HTTP transport)
    #[serde(default = "default_port")]
    pub port: u16,
    
    /// Enable stdio transport (default for MCP)
    #[serde(default = "default_true")]
    pub stdio: bool,
    
    /// Maximum concurrent connections
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    
    /// Request timeout in seconds
    #[serde(default = "default_timeout")]
    pub request_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    /// Enable unicode threat detection
    #[serde(default = "default_true")]
    pub unicode_detection: bool,
    
    /// Enable injection detection
    #[serde(default = "default_true")]
    pub injection_detection: bool,
    
    /// Enable path traversal detection
    #[serde(default = "default_true")]
    pub path_traversal_detection: bool,
    
    /// Custom threat patterns file
    pub custom_patterns: Option<PathBuf>,
    
    /// Maximum scan depth for nested structures
    #[serde(default = "default_max_depth")]
    pub max_scan_depth: usize,
    
    /// Enable high-performance event buffer
    #[serde(default = "default_false")]
    pub enable_event_buffer: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldConfig {
    /// Enable shield display
    #[serde(default = "default_false")]
    pub enabled: bool,
    
    /// Update interval in milliseconds
    #[serde(default = "default_update_interval")]
    pub update_interval_ms: u64,
    
    /// Show detailed statistics
    #[serde(default = "default_false")]
    pub detailed_stats: bool,
    
    /// Enable color output
    #[serde(default = "default_true")]
    pub color: bool,
}

impl Config {
    /// Load configuration from environment and files
    pub fn load() -> Result<Self> {
        // First, try to load from config file
        let config_path = std::env::var("KINDLY_GUARD_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("kindly-guard.toml"));
        
        if config_path.exists() {
            Self::load_from_file(&config_path.to_string_lossy())
        } else {
            // Use default configuration
            Ok(Self::default())
        }
    }
    
    /// Load configuration from a specific file
    pub fn load_from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                port: default_port(),
                stdio: default_true(),
                max_connections: default_max_connections(),
                request_timeout_secs: default_timeout(),
            },
            scanner: ScannerConfig {
                unicode_detection: default_true(),
                injection_detection: default_true(),
                path_traversal_detection: default_true(),
                custom_patterns: None,
                max_scan_depth: default_max_depth(),
                enable_event_buffer: default_false(),
            },
            shield: ShieldConfig {
                enabled: default_false(),
                update_interval_ms: default_update_interval(),
                detailed_stats: default_false(),
                color: default_true(),
            },
        }
    }
}

impl Default for ShieldConfig {
    fn default() -> Self {
        Self {
            enabled: default_false(),
            update_interval_ms: default_update_interval(),
            detailed_stats: default_false(),
            color: default_true(),
        }
    }
}

// Default value functions
fn default_port() -> u16 { 8080 }
fn default_true() -> bool { true }
fn default_false() -> bool { false }
fn default_max_connections() -> usize { 100 }
fn default_max_depth() -> usize { 10 }
fn default_update_interval() -> u64 { 1000 }
fn default_timeout() -> u64 { 30 }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.server.stdio);
        assert!(config.scanner.unicode_detection);
        assert_eq!(config.server.port, 8080);
    }
}