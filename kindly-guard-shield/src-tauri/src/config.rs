// Copyright 2025 Kindly-Software
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//! Configuration management for KindlyGuard Shield
//!
//! This module handles runtime configuration including enhanced mode settings

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Enable enhanced mode with optimized implementations
    #[serde(default)]
    pub enhanced_mode: bool,
    
    /// Event buffer size in megabytes
    #[serde(default = "default_event_buffer_size")]
    pub event_buffer_size_mb: usize,
    
    /// Enable WebSocket compression
    #[serde(default = "default_compression")]
    pub enable_compression: bool,
    
    /// Security settings
    #[serde(default)]
    pub security: SecurityConfig,
    
    /// WebSocket settings
    #[serde(default)]
    pub websocket: WebSocketConfig,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable advanced pattern detection
    #[serde(default = "default_true")]
    pub enable_pattern_detection: bool,
    
    /// Maximum message size in bytes
    #[serde(default = "default_max_message_size")]
    pub max_message_size: usize,
    
    /// Rate limit per minute
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_minute: u32,
}

/// WebSocket configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebSocketConfig {
    /// Listen address
    #[serde(default = "default_listen_address")]
    pub listen_address: String,
    
    /// Enable binary protocol (requires enhanced mode)
    #[serde(default)]
    pub enable_binary_protocol: bool,
    
    /// Connection timeout in seconds
    #[serde(default = "default_connection_timeout")]
    pub connection_timeout_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enhanced_mode: false,
            event_buffer_size_mb: default_event_buffer_size(),
            enable_compression: default_compression(),
            security: SecurityConfig::default(),
            websocket: WebSocketConfig::default(),
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_pattern_detection: default_true(),
            max_message_size: default_max_message_size(),
            rate_limit_per_minute: default_rate_limit(),
        }
    }
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            listen_address: default_listen_address(),
            enable_binary_protocol: false,
            connection_timeout_secs: default_connection_timeout(),
        }
    }
}

// Default value functions
fn default_event_buffer_size() -> usize { 64 }
fn default_compression() -> bool { true }
fn default_true() -> bool { true }
fn default_max_message_size() -> usize { 1024 * 1024 } // 1MB
fn default_rate_limit() -> u32 { 60 }
fn default_listen_address() -> String { "127.0.0.1:9955".to_string() }
fn default_connection_timeout() -> u64 { 30 }

impl Config {
    /// Load configuration from file
    pub fn load_from_file(path: PathBuf) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config = toml::from_str(&content)?;
        Ok(config)
    }
    
    /// Load configuration with defaults
    pub fn load() -> Self {
        // Try to load from file, otherwise use defaults
        if let Ok(home) = std::env::var("HOME") {
            let config_path = PathBuf::from(home)
                .join(".config")
                .join("kindly-guard")
                .join("shield.toml");
            
            if config_path.exists() {
                match Self::load_from_file(config_path) {
                    Ok(config) => {
                        tracing::info!("Loaded configuration from file");
                        return config;
                    }
                    Err(e) => {
                        tracing::warn!("Failed to load config file: {}", e);
                    }
                }
            }
        }
        
        tracing::info!("Using default configuration");
        Self::default()
    }
    
    /// Check if enhanced features are available and enabled
    pub fn is_enhanced_available(&self) -> bool {
        #[cfg(feature = "enhanced")]
        {
            self.enhanced_mode
        }
        #[cfg(not(feature = "enhanced"))]
        {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(!config.enhanced_mode);
        assert_eq!(config.event_buffer_size_mb, 64);
        assert!(config.enable_compression);
    }
    
    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let toml = toml::to_string(&config).unwrap();
        assert!(toml.contains("enhanced_mode = false"));
    }
}