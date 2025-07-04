// Copyright 2025 Kindly Software Inc.
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
//! Plugin system for extensible security scanning
//!
//! This module provides a trait-based plugin architecture that allows
//! users to extend `KindlyGuard` with custom security scanners without
//! modifying the core code.

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

pub mod manager;
pub mod native;
// WASM support planned for future release
// #[cfg(feature = "wasm")]
// pub mod wasm;

// Re-exports
pub use manager::DefaultPluginManager;
pub use native::NativePluginLoader;
// #[cfg(feature = "wasm")]
// pub use wasm::WasmPluginLoader;

use crate::scanner::{Severity, Threat, ThreatType};

/// Unique plugin identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PluginId(pub String);

impl Default for PluginId {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginId {
    /// Create a new random plugin ID
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// Create from a string
    pub const fn from_string(s: String) -> Self {
        Self(s)
    }
}

/// Plugin metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    /// Plugin name
    pub name: String,
    /// Plugin version
    pub version: String,
    /// Plugin author
    pub author: String,
    /// Plugin description
    pub description: String,
    /// Plugin homepage
    pub homepage: Option<String>,
    /// Supported threat types
    pub threat_types: Vec<String>,
    /// Plugin capabilities
    pub capabilities: PluginCapabilities,
}

/// Plugin capabilities
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginCapabilities {
    /// Can scan text
    pub scan_text: bool,
    /// Can scan JSON
    pub scan_json: bool,
    /// Can scan binary data
    pub scan_binary: bool,
    /// Supports async scanning
    pub async_scan: bool,
    /// Supports batch scanning
    pub batch_scan: bool,
    /// Maximum data size in MB
    pub max_data_size_mb: Option<u32>,
}

/// Scan context provided to plugins
#[derive(Debug, Clone)]
pub struct ScanContext<'a> {
    /// Data to scan
    pub data: &'a [u8],
    /// Content type hint
    pub content_type: Option<&'a str>,
    /// Client ID
    pub client_id: &'a str,
    /// Request metadata
    pub metadata: &'a HashMap<String, String>,
    /// Scan options
    pub options: ScanOptions,
}

/// Scan options
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanOptions {
    /// Maximum scan depth
    pub max_depth: Option<u32>,
    /// Timeout in milliseconds
    pub timeout_ms: Option<u64>,
    /// Enable detailed reporting
    pub detailed: bool,
    /// Custom plugin options
    pub plugin_options: HashMap<String, serde_json::Value>,
}

/// Plugin health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Is healthy
    pub healthy: bool,
    /// Status message
    pub message: String,
    /// Last check time
    pub last_check: chrono::DateTime<chrono::Utc>,
    /// Performance metrics
    pub metrics: PluginMetrics,
}

/// Plugin performance metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PluginMetrics {
    /// Total scans performed
    pub scans_performed: u64,
    /// Total threats detected
    pub threats_detected: u64,
    /// Average scan time in microseconds
    pub avg_scan_time_us: u64,
    /// Errors encountered
    pub errors: u64,
}

/// Security plugin trait
#[async_trait]
pub trait SecurityPlugin: Send + Sync {
    /// Get plugin metadata
    fn metadata(&self) -> PluginMetadata;

    /// Initialize plugin with configuration
    async fn initialize(&mut self, config: serde_json::Value) -> Result<()>;

    /// Scan data for threats
    async fn scan(&self, context: ScanContext<'_>) -> Result<Vec<Threat>>;

    /// Perform health check
    async fn health_check(&self) -> Result<HealthStatus>;

    /// Shutdown plugin
    async fn shutdown(&mut self) -> Result<()>;

    /// Update plugin configuration
    async fn update_config(&mut self, config: serde_json::Value) -> Result<()> {
        // Default implementation reinitializes
        self.shutdown().await?;
        self.initialize(config).await
    }

    /// Get current metrics
    fn get_metrics(&self) -> PluginMetrics {
        PluginMetrics::default()
    }
}

/// Plugin loader trait for different plugin types
#[async_trait]
pub trait PluginLoader: Send + Sync {
    /// Load a plugin from path
    async fn load_plugin(&self, path: &Path) -> Result<Box<dyn SecurityPlugin>>;

    /// Validate plugin before loading
    async fn validate_plugin(&self, path: &Path) -> Result<PluginMetadata>;

    /// Get loader type
    fn loader_type(&self) -> &'static str;
}

/// Plugin info returned by manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    pub id: PluginId,
    pub metadata: PluginMetadata,
    pub enabled: bool,
    pub loaded_at: chrono::DateTime<chrono::Utc>,
}

/// Plugin manager trait
#[async_trait]
pub trait PluginManagerTrait: Send + Sync {
    /// Load plugin from file
    async fn load_plugin(&self, path: &Path) -> Result<PluginId>;

    /// Unload a plugin
    async fn unload_plugin(&self, id: &PluginId) -> Result<()>;

    /// Get plugin info
    async fn get_plugin(&self, id: &PluginId) -> Result<PluginInfo>;

    /// List all plugins
    async fn list_plugins(&self) -> Result<Vec<PluginInfo>>;

    /// Scan with specific plugin
    async fn scan(&self, id: &PluginId, context: ScanContext<'_>) -> Result<Vec<Threat>>;

    /// Scan with all plugins
    async fn scan_all(&self, context: ScanContext<'_>) -> Result<HashMap<PluginId, Vec<Threat>>>;

    /// Reload a plugin
    async fn reload_plugin(&self, id: &PluginId) -> Result<()>;

    /// Get plugin health status
    async fn get_health(&self, id: &PluginId) -> Result<HealthStatus>;
}

/// Plugin configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    /// Enable plugin system
    pub enabled: bool,
    /// Plugin directories
    pub plugin_dirs: Vec<PathBuf>,
    /// Auto-load plugins on startup
    pub auto_load: bool,
    /// Plugin allowlist (if empty, all allowed)
    pub allowlist: Vec<String>,
    /// Plugin denylist
    pub denylist: Vec<String>,
    /// Enable WASM plugins (planned for future release)
    // #[cfg(feature = "wasm")]
    // pub wasm_enabled: bool,
    /// Maximum plugin execution time
    pub max_execution_time_ms: u64,
    /// Plugin isolation level
    pub isolation_level: IsolationLevel,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            plugin_dirs: vec![PathBuf::from("./plugins")],
            auto_load: true,
            allowlist: Vec::new(),
            denylist: Vec::new(),
            // #[cfg(feature = "wasm")]
            // wasm_enabled: true,
            max_execution_time_ms: 5000,
            isolation_level: IsolationLevel::Standard,
        }
    }
}

/// Plugin isolation level
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IsolationLevel {
    /// No isolation (native plugins)
    None,
    /// Standard isolation (separate process)
    Standard,
    /// Strong isolation (WASM sandbox)
    Strong,
}

/// Plugin handle for active plugins
pub struct PluginHandle {
    pub id: PluginId,
    pub metadata: PluginMetadata,
    pub plugin: Arc<dyn SecurityPlugin>,
    pub enabled: bool,
    pub loaded_at: chrono::DateTime<chrono::Utc>,
    pub metrics: Arc<tokio::sync::RwLock<PluginMetrics>>,
}

/// Factory for creating plugin managers
pub trait PluginManagerFactory: Send + Sync {
    /// Create a plugin manager
    fn create(&self, config: &PluginConfig) -> Result<Arc<dyn PluginManagerTrait>>;
}

/// Default plugin manager factory
pub struct DefaultPluginManagerFactory;

impl PluginManagerFactory for DefaultPluginManagerFactory {
    fn create(&self, config: &PluginConfig) -> Result<Arc<dyn PluginManagerTrait>> {
        if !config.enabled {
            // Return a no-op manager when plugins are disabled
            return Ok(Arc::new(NoOpPluginManager));
        }

        let manager = DefaultPluginManager::new(config.clone())?;

        // Note: Plugin auto-loading happens later, not during factory creation
        // to avoid runtime-in-runtime issues
        if config.auto_load {
            tracing::info!("Plugin auto-loading enabled; plugins will be loaded on first use");
        }

        Ok(Arc::new(manager))
    }
}

/// No-op plugin manager for when plugins are disabled
struct NoOpPluginManager;

#[async_trait]
impl PluginManagerTrait for NoOpPluginManager {
    async fn load_plugin(&self, _path: &Path) -> Result<PluginId> {
        Err(anyhow::anyhow!("Plugin system disabled"))
    }

    async fn unload_plugin(&self, _id: &PluginId) -> Result<()> {
        Ok(())
    }

    async fn get_plugin(&self, _id: &PluginId) -> Result<PluginInfo> {
        Err(anyhow::anyhow!("Plugin system disabled"))
    }

    async fn list_plugins(&self) -> Result<Vec<PluginInfo>> {
        Ok(Vec::new())
    }

    async fn scan(&self, _id: &PluginId, _context: ScanContext<'_>) -> Result<Vec<Threat>> {
        Ok(Vec::new())
    }

    async fn scan_all(&self, _context: ScanContext<'_>) -> Result<HashMap<PluginId, Vec<Threat>>> {
        Ok(HashMap::new())
    }

    async fn reload_plugin(&self, _id: &PluginId) -> Result<()> {
        Err(anyhow::anyhow!("Plugin system disabled"))
    }

    async fn get_health(&self, _id: &PluginId) -> Result<HealthStatus> {
        Err(anyhow::anyhow!("Plugin system disabled"))
    }
}
