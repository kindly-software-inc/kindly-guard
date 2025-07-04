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
//! Plugin manager implementation
//!
//! Manages the lifecycle of security plugins and coordinates scanning

use super::{
    async_trait, HealthStatus, NativePluginLoader, Path, PluginConfig, PluginHandle, PluginId,
    PluginInfo, PluginLoader, PluginManagerTrait, PluginMetadata, PluginMetrics, Result,
    ScanContext, SecurityPlugin, Threat,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Default plugin manager implementation
pub struct DefaultPluginManager {
    config: PluginConfig,
    plugins: Arc<RwLock<HashMap<PluginId, PluginHandle>>>,
    loaders: Vec<Box<dyn PluginLoader>>,
}

impl DefaultPluginManager {
    /// Create a new plugin manager
    pub fn new(config: PluginConfig) -> Result<Self> {
        let loaders: Vec<Box<dyn PluginLoader>> = vec![Box::new(NativePluginLoader::new())];

        // WASM support planned for future release
        // #[cfg(feature = "wasm")]
        // if config.wasm_enabled {
        //     loaders.push(Box::new(WasmPluginLoader::new()?));
        // }

        let manager = Self {
            config,
            plugins: Arc::new(RwLock::new(HashMap::new())),
            loaders,
        };

        Ok(manager)
    }

    /// Initialize and auto-load plugins
    pub async fn initialize(&self) -> Result<()> {
        if !self.config.enabled {
            info!("Plugin system is disabled");
            return Ok(());
        }

        info!("Initializing plugin system");

        if self.config.auto_load {
            for dir in &self.config.plugin_dirs {
                if dir.exists() {
                    self.load_plugins_from_directory(dir).await?;
                } else {
                    warn!("Plugin directory does not exist: {:?}", dir);
                }
            }
        }

        let plugins = self.plugins.read().await;
        info!("Loaded {} plugins", plugins.len());

        Ok(())
    }

    /// Load all plugins from a directory
    pub async fn load_plugins_from_directory(&self, dir: &Path) -> Result<()> {
        debug!("Scanning directory for plugins: {:?}", dir);

        let entries = std::fs::read_dir(dir)?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            // Skip non-files
            if !path.is_file() {
                continue;
            }

            // Try to load as plugin
            match self.load_plugin(&path).await {
                Ok(id) => {
                    info!("Loaded plugin {} from {:?}", id.0, path);
                }
                Err(e) => {
                    warn!("Failed to load plugin from {:?}: {}", path, e);
                }
            }
        }

        Ok(())
    }

    /// Check if plugin is allowed
    fn is_plugin_allowed(&self, metadata: &PluginMetadata) -> bool {
        // Check denylist first
        if self.config.denylist.contains(&metadata.name) {
            return false;
        }

        // Check allowlist if not empty
        if !self.config.allowlist.is_empty() {
            return self.config.allowlist.contains(&metadata.name);
        }

        true
    }
}

impl DefaultPluginManager {
    async fn register_plugin(&self, mut plugin: Box<dyn SecurityPlugin>) -> Result<PluginId> {
        let metadata = plugin.metadata();

        // Check if allowed
        if !self.is_plugin_allowed(&metadata) {
            return Err(anyhow::anyhow!("Plugin '{}' is not allowed", metadata.name));
        }

        // Initialize plugin
        plugin
            .initialize(serde_json::Value::Object(Default::default()))
            .await?;

        let id = PluginId::new();
        let handle = PluginHandle {
            id: id.clone(),
            metadata: metadata.clone(),
            plugin: Arc::from(plugin),
            enabled: true,
            loaded_at: chrono::Utc::now(),
            metrics: Arc::new(RwLock::new(PluginMetrics::default())),
        };

        let mut plugins = self.plugins.write().await;
        plugins.insert(id.clone(), handle);

        info!("Registered plugin: {} v{}", metadata.name, metadata.version);

        Ok(id)
    }
}

#[async_trait]
impl PluginManagerTrait for DefaultPluginManager {
    async fn load_plugin(&self, path: &Path) -> Result<PluginId> {
        // Try each loader
        for loader in &self.loaders {
            match loader.validate_plugin(path).await {
                Ok(metadata) => {
                    debug!(
                        "Plugin validated by {} loader: {}",
                        loader.loader_type(),
                        metadata.name
                    );

                    if !self.is_plugin_allowed(&metadata) {
                        return Err(anyhow::anyhow!("Plugin '{}' is not allowed", metadata.name));
                    }

                    let plugin = loader.load_plugin(path).await?;
                    return self.register_plugin(plugin).await;
                }
                Err(_) => continue,
            }
        }

        Err(anyhow::anyhow!(
            "No loader could handle plugin at {:?}",
            path
        ))
    }

    async fn unload_plugin(&self, id: &PluginId) -> Result<()> {
        let mut plugins = self.plugins.write().await;

        if let Some(mut handle) = plugins.remove(id) {
            // Shutdown plugin
            if let Some(plugin) = Arc::get_mut(&mut handle.plugin) {
                plugin.shutdown().await?;
            }

            info!("Unloaded plugin: {}", handle.metadata.name);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Plugin not found: {}", id.0))
        }
    }

    async fn get_plugin(&self, id: &PluginId) -> Result<PluginInfo> {
        let plugins = self.plugins.read().await;
        let handle = plugins
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("Plugin not found: {}", id.0))?;

        Ok(PluginInfo {
            id: handle.id.clone(),
            metadata: handle.metadata.clone(),
            enabled: handle.enabled,
            loaded_at: handle.loaded_at,
        })
    }

    async fn list_plugins(&self) -> Result<Vec<PluginInfo>> {
        let plugins = self.plugins.read().await;
        Ok(plugins
            .values()
            .map(|handle| PluginInfo {
                id: handle.id.clone(),
                metadata: handle.metadata.clone(),
                enabled: handle.enabled,
                loaded_at: handle.loaded_at,
            })
            .collect())
    }

    async fn scan_all(&self, context: ScanContext<'_>) -> Result<HashMap<PluginId, Vec<Threat>>> {
        let plugins = self.plugins.read().await;
        let mut results = HashMap::new();

        for (id, handle) in plugins.iter() {
            if !handle.enabled {
                continue;
            }

            let start = std::time::Instant::now();

            // Apply timeout
            let scan_future = handle.plugin.scan(context.clone());
            let timeout = tokio::time::Duration::from_millis(self.config.max_execution_time_ms);

            match tokio::time::timeout(timeout, scan_future).await {
                Ok(Ok(threats)) => {
                    let elapsed = start.elapsed().as_micros() as u64;

                    // Update metrics
                    {
                        let mut metrics = handle.metrics.write().await;
                        metrics.scans_performed += 1;
                        metrics.threats_detected += threats.len() as u64;
                        metrics.avg_scan_time_us =
                            (metrics.avg_scan_time_us * (metrics.scans_performed - 1) + elapsed)
                                / metrics.scans_performed;
                    }

                    if !threats.is_empty() {
                        debug!(
                            "Plugin {} found {} threats",
                            handle.metadata.name,
                            threats.len()
                        );
                    }

                    results.insert(id.clone(), threats);
                }
                Ok(Err(e)) => {
                    error!("Plugin {} scan error: {}", handle.metadata.name, e);

                    // Update error count
                    {
                        let mut metrics = handle.metrics.write().await;
                        metrics.errors += 1;
                    }
                }
                Err(_) => {
                    error!("Plugin {} scan timeout", handle.metadata.name);

                    // Update error count
                    {
                        let mut metrics = handle.metrics.write().await;
                        metrics.errors += 1;
                    }
                }
            }
        }

        Ok(results)
    }

    async fn scan(&self, id: &PluginId, context: ScanContext<'_>) -> Result<Vec<Threat>> {
        let plugins = self.plugins.read().await;

        let handle = plugins
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("Plugin not found: {}", id.0))?;

        if !handle.enabled {
            return Err(anyhow::anyhow!("Plugin is disabled: {}", id.0));
        }

        let start = std::time::Instant::now();

        // Apply timeout
        let scan_future = handle.plugin.scan(context);
        let timeout = tokio::time::Duration::from_millis(self.config.max_execution_time_ms);

        let result = tokio::time::timeout(timeout, scan_future)
            .await
            .map_err(|_| anyhow::anyhow!("Plugin scan timeout"))?;

        let threats = result?;
        let elapsed = start.elapsed().as_micros() as u64;

        // Update metrics
        {
            let mut metrics = handle.metrics.write().await;
            metrics.scans_performed += 1;
            metrics.threats_detected += threats.len() as u64;
            metrics.avg_scan_time_us = (metrics.avg_scan_time_us * (metrics.scans_performed - 1)
                + elapsed)
                / metrics.scans_performed;
        }

        Ok(threats)
    }

    async fn get_health(&self, id: &PluginId) -> Result<HealthStatus> {
        let plugins = self.plugins.read().await;

        let handle = plugins
            .get(id)
            .ok_or_else(|| anyhow::anyhow!("Plugin not found: {}", id.0))?;

        let mut health = handle.plugin.health_check().await?;

        // Add metrics from handle
        let metrics = handle.metrics.read().await;
        health.metrics = (*metrics).clone();

        Ok(health)
    }

    async fn reload_plugin(&self, _id: &PluginId) -> Result<()> {
        // For now, reload is not implemented for in-memory plugins
        // This would require storing the original path and reloading from disk
        Err(anyhow::anyhow!(
            "Hot reload not implemented for this plugin type"
        ))
    }
}
