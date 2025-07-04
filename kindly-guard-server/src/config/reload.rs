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
//! Configuration hot-reload support
//!
//! This module provides runtime configuration reloading capabilities
//! allowing `KindlyGuard` to adapt to configuration changes without restart.

use anyhow::Result;
use async_trait::async_trait;
use notify::{Event as NotifyEvent, EventKind, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, Duration};
use tracing::{debug, error, info};

use super::Config;

/// Configuration reload event
#[derive(Debug, Clone)]
pub enum ConfigReloadEvent {
    /// Configuration successfully reloaded
    Reloaded {
        old_config: Arc<Config>,
        new_config: Arc<Config>,
        changed_fields: Vec<String>,
    },
    /// Reload failed
    Failed {
        error: String,
        current_config: Arc<Config>,
    },
    /// Validation failed
    ValidationFailed {
        errors: Vec<ValidationError>,
        current_config: Arc<Config>,
    },
}

/// Configuration validation error
#[derive(Debug, Clone)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
    pub severity: ValidationSeverity,
}

/// Validation severity
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationSeverity {
    Warning,
    Error,
}

/// Configuration change handler trait
#[async_trait]
pub trait ConfigChangeHandler: Send + Sync {
    /// Handle configuration change
    async fn handle_change(&self, event: ConfigReloadEvent) -> Result<()>;

    /// Validate configuration before applying
    async fn validate_config(&self, config: &Config) -> Result<Vec<ValidationError>>;

    /// Get reloadable fields
    fn get_reloadable_fields(&self) -> Vec<String>;
}

/// Configuration watcher
pub struct ConfigWatcher {
    config_path: PathBuf,
    current_config: Arc<RwLock<Arc<Config>>>,
    handlers: Arc<RwLock<Vec<Arc<dyn ConfigChangeHandler>>>>,
    reload_tx: mpsc::Sender<()>,
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl ConfigWatcher {
    /// Create new config watcher
    pub fn new(config_path: PathBuf, initial_config: Config) -> Result<Self> {
        let (reload_tx, _) = mpsc::channel(10);

        Ok(Self {
            config_path,
            current_config: Arc::new(RwLock::new(Arc::new(initial_config))),
            handlers: Arc::new(RwLock::new(Vec::new())),
            reload_tx,
            shutdown_tx: None,
        })
    }

    /// Add change handler
    pub async fn add_handler(&self, handler: Arc<dyn ConfigChangeHandler>) {
        let mut handlers = self.handlers.write().await;
        handlers.push(handler);
    }

    /// Get current configuration
    pub async fn current_config(&self) -> Arc<Config> {
        self.current_config.read().await.clone()
    }

    /// Start watching for changes
    pub async fn start(&mut self) -> Result<()> {
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
        self.shutdown_tx = Some(shutdown_tx);

        // Clone for move into spawned tasks
        let config_path = self.config_path.clone();
        let current_config = self.current_config.clone();
        let handlers = self.handlers.clone();
        let (reload_tx, mut reload_rx) = mpsc::channel(10);
        self.reload_tx = reload_tx.clone();

        // File watcher task
        let watcher_path = config_path.clone();
        let watcher_tx = reload_tx;
        tokio::spawn(async move {
            if let Err(e) = watch_config_file(watcher_path, watcher_tx).await {
                error!("Config file watcher error: {}", e);
            }
        });

        // Reload handler task
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(()) = reload_rx.recv() => {
                        debug!("Config reload triggered");
                        if let Err(e) = reload_config(
                            &config_path,
                            &current_config,
                            &handlers
                        ).await {
                            error!("Failed to reload config: {}", e);
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("Config watcher shutting down");
                        break;
                    }
                }
            }
        });

        info!("Config watcher started for {:?}", self.config_path);
        Ok(())
    }

    /// Stop watching
    pub async fn stop(&mut self) -> Result<()> {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(()).await;
        }
        Ok(())
    }

    /// Trigger manual reload
    pub async fn reload(&self) -> Result<()> {
        self.reload_tx.send(()).await?;
        Ok(())
    }
}

/// Watch config file for changes
async fn watch_config_file(path: PathBuf, reload_tx: mpsc::Sender<()>) -> Result<()> {
    let (notify_tx, mut notify_rx) = mpsc::channel(100);

    let mut watcher = notify::recommended_watcher(move |res: notify::Result<NotifyEvent>| {
        if let Ok(event) = res {
            if matches!(event.kind, EventKind::Modify(_)) {
                let _ = notify_tx.blocking_send(());
            }
        }
    })?;

    watcher.watch(&path, RecursiveMode::NonRecursive)?;

    // Keep watcher alive by moving it into an Arc
    let _watcher = Arc::new(watcher);

    // Debounce rapid changes
    let mut debounce_interval = interval(Duration::from_secs(1));
    let mut pending_reload = false;

    loop {
        tokio::select! {
            _ = debounce_interval.tick() => {
                if pending_reload {
                    pending_reload = false;
                    reload_tx.send(()).await?;
                }
            }
            Some(()) = notify_rx.recv() => {
                pending_reload = true;
            }
        }
    }
}

/// Reload configuration
async fn reload_config(
    config_path: &Path,
    current_config: &Arc<RwLock<Arc<Config>>>,
    handlers: &Arc<RwLock<Vec<Arc<dyn ConfigChangeHandler>>>>,
) -> Result<()> {
    // Load new config
    let new_config = match Config::load_from_file(&config_path.to_string_lossy()) {
        Ok(config) => config,
        Err(e) => {
            let event = ConfigReloadEvent::Failed {
                error: e.to_string(),
                current_config: current_config.read().await.clone(),
            };

            notify_handlers(handlers, event).await;
            return Err(e);
        }
    };

    // Validate with all handlers
    let mut all_errors = Vec::new();
    {
        let handlers = handlers.read().await;
        for handler in handlers.iter() {
            match handler.validate_config(&new_config).await {
                Ok(errors) => all_errors.extend(errors),
                Err(e) => {
                    all_errors.push(ValidationError {
                        field: "unknown".to_string(),
                        message: e.to_string(),
                        severity: ValidationSeverity::Error,
                    });
                }
            }
        }
    }

    // Check for validation errors
    let has_errors = all_errors
        .iter()
        .any(|e| e.severity == ValidationSeverity::Error);

    if has_errors {
        let event = ConfigReloadEvent::ValidationFailed {
            errors: all_errors,
            current_config: current_config.read().await.clone(),
        };

        notify_handlers(handlers, event).await;
        return Err(anyhow::anyhow!("Configuration validation failed"));
    }

    // Get changed fields
    let old_config = current_config.read().await.clone();
    let changed_fields = get_changed_fields(&old_config, &new_config);

    if changed_fields.is_empty() {
        debug!("No configuration changes detected");
        return Ok(());
    }

    // Update current config
    {
        let mut config_guard = current_config.write().await;
        *config_guard = Arc::new(new_config.clone());
    }

    // Notify handlers
    let event = ConfigReloadEvent::Reloaded {
        old_config,
        new_config: Arc::new(new_config),
        changed_fields,
    };

    notify_handlers(handlers, event).await;

    info!("Configuration successfully reloaded");
    Ok(())
}

/// Notify all handlers of config change
async fn notify_handlers(
    handlers: &Arc<RwLock<Vec<Arc<dyn ConfigChangeHandler>>>>,
    event: ConfigReloadEvent,
) {
    let handlers = handlers.read().await;
    for handler in handlers.iter() {
        if let Err(e) = handler.handle_change(event.clone()).await {
            error!("Config change handler error: {}", e);
        }
    }
}

/// Get list of changed fields
fn get_changed_fields(old: &Config, new: &Config) -> Vec<String> {
    let mut changed = Vec::new();

    // Compare major sections
    // This is simplified - in real implementation would use reflection or macros
    if old.server.port != new.server.port {
        changed.push("server.port".to_string());
    }
    if old.server.stdio != new.server.stdio {
        changed.push("server.stdio".to_string());
    }

    // Scanner config
    if old.scanner.unicode_detection != new.scanner.unicode_detection {
        changed.push("scanner.unicode_detection".to_string());
    }
    if old.scanner.injection_detection != new.scanner.injection_detection {
        changed.push("scanner.injection_detection".to_string());
    }

    // Rate limit config
    if old.rate_limit.enabled != new.rate_limit.enabled {
        changed.push("rate_limit.enabled".to_string());
    }
    if old.rate_limit.default_rpm != new.rate_limit.default_rpm {
        changed.push("rate_limit.default_rpm".to_string());
    }

    // Shield config
    if old.shield.enabled != new.shield.enabled {
        changed.push("shield.enabled".to_string());
    }

    // Audit config
    if old.audit.enabled != new.audit.enabled {
        changed.push("audit.enabled".to_string());
    }

    // Plugin config
    if old.plugins.enabled != new.plugins.enabled {
        changed.push("plugins.enabled".to_string());
    }

    // Add more field comparisons as needed

    changed
}

/// Default config change handler
pub struct DefaultConfigChangeHandler {
    reloadable_fields: Vec<String>,
}

impl Default for DefaultConfigChangeHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultConfigChangeHandler {
    pub fn new() -> Self {
        Self {
            reloadable_fields: vec![
                "scanner.*".to_string(),
                "rate_limit.*".to_string(),
                "shield.*".to_string(),
                "audit.enabled".to_string(),
                "plugins.enabled".to_string(),
                "telemetry.*".to_string(),
            ],
        }
    }
}

#[async_trait]
impl ConfigChangeHandler for DefaultConfigChangeHandler {
    async fn handle_change(&self, event: ConfigReloadEvent) -> Result<()> {
        match event {
            ConfigReloadEvent::Reloaded { changed_fields, .. } => {
                info!(
                    "Configuration reloaded. Changed fields: {:?}",
                    changed_fields
                );

                // Log audit event
                use crate::audit::{AuditEvent, AuditEventType, AuditSeverity};
                let _audit_event = AuditEvent::new(
                    AuditEventType::ConfigChanged {
                        changed_by: "hot-reload".to_string(),
                        changes: changed_fields
                            .into_iter()
                            .map(|f| (f, "updated".to_string()))
                            .collect(),
                    },
                    AuditSeverity::Info,
                );
                // Would log to audit system here

                Ok(())
            }
            ConfigReloadEvent::Failed { error, .. } => {
                error!("Configuration reload failed: {}", error);
                Ok(())
            }
            ConfigReloadEvent::ValidationFailed { errors, .. } => {
                error!("Configuration validation failed:");
                for err in errors {
                    error!("  {}: {} ({:?})", err.field, err.message, err.severity);
                }
                Ok(())
            }
        }
    }

    async fn validate_config(&self, config: &Config) -> Result<Vec<ValidationError>> {
        let mut errors = Vec::new();

        // Validate rate limit settings
        if config.rate_limit.enabled && config.rate_limit.default_rpm == 0 {
            errors.push(ValidationError {
                field: "rate_limit.default_rpm".to_string(),
                message: "Rate limit cannot be 0 when enabled".to_string(),
                severity: ValidationSeverity::Error,
            });
        }

        // Validate server settings
        if config.server.request_timeout_secs == 0 {
            errors.push(ValidationError {
                field: "server.request_timeout_secs".to_string(),
                message: "Request timeout should be greater than 0".to_string(),
                severity: ValidationSeverity::Warning,
            });
        }

        // Validate audit settings
        if config.audit.enabled && config.audit.retention_days == 0 {
            errors.push(ValidationError {
                field: "audit.retention_days".to_string(),
                message: "Audit retention should be greater than 0 days".to_string(),
                severity: ValidationSeverity::Warning,
            });
        }

        Ok(errors)
    }

    fn get_reloadable_fields(&self) -> Vec<String> {
        self.reloadable_fields.clone()
    }
}
