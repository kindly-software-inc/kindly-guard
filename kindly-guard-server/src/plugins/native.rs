//! Native plugin loader for Rust-based plugins
//!
//! Loads plugins compiled as dynamic libraries (.so, .dll, .dylib)

use super::{
    async_trait, HealthStatus, PluginCapabilities, PluginLoader, PluginMetadata, ScanContext,
    SecurityPlugin, Severity, Threat, ThreatType,
};
use anyhow::Result;
use std::path::Path;
use tracing::{debug, info};

/// Native plugin loader
pub struct NativePluginLoader {
    _private: (),
}

impl Default for NativePluginLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl NativePluginLoader {
    /// Create a new native plugin loader
    pub const fn new() -> Self {
        Self { _private: () }
    }
}

#[async_trait]
impl PluginLoader for NativePluginLoader {
    async fn load_plugin(&self, path: &Path) -> Result<Box<dyn SecurityPlugin>> {
        // For now, we'll create example plugins
        // In a real implementation, this would use libloading to load .so/.dll files

        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid filename"))?;

        // Example: Create different plugins based on filename
        match filename {
            "sql_injection_plugin.so" | "sql_injection_plugin.dll" => {
                Ok(Box::new(SqlInjectionPlugin::new()))
            }
            "xss_plugin.so" | "xss_plugin.dll" => Ok(Box::new(XssPlugin::new())),
            "custom_pattern_plugin.so" | "custom_pattern_plugin.dll" => {
                Ok(Box::new(CustomPatternPlugin::new()))
            }
            _ => Err(anyhow::anyhow!("Unknown plugin type: {}", filename)),
        }
    }

    async fn validate_plugin(&self, path: &Path) -> Result<PluginMetadata> {
        // Check if it's a valid plugin file
        let extension = path
            .extension()
            .and_then(|e| e.to_str())
            .ok_or_else(|| anyhow::anyhow!("No file extension"))?;

        match extension {
            "so" | "dll" | "dylib" => {
                // In real implementation, would load and check plugin interface
                // For now, return mock metadata based on filename
                let filename = path
                    .file_stem()
                    .and_then(|n| n.to_str())
                    .ok_or_else(|| anyhow::anyhow!("Invalid filename"))?;

                Ok(PluginMetadata {
                    name: filename.to_string(),
                    version: "1.0.0".to_string(),
                    author: "Plugin Author".to_string(),
                    description: format!("Native plugin: {filename}"),
                    homepage: None,
                    threat_types: vec!["custom".to_string()],
                    capabilities: PluginCapabilities {
                        scan_text: true,
                        scan_json: true,
                        scan_binary: false,
                        async_scan: true,
                        batch_scan: false,
                        max_data_size_mb: Some(10),
                    },
                })
            }
            _ => Err(anyhow::anyhow!("Not a native plugin file")),
        }
    }

    fn loader_type(&self) -> &'static str {
        "native"
    }
}

/// Example SQL injection detection plugin
struct SqlInjectionPlugin {
    patterns: Vec<regex::Regex>,
    config: serde_json::Value,
}

impl SqlInjectionPlugin {
    fn new() -> Self {
        let patterns = vec![
            regex::Regex::new(r"(?i)(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b.*\b(from|where|table|database)\b)").unwrap(),
            regex::Regex::new(r#"(?i)('|"|;|--|xp_|sp_)"#).unwrap(),
            regex::Regex::new(r"(?i)(admin'|'or'|'=')").unwrap(),
        ];

        Self {
            patterns,
            config: serde_json::Value::Null,
        }
    }
}

#[async_trait]
impl SecurityPlugin for SqlInjectionPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "SQL Injection Detector".to_string(),
            version: "1.0.0".to_string(),
            author: "KindlyGuard Team".to_string(),
            description: "Detects SQL injection attempts in text and JSON data".to_string(),
            homepage: Some("https://kindlyguard.dev/plugins/sql-injection".to_string()),
            threat_types: vec!["sql_injection".to_string()],
            capabilities: PluginCapabilities {
                scan_text: true,
                scan_json: true,
                scan_binary: false,
                async_scan: true,
                batch_scan: false,
                max_data_size_mb: Some(10),
            },
        }
    }

    async fn initialize(&mut self, config: serde_json::Value) -> Result<()> {
        self.config = config;
        info!("SQL Injection plugin initialized");
        Ok(())
    }

    async fn scan(&self, context: ScanContext<'_>) -> Result<Vec<Threat>> {
        let text = String::from_utf8_lossy(context.data);
        let mut threats = Vec::new();

        for (i, pattern) in self.patterns.iter().enumerate() {
            if let Some(m) = pattern.find(&text) {
                threats.push(Threat {
                    threat_type: ThreatType::SqlInjection,
                    severity: Severity::High,
                    location: crate::scanner::Location::Text {
                        offset: m.start(),
                        length: m.len(),
                    },
                    description: format!("SQL injection pattern {} detected", i + 1),
                    remediation: Some("Sanitize input and use parameterized queries".to_string()),
                });
            }
        }

        Ok(threats)
    }

    async fn health_check(&self) -> Result<HealthStatus> {
        Ok(HealthStatus {
            healthy: true,
            message: "SQL Injection plugin is healthy".to_string(),
            last_check: chrono::Utc::now(),
            metrics: self.get_metrics(),
        })
    }

    async fn shutdown(&mut self) -> Result<()> {
        info!("SQL Injection plugin shutting down");
        Ok(())
    }
}

/// Example XSS detection plugin
struct XssPlugin {
    patterns: Vec<regex::Regex>,
}

impl XssPlugin {
    fn new() -> Self {
        let patterns = vec![
            regex::Regex::new(r"<script[^>]*>.*?</script>").unwrap(),
            regex::Regex::new(r"javascript:").unwrap(),
            regex::Regex::new(r"on\w+\s*=").unwrap(),
        ];

        Self { patterns }
    }
}

#[async_trait]
impl SecurityPlugin for XssPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "XSS Detector".to_string(),
            version: "1.0.0".to_string(),
            author: "KindlyGuard Team".to_string(),
            description: "Detects cross-site scripting attempts".to_string(),
            homepage: None,
            threat_types: vec!["xss".to_string()],
            capabilities: PluginCapabilities {
                scan_text: true,
                scan_json: true,
                scan_binary: false,
                async_scan: true,
                batch_scan: false,
                max_data_size_mb: Some(5),
            },
        }
    }

    async fn initialize(&mut self, _config: serde_json::Value) -> Result<()> {
        info!("XSS plugin initialized");
        Ok(())
    }

    async fn scan(&self, context: ScanContext<'_>) -> Result<Vec<Threat>> {
        let text = String::from_utf8_lossy(context.data);
        let mut threats = Vec::new();

        for pattern in &self.patterns {
            if let Some(m) = pattern.find(&text) {
                threats.push(Threat {
                    threat_type: ThreatType::CrossSiteScripting,
                    severity: Severity::High,
                    location: crate::scanner::Location::Text {
                        offset: m.start(),
                        length: m.len(),
                    },
                    description: "XSS pattern detected".to_string(),
                    remediation: Some("Escape HTML entities and validate input".to_string()),
                });
            }
        }

        Ok(threats)
    }

    async fn health_check(&self) -> Result<HealthStatus> {
        Ok(HealthStatus {
            healthy: true,
            message: "XSS plugin is healthy".to_string(),
            last_check: chrono::Utc::now(),
            metrics: self.get_metrics(),
        })
    }

    async fn shutdown(&mut self) -> Result<()> {
        info!("XSS plugin shutting down");
        Ok(())
    }
}

/// Example custom pattern plugin
struct CustomPatternPlugin {
    patterns: Vec<(String, regex::Regex, Severity)>,
}

impl CustomPatternPlugin {
    const fn new() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }
}

#[async_trait]
impl SecurityPlugin for CustomPatternPlugin {
    fn metadata(&self) -> PluginMetadata {
        PluginMetadata {
            name: "Custom Pattern Detector".to_string(),
            version: "1.0.0".to_string(),
            author: "User".to_string(),
            description: "Detects custom threat patterns".to_string(),
            homepage: None,
            threat_types: vec!["custom".to_string()],
            capabilities: PluginCapabilities {
                scan_text: true,
                scan_json: false,
                scan_binary: false,
                async_scan: true,
                batch_scan: false,
                max_data_size_mb: Some(1),
            },
        }
    }

    async fn initialize(&mut self, config: serde_json::Value) -> Result<()> {
        // Load patterns from config
        if let Some(patterns) = config.get("patterns").and_then(|p| p.as_array()) {
            for pattern_config in patterns {
                if let (Some(name), Some(regex), Some(severity)) = (
                    pattern_config.get("name").and_then(|n| n.as_str()),
                    pattern_config.get("pattern").and_then(|p| p.as_str()),
                    pattern_config.get("severity").and_then(|s| s.as_str()),
                ) {
                    let severity = match severity {
                        "low" => Severity::Low,
                        "medium" => Severity::Medium,
                        "high" => Severity::High,
                        "critical" => Severity::Critical,
                        _ => Severity::Medium,
                    };

                    if let Ok(re) = regex::Regex::new(regex) {
                        self.patterns.push((name.to_string(), re, severity));
                        debug!("Added custom pattern: {}", name);
                    }
                }
            }
        }

        info!(
            "Custom pattern plugin initialized with {} patterns",
            self.patterns.len()
        );
        Ok(())
    }

    async fn scan(&self, context: ScanContext<'_>) -> Result<Vec<Threat>> {
        let text = String::from_utf8_lossy(context.data);
        let mut threats = Vec::new();

        for (name, pattern, severity) in &self.patterns {
            if let Some(m) = pattern.find(&text) {
                threats.push(Threat {
                    threat_type: ThreatType::Custom(name.clone()),
                    severity: *severity,
                    location: crate::scanner::Location::Text {
                        offset: m.start(),
                        length: m.len(),
                    },
                    description: format!("Custom pattern '{name}' detected"),
                    remediation: None,
                });
            }
        }

        Ok(threats)
    }

    async fn health_check(&self) -> Result<HealthStatus> {
        Ok(HealthStatus {
            healthy: true,
            message: format!(
                "Custom pattern plugin with {} patterns",
                self.patterns.len()
            ),
            last_check: chrono::Utc::now(),
            metrics: self.get_metrics(),
        })
    }

    async fn shutdown(&mut self) -> Result<()> {
        info!("Custom pattern plugin shutting down");
        self.patterns.clear();
        Ok(())
    }
}
