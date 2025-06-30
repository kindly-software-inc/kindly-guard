//! Security scanner module for threat detection

use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;
use thiserror::Error;

pub mod unicode;
pub mod injection;
pub mod patterns;

pub use unicode::UnicodeScanner;
pub use injection::InjectionScanner;
pub use patterns::ThreatPatterns;

/// Main security scanner combining all threat detection
pub struct SecurityScanner {
    unicode_scanner: UnicodeScanner,
    injection_scanner: InjectionScanner,
    pub patterns: ThreatPatterns,
    config: crate::config::ScannerConfig,
    plugin_manager: Option<Arc<dyn crate::plugins::PluginManagerTrait>>,
    #[allow(dead_code)]
    #[cfg(feature = "enhanced")]
    event_processor: Option<Arc<dyn crate::traits::SecurityEventProcessor>>,
}

/// Represents a detected security threat
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Threat {
    pub threat_type: ThreatType,
    pub severity: Severity,
    pub location: Location,
    pub description: String,
    pub remediation: Option<String>,
}

/// Types of security threats
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ThreatType {
    // Unicode threats
    UnicodeInvisible,
    UnicodeBiDi,
    UnicodeHomograph,
    UnicodeControl,
    
    // Injection threats
    PromptInjection,
    CommandInjection,
    PathTraversal,
    SqlInjection,
    CrossSiteScripting,
    
    // MCP-specific threats
    SessionIdExposure,
    ToolPoisoning,
    TokenTheft,
    
    // Plugin-detected threats
    Custom(String),
}

/// Threat severity levels
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Location of a threat in the input
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Location {
    Text { offset: usize, length: usize },
    Json { path: String },
    Binary { offset: usize },
}

/// Scanner errors
#[derive(Error, Debug)]
pub enum ScanError {
    #[error("Maximum scan depth exceeded")]
    MaxDepthExceeded,
    
    #[error("Invalid input format: {0}")]
    InvalidInput(String),
    
    #[error("Pattern compilation failed: {0}")]
    PatternError(String),
}

/// Result type for scanner operations
pub type ScanResult = Result<Vec<Threat>, ScanError>;

impl SecurityScanner {
    /// Set the plugin manager for this scanner
    pub fn set_plugin_manager(&mut self, plugin_manager: Arc<dyn crate::plugins::PluginManagerTrait>) {
        self.plugin_manager = Some(plugin_manager);
    }
    
    /// Create a new security scanner with the given configuration
    pub fn new(config: crate::config::ScannerConfig) -> Result<Self, ScanError> {
        Self::with_processor(config, None)
    }
    
    /// Create a new security scanner with an optional event processor
    pub fn with_processor(
        config: crate::config::ScannerConfig,
        event_processor: Option<Arc<dyn crate::traits::SecurityEventProcessor>>
    ) -> Result<Self, ScanError> {
        let patterns = if let Some(path) = &config.custom_patterns {
            ThreatPatterns::load_from_file(path)?
        } else {
            ThreatPatterns::default()
        };
        
        // Use provided event processor if available and enabled
        #[cfg(feature = "enhanced")]
        let event_processor = if config.enable_event_buffer {
            event_processor
        } else {
            None
        };
        
        #[cfg(not(feature = "enhanced"))]
        let event_processor: Option<Arc<dyn crate::traits::SecurityEventProcessor>> = None;
        
        // Create scanners with optional enhancement
        let mut unicode_scanner = UnicodeScanner::new();
        let mut injection_scanner = InjectionScanner::new(&patterns)?;
        
        // Enhance scanners when processor is available
        #[cfg(feature = "enhanced")]
        if event_processor.is_some() {
            unicode_scanner.enable_enhancement();
            injection_scanner.enable_enhancement();
            tracing::debug!("Scanner optimization enabled");
        }
        
        Ok(Self {
            unicode_scanner,
            injection_scanner,
            patterns,
            config,
            plugin_manager: None, // Will be set later
            #[cfg(feature = "enhanced")]
            event_processor,
        })
    }
    
    /// Scan text for threats
    pub fn scan_text(&self, text: &str) -> ScanResult {
        let mut threats = Vec::new();
        
        // Use enhanced scanning when available
        #[cfg(feature = "enhanced")]
        if let Some(processor) = &self.event_processor {
            // Process scan event for correlation
            let event = crate::traits::SecurityEvent {
                event_type: "scan".to_string(),
                client_id: "scanner".to_string(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                metadata: serde_json::json!({
                    "preview": &text[..text.len().min(100)]
                }),
            };
            let _ = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(processor.process_event(event))
            });
            
            tracing::trace!("Optimized scanning active");
        }
        
        if self.config.unicode_detection {
            threats.extend(self.unicode_scanner.scan_text(text)?);
        }
        
        if self.config.injection_detection {
            threats.extend(self.injection_scanner.scan_text(text)?);
        }
        
        // Run plugin scanners if available
        if let Some(plugin_manager) = &self.plugin_manager {
            // Note: Plugin scanning is currently only supported when called from
            // non-async contexts (e.g., from the MCP server). The CLI uses async
            // and cannot call plugins from within its runtime.
            if tokio::runtime::Handle::try_current().is_err() {
                use crate::plugins::{ScanContext, ScanOptions};
                use tokio::runtime::Runtime;
                
                let context = ScanContext {
                    data: text.as_bytes(),
                    content_type: Some("text/plain"),
                    client_id: "scanner",
                    metadata: &std::collections::HashMap::new(),
                    options: ScanOptions::default(),
                };
                
                // Create runtime for async plugin calls
                let rt = Runtime::new().map_err(|e| ScanError::InvalidInput(e.to_string()))?;
                
                match rt.block_on(plugin_manager.scan_all(context)) {
                    Ok(plugin_results) => {
                        for (_plugin_id, plugin_threats) in plugin_results {
                            threats.extend(plugin_threats);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Plugin scan error: {}", e);
                    }
                }
            } else {
                tracing::debug!("Plugin scanning skipped in async context");
            }
        }
        
        // Track threats through processor for pattern analysis
        #[cfg(feature = "enhanced")]
        if !threats.is_empty() {
            if let Some(processor) = &self.event_processor {
                for threat in &threats {
                    let event = crate::traits::SecurityEvent {
                        event_type: "threat_detected".to_string(),
                        client_id: "scanner".to_string(),
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                        metadata: serde_json::json!({
                            "threat_type": match &threat.threat_type {
                                ThreatType::Custom(name) => name.clone(),
                                _ => format!("{:?}", threat.threat_type),
                            },
                            "severity": format!("{:?}", threat.severity)
                        }),
                    };
                    let _ = tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current().block_on(processor.process_event(event))
                    });
                }
            }
        }
        
        Ok(threats)
    }
    
    /// Scan JSON value for threats
    pub fn scan_json(&self, value: &serde_json::Value) -> ScanResult {
        let mut threats = self.scan_json_recursive(value, "$", 0)?;
        
        // Run plugin scanners if available
        if let Some(plugin_manager) = &self.plugin_manager {
            // Note: Plugin scanning is currently only supported when called from
            // non-async contexts (e.g., from the MCP server). The CLI uses async
            // and cannot call plugins from within its runtime.
            if tokio::runtime::Handle::try_current().is_err() {
                use crate::plugins::{ScanContext, ScanOptions};
                use tokio::runtime::Runtime;
                
                // Convert JSON to bytes for plugin scanning
                let json_bytes = serde_json::to_vec(value).map_err(|e| ScanError::InvalidInput(e.to_string()))?;
                
                let context = ScanContext {
                    data: &json_bytes,
                    content_type: Some("application/json"),
                    client_id: "scanner",
                    metadata: &std::collections::HashMap::new(),
                    options: ScanOptions::default(),
                };
                
                // Create runtime for async plugin calls
                let rt = Runtime::new().map_err(|e| ScanError::InvalidInput(e.to_string()))?;
                
                match rt.block_on(plugin_manager.scan_all(context)) {
                    Ok(plugin_results) => {
                        for (_plugin_id, plugin_threats) in plugin_results {
                            // Convert plugin threats to have JSON location
                            for mut threat in plugin_threats {
                                if matches!(threat.location, Location::Text { .. }) {
                                    threat.location = Location::Json { path: "$".to_string() };
                                }
                                threats.push(threat);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Plugin scan error: {}", e);
                    }
                }
            } else {
                tracing::debug!("Plugin scanning skipped in async context");
            }
        }
        
        Ok(threats)
    }
    
    fn scan_json_recursive(&self, value: &serde_json::Value, path: &str, depth: usize) -> ScanResult {
        if depth > self.config.max_scan_depth {
            return Err(ScanError::MaxDepthExceeded);
        }
        
        let mut threats = Vec::new();
        
        match value {
            serde_json::Value::String(s) => {
                let text_threats = self.scan_text(s)?;
                for mut threat in text_threats {
                    threat.location = Location::Json { path: path.to_string() };
                    threats.push(threat);
                }
            }
            serde_json::Value::Object(map) => {
                for (key, val) in map {
                    // Check the key itself
                    if let Ok(key_threats) = self.scan_text(key) {
                        for mut threat in key_threats {
                            threat.location = Location::Json { path: format!("{}.{}", path, key) };
                            threats.push(threat);
                        }
                    }
                    
                    // Recursively check the value
                    let sub_path = format!("{}.{}", path, key);
                    threats.extend(self.scan_json_recursive(val, &sub_path, depth + 1)?);
                }
            }
            serde_json::Value::Array(arr) => {
                for (i, val) in arr.iter().enumerate() {
                    let sub_path = format!("{}[{}]", path, i);
                    threats.extend(self.scan_json_recursive(val, &sub_path, depth + 1)?);
                }
            }
            _ => {} // Numbers, booleans, null are safe
        }
        
        Ok(threats)
    }
    
    /// Get scanner statistics
    pub fn stats(&self) -> ScannerStats {
        let mut stats = ScannerStats {
            unicode_threats_detected: self.unicode_scanner.threats_detected(),
            injection_threats_detected: self.injection_scanner.threats_detected(),
            total_scans: self.unicode_scanner.total_scans() + self.injection_scanner.total_scans(),
        };
        
        // Enhance stats with processor metrics
        #[cfg(feature = "enhanced")]
        if let Some(processor) = &self.event_processor {
            let processor_stats = processor.get_stats();
            // Add processed events to total scans for more accurate metrics
            stats.total_scans += processor_stats.events_processed / 10; // Approximate scan count
            tracing::trace!("Analytics enhanced");
        }
        
        stats
    }
}

/// Scanner statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerStats {
    pub unicode_threats_detected: u64,
    pub injection_threats_detected: u64,
    pub total_scans: u64,
}

impl fmt::Display for ThreatType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThreatType::UnicodeInvisible => write!(f, "Invisible Unicode Character"),
            ThreatType::UnicodeBiDi => write!(f, "BiDi Text Spoofing"),
            ThreatType::UnicodeHomograph => write!(f, "Homograph Attack"),
            ThreatType::UnicodeControl => write!(f, "Dangerous Control Character"),
            ThreatType::PromptInjection => write!(f, "Prompt Injection"),
            ThreatType::CommandInjection => write!(f, "Command Injection"),
            ThreatType::PathTraversal => write!(f, "Path Traversal"),
            ThreatType::SqlInjection => write!(f, "SQL Injection"),
            ThreatType::CrossSiteScripting => write!(f, "Cross-Site Scripting"),
            ThreatType::SessionIdExposure => write!(f, "Session ID Exposure"),
            ThreatType::ToolPoisoning => write!(f, "Tool Poisoning"),
            ThreatType::TokenTheft => write!(f, "Token Theft Risk"),
            ThreatType::Custom(name) => write!(f, "{}", name),
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Low => write!(f, "Low"),
            Severity::Medium => write!(f, "Medium"),
            Severity::High => write!(f, "High"),
            Severity::Critical => write!(f, "Critical"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_threat_type_display() {
        assert_eq!(ThreatType::UnicodeInvisible.to_string(), "Invisible Unicode Character");
        assert_eq!(ThreatType::PromptInjection.to_string(), "Prompt Injection");
    }
    
    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }
}