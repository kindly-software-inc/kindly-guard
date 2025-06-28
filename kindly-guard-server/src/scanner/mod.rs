//! Security scanner module for threat detection

use serde::{Deserialize, Serialize};
use std::fmt;
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
    patterns: ThreatPatterns,
    config: crate::config::ScannerConfig,
    #[allow(dead_code)]
    event_buffer: Option<kindly_guard_core::AtomicEventBuffer>,
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
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
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
    
    // MCP-specific threats
    SessionIdExposure,
    ToolPoisoning,
    TokenTheft,
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
    /// Create a new security scanner with the given configuration
    pub fn new(config: crate::config::ScannerConfig) -> Result<Self, ScanError> {
        let patterns = if let Some(path) = &config.custom_patterns {
            ThreatPatterns::load_from_file(path)?
        } else {
            ThreatPatterns::default()
        };
        
        // Initialize high-performance event buffer if configured
        let event_buffer = if config.enable_event_buffer {
            Some(kindly_guard_core::AtomicEventBuffer::new(
                10, // 10MB buffer
                100, // 100 endpoints
                10000.0, // 10k events/sec
                5, // 5 failures before circuit opens
            ))
        } else {
            None
        };
        
        Ok(Self {
            unicode_scanner: UnicodeScanner::new(),
            injection_scanner: InjectionScanner::new(&patterns)?,
            patterns,
            config,
            event_buffer,
        })
    }
    
    /// Scan text for threats
    pub fn scan_text(&self, text: &str) -> ScanResult {
        let mut threats = Vec::new();
        
        if self.config.unicode_detection {
            threats.extend(self.unicode_scanner.scan_text(text)?);
        }
        
        if self.config.injection_detection {
            threats.extend(self.injection_scanner.scan_text(text)?);
        }
        
        Ok(threats)
    }
    
    /// Scan JSON value for threats
    pub fn scan_json(&self, value: &serde_json::Value) -> ScanResult {
        self.scan_json_recursive(value, "$", 0)
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
        ScannerStats {
            unicode_threats_detected: self.unicode_scanner.threats_detected(),
            injection_threats_detected: self.injection_scanner.threats_detected(),
            total_scans: self.unicode_scanner.total_scans() + self.injection_scanner.total_scans(),
        }
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
            ThreatType::SessionIdExposure => write!(f, "Session ID Exposure"),
            ThreatType::ToolPoisoning => write!(f, "Tool Poisoning"),
            ThreatType::TokenTheft => write!(f, "Token Theft Risk"),
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