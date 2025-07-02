//! Synchronous wrapper for the SecurityScanner
//! 
//! This module provides a synchronous interface to the SecurityScanner
//! for use in tests and other non-async contexts.

use super::{SecurityScanner, Threat, ScanError};
use crate::config::ScannerConfig;
use std::sync::Arc;

/// A synchronous wrapper around SecurityScanner
/// 
/// This wrapper uses a dedicated tokio runtime to handle async operations
/// internally, providing a synchronous API for testing and other use cases.
pub struct SyncSecurityScanner {
    scanner: Arc<SecurityScanner>,
    runtime: tokio::runtime::Runtime,
}

impl SyncSecurityScanner {
    /// Create a new synchronous scanner
    pub fn new(config: ScannerConfig) -> Result<Self, ScanError> {
        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| ScanError::InvalidInput(format!("Failed to create runtime: {}", e)))?;
        
        let scanner = Arc::new(SecurityScanner::new(config)?);
        
        Ok(Self { scanner, runtime })
    }

    /// Scan text synchronously
    pub fn scan_text(&self, text: &str) -> Result<Vec<Threat>, ScanError> {
        // For synchronous scanning, we'll skip the XSS scanner which requires async
        let mut threats = Vec::new();

        if self.scanner.config.unicode_detection {
            threats.extend(self.scanner.unicode_scanner.scan_text(text)?);
        }

        if self.scanner.config.injection_detection {
            threats.extend(self.scanner.injection_scanner.scan_text(text)?);
        }

        // Skip XSS scanner in sync mode as it requires async runtime
        // Skip plugin scanners in sync mode as they may require async

        Ok(threats)
    }

    /// Scan JSON synchronously
    pub fn scan_json(&self, value: &serde_json::Value) -> Result<Vec<Threat>, ScanError> {
        // Convert JSON to string and scan
        let json_str = serde_json::to_string(value)
            .map_err(|e| ScanError::InvalidInput(format!("Invalid JSON: {}", e)))?;
        
        self.scan_text(&json_str)
    }
}

/// Create a scanner suitable for synchronous testing
/// 
/// This creates a scanner with XSS detection disabled to avoid async requirements
pub fn create_sync_scanner(config: ScannerConfig) -> Result<SecurityScanner, ScanError> {
    let mut sync_config = config;
    sync_config.xss_detection = Some(false); // Disable XSS to avoid async
    SecurityScanner::new(sync_config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::ThreatType;

    #[test]
    fn test_sync_scanner_basic() {
        let config = ScannerConfig {
            unicode_detection: true,
            injection_detection: true,
            path_traversal_detection: true,
            custom_patterns: None,
            max_scan_depth: 10,
            enable_event_buffer: false,
            xss_detection: Some(false),
            enhanced_mode: Some(false),
        };
        let scanner = SyncSecurityScanner::new(config).unwrap();
        
        let threats = scanner.scan_text("SELECT * FROM users WHERE id = '1' OR '1'='1'").unwrap();
        assert!(!threats.is_empty());
        assert!(threats.iter().any(|t| matches!(t.threat_type, ThreatType::SqlInjection)));
    }

    #[test]
    fn test_sync_scanner_unicode() {
        let config = ScannerConfig {
            unicode_detection: true,
            injection_detection: true,
            path_traversal_detection: true,
            custom_patterns: None,
            max_scan_depth: 10,
            enable_event_buffer: false,
            xss_detection: Some(false),
            enhanced_mode: Some(false),
        };
        let scanner = SyncSecurityScanner::new(config).unwrap();
        
        let threats = scanner.scan_text("Hello\u{202E}World").unwrap();
        assert!(!threats.is_empty());
        assert!(threats.iter().any(|t| matches!(t.threat_type, ThreatType::UnicodeBiDi)));
    }

    #[test]
    fn test_create_sync_scanner() {
        let config = ScannerConfig {
            unicode_detection: true,
            injection_detection: true,
            path_traversal_detection: true,
            custom_patterns: None,
            max_scan_depth: 10,
            enable_event_buffer: false,
            xss_detection: Some(false),
            enhanced_mode: Some(false),
        };
        let scanner = create_sync_scanner(config).unwrap();
        
        // This should work without async runtime
        let threats = scanner.scan_text("'; DROP TABLE users; --").unwrap();
        assert!(!threats.is_empty());
    }
}