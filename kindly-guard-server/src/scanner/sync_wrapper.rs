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
//! Synchronous wrapper for the SecurityScanner
//!
//! This module provides a synchronous interface to the SecurityScanner
//! for use in tests and other non-async contexts.

use super::{ScanError, SecurityScanner, Threat};
use crate::config::ScannerConfig;
use std::sync::Arc;

/// A synchronous wrapper around SecurityScanner
///
/// This wrapper uses a dedicated tokio runtime to handle async operations
/// internally, providing a synchronous API for testing and other use cases.
pub struct SyncSecurityScanner {
    scanner: Arc<SecurityScanner>,
    #[allow(dead_code)] // Runtime kept for potential async operations
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
            xss_detection: Some(false),
            crypto_detection: true,
            enhanced_mode: Some(false),
            custom_patterns: None,
            max_scan_depth: 10,
            enable_event_buffer: false,
            max_content_size: 5 * 1024 * 1024, // 5MB
        };
        let scanner = SyncSecurityScanner::new(config).unwrap();

        let threats = scanner
            .scan_text("SELECT * FROM users WHERE id = '1' OR '1'='1'")
            .unwrap();
        assert!(!threats.is_empty());
        assert!(threats
            .iter()
            .any(|t| matches!(t.threat_type, ThreatType::SqlInjection)));
    }

    #[test]
    fn test_sync_scanner_unicode() {
        let config = ScannerConfig {
            unicode_detection: true,
            injection_detection: true,
            path_traversal_detection: true,
            xss_detection: Some(false),
            crypto_detection: true,
            enhanced_mode: Some(false),
            custom_patterns: None,
            max_scan_depth: 10,
            enable_event_buffer: false,
            max_content_size: 5 * 1024 * 1024, // 5MB
        };
        let scanner = SyncSecurityScanner::new(config).unwrap();

        let threats = scanner.scan_text("Hello\u{202E}World").unwrap();
        assert!(!threats.is_empty());
        assert!(threats
            .iter()
            .any(|t| matches!(t.threat_type, ThreatType::UnicodeBiDi)));
    }

    #[test]
    fn test_create_sync_scanner() {
        let config = ScannerConfig {
            unicode_detection: true,
            injection_detection: true,
            path_traversal_detection: true,
            xss_detection: Some(false),
            crypto_detection: true,
            enhanced_mode: Some(false),
            custom_patterns: None,
            max_scan_depth: 10,
            enable_event_buffer: false,
            max_content_size: 5 * 1024 * 1024, // 5MB
        };
        let scanner = create_sync_scanner(config).unwrap();

        // This should work without async runtime
        let threats = scanner.scan_text("'; DROP TABLE users; --").unwrap();
        assert!(!threats.is_empty());
    }
}
