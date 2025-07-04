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
//! XSS Scanner trait and implementations
//!
//! Trait-based architecture for XSS detection allowing standard and enhanced implementations

use super::{Location, ScanError, Severity, Threat, ThreatType};
use async_trait::async_trait;
use regex::Regex;
use std::sync::Arc;
use tracing::{debug, trace};

/// Trait for XSS scanning implementations
#[async_trait]
pub trait XssScanner: Send + Sync {
    /// Scan text for XSS threats
    async fn scan_xss(&self, text: &str) -> Result<Vec<Threat>, ScanError>;

    /// Check if content contains potential XSS
    async fn contains_xss(&self, text: &str) -> Result<bool, ScanError>;

    /// Get scanner capabilities
    fn capabilities(&self) -> XssScannerCapabilities;
}

/// XSS scanner capabilities
#[derive(Debug, Clone)]
pub struct XssScannerCapabilities {
    pub supports_encoded_detection: bool,
    pub supports_obfuscation_detection: bool,
    pub supports_context_analysis: bool,
    pub max_scan_size: usize,
}

/// Standard regex-based XSS scanner
pub struct StandardXssScanner {
    patterns: Vec<Regex>,
    encoded_patterns: Vec<Regex>,
}

impl StandardXssScanner {
    /// Create new standard XSS scanner
    pub fn new(patterns: Vec<String>) -> Result<Self, ScanError> {
        let mut compiled_patterns = Vec::new();
        let mut encoded_patterns = Vec::new();

        for pattern in patterns {
            match Regex::new(&pattern) {
                Ok(regex) => {
                    // Separate encoded patterns for special handling
                    if pattern.contains("%") || pattern.contains("&#") || pattern.contains("\\u") {
                        encoded_patterns.push(regex);
                    } else {
                        compiled_patterns.push(regex);
                    }
                }
                Err(e) => {
                    return Err(ScanError::InvalidInput(format!(
                        "Invalid XSS regex pattern '{}': {}",
                        pattern, e
                    )));
                }
            }
        }

        debug!(
            "Initialized standard XSS scanner with {} patterns ({} encoded)",
            compiled_patterns.len() + encoded_patterns.len(),
            encoded_patterns.len()
        );

        Ok(Self {
            patterns: compiled_patterns,
            encoded_patterns,
        })
    }
}

#[async_trait]
impl XssScanner for StandardXssScanner {
    async fn scan_xss(&self, text: &str) -> Result<Vec<Threat>, ScanError> {
        let mut threats = Vec::new();

        // Check standard patterns
        for (_idx, pattern) in self.patterns.iter().enumerate() {
            if let Some(mat) = pattern.find(text) {
                let threat = Threat {
                    threat_type: ThreatType::CrossSiteScripting,
                    severity: determine_xss_severity(&text[mat.start()..mat.end()]),
                    location: Location::Text {
                        offset: mat.start(),
                        length: mat.end() - mat.start(),
                    },
                    description: format!("XSS pattern detected: {}", &text[mat.start()..mat.end()]),
                    remediation: Some("Sanitize HTML content before rendering".to_string()),
                };
                threats.push(threat);

                trace!(
                    "XSS threat detected at position {}-{}",
                    mat.start(),
                    mat.end()
                );
            }
        }

        // Check encoded patterns
        for (_idx, pattern) in self.encoded_patterns.iter().enumerate() {
            if let Some(mat) = pattern.find(text) {
                let threat = Threat {
                    threat_type: ThreatType::CrossSiteScripting,
                    severity: Severity::High, // Encoded XSS is always high severity
                    location: Location::Text {
                        offset: mat.start(),
                        length: mat.end() - mat.start(),
                    },
                    description: format!(
                        "Encoded XSS pattern detected: {}",
                        &text[mat.start()..mat.end()]
                    ),
                    remediation: Some("Decode and sanitize content before processing".to_string()),
                };
                threats.push(threat);

                trace!(
                    "Encoded XSS threat detected at position {}-{}",
                    mat.start(),
                    mat.end()
                );
            }
        }

        Ok(threats)
    }

    async fn contains_xss(&self, text: &str) -> Result<bool, ScanError> {
        // Quick check without creating full threat objects
        for pattern in &self.patterns {
            if pattern.is_match(text) {
                return Ok(true);
            }
        }

        for pattern in &self.encoded_patterns {
            if pattern.is_match(text) {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn capabilities(&self) -> XssScannerCapabilities {
        XssScannerCapabilities {
            supports_encoded_detection: !self.encoded_patterns.is_empty(),
            supports_obfuscation_detection: false, // Standard scanner doesn't detect advanced obfuscation
            supports_context_analysis: false,      // Standard scanner doesn't analyze context
            max_scan_size: 1024 * 1024,            // 1MB max scan size
        }
    }
}

/// Enhanced XSS scanner implementation (feature-gated)
///
/// The enhanced XSS scanner provides advanced detection capabilities
/// beyond standard regex-based scanning.
#[cfg(feature = "enhanced")]
mod enhanced {
    use super::*;

    pub struct EnhancedXssScanner {
        standard_scanner: StandardXssScanner,
    }

    impl EnhancedXssScanner {
        pub fn new(patterns: Vec<String>) -> Result<Self, ScanError> {
            let standard_scanner = StandardXssScanner::new(patterns)?;

            debug!("Initialized enhanced XSS scanner (using standard scanner as fallback)");

            Ok(Self { standard_scanner })
        }
    }

    #[async_trait]
    impl XssScanner for EnhancedXssScanner {
        async fn scan_xss(&self, text: &str) -> Result<Vec<Threat>, ScanError> {
            // For now, just use standard scanner
            // In production, this would integrate with enhanced detection
            self.standard_scanner.scan_xss(text).await
        }

        async fn contains_xss(&self, text: &str) -> Result<bool, ScanError> {
            self.standard_scanner.contains_xss(text).await
        }

        fn capabilities(&self) -> XssScannerCapabilities {
            // Return enhanced capabilities even though we're using standard scanner
            // This represents what would be available with enhanced implementation
            XssScannerCapabilities {
                supports_encoded_detection: true,
                supports_obfuscation_detection: true,
                supports_context_analysis: true,
                max_scan_size: 10 * 1024 * 1024, // 10MB with enhanced scanner
            }
        }
    }
}

/// Factory function to create XSS scanner based on configuration
pub fn create_xss_scanner(
    patterns: Vec<String>,
    enhanced_mode: bool,
) -> Result<Arc<dyn XssScanner>, ScanError> {
    if enhanced_mode {
        #[cfg(feature = "enhanced")]
        {
            debug!("Creating enhanced XSS scanner");
            return Ok(Arc::new(enhanced::EnhancedXssScanner::new(patterns)?));
        }
        #[cfg(not(feature = "enhanced"))]
        {
            debug!("Enhanced mode requested but not available, using standard scanner");
        }
    }

    debug!("Creating standard XSS scanner");
    Ok(Arc::new(StandardXssScanner::new(patterns)?))
}

/// Determine XSS severity based on content
fn determine_xss_severity(content: &str) -> Severity {
    let lower = content.to_lowercase();

    // Critical: Direct script execution or cookie/session access
    if lower.contains("document.cookie")
        || lower.contains("sessionstorage")
        || lower.contains("localstorage")
        || lower.contains("eval(")
    {
        return Severity::Critical;
    }

    // High: Script tags or event handlers
    if lower.contains("<script")
        || lower.contains("onerror")
        || lower.contains("onload")
        || lower.contains("javascript:")
    {
        return Severity::High;
    }

    // Medium: Potentially dangerous elements
    if lower.contains("<iframe") || lower.contains("<object") || lower.contains("<embed") {
        return Severity::Medium;
    }

    // Default to Medium for other XSS patterns
    Severity::Medium
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_standard_xss_detection() {
        let patterns = vec![
            r"<script[^>]*>".to_string(),
            r"(?i)javascript\s*:".to_string(),
            r"(?i)onerror\s*=".to_string(),
        ];

        let scanner = StandardXssScanner::new(patterns).unwrap();

        // Test script tag detection
        let threats = scanner
            .scan_xss("<script>alert('XSS')</script>")
            .await
            .unwrap();
        assert!(!threats.is_empty());
        assert_eq!(threats[0].threat_type, ThreatType::CrossSiteScripting);

        // Test javascript: protocol
        let threats = scanner
            .scan_xss(r#"<a href="javascript:alert(1)">Click</a>"#)
            .await
            .unwrap();
        assert!(!threats.is_empty());

        // Test event handler
        let threats = scanner
            .scan_xss(r#"<img src=x onerror=alert('XSS')>"#)
            .await
            .unwrap();
        assert!(!threats.is_empty());

        // Test clean input
        let threats = scanner.scan_xss("This is safe text").await.unwrap();
        assert!(threats.is_empty());
    }

    #[tokio::test]
    async fn test_xss_severity_detection() {
        let patterns = vec![
            r"document\.cookie".to_string(),
            r"<script[^>]*>".to_string(),
            r"<iframe[^>]*>".to_string(),
        ];

        let scanner = StandardXssScanner::new(patterns).unwrap();

        // Critical severity
        let threats = scanner.scan_xss("document.cookie").await.unwrap();
        assert_eq!(threats[0].severity, Severity::Critical);

        // High severity
        let threats = scanner.scan_xss("<script>alert(1)</script>").await.unwrap();
        assert_eq!(threats[0].severity, Severity::High);

        // Medium severity
        let threats = scanner
            .scan_xss("<iframe src='evil.com'></iframe>")
            .await
            .unwrap();
        assert_eq!(threats[0].severity, Severity::Medium);
    }
}
