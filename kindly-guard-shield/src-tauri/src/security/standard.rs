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
//! Standard pattern detector implementation
//!
//! This provides basic security pattern detection without enhanced features

use anyhow::Result;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::security::{PatternDetectorTrait, SecurityThreat, ThreatType};

/// Standard pattern detector with basic detection capabilities
pub struct StandardPatternDetector {
    scans_performed: AtomicU64,
    threats_detected: AtomicU64,
}

impl StandardPatternDetector {
    /// Create new standard detector
    pub fn new() -> Self {
        Self {
            scans_performed: AtomicU64::new(0),
            threats_detected: AtomicU64::new(0),
        }
    }
    
    /// Check for SQL injection patterns
    fn check_sql_injection(text: &str) -> Vec<SecurityThreat> {
        let mut threats = Vec::new();
        let sql_patterns = [
            ("' OR '1'='1", 0.9),
            ("'; DROP TABLE", 0.95),
            ("' OR 1=1--", 0.9),
            ("UNION SELECT", 0.8),
            ("'; EXEC", 0.85),
        ];
        
        let lower_text = text.to_lowercase();
        for (pattern, severity) in sql_patterns {
            if let Some(pos) = lower_text.find(&pattern.to_lowercase()) {
                threats.push(SecurityThreat {
                    threat_type: ThreatType::SqlInjection,
                    severity,
                    location: pos,
                    description: format!("SQL injection pattern: {}", pattern),
                    confidence: 0.8,
                });
            }
        }
        
        threats
    }
    
    /// Check for XSS patterns
    fn check_xss(text: &str) -> Vec<SecurityThreat> {
        let mut threats = Vec::new();
        let xss_patterns = [
            ("<script", 0.95),
            ("javascript:", 0.9),
            ("onerror=", 0.85),
            ("onclick=", 0.85),
            ("<iframe", 0.8),
            ("onload=", 0.85),
        ];
        
        let lower_text = text.to_lowercase();
        for (pattern, severity) in xss_patterns {
            if let Some(pos) = lower_text.find(pattern) {
                threats.push(SecurityThreat {
                    threat_type: ThreatType::XssAttempt,
                    severity,
                    location: pos,
                    description: format!("XSS pattern: {}", pattern),
                    confidence: 0.8,
                });
            }
        }
        
        threats
    }
    
    /// Check for path traversal
    fn check_path_traversal(text: &str) -> Vec<SecurityThreat> {
        let mut threats = Vec::new();
        let patterns = [
            ("../", 0.8),
            ("..\\", 0.8),
            ("..%2F", 0.85),
            ("..%5C", 0.85),
        ];
        
        for (pattern, severity) in patterns {
            if let Some(pos) = text.find(pattern) {
                threats.push(SecurityThreat {
                    threat_type: ThreatType::PathTraversal,
                    severity,
                    location: pos,
                    description: format!("Path traversal pattern: {}", pattern),
                    confidence: 0.9,
                });
            }
        }
        
        threats
    }
    
    /// Check for unicode exploits
    fn check_unicode_exploits(text: &str) -> Vec<SecurityThreat> {
        let mut threats = Vec::new();
        
        // Check for bidi override characters
        let bidi_chars = [
            ('\u{202A}', "LEFT-TO-RIGHT EMBEDDING"),
            ('\u{202B}', "RIGHT-TO-LEFT EMBEDDING"),
            ('\u{202D}', "LEFT-TO-RIGHT OVERRIDE"),
            ('\u{202E}', "RIGHT-TO-LEFT OVERRIDE"),
            ('\u{2066}', "LEFT-TO-RIGHT ISOLATE"),
            ('\u{2067}', "RIGHT-TO-LEFT ISOLATE"),
        ];
        
        for (i, ch) in text.chars().enumerate() {
            for (bidi_char, desc) in &bidi_chars {
                if ch == *bidi_char {
                    threats.push(SecurityThreat {
                        threat_type: ThreatType::UnicodeExploit,
                        severity: 0.7,
                        location: i,
                        description: format!("Unicode bidi character: {}", desc),
                        confidence: 1.0,
                    });
                }
            }
        }
        
        threats
    }
}

impl PatternDetectorTrait for StandardPatternDetector {
    fn scan_text(&self, text: &str) -> Vec<SecurityThreat> {
        self.scans_performed.fetch_add(1, Ordering::Relaxed);
        
        let mut threats = Vec::new();
        
        // Run all detection methods
        threats.extend(Self::check_sql_injection(text));
        threats.extend(Self::check_xss(text));
        threats.extend(Self::check_path_traversal(text));
        threats.extend(Self::check_unicode_exploits(text));
        
        self.threats_detected.fetch_add(threats.len() as u64, Ordering::Relaxed);
        threats
    }
    
    fn scan_json(&self, json: &serde_json::Value) -> Vec<SecurityThreat> {
        self.scans_performed.fetch_add(1, Ordering::Relaxed);
        
        let mut threats = Vec::new();
        
        // Convert JSON to string and scan
        let json_str = json.to_string();
        threats.extend(self.scan_text(&json_str));
        
        // Also scan individual string values
        match json {
            serde_json::Value::String(s) => {
                threats.extend(self.scan_text(s));
            }
            serde_json::Value::Object(map) => {
                for (_, value) in map {
                    threats.extend(self.scan_json(value));
                }
            }
            serde_json::Value::Array(arr) => {
                for value in arr {
                    threats.extend(self.scan_json(value));
                }
            }
            _ => {}
        }
        
        self.threats_detected.fetch_add(threats.len() as u64, Ordering::Relaxed);
        threats
    }
    
    fn preload_patterns(&self, _patterns: Vec<String>) -> Result<()> {
        // Standard implementation doesn't support custom patterns
        Ok(())
    }
    
    fn get_scan_stats(&self) -> (u64, u64) {
        (
            self.scans_performed.load(Ordering::Relaxed),
            self.threats_detected.load(Ordering::Relaxed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sql_injection_detection() {
        let detector = StandardPatternDetector::new();
        let threats = detector.scan_text("SELECT * FROM users WHERE id = '1' OR '1'='1'");
        
        assert!(!threats.is_empty());
        assert_eq!(threats[0].threat_type, ThreatType::SqlInjection);
    }
    
    #[test]
    fn test_xss_detection() {
        let detector = StandardPatternDetector::new();
        let threats = detector.scan_text("<script>alert('xss')</script>");
        
        assert!(!threats.is_empty());
        assert_eq!(threats[0].threat_type, ThreatType::XssAttempt);
    }
    
    #[test]
    fn test_unicode_detection() {
        let detector = StandardPatternDetector::new();
        let threats = detector.scan_text("Hello\u{202E}World");
        
        assert!(!threats.is_empty());
        assert_eq!(threats[0].threat_type, ThreatType::UnicodeExploit);
    }
}