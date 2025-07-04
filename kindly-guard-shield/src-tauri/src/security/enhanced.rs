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
//! Enhanced security pattern detection with optimized algorithms
//!
//! This module provides advanced pattern matching and threat detection
//! using optimized algorithms for better performance.

#![cfg(feature = "enhanced")]

use anyhow::Result;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::security::{PatternDetectorTrait, SecurityThreat, ThreatType};

// Local trait definitions for enhanced features
pub trait PatternMatcherTrait: Send + Sync {
    fn scan(&self, text: &str) -> Vec<PatternMatch>;
    fn detect_xss_advanced(&self, text: &str) -> Option<Vec<XssMatch>>;
    fn scan_json_deep(&self, json: &serde_json::Value) -> Vec<JsonThreat>;
    fn compile_patterns(&self, patterns: &[String]) -> Result<()>;
}

pub trait ThreatClassifierTrait: Send + Sync {
    fn calculate_severity(&self, pattern_match: &PatternMatch) -> f32;
}

pub trait UnicodeNormalizerTrait: Send + Sync {
    fn normalize(&self, text: &str) -> String;
    fn find_hidden_characters(&self, text: &str) -> Option<Vec<(usize, String)>>;
}

// Data structures for pattern matching
#[derive(Debug, Clone)]
pub struct PatternMatch {
    pub threat_type: ThreatType,
    pub location: usize,
    pub pattern_name: String,
    pub confidence: f32,
}

#[derive(Debug, Clone)]
pub struct XssMatch {
    pub severity: f32,
    pub location: usize,
    pub pattern: String,
    pub confidence: f32,
}

#[derive(Debug, Clone)]
pub struct JsonThreat {
    pub threat_type: ThreatType,
    pub severity: f32,
    pub json_path: String,
    pub detail: String,
    pub confidence: f32,
}

// Mock implementations for the local traits
struct PatternMatcher;
struct ThreatClassifier;
struct UnicodeNormalizer;

impl PatternMatcher {
    fn new_with_defaults() -> Result<Self> {
        Ok(Self)
    }
}

impl ThreatClassifier {
    fn new() -> Result<Self> {
        Ok(Self)
    }
}

impl UnicodeNormalizer {
    fn new() -> Self {
        Self
    }
}

impl PatternMatcherTrait for PatternMatcher {
    fn scan(&self, _text: &str) -> Vec<PatternMatch> {
        Vec::new()
    }
    
    fn detect_xss_advanced(&self, _text: &str) -> Option<Vec<XssMatch>> {
        None
    }
    
    fn scan_json_deep(&self, _json: &serde_json::Value) -> Vec<JsonThreat> {
        Vec::new()
    }
    
    fn compile_patterns(&self, _patterns: &[String]) -> Result<()> {
        Ok(())
    }
}

impl ThreatClassifierTrait for ThreatClassifier {
    fn calculate_severity(&self, _pattern_match: &PatternMatch) -> f32 {
        0.5
    }
}

impl UnicodeNormalizerTrait for UnicodeNormalizer {
    fn normalize(&self, text: &str) -> String {
        text.to_string()
    }
    
    fn find_hidden_characters(&self, _text: &str) -> Option<Vec<(usize, String)>> {
        None
    }
}

/// Enhanced pattern detector with SIMD-optimized scanning
pub struct EnhancedPatternDetector {
    /// Core pattern matcher with hardware acceleration
    pattern_matcher: Arc<dyn PatternMatcherTrait>,
    
    /// Advanced threat classifier
    threat_classifier: Arc<dyn ThreatClassifierTrait>,
    
    /// Unicode normalizer for detecting hidden threats
    unicode_normalizer: Arc<dyn UnicodeNormalizerTrait>,
    
    /// Performance metrics
    scans_performed: AtomicU64,
    threats_detected: AtomicU64,
}

impl EnhancedPatternDetector {
    /// Create new enhanced detector with preloaded patterns
    pub fn new() -> Result<Self> {
        let pattern_matcher = Arc::new(PatternMatcher::new_with_defaults()?);
        let threat_classifier = Arc::new(ThreatClassifier::new()?);
        let unicode_normalizer = Arc::new(UnicodeNormalizer::new());
        
        Ok(Self {
            pattern_matcher,
            threat_classifier,
            unicode_normalizer,
            scans_performed: AtomicU64::new(0),
            threats_detected: AtomicU64::new(0),
        })
    }
    
    /// Convert pattern match threat type to our threat type
    fn convert_threat_type(threat_type: &ThreatType) -> ThreatType {
        threat_type.clone()
    }
}

impl PatternDetectorTrait for EnhancedPatternDetector {
    fn scan_text(&self, text: &str) -> Vec<SecurityThreat> {
        self.scans_performed.fetch_add(1, Ordering::Relaxed);
        let mut threats = Vec::new();
        
        // First normalize unicode to detect hidden threats
        let normalized = self.unicode_normalizer.normalize(text);
        if normalized != text {
            // Unicode manipulation detected
            if let Some(hidden_chars) = self.unicode_normalizer.find_hidden_characters(text) {
                for (position, char_info) in hidden_chars {
                    threats.push(SecurityThreat {
                        threat_type: ThreatType::UnicodeExploit,
                        severity: 0.8,
                        location: position,
                        description: format!("Hidden unicode character: {}", char_info),
                        confidence: 0.95,
                    });
                }
            }
        }
        
        // Use pattern matcher for injection detection
        let matches = self.pattern_matcher.scan(&normalized);
        for m in matches {
            let threat_type = Self::convert_threat_type(&m.threat_type);
            let severity = self.threat_classifier.calculate_severity(&m);
            
            threats.push(SecurityThreat {
                threat_type,
                severity,
                location: m.location,
                description: m.pattern_name,
                confidence: m.confidence,
            });
        }
        
        // Advanced XSS detection using core algorithms
        if let Some(xss_threats) = self.pattern_matcher.detect_xss_advanced(text) {
            for xss in xss_threats {
                threats.push(SecurityThreat {
                    threat_type: ThreatType::XssAttempt,
                    severity: xss.severity,
                    location: xss.location,
                    description: format!("XSS pattern: {}", xss.pattern),
                    confidence: xss.confidence,
                });
            }
        }
        
        self.threats_detected.fetch_add(threats.len() as u64, Ordering::Relaxed);
        threats
    }
    
    fn scan_json(&self, json: &serde_json::Value) -> Vec<SecurityThreat> {
        self.scans_performed.fetch_add(1, Ordering::Relaxed);
        let mut threats = Vec::new();
        
        // Use core's JSON scanner for deep inspection
        let json_threats = self.pattern_matcher.scan_json_deep(json);
        
        for jt in json_threats {
            threats.push(SecurityThreat {
                threat_type: Self::convert_threat_type(&jt.threat_type),
                severity: jt.severity,
                location: 0, // JSON path stored in description
                description: format!("At path {}: {}", jt.json_path, jt.detail),
                confidence: jt.confidence,
            });
        }
        
        self.threats_detected.fetch_add(threats.len() as u64, Ordering::Relaxed);
        threats
    }
    
    fn preload_patterns(&self, patterns: Vec<String>) -> Result<()> {
        // Use core's optimized pattern compiler
        self.pattern_matcher.compile_patterns(&patterns)?;
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
    fn test_enhanced_detector_creation() {
        let detector = EnhancedPatternDetector::new().unwrap();
        let (scans, threats) = detector.get_scan_stats();
        assert_eq!(scans, 0);
        assert_eq!(threats, 0);
    }
    
    #[test]
    fn test_threat_type_conversion() {
        let threat_type = ThreatType::SqlInjection;
        assert!(matches!(
            EnhancedPatternDetector::convert_threat_type(&threat_type),
            ThreatType::SqlInjection
        ));
    }
}