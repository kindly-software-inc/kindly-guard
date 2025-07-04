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
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use nonzero_ext::nonzero;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{debug, warn};

// Enhanced implementation module
#[cfg(feature = "enhanced")]
pub mod enhanced;

// Standard implementation module
pub mod standard;

use anyhow::Result;

#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    #[error("Invalid message format")]
    InvalidFormat,
    
    #[error("Message too large: {0} bytes")]
    MessageTooLarge(usize),
    
    #[error("Suspicious pattern detected: {0}")]
    SuspiciousPattern(String),
    
    #[error("Authentication failed")]
    AuthenticationFailed,
}

/// Threat types detected by pattern detector
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ThreatType {
    SqlInjection,
    XssAttempt,
    CommandInjection,
    PathTraversal,
    UnicodeExploit,
    Unknown,
}

/// Security threat information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityThreat {
    pub threat_type: ThreatType,
    pub severity: f32,
    pub location: usize,
    pub description: String,
    pub confidence: f32,
}

/// Pattern detector trait for security scanning
pub trait PatternDetectorTrait: Send + Sync {
    /// Scan text for security threats
    fn scan_text(&self, text: &str) -> Vec<SecurityThreat>;
    
    /// Scan JSON for security threats
    fn scan_json(&self, json: &serde_json::Value) -> Vec<SecurityThreat>;
    
    /// Preload patterns for optimization
    fn preload_patterns(&self, patterns: Vec<String>) -> Result<()>;
    
    /// Get scan statistics
    fn get_scan_stats(&self) -> (u64, u64); // (scans_performed, threats_detected)
}

/// Factory for creating pattern detectors
pub struct PatternDetectorFactory;

impl PatternDetectorFactory {
    /// Create appropriate pattern detector based on configuration
    pub fn create(config: &crate::config::Config) -> Result<Arc<dyn PatternDetectorTrait>> {
        #[cfg(feature = "enhanced")]
        {
            if config.enhanced_mode {
                return Ok(Arc::new(enhanced::EnhancedPatternDetector::new()?));
            }
        }
        
        // Default to standard implementation
        Ok(Arc::new(standard::StandardPatternDetector::new()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub max_message_size: usize,
    pub rate_limit_per_minute: u32,
    pub enable_pattern_detection: bool,
    pub require_authentication: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_message_size: 1024 * 1024, // 1MB
            rate_limit_per_minute: 60,
            enable_pattern_detection: true,
            require_authentication: false,
        }
    }
}

pub struct SecurityValidator {
    config: RwLock<SecurityConfig>,
    rate_limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
    message_hashes: Arc<DashMap<Vec<u8>, Instant>>,
}

impl SecurityValidator {
    pub fn new() -> Self {
        Self::with_config(SecurityConfig::default())
    }
    
    pub fn with_config(config: SecurityConfig) -> Self {
        let quota = Quota::per_minute(nonzero!(config.rate_limit_per_minute));
        let rate_limiter = Arc::new(RateLimiter::direct(quota));
        
        Self {
            config: RwLock::new(config),
            rate_limiter,
            message_hashes: Arc::new(DashMap::new()),
        }
    }
    
    pub fn validate_message(&self, message: &[u8]) -> Result<(), SecurityError> {
        let config = self.config.read();
        
        // Check message size
        if message.len() > config.max_message_size {
            return Err(SecurityError::MessageTooLarge(message.len()));
        }
        
        // Check rate limit
        match self.rate_limiter.check() {
            Ok(_) => {}
            Err(_) => return Err(SecurityError::RateLimitExceeded),
        }
        
        // Check for duplicate messages (replay attack protection)
        let hash = self.compute_hash(message);
        let now = Instant::now();
        
        // Clean old hashes (older than 5 minutes)
        self.message_hashes.retain(|_, timestamp| {
            now.duration_since(*timestamp) < Duration::from_secs(300)
        });
        
        if self.message_hashes.contains_key(&hash) {
            warn!("Duplicate message detected");
            return Err(SecurityError::SuspiciousPattern(
                "Duplicate message".to_string(),
            ));
        }
        
        self.message_hashes.insert(hash, now);
        
        // Pattern detection
        if config.enable_pattern_detection {
            self.detect_suspicious_patterns(message)?;
        }
        
        Ok(())
    }
    
    pub fn validate_json(&self, json: &serde_json::Value) -> Result<(), SecurityError> {
        let serialized = serde_json::to_vec(json)
            .map_err(|_| SecurityError::InvalidFormat)?;
        self.validate_message(&serialized)
    }
    
    fn compute_hash(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
    
    fn detect_suspicious_patterns(&self, message: &[u8]) -> Result<(), SecurityError> {
        // Convert to string for pattern detection
        let text = match std::str::from_utf8(message) {
            Ok(s) => s,
            Err(_) => return Ok(()), // Skip pattern detection for binary data
        };
        
        // Check for common injection patterns
        let suspicious_patterns = [
            "<script",
            "javascript:",
            "onerror=",
            "onclick=",
            "../",
            "..\\",
            "\0",
            "%00",
            "\\x00",
        ];
        
        for pattern in &suspicious_patterns {
            if text.to_lowercase().contains(pattern) {
                return Err(SecurityError::SuspiciousPattern(
                    format!("Potential injection: {}", pattern),
                ));
            }
        }
        
        // Check for unicode bidi override characters
        let bidi_chars = [
            '\u{202A}', // LEFT-TO-RIGHT EMBEDDING
            '\u{202B}', // RIGHT-TO-LEFT EMBEDDING
            '\u{202D}', // LEFT-TO-RIGHT OVERRIDE
            '\u{202E}', // RIGHT-TO-LEFT OVERRIDE
            '\u{2066}', // LEFT-TO-RIGHT ISOLATE
            '\u{2067}', // RIGHT-TO-LEFT ISOLATE
        ];
        
        for ch in text.chars() {
            if bidi_chars.contains(&ch) {
                return Err(SecurityError::SuspiciousPattern(
                    "Unicode bidirectional override detected".to_string(),
                ));
            }
        }
        
        Ok(())
    }
    
    pub fn update_config(&self, config: SecurityConfig) {
        *self.config.write() = config;
    }
    
    pub fn authenticate(&self, _token: Option<&str>) -> Result<(), SecurityError> {
        let config = self.config.read();
        
        if !config.require_authentication {
            return Ok(());
        }
        
        // TODO: Implement proper authentication
        // For now, just check if a token is provided
        match _token {
            Some(_) => Ok(()),
            None => Err(SecurityError::AuthenticationFailed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_message_validation() {
        let validator = SecurityValidator::new();
        
        // Valid message
        let valid_msg = b"Hello, world!";
        assert!(validator.validate_message(valid_msg).is_ok());
        
        // Duplicate message should fail
        assert!(validator.validate_message(valid_msg).is_err());
    }
    
    #[test]
    fn test_pattern_detection() {
        let validator = SecurityValidator::new();
        
        // Script injection
        let malicious = b"<script>alert('xss')</script>";
        assert!(matches!(
            validator.validate_message(malicious),
            Err(SecurityError::SuspiciousPattern(_))
        ));
        
        // Path traversal
        let traversal = b"../../etc/passwd";
        assert!(matches!(
            validator.validate_message(traversal),
            Err(SecurityError::SuspiciousPattern(_))
        ));
    }
    
    #[test]
    fn test_unicode_detection() {
        let validator = SecurityValidator::new();
        
        // Unicode bidi override
        let bidi = "Hello\u{202E}World".as_bytes();
        assert!(matches!(
            validator.validate_message(bidi),
            Err(SecurityError::SuspiciousPattern(_))
        ));
    }
    
    #[test]
    fn test_rate_limiting() {
        let mut config = SecurityConfig::default();
        config.rate_limit_per_minute = 2;
        let validator = SecurityValidator::with_config(config);
        
        // First two should succeed
        assert!(validator.validate_message(b"msg1").is_ok());
        std::thread::sleep(Duration::from_millis(100));
        assert!(validator.validate_message(b"msg2").is_ok());
        
        // Third should fail (rate limit)
        std::thread::sleep(Duration::from_millis(100));
        assert!(matches!(
            validator.validate_message(b"msg3"),
            Err(SecurityError::RateLimitExceeded)
        ));
    }
}