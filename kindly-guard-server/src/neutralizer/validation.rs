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
//! Neutralization validation for production safety
//!
//! Provides comprehensive input/output validation to ensure neutralization
//! operations are safe, bounded, and produce valid results.

use crate::neutralizer::{NeutralizeAction, NeutralizeResult};
use crate::scanner::{Threat, ThreatType};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

/// Validation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationConfig {
    /// Maximum content size in bytes (default: 10MB)
    pub max_content_size: usize,

    /// Maximum threat location range (default: 1MB)
    pub max_location_range: usize,

    /// Maximum processing time in milliseconds (default: 5000ms)
    pub max_processing_time_ms: u64,

    /// Require output to be smaller than input
    pub enforce_size_reduction: bool,

    /// Maximum regex pattern length for injection threats
    pub max_pattern_length: usize,

    /// Validate output doesn't contain original threat
    pub validate_threat_removed: bool,

    /// Allow empty output
    pub allow_empty_output: bool,

    /// Maximum number of parameters extracted
    pub max_extracted_params: usize,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            max_content_size: 10 * 1024 * 1024, // 10MB
            max_location_range: 1024 * 1024,    // 1MB
            max_processing_time_ms: 5000,       // 5 seconds
            enforce_size_reduction: false,
            max_pattern_length: 1000,
            validate_threat_removed: true,
            allow_empty_output: true,
            max_extracted_params: 100,
        }
    }
}

/// Input validator for neutralization
pub struct NeutralizationValidator {
    config: ValidationConfig,
}

impl NeutralizationValidator {
    pub const fn new(config: ValidationConfig) -> Self {
        Self { config }
    }

    /// Validate input before neutralization
    pub fn validate_input(&self, threat: &Threat, content: &str) -> Result<()> {
        // Check content size
        ensure!(
            content.len() <= self.config.max_content_size,
            "Content size {} exceeds maximum allowed size of {} bytes",
            content.len(),
            self.config.max_content_size
        );

        // Validate threat location
        match &threat.location {
            crate::scanner::Location::Text { offset, length } => {
                ensure!(
                    *offset < content.len(),
                    "Threat offset {} exceeds content length {}",
                    offset,
                    content.len()
                );

                ensure!(
                    offset + length <= content.len(),
                    "Threat range [{}, {}] exceeds content bounds",
                    offset,
                    offset + length
                );

                ensure!(
                    *length <= self.config.max_location_range,
                    "Threat range {} exceeds maximum allowed range {}",
                    length,
                    self.config.max_location_range
                );
            }
            crate::scanner::Location::Json { path } => {
                ensure!(
                    path.len() <= self.config.max_pattern_length,
                    "JSON path length {} exceeds maximum {}",
                    path.len(),
                    self.config.max_pattern_length
                );

                // Validate JSON path format
                ensure!(
                    Self::is_valid_json_path(path),
                    "Invalid JSON path format: {}",
                    path
                );
            }
            crate::scanner::Location::Binary { offset } => {
                ensure!(
                    *offset < content.len(),
                    "Binary offset {} exceeds content length {}",
                    offset,
                    content.len()
                );
            }
        }

        // Validate threat description
        ensure!(
            !threat.description.is_empty(),
            "Threat description cannot be empty"
        );

        ensure!(
            threat.description.len() <= 1000,
            "Threat description too long: {} chars",
            threat.description.len()
        );

        // Validate content is valid UTF-8 (already guaranteed by &str)
        // But check for specific dangerous patterns
        Self::validate_content_safety(content)?;

        Ok(())
    }

    /// Validate output after neutralization
    pub fn validate_output(
        &self,
        threat: &Threat,
        original: &str,
        result: &NeutralizeResult,
    ) -> Result<()> {
        // Validate processing time
        ensure!(
            result.processing_time_us <= self.config.max_processing_time_ms * 1000,
            "Processing time {}μs exceeds maximum {}ms",
            result.processing_time_us,
            self.config.max_processing_time_ms
        );

        // Validate confidence score
        ensure!(
            (0.0..=1.0).contains(&result.confidence_score),
            "Confidence score {} out of valid range [0.0, 1.0]",
            result.confidence_score
        );

        // Validate sanitized content if present
        if let Some(ref sanitized) = result.sanitized_content {
            // Check size constraints
            if self.config.enforce_size_reduction {
                ensure!(
                    sanitized.len() <= original.len(),
                    "Sanitized content ({} bytes) larger than original ({} bytes)",
                    sanitized.len(),
                    original.len()
                );
            }

            // Check empty output
            if !self.config.allow_empty_output {
                ensure!(
                    !sanitized.is_empty(),
                    "Empty output not allowed for threat type {:?}",
                    threat.threat_type
                );
            }

            // Validate threat was actually removed
            if self.config.validate_threat_removed {
                self.validate_threat_neutralized(threat, sanitized)?;
            }

            // Validate output is safe
            Self::validate_content_safety(sanitized)?;
        }

        // Validate action consistency
        match result.action_taken {
            NeutralizeAction::NoAction => {
                ensure!(
                    result.sanitized_content.is_none(),
                    "NoAction should not produce sanitized content"
                );
            }
            NeutralizeAction::Removed => {
                if let Some(ref content) = result.sanitized_content {
                    ensure!(
                        content.is_empty() || content.len() < original.len(),
                        "Removed action should reduce content size"
                    );
                }
            }
            _ => {
                // Other actions should produce output
                ensure!(
                    result.sanitized_content.is_some(),
                    "Action {:?} should produce sanitized content",
                    result.action_taken
                );
            }
        }

        // Validate extracted parameters
        if let Some(ref params) = result.extracted_params {
            ensure!(
                params.len() <= self.config.max_extracted_params,
                "Too many extracted parameters: {} (max: {})",
                params.len(),
                self.config.max_extracted_params
            );

            // Validate each parameter
            for param in params {
                ensure!(
                    param.len() <= 1000,
                    "Extracted parameter too long: {} chars",
                    param.len()
                );
            }
        }

        Ok(())
    }

    /// Validate content doesn't contain dangerous patterns
    fn validate_content_safety(content: &str) -> Result<()> {
        // Check for null bytes
        ensure!(!content.contains('\0'), "Content contains null bytes");

        // Check for excessive control characters
        let control_char_count = content
            .chars()
            .filter(|c| c.is_control() && !c.is_whitespace())
            .count();

        ensure!(
            control_char_count <= content.len() / 100, // Max 1% control chars
            "Content contains too many control characters: {}",
            control_char_count
        );

        Ok(())
    }

    /// Validate JSON path format
    fn is_valid_json_path(path: &str) -> bool {
        // Simple validation - can be enhanced
        !path.is_empty()
            && !path.contains('\0')
            && !path.contains("..")
            && path
                .chars()
                .all(|c| c.is_ascii() || c.is_alphanumeric() || "$.[]._-".contains(c))
    }

    /// Validate threat was neutralized in output
    fn validate_threat_neutralized(&self, threat: &Threat, sanitized: &str) -> Result<()> {
        match &threat.threat_type {
            ThreatType::UnicodeInvisible => {
                // Check no invisible unicode remains
                ensure!(
                    !Self::contains_invisible_unicode(sanitized),
                    "Sanitized content still contains invisible unicode"
                );
            }
            ThreatType::UnicodeBiDi => {
                // Check no BiDi characters remain
                ensure!(
                    !Self::contains_bidi_chars(sanitized),
                    "Sanitized content still contains BiDi override characters"
                );
            }
            ThreatType::SqlInjection => {
                // Basic check - no raw SQL keywords in unsafe context
                ensure!(
                    !Self::contains_unsafe_sql(sanitized),
                    "Sanitized content may still contain SQL injection"
                );
            }
            ThreatType::PathTraversal => {
                // Check no path traversal patterns
                ensure!(
                    !sanitized.contains("..") && !sanitized.contains('~'),
                    "Sanitized content still contains path traversal patterns"
                );
            }
            _ => {
                // For other types, trust the neutralizer
                // Could add more specific checks
            }
        }

        Ok(())
    }

    /// Check for invisible unicode characters
    fn contains_invisible_unicode(text: &str) -> bool {
        text.chars().any(|c| {
            matches!(c,
                '\u{200B}'..='\u{200F}' | // Zero-width spaces
                '\u{202A}'..='\u{202E}' | // BiDi overrides
                '\u{2060}'..='\u{206F}'   // Other invisible
            )
        })
    }

    /// Check for `BiDi` override characters
    fn contains_bidi_chars(text: &str) -> bool {
        text.chars()
            .any(|c| matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'))
    }

    /// Check for potentially unsafe SQL
    fn contains_unsafe_sql(text: &str) -> bool {
        // Very basic check - would need enhancement for production
        let dangerous_patterns = [
            "' OR '",
            "'; DROP",
            "'; DELETE",
            "UNION SELECT",
            "/*",
            "*/",
            "--",
        ];

        let text_upper = text.to_uppercase();
        dangerous_patterns
            .iter()
            .any(|pattern| text_upper.contains(pattern))
    }
}

/// Validation errors for specific failure types
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("Content too large: {size} bytes (max: {max})")]
    ContentTooLarge { size: usize, max: usize },

    #[error("Invalid threat location: {0}")]
    InvalidLocation(String),

    #[error("Processing timeout: {duration_ms}ms (max: {max_ms}ms)")]
    ProcessingTimeout { duration_ms: u64, max_ms: u64 },

    #[error("Invalid output: {0}")]
    InvalidOutput(String),

    #[error("Threat not neutralized: {0}")]
    ThreatNotNeutralized(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::Location;

    #[test]
    fn test_input_validation() {
        let validator = NeutralizationValidator::new(ValidationConfig::default());

        // Valid input
        let threat = Threat {
            threat_type: ThreatType::SqlInjection,
            severity: crate::scanner::Severity::High,
            location: Location::Text {
                offset: 0,
                length: 10,
            },
            description: "SQL injection detected".to_string(),
            remediation: None,
        };

        assert!(validator
            .validate_input(&threat, "SELECT * FROM users")
            .is_ok());

        // Invalid offset
        let bad_threat = Threat {
            location: Location::Text {
                offset: 100,
                length: 10,
            },
            ..threat.clone()
        };

        assert!(validator.validate_input(&bad_threat, "short").is_err());
    }

    #[test]
    fn test_output_validation() {
        let validator = NeutralizationValidator::new(ValidationConfig::default());

        let threat = Threat {
            threat_type: ThreatType::UnicodeInvisible,
            severity: crate::scanner::Severity::High,
            location: Location::Text {
                offset: 5,
                length: 1,
            },
            description: "Invisible unicode detected".to_string(),
            remediation: None,
        };

        let result = NeutralizeResult {
            action_taken: NeutralizeAction::Removed,
            sanitized_content: Some("Hello World".to_string()),
            confidence_score: 0.95,
            processing_time_us: 1000,
            correlation_data: None,
            extracted_params: None,
        };

        assert!(validator
            .validate_output(&threat, "Hello\u{200B}World", &result)
            .is_ok());
    }
}
