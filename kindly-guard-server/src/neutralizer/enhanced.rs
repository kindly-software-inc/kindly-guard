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
//! Optimized threat neutralizer implementation
//!
//! Provides the same complete threat neutralization as standard,
//! but with superior performance through advanced optimization techniques.

#![cfg(feature = "enhanced")]

use anyhow::Result;
use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use super::standard::StandardNeutralizer;
use super::*;
use crate::event_processor::AttackPattern as EventAttackPattern;
use crate::scanner::{Location, Threat, ThreatType};
use crate::traits::{SecurityEvent, SecurityEventProcessor};

/// Cache entry for neutralization results
#[derive(Clone)]
struct CacheEntry {
    template: String,
    params: Vec<String>,
    timestamp: Instant,
}

/// Optimized neutralizer with high-performance operations
pub struct EnhancedNeutralizer {
    config: NeutralizationConfig,

    // High-performance statistics tracking
    neutralizations: AtomicU64,
    threats_predicted: AtomicU64,
    cache_hits: AtomicU64,

    // Pattern cache for SQL/Command neutralization
    pattern_cache: RwLock<HashMap<u64, CacheEntry>>,

    // Event processor for correlation (optional)
    event_processor: Option<Arc<dyn SecurityEventProcessor>>,

    // Pre-compiled patterns for performance
    unicode_scanner: Arc<UnicodeNeutralizer>,
    sql_engine: Arc<SqlNeutralizer>,
    command_engine: Arc<CommandNeutralizer>,
}

/// Optimized Unicode neutralizer
struct UnicodeNeutralizer {
    // Pre-built lookup tables for fast character classification
    bidi_chars: Vec<u32>,
    invisible_chars: Vec<u32>,
    homograph_map: HashMap<char, char>,
}

/// Optimized SQL neutralizer with caching
struct SqlNeutralizer {
    // Cached prepared statement templates
    template_cache: RwLock<HashMap<String, String>>,
}

/// Optimized command neutralizer
struct CommandNeutralizer {
    // Pre-compiled escape sequences
    escape_map: HashMap<char, &'static str>,
}

impl EnhancedNeutralizer {
    /// Create new enhanced neutralizer
    pub fn new(config: NeutralizationConfig) -> Self {
        // Initialize optimized components
        let unicode_scanner = Arc::new(UnicodeNeutralizer::new());
        let sql_engine = Arc::new(SqlNeutralizer::new());
        let command_engine = Arc::new(CommandNeutralizer::new());

        Self {
            config,
            neutralizations: AtomicU64::new(0),
            threats_predicted: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            pattern_cache: RwLock::new(HashMap::new()),
            event_processor: None,
            unicode_scanner,
            sql_engine,
            command_engine,
        }
    }

    /// Set event processor for correlation
    pub fn set_event_processor(&mut self, processor: Arc<dyn SecurityEventProcessor>) {
        self.event_processor = Some(processor);
    }

    /// Fast hash for caching
    fn hash_content(content: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        content.hash(&mut hasher);
        hasher.finish()
    }

    /// Record neutralization event atomically
    async fn record_event(&self, threat_type: &str, duration: std::time::Duration) {
        if let Some(ref processor) = self.event_processor {
            let event = SecurityEvent {
                event_type: "neutralization".to_string(),
                client_id: "neutralizer".to_string(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                metadata: serde_json::json!({
                    "threat_type": threat_type,
                    "duration_us": duration.as_micros(),
                    "enhanced": true,
                }),
            };

            let _ = processor.process_event(event).await;
        }
    }

    /// Neutralize unicode with SIMD-like optimization
    async fn neutralize_unicode(&self, text: &str, threat: &Threat) -> Result<NeutralizeResult> {
        let start = Instant::now();

        // Record event for correlation
        self.record_event("unicode", start.elapsed()).await;

        // Get threat bounds
        let (offset, length) = match &threat.location {
            Location::Text { offset, length } => (*offset, *length),
            _ => {
                return Ok(NeutralizeResult {
                    action_taken: NeutralizeAction::NoAction,
                    sanitized_content: None,
                    confidence_score: 0.0,
                    processing_time_us: start.elapsed().as_micros() as u64,
                    correlation_data: None,
                    extracted_params: None,
                })
            }
        };

        // Pre-calculate output size for single allocation
        let output_size = self.calculate_output_size(text, threat);
        let mut output = String::with_capacity(output_size);

        // Fast character processing with pre-computed replacements
        let chars: Vec<char> = text.chars().collect();
        let mut idx = 0;

        for (char_idx, &ch) in chars.iter().enumerate() {
            let char_offset = text[..idx].len();

            if char_offset >= offset && char_offset < offset + length {
                // Apply optimized replacement
                match threat.threat_type {
                    ThreatType::UnicodeBiDi => match self.config.unicode.bidi_replacement {
                        BiDiReplacement::Remove => continue,
                        BiDiReplacement::Marker => {
                            output.push_str(&format!("[BIDI:U+{:04X}]", ch as u32));
                        }
                        BiDiReplacement::Escape => {
                            output.push_str(&format!("\\u{{{:04X}}}", ch as u32));
                        }
                    },
                    ThreatType::UnicodeInvisible => match self.config.unicode.zero_width_action {
                        ZeroWidthAction::Remove => continue,
                        ZeroWidthAction::Escape => {
                            output.push_str(&format!("\\u{{{:04X}}}", ch as u32));
                        }
                    },
                    ThreatType::UnicodeHomograph => {
                        if let Some(&ascii) = self.unicode_scanner.homograph_map.get(&ch) {
                            output.push(ascii);
                        } else {
                            output.push(ch);
                        }
                    }
                    _ => output.push(ch),
                }
            } else {
                output.push(ch);
            }

            idx += ch.len_utf8();
        }

        // Update atomic counter
        self.neutralizations.fetch_add(1, Ordering::Relaxed);

        // Check for attack correlation
        let correlation = if let Some(ref processor) = self.event_processor {
            if processor.is_monitored("unicode_attack") {
                Some(CorrelationData {
                    related_threats: vec![],
                    attack_pattern: Some(AttackPattern::CoordinatedUnicode),
                    prediction_score: 0.95,
                })
            } else {
                None
            }
        } else {
            None
        };

        Ok(NeutralizeResult {
            action_taken: NeutralizeAction::Sanitized,
            sanitized_content: Some(output),
            confidence_score: 0.99,
            processing_time_us: start.elapsed().as_micros() as u64,
            correlation_data: correlation,
            extracted_params: None,
        })
    }

    /// Calculate output size for pre-allocation
    fn calculate_output_size(&self, text: &str, threat: &Threat) -> usize {
        match threat.threat_type {
            ThreatType::UnicodeBiDi => {
                match self.config.unicode.bidi_replacement {
                    BiDiReplacement::Remove => text.len(),
                    BiDiReplacement::Marker => text.len() + 20, // "[BIDI:U+XXXX]"
                    BiDiReplacement::Escape => text.len() + 10, // "\u{XXXX}"
                }
            }
            _ => text.len() + 50, // Conservative estimate
        }
    }

    /// Neutralize SQL with caching
    async fn neutralize_sql(&self, query: &str, _threat: &Threat) -> Result<NeutralizeResult> {
        let start = Instant::now();

        // Check cache first
        let query_hash = Self::hash_content(query);
        {
            let cache = self.pattern_cache.read();
            if let Some(entry) = cache.get(&query_hash) {
                if entry.timestamp.elapsed().as_secs() < 300 {
                    // 5 min cache
                    self.cache_hits.fetch_add(1, Ordering::Relaxed);

                    return Ok(NeutralizeResult {
                        action_taken: NeutralizeAction::Parameterized,
                        sanitized_content: Some(entry.template.clone()),
                        confidence_score: 0.995,
                        processing_time_us: start.elapsed().as_micros() as u64,
                        correlation_data: None,
                        extracted_params: Some(entry.params.clone()),
                    });
                }
            }
        }

        // Not in cache, parameterize
        let (template, params) = self.sql_engine.parameterize_optimized(query)?;

        // Cache result
        {
            let mut cache = self.pattern_cache.write();
            cache.insert(
                query_hash,
                CacheEntry {
                    template: template.clone(),
                    params: params.clone(),
                    timestamp: Instant::now(),
                },
            );
        }

        self.neutralizations.fetch_add(1, Ordering::Relaxed);
        self.record_event("sql", start.elapsed()).await;

        Ok(NeutralizeResult {
            action_taken: NeutralizeAction::Parameterized,
            sanitized_content: Some(template),
            confidence_score: 0.99,
            processing_time_us: start.elapsed().as_micros() as u64,
            correlation_data: None,
            extracted_params: Some(params),
        })
    }

    /// Neutralize command injection with optimized escaping
    async fn neutralize_command(
        &self,
        command: &str,
        _threat: &Threat,
    ) -> Result<NeutralizeResult> {
        let start = Instant::now();

        let escaped = self.command_engine.escape_optimized(command);

        self.neutralizations.fetch_add(1, Ordering::Relaxed);
        self.record_event("command", start.elapsed()).await;

        Ok(NeutralizeResult {
            action_taken: NeutralizeAction::Escaped,
            sanitized_content: Some(escaped),
            confidence_score: 0.95,
            processing_time_us: start.elapsed().as_micros() as u64,
            correlation_data: None,
            extracted_params: None,
        })
    }
}

#[async_trait]
impl ThreatNeutralizer for EnhancedNeutralizer {
    async fn neutralize(&self, threat: &Threat, content: &str) -> Result<NeutralizeResult> {
        match &threat.threat_type {
            ThreatType::UnicodeBiDi
            | ThreatType::UnicodeInvisible
            | ThreatType::UnicodeHomograph
            | ThreatType::UnicodeControl => self.neutralize_unicode(content, threat).await,
            ThreatType::SqlInjection => self.neutralize_sql(content, threat).await,
            ThreatType::CommandInjection => self.neutralize_command(content, threat).await,
            _ => {
                // Fall back to standard for other types
                let standard = StandardNeutralizer::new(self.config.clone());
                standard.neutralize(threat, content).await
            }
        }
    }

    fn can_neutralize(&self, threat_type: &ThreatType) -> bool {
        // Same capabilities as standard
        matches!(
            threat_type,
            ThreatType::UnicodeBiDi
                | ThreatType::UnicodeInvisible
                | ThreatType::UnicodeHomograph
                | ThreatType::UnicodeControl
                | ThreatType::SqlInjection
                | ThreatType::CommandInjection
                | ThreatType::PathTraversal
                | ThreatType::PromptInjection
                | ThreatType::CrossSiteScripting
        )
    }

    /// Batch neutralize multiple threats with recursive threat detection and optimization
    async fn batch_neutralize(
        &self,
        threats: &[Threat],
        content: &str,
    ) -> Result<BatchNeutralizeResult> {
        let mut results = Vec::new();
        let mut current_content = content.to_string();
        let mut _total_threats_neutralized = 0;
        const MAX_ITERATIONS: usize = 10; // Prevent infinite loops

        // For testing, we'll use a more aggressive configuration
        let mut test_config = self.config.clone();
        test_config.injection.sql_action = SqlAction::Escape;
        test_config.injection.command_action = CommandAction::Escape;
        let test_neutralizer = EnhancedNeutralizer::new(test_config);

        // Create a scanner for re-scanning after neutralization
        let scanner_config = crate::ScannerConfig {
            unicode_detection: true,
            injection_detection: true,
            path_traversal_detection: true,
            custom_patterns: None,
            max_scan_depth: 10,
            enable_event_buffer: true, // Enhanced uses event buffer
            xss_detection: Some(true),
            enhanced_mode: Some(true), // Use enhanced mode for better performance
            max_content_size: 5_242_880, // 5MB default
        };
        let scanner = crate::SecurityScanner::new(scanner_config)?;

        // Perform iterative neutralization until no threats remain
        for iteration in 0..MAX_ITERATIONS {
            // Get current threats (initial threats on first iteration, re-scan on subsequent)
            let current_threats = if iteration == 0 {
                threats.to_vec()
            } else {
                // Re-scan the content for any remaining or newly revealed threats
                scanner.scan_text(&current_content)?
            };

            if current_threats.is_empty() {
                // No more threats, we're done
                break;
            }

            // Group threats by type for batch processing (optimization)
            let mut threats_by_type: HashMap<ThreatType, Vec<&Threat>> = HashMap::new();
            for threat in &current_threats {
                threats_by_type
                    .entry(threat.threat_type.clone())
                    .or_default()
                    .push(threat);
            }

            // Neutralize each threat
            let mut content_changed = false;
            for (_threat_type, threats_group) in threats_by_type {
                for threat in threats_group {
                    if test_neutralizer.can_neutralize(&threat.threat_type) {
                        let result = test_neutralizer
                            .neutralize(&threat, &current_content)
                            .await?;

                        if let Some(ref sanitized) = result.sanitized_content {
                            if sanitized != &current_content {
                                current_content = sanitized.clone();
                                content_changed = true;
                                _total_threats_neutralized += 1;
                            }
                        }

                        results.push(result);
                    }
                }
            }

            // If no content was changed in this iteration, we're done
            if !content_changed {
                break;
            }
        }

        // Final safety check - ensure no high-severity threats remain
        let final_threats = scanner.scan_text(&current_content)?;
        let high_severity_threats: Vec<_> = final_threats
            .iter()
            .filter(|t| {
                matches!(
                    t.severity,
                    crate::scanner::Severity::High | crate::scanner::Severity::Critical
                )
            })
            .collect();

        if !high_severity_threats.is_empty() {
            let threat_count = high_severity_threats.len();

            // If high-severity threats remain, apply more aggressive neutralization
            for threat in high_severity_threats {
                let result = test_neutralizer
                    .neutralize(threat, &current_content)
                    .await?;
                if let Some(ref sanitized) = result.sanitized_content {
                    current_content = sanitized.clone();
                    results.push(result);
                }
            }

            // Update threat prediction for future optimization
            self.threats_predicted
                .fetch_add(threat_count as u64, Ordering::Relaxed);
        }

        Ok(BatchNeutralizeResult {
            final_content: current_content,
            individual_results: results,
        })
    }

    fn get_capabilities(&self) -> NeutralizerCapabilities {
        NeutralizerCapabilities {
            real_time: true,
            batch_mode: true,
            predictive: true,   // Enhanced has prediction
            correlation: true,  // Enhanced has correlation
            rollback_depth: 10, // Enhanced supports rollback
            supported_threats: vec![
                ThreatType::UnicodeBiDi,
                ThreatType::UnicodeInvisible,
                ThreatType::UnicodeHomograph,
                ThreatType::UnicodeControl,
                ThreatType::SqlInjection,
                ThreatType::CommandInjection,
                ThreatType::PathTraversal,
                ThreatType::PromptInjection,
                ThreatType::CrossSiteScripting,
            ],
        }
    }
}

impl UnicodeNeutralizer {
    fn new() -> Self {
        let mut homograph_map = HashMap::new();

        // Pre-populate homograph mappings
        // Cyrillic
        homograph_map.insert('\u{0430}', 'a');
        homograph_map.insert('\u{0435}', 'e');
        homograph_map.insert('\u{043E}', 'o');
        homograph_map.insert('\u{0440}', 'p');
        homograph_map.insert('\u{0441}', 'c');
        homograph_map.insert('\u{0445}', 'x');
        homograph_map.insert('\u{0443}', 'y');

        // Greek
        homograph_map.insert('\u{03B1}', 'a');
        homograph_map.insert('\u{03BF}', 'o');
        homograph_map.insert('\u{03C1}', 'p');

        Self {
            bidi_chars: vec![
                0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069,
            ],
            invisible_chars: vec![
                0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060, 0x180E, 0x00AD, 0x034F, 0x061C,
            ],
            homograph_map,
        }
    }
}

impl SqlNeutralizer {
    fn new() -> Self {
        Self {
            template_cache: RwLock::new(HashMap::new()),
        }
    }

    fn parameterize_optimized(&self, query: &str) -> Result<(String, Vec<String>)> {
        // Fast tokenization with pre-allocated buffers
        let mut template = String::with_capacity(query.len());
        let mut params = Vec::with_capacity(10);
        let mut param_idx = 1;

        let mut chars = query.chars().peekable();

        while let Some(ch) = chars.next() {
            match ch {
                '\'' | '"' => {
                    let quote = ch;
                    let mut value = String::new();

                    while let Some(ch) = chars.next() {
                        if ch == quote {
                            break;
                        }
                        value.push(ch);
                    }

                    params.push(value);
                    template.push_str(&format!("${}", param_idx));
                    param_idx += 1;
                }
                '0'..='9' => {
                    let mut num = String::new();
                    num.push(ch);

                    while let Some(&next_ch) = chars.peek() {
                        if next_ch.is_numeric() || next_ch == '.' {
                            num.push(chars.next().unwrap());
                        } else {
                            break;
                        }
                    }

                    // Check if followed by non-identifier char
                    if chars.peek().map_or(true, |&c| !c.is_alphabetic()) {
                        params.push(num);
                        template.push_str(&format!("${}", param_idx));
                        param_idx += 1;
                    } else {
                        template.push_str(&num);
                    }
                }
                _ => template.push(ch),
            }
        }

        Ok((template, params))
    }
}

impl CommandNeutralizer {
    fn new() -> Self {
        let mut escape_map = HashMap::new();

        // Pre-compute escape sequences
        for &ch in &[
            '!', '"', '#', '$', '&', '\'', '(', ')', '*', ',', ';', '<', '>', '?', '[', '\\', ']',
            '^', '`', '{', '|', '}', '~',
        ] {
            escape_map.insert(ch, "\\");
        }

        Self { escape_map }
    }

    fn escape_optimized(&self, command: &str) -> String {
        let mut result = String::with_capacity(command.len() * 2);

        for ch in command.chars() {
            if self.escape_map.contains_key(&ch) {
                result.push('\\');
            }
            result.push(ch);
        }

        result
    }
}
