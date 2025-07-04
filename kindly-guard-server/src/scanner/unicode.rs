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
//! Unicode threat detection
//!
//! Detects various Unicode-based attacks including:
//! - Zero-width and invisible characters
//! - `BiDi` (bidirectional) text spoofing
//! - Homograph attacks using lookalike characters
//! - Dangerous control characters

use super::{Location, ScanResult, Severity, Threat, ThreatType};
use std::sync::atomic::{AtomicU64, Ordering};
use unicode_security::MixedScript;

/// Unicode threat scanner
pub struct UnicodeScanner {
    threats_detected: AtomicU64,
    total_scans: AtomicU64,
    /// Internal marker for enhanced mode
    #[allow(dead_code)]
    #[cfg(feature = "enhanced")]
    enhanced_mode: bool,
}

impl Default for UnicodeScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl UnicodeScanner {
    /// Create a new Unicode scanner
    pub const fn new() -> Self {
        Self {
            threats_detected: AtomicU64::new(0),
            total_scans: AtomicU64::new(0),
            #[cfg(feature = "enhanced")]
            enhanced_mode: false,
        }
    }

    /// Enable enhanced mode (internal use only)
    #[allow(dead_code)]
    #[cfg(feature = "enhanced")]
    pub(crate) fn enable_enhancement(&mut self) {
        self.enhanced_mode = true;
    }

    /// Scan text for Unicode threats
    pub fn scan_text(&self, text: &str) -> ScanResult {
        self.total_scans.fetch_add(1, Ordering::Relaxed);
        let mut threats = Vec::new();

        // Use accelerated pattern matching when available
        #[cfg(feature = "enhanced")]
        if self.enhanced_mode {
            // Enhanced pattern matching is active
            tracing::trace!("Enhanced unicode scanning active for {} chars", text.len());
        }

        // Check each character and its position
        for (pos, ch) in text.char_indices() {
            // Check for invisible/zero-width characters
            if is_invisible_char(ch) {
                threats.push(Threat {
                    threat_type: ThreatType::UnicodeInvisible,
                    severity: Severity::High,
                    location: Location::Text {
                        offset: pos,
                        length: ch.len_utf8(),
                    },
                    description: format!("Invisible character U+{:04X} detected", ch as u32),
                    remediation: Some("Remove or replace invisible characters".to_string()),
                });
            }

            // Check for BiDi control characters
            if is_bidi_control(ch) {
                threats.push(Threat {
                    threat_type: ThreatType::UnicodeBiDi,
                    severity: Severity::Critical,
                    location: Location::Text {
                        offset: pos,
                        length: ch.len_utf8(),
                    },
                    description: format!(
                        "BiDi control character U+{:04X} can reverse text display",
                        ch as u32
                    ),
                    remediation: Some(
                        "Remove BiDi control characters or validate text direction".to_string(),
                    ),
                });
            }

            // Check for dangerous control characters
            if is_dangerous_control(ch) {
                threats.push(Threat {
                    threat_type: ThreatType::UnicodeControl,
                    severity: Severity::Medium,
                    location: Location::Text {
                        offset: pos,
                        length: ch.len_utf8(),
                    },
                    description: format!("Dangerous control character U+{:04X}", ch as u32),
                    remediation: Some("Filter out control characters".to_string()),
                });
            }
        }

        // Check for mixed scripts (potential homograph attack)
        if !text.is_single_script() {
            threats.push(Threat {
                threat_type: ThreatType::UnicodeHomograph,
                severity: Severity::High,
                location: Location::Text {
                    offset: 0,
                    length: text.len(),
                },
                description: "Mixed scripts detected - potential homograph attack".to_string(),
                remediation: Some(
                    "Restrict to single script or validate mixed script usage".to_string(),
                ),
            });
        }

        // Check for confusable characters
        let has_confusables = text.chars().any(|ch| {
            // Check for common confusables like Cyrillic 'о' vs Latin 'o'
            matches!(ch, '\u{0430}'..='\u{044F}' | // Cyrillic lowercase
                        '\u{0410}'..='\u{042F}' | // Cyrillic uppercase
                        '\u{1D00}'..='\u{1D7F}' | // Phonetic extensions
                        '\u{2100}'..='\u{214F}') // Letterlike symbols
        });

        if has_confusables {
            threats.push(Threat {
                threat_type: ThreatType::UnicodeHomograph,
                severity: Severity::Medium,
                location: Location::Text {
                    offset: 0,
                    length: text.len(),
                },
                description: "Text contains potentially confusable characters".to_string(),
                remediation: Some(
                    "Consider restricting to ASCII or validated Unicode subsets".to_string(),
                ),
            });
        }

        // Update statistics
        if !threats.is_empty() {
            self.threats_detected
                .fetch_add(threats.len() as u64, Ordering::Relaxed);
        }

        Ok(threats)
    }

    /// Get number of threats detected
    pub fn threats_detected(&self) -> u64 {
        self.threats_detected.load(Ordering::Relaxed)
    }

    /// Get total number of scans performed
    pub fn total_scans(&self) -> u64 {
        self.total_scans.load(Ordering::Relaxed)
    }
}

/// Check if a character is invisible or zero-width
const fn is_invisible_char(ch: char) -> bool {
    matches!(
        ch,
        '\u{200B}' | // Zero-width space
        '\u{200C}' | // Zero-width non-joiner
        '\u{200D}' | // Zero-width joiner
        '\u{FEFF}' | // Zero-width no-break space
        '\u{2060}' | // Word joiner
        '\u{180E}' | // Mongolian vowel separator
        '\u{00AD}' | // Soft hyphen
        '\u{034F}' | // Combining grapheme joiner
        '\u{061C}' | // Arabic letter mark
        '\u{115F}' | // Hangul choseong filler
        '\u{1160}' | // Hangul jungseong filler
        '\u{17B4}' | // Khmer vowel inherent aq
        '\u{17B5}' | // Khmer vowel inherent aa
        '\u{3164}' // Hangul filler
    )
}

/// Check if a character is a `BiDi` control character
const fn is_bidi_control(ch: char) -> bool {
    matches!(
        ch,
        '\u{202A}' | // Left-to-right embedding
        '\u{202B}' | // Right-to-left embedding
        '\u{202C}' | // Pop directional formatting
        '\u{202D}' | // Left-to-right override
        '\u{202E}' | // Right-to-left override
        '\u{2066}' | // Left-to-right isolate
        '\u{2067}' | // Right-to-left isolate
        '\u{2068}' | // First strong isolate
        '\u{2069}' // Pop directional isolate
    )
}

/// Check if a character is a dangerous control character
const fn is_dangerous_control(ch: char) -> bool {
    match ch {
        '\0' => true,                    // Null byte
        '\u{0001}'..='\u{001F}' => true, // C0 control codes (except some)
        '\u{007F}' => true,              // Delete
        '\u{0080}'..='\u{009F}' => true, // C1 control codes
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invisible_char_detection() {
        let scanner = UnicodeScanner::new();

        // Test zero-width space
        let threats = scanner.scan_text("Hello\u{200B}World").unwrap();
        assert_eq!(threats.len(), 1);
        assert_eq!(threats[0].threat_type, ThreatType::UnicodeInvisible);

        // Test clean text
        let threats = scanner.scan_text("Hello World").unwrap();
        assert_eq!(threats.len(), 0);
    }

    #[test]
    fn test_bidi_detection() {
        let scanner = UnicodeScanner::new();

        // Test RTL override
        let threats = scanner.scan_text("Hello\u{202E}World").unwrap();
        assert!(threats
            .iter()
            .any(|t| t.threat_type == ThreatType::UnicodeBiDi));
        assert!(threats.iter().any(|t| t.severity == Severity::Critical));
    }

    #[test]
    fn test_mixed_script_detection() {
        let scanner = UnicodeScanner::new();

        // Test Latin + Cyrillic (common homograph attack)
        let threats = scanner.scan_text("Hellо").unwrap(); // 'о' is Cyrillic
        assert!(threats
            .iter()
            .any(|t| t.threat_type == ThreatType::UnicodeHomograph));
    }

    #[test]
    fn test_null_byte_detection() {
        let scanner = UnicodeScanner::new();

        let threats = scanner.scan_text("Hello\0World").unwrap();
        assert!(threats
            .iter()
            .any(|t| t.threat_type == ThreatType::UnicodeControl));
    }
}
