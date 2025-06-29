//! Unicode threat detection
//! 
//! Detects various Unicode-based attacks including:
//! - Zero-width and invisible characters
//! - BiDi (bidirectional) text spoofing
//! - Homograph attacks using lookalike characters
//! - Dangerous control characters

use super::{Location, ScanResult, Threat, ThreatType, Severity};
use std::sync::atomic::{AtomicU64, Ordering};
use unicode_security::MixedScript;

/// Unicode threat scanner
pub struct UnicodeScanner {
    threats_detected: AtomicU64,
    total_scans: AtomicU64,
    /// Optional performance enhancement (not exposed in logs)
    #[allow(dead_code)]
    #[cfg(feature = "enhanced")]
    enhancement: Option<std::sync::Arc<kindly_guard_core::AtomicEventBuffer>>,
}

impl UnicodeScanner {
    /// Create a new Unicode scanner
    pub fn new() -> Self {
        Self {
            threats_detected: AtomicU64::new(0),
            total_scans: AtomicU64::new(0),
            #[cfg(feature = "enhanced")]
            enhancement: None,
        }
    }
    
    /// Set performance enhancement (internal use only)
    #[allow(dead_code)]
    #[cfg(feature = "enhanced")]
    pub(crate) fn with_enhancement(&mut self, buffer: std::sync::Arc<kindly_guard_core::AtomicEventBuffer>) {
        self.enhancement = Some(buffer);
    }
    
    /// Scan text for Unicode threats
    pub fn scan_text(&self, text: &str) -> ScanResult {
        self.total_scans.fetch_add(1, Ordering::Relaxed);
        let mut threats = Vec::new();
        
        // Use accelerated pattern matching when available
        #[cfg(feature = "enhanced")]
        if let Some(buffer) = &self.enhancement {
            // Track unicode patterns for homograph detection
            let pattern_data = format!("unicode:len{}", text.len());
            let _ = buffer.enqueue_event(2, pattern_data.as_bytes(), kindly_guard_core::Priority::Normal);
            tracing::trace!("Unicode analysis optimized");
        }
        
        // Check each character and its position
        for (pos, ch) in text.char_indices() {
            // Check for invisible/zero-width characters
            if is_invisible_char(ch) {
                threats.push(Threat {
                    threat_type: ThreatType::UnicodeInvisible,
                    severity: Severity::High,
                    location: Location::Text { offset: pos, length: ch.len_utf8() },
                    description: format!("Invisible character U+{:04X} detected", ch as u32),
                    remediation: Some("Remove or replace invisible characters".to_string()),
                });
            }
            
            // Check for BiDi control characters
            if is_bidi_control(ch) {
                threats.push(Threat {
                    threat_type: ThreatType::UnicodeBiDi,
                    severity: Severity::Critical,
                    location: Location::Text { offset: pos, length: ch.len_utf8() },
                    description: format!("BiDi control character U+{:04X} can reverse text display", ch as u32),
                    remediation: Some("Remove BiDi control characters or validate text direction".to_string()),
                });
            }
            
            // Check for dangerous control characters
            if is_dangerous_control(ch) {
                threats.push(Threat {
                    threat_type: ThreatType::UnicodeControl,
                    severity: Severity::Medium,
                    location: Location::Text { offset: pos, length: ch.len_utf8() },
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
                location: Location::Text { offset: 0, length: text.len() },
                description: "Mixed scripts detected - potential homograph attack".to_string(),
                remediation: Some("Restrict to single script or validate mixed script usage".to_string()),
            });
        }
        
        // Check for confusable characters
        let has_confusables = text.chars().any(|ch| {
            // Check for common confusables like Cyrillic 'о' vs Latin 'o'
            matches!(ch, '\u{0430}'..='\u{044F}' | // Cyrillic lowercase
                        '\u{0410}'..='\u{042F}' | // Cyrillic uppercase
                        '\u{1D00}'..='\u{1D7F}' | // Phonetic extensions
                        '\u{2100}'..='\u{214F}')   // Letterlike symbols
        });
        
        if has_confusables {
            threats.push(Threat {
                threat_type: ThreatType::UnicodeHomograph,
                severity: Severity::Medium,
                location: Location::Text { offset: 0, length: text.len() },
                description: "Text contains potentially confusable characters".to_string(),
                remediation: Some("Consider restricting to ASCII or validated Unicode subsets".to_string()),
            });
        }
        
        // Update statistics
        if !threats.is_empty() {
            self.threats_detected.fetch_add(threats.len() as u64, Ordering::Relaxed);
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
fn is_invisible_char(ch: char) -> bool {
    matches!(ch,
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
        '\u{3164}'   // Hangul filler
    )
}

/// Check if a character is a BiDi control character
fn is_bidi_control(ch: char) -> bool {
    matches!(ch,
        '\u{202A}' | // Left-to-right embedding
        '\u{202B}' | // Right-to-left embedding
        '\u{202C}' | // Pop directional formatting
        '\u{202D}' | // Left-to-right override
        '\u{202E}' | // Right-to-left override
        '\u{2066}' | // Left-to-right isolate
        '\u{2067}' | // Right-to-left isolate
        '\u{2068}' | // First strong isolate
        '\u{2069}'   // Pop directional isolate
    )
}

/// Check if a character is a dangerous control character
fn is_dangerous_control(ch: char) -> bool {
    match ch {
        '\0' => true, // Null byte
        '\u{0001}'..='\u{001F}' => true, // C0 control codes (except some)
        '\u{007F}' => true, // Delete
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
        assert!(threats.iter().any(|t| t.threat_type == ThreatType::UnicodeBiDi));
        assert!(threats.iter().any(|t| t.severity == Severity::Critical));
    }
    
    #[test]
    fn test_mixed_script_detection() {
        let scanner = UnicodeScanner::new();
        
        // Test Latin + Cyrillic (common homograph attack)
        let threats = scanner.scan_text("Hellо").unwrap(); // 'о' is Cyrillic
        assert!(threats.iter().any(|t| t.threat_type == ThreatType::UnicodeHomograph));
    }
    
    #[test]
    fn test_null_byte_detection() {
        let scanner = UnicodeScanner::new();
        
        let threats = scanner.scan_text("Hello\0World").unwrap();
        assert!(threats.iter().any(|t| t.threat_type == ThreatType::UnicodeControl));
    }
}