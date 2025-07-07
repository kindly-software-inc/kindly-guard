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

//! Integration tests for SIMD scanner functionality

#[cfg(feature = "enhanced")]
mod simd_tests {
    use kindly_guard_server::{
        config::{Config, ScannerConfig},
        enhanced_impl::EnhancedComponentFactory,
        scanner::ThreatType,
        traits::SecurityComponentFactory,
    };

    #[test]
    fn test_simd_scanner_creation_with_enhanced_mode() {
        let mut config = Config::default();
        config.scanner.enhanced_mode = Some(true);
        config.scanner.unicode_detection = true;
        
        let factory = EnhancedComponentFactory;
        let scanner_result = factory.create_security_scanner(&config);
        
        assert!(scanner_result.is_ok(), "Should create SIMD scanner successfully");
    }

    #[test]
    fn test_simd_scanner_detects_unicode_threats() {
        let mut config = Config::default();
        config.scanner.enhanced_mode = Some(true);
        config.scanner.unicode_detection = true;
        
        let factory = EnhancedComponentFactory;
        let scanner = factory.create_security_scanner(&config).unwrap();
        
        // Test with zero-width space
        let text = "Hello\u{200B}World";
        let threats = scanner.scan_text(text);
        
        assert!(!threats.is_empty(), "Should detect zero-width space");
        assert!(
            threats.iter().any(|t| matches!(t.threat_type, ThreatType::UnicodeInvisible)),
            "Should identify as Unicode invisible character"
        );
    }

    #[test]
    fn test_simd_scanner_performance_characteristics() {
        let mut config = Config::default();
        config.scanner.enhanced_mode = Some(true);
        config.scanner.unicode_detection = true;
        config.scanner.injection_detection = true;
        
        let factory = EnhancedComponentFactory;
        let scanner = factory.create_security_scanner(&config).unwrap();
        
        // Create a moderately large text with various threats
        let mut text = String::new();
        for i in 0..1000 {
            text.push_str(&format!("Line {}: Normal text\n", i));
            if i % 100 == 0 {
                text.push_str("Hidden\u{200B}threat\n");
            }
            if i % 200 == 0 {
                text.push_str("SELECT * FROM users WHERE id = '1' OR '1'='1'\n");
            }
        }
        
        let start = std::time::Instant::now();
        let threats = scanner.scan_text(&text);
        let duration = start.elapsed();
        
        println!("SIMD scan of {} bytes took {:?}", text.len(), duration);
        println!("Found {} threats", threats.len());
        
        // Should complete quickly even for large text
        assert!(duration.as_millis() < 100, "SIMD scan should be fast");
        assert!(!threats.is_empty(), "Should detect planted threats");
    }

    #[test]
    fn test_simd_scanner_fallback_when_disabled() {
        let mut config = Config::default();
        config.scanner.enhanced_mode = Some(false); // Disabled
        config.scanner.unicode_detection = true;
        
        let factory = EnhancedComponentFactory;
        let scanner = factory.create_security_scanner(&config).unwrap();
        
        // Should still work but use standard scanner
        let text = "Hello\u{200B}World";
        let threats = scanner.scan_text(text);
        
        assert!(!threats.is_empty(), "Standard scanner should still detect threats");
    }
}

#[cfg(not(feature = "enhanced"))]
mod no_simd_tests {
    use kindly_guard_server::{
        config::Config,
        enhanced_impl::EnhancedComponentFactory,
        scanner::ThreatType,
        traits::SecurityComponentFactory,
    };

    #[test]
    fn test_standard_scanner_when_enhanced_not_available() {
        let mut config = Config::default();
        config.scanner.enhanced_mode = Some(true); // Request enhanced but feature not enabled
        config.scanner.unicode_detection = true;
        
        let factory = EnhancedComponentFactory;
        let scanner = factory.create_security_scanner(&config).unwrap();
        
        // Should fall back to standard scanner
        let text = "Hello\u{200B}World";
        let threats = scanner.scan_text(text);
        
        assert!(!threats.is_empty(), "Should still detect threats with standard scanner");
        assert!(
            threats.iter().any(|t| matches!(t.threat_type, ThreatType::UnicodeInvisible)),
            "Should identify Unicode threats"
        );
    }
}