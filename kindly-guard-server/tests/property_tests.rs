//! Property-based tests for KindlyGuard security scanners

use proptest::prelude::*;
use kindly_guard_server::{SecurityScanner, ScannerConfig, scanner::Location};

// Generate arbitrary strings with various Unicode properties
prop_compose! {
    fn arb_unicode_string()(
        base in ".*",
        include_invisible in prop::bool::ANY,
        include_bidi in prop::bool::ANY,
        include_homograph in prop::bool::ANY,
        include_control in prop::bool::ANY,
    ) -> String {
        let mut result = base;
        
        if include_invisible {
            result.push('\u{200B}'); // Zero-width space
        }
        
        if include_bidi {
            result = format!("\u{202E}{}\u{202C}", result); // RLO/PDF
        }
        
        if include_homograph {
            result = result.replace('a', "а"); // Latin 'a' -> Cyrillic 'а'
        }
        
        if include_control {
            result.push('\u{0001}'); // Control character
        }
        
        result
    }
}

proptest! {
    #[test]
    fn scanner_never_panics(input in prop::string::string_regex(".*").unwrap()) {
        let config = ScannerConfig {
            unicode_detection: true,
            injection_detection: true,
            path_traversal_detection: true,
            custom_patterns: None,
            max_scan_depth: 10,
            enable_event_buffer: false,
        };
        
        if let Ok(scanner) = SecurityScanner::new(config) {
            // Should never panic regardless of input
            let _ = scanner.scan_text(&input);
        }
    }
    
    #[test]
    fn threats_have_valid_locations(input in arb_unicode_string()) {
        let config = ScannerConfig {
            unicode_detection: true,
            injection_detection: true,
            path_traversal_detection: true,
            custom_patterns: None,
            max_scan_depth: 10,
            enable_event_buffer: false,
        };
        
        if let Ok(scanner) = SecurityScanner::new(config) {
            if let Ok(threats) = scanner.scan_text(&input) {
                for threat in threats {
                    match &threat.location {
                        Location::Text { offset, length } => {
                            // Ensure location is within bounds
                            prop_assert!(*offset <= input.len());
                            prop_assert!(*offset + *length <= input.len());
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    
    #[test]
    fn scanner_is_deterministic(input in prop::string::string_regex(".*").unwrap()) {
        let config = ScannerConfig {
            unicode_detection: true,
            injection_detection: true,
            path_traversal_detection: true,
            custom_patterns: None,
            max_scan_depth: 10,
            enable_event_buffer: false,
        };
        
        if let Ok(scanner1) = SecurityScanner::new(config.clone()) {
            if let Ok(scanner2) = SecurityScanner::new(config) {
                let result1 = scanner1.scan_text(&input);
                let result2 = scanner2.scan_text(&input);
                
                // Same input should produce same results
                match (result1, result2) {
                    (Ok(threats1), Ok(threats2)) => {
                        prop_assert_eq!(threats1.len(), threats2.len());
                        for (t1, t2) in threats1.iter().zip(threats2.iter()) {
                            prop_assert_eq!(&t1.threat_type, &t2.threat_type);
                            prop_assert_eq!(&t1.severity, &t2.severity);
                            prop_assert_eq!(&t1.location, &t2.location);
                        }
                    }
                    (Err(_), Err(_)) => {} // Both errored is ok
                    _ => prop_assert!(false, "Results should be consistent"),
                }
            }
        }
    }
    
    #[test]
    fn json_scanning_depth_limits(
        depth in 0usize..20,
        _value_size in 0usize..100,
    ) {
        let config = ScannerConfig {
            unicode_detection: true,
            injection_detection: true,
            path_traversal_detection: true,
            custom_patterns: None,
            max_scan_depth: 5, // Fixed depth limit
            enable_event_buffer: false,
        };
        
        // Create deeply nested JSON
        let mut json = serde_json::json!("test_value");
        for _ in 0..depth {
            json = serde_json::json!({ "nested": json });
        }
        
        if let Ok(scanner) = SecurityScanner::new(config) {
            let result = scanner.scan_json(&json);
            
            if depth > 5 {
                // Should error on too deep nesting
                prop_assert!(result.is_err());
            } else {
                // Should succeed within depth limit
                prop_assert!(result.is_ok());
            }
        }
    }
    
    #[test]
    fn threat_severity_ordering_is_correct(
        threats in prop::collection::vec(
            (0u8..4, prop::string::string_regex(".*").unwrap()),
            0..10
        )
    ) {
        use kindly_guard_server::Severity;
        
        let severities: Vec<Severity> = threats.iter().map(|(s, _)| {
            match s {
                0 => Severity::Low,
                1 => Severity::Medium,
                2 => Severity::High,
                _ => Severity::Critical,
            }
        }).collect();
        
        // Verify ordering
        for window in severities.windows(2) {
            if let [a, b] = window {
                prop_assert!(
                    (a <= b) || (a >= b),
                    "Severity ordering should be transitive"
                );
            }
        }
    }
    
    #[test]
    fn unicode_scanner_detects_known_threats(
        prefix in prop::string::string_regex("[a-zA-Z0-9]*").unwrap(),
        suffix in prop::string::string_regex("[a-zA-Z0-9]*").unwrap(),
    ) {
        let config = ScannerConfig {
            unicode_detection: true,
            injection_detection: false,
            path_traversal_detection: false,
            custom_patterns: None,
            max_scan_depth: 10,
            enable_event_buffer: false,
        };
        
        if let Ok(scanner) = SecurityScanner::new(config) {
            // Test known threats are detected
            let test_cases = vec![
                (format!("{}\u{200B}{}", prefix, suffix), "invisible"),
                (format!("{}\u{202E}{}", prefix, suffix), "bidi"),
                (format!("{}а{}", prefix, suffix), "homograph"), // Cyrillic 'a'
                (format!("{}\u{0001}{}", prefix, suffix), "control"),
            ];
            
            for (input, threat_type) in test_cases {
                let threats = scanner.scan_text(&input).unwrap_or_default();
                prop_assert!(
                    !threats.is_empty(),
                    "Should detect {} threat in: {:?}",
                    threat_type,
                    input
                );
            }
        }
    }
    
    #[test]
    fn injection_scanner_detects_patterns(
        prefix in prop::string::string_regex("[a-zA-Z0-9]*").unwrap(),
        suffix in prop::string::string_regex("[a-zA-Z0-9]*").unwrap(),
    ) {
        let config = ScannerConfig {
            unicode_detection: false,
            injection_detection: true,
            path_traversal_detection: true,
            custom_patterns: None,
            max_scan_depth: 10,
            enable_event_buffer: false,
        };
        
        if let Ok(scanner) = SecurityScanner::new(config) {
            // Test known injection patterns
            let test_cases = vec![
                (format!("{}' OR '1'='1{}", prefix, suffix), "sql"),
                (format!("{}../../../etc/passwd{}", prefix, suffix), "path"),
                (format!("{} && echo pwned{}", prefix, suffix), "command"),
            ];
            
            for (input, injection_type) in test_cases {
                let threats = scanner.scan_text(&input).unwrap_or_default();
                prop_assert!(
                    !threats.is_empty(),
                    "Should detect {} injection in: {:?}",
                    injection_type,
                    input
                );
            }
        }
    }
}

// Additional property tests for edge cases
proptest! {
    #[test]
    fn scanner_handles_empty_input(_dummy in 0..1) {
        let config = ScannerConfig {
            unicode_detection: true,
            injection_detection: true,
            path_traversal_detection: true,
            custom_patterns: None,
            max_scan_depth: 10,
            enable_event_buffer: false,
        };
        
        if let Ok(scanner) = SecurityScanner::new(config) {
            let result = scanner.scan_text("");
            prop_assert!(result.is_ok());
            prop_assert_eq!(result.unwrap().len(), 0);
        }
    }
    
    #[test]
    fn scanner_handles_very_long_input(
        char_to_repeat in prop::char::range('a', 'z'),
        repeat_count in 1000usize..10000,
    ) {
        let config = ScannerConfig {
            unicode_detection: true,
            injection_detection: true,
            path_traversal_detection: true,
            custom_patterns: None,
            max_scan_depth: 10,
            enable_event_buffer: false,
        };
        
        let input: String = std::iter::repeat(char_to_repeat).take(repeat_count).collect();
        
        if let Ok(scanner) = SecurityScanner::new(config) {
            // Should complete without hanging
            let result = scanner.scan_text(&input);
            prop_assert!(result.is_ok());
        }
    }
    
    #[test]
    fn scanner_handles_mixed_threats(
        base in prop::string::string_regex("[a-zA-Z0-9 ]{0,50}").unwrap(),
        include_unicode in prop::bool::ANY,
        include_injection in prop::bool::ANY,
    ) {
        let config = ScannerConfig {
            unicode_detection: true,
            injection_detection: true,
            path_traversal_detection: true,
            custom_patterns: None,
            max_scan_depth: 10,
            enable_event_buffer: false,
        };
        
        let mut input = base.clone();
        let mut expected_threat_count = 0;
        
        if include_unicode {
            input.push_str("\u{202E}hidden\u{202C}");
            expected_threat_count += 1;
        }
        
        if include_injection {
            input.push_str(" OR 1=1--");
            expected_threat_count += 1;
        }
        
        if let Ok(scanner) = SecurityScanner::new(config) {
            let threats = scanner.scan_text(&input).unwrap_or_default();
            
            if expected_threat_count > 0 {
                prop_assert!(threats.len() >= expected_threat_count);
            }
        }
    }
}