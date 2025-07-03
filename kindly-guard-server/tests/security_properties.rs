//! Security property-based tests for KindlyGuard
//! 
//! These tests verify that critical security properties hold across all implementations
//! using property-based testing with proptest. The tests ensure:
//! 
//! 1. No injection bypasses are possible
//! 2. All malicious inputs are neutralized
//! 3. Neutralized content is always safe
//! 4. Security properties hold for random/fuzzy inputs
//! 5. Security guarantees are maintained for all implementations
//! 6. Adversarial test cases don't break security

use anyhow::Result;
use kindly_guard_server::{
    config::Config,
    neutralizer::{NeutralizeAction, ThreatNeutralizer},
    scanner::{Location, SecurityScanner, Severity, Threat, ThreatType},
    ScannerConfig,
};
use proptest::prelude::*;
use std::sync::Arc;
use tokio::runtime::Runtime;

// Helper to create all neutralizer implementations
fn get_all_neutralizers() -> Vec<Arc<dyn ThreatNeutralizer>> {
    let mut neutralizers = vec![];

    // Create neutralizer with default config
    // The implementation (standard vs enhanced) is determined by feature flags
    let config = Config::default();
    neutralizers.push(kindly_guard_server::neutralizer::create_neutralizer(
        &config.neutralization,
        None, // No rate limiter for tests
    ));

    neutralizers
}

// Helper to create scanner
fn create_test_scanner(enhanced: bool) -> Result<Arc<SecurityScanner>> {
    let config = ScannerConfig {
        unicode_detection: true,
        injection_detection: true,
        path_traversal_detection: true,
        custom_patterns: None,
        max_scan_depth: 10,
        enable_event_buffer: enhanced,
        xss_detection: Some(true),
        enhanced_mode: Some(enhanced),
    };
    Ok(Arc::new(SecurityScanner::new(config)?))
}

// Property composer for generating adversarial inputs
prop_compose! {
    fn adversarial_input()(
        base in prop::string::string_regex("[a-zA-Z0-9 ]{0,100}").unwrap(),
        injection_type in prop::sample::select(vec![
            "sql", "command", "ldap", "xpath", "nosql", "template"
        ]),
        evasion_technique in prop::sample::select(vec![
            "none", "encoding", "case_variation", "whitespace", "comments", "unicode"
        ]),
        payload_position in prop::sample::select(vec!["prefix", "suffix", "middle", "wrapped"]),
    ) -> String {
        let payload = match injection_type {
            "sql" => "' OR '1'='1' --",
            "command" => "; cat /etc/passwd",
            "ldap" => ")(cn=*)",
            "xpath" => "' or '1'='1",
            "nosql" => "{'$ne': null}",
            "template" => "{{7*7}}",
            _ => "UNION SELECT * FROM users",
        };

        let evaded_payload = match evasion_technique {
            "encoding" => percent_encode(payload),
            "case_variation" => randomize_case(payload),
            "whitespace" => add_whitespace(payload),
            "comments" => add_sql_comments(payload),
            "unicode" => add_unicode_tricks(payload),
            _ => payload.to_string(),
        };

        match payload_position {
            "prefix" => format!("{}{}", evaded_payload, base),
            "suffix" => format!("{}{}", base, evaded_payload),
            "middle" => {
                let mid = base.len() / 2;
                format!("{}{}{}", &base[..mid], evaded_payload, &base[mid..])
            }
            "wrapped" => format!("{}{}{}", base, evaded_payload, base),
            _ => evaded_payload,
        }
    }
}

// Helper functions for evasion techniques
fn percent_encode(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() {
                c.to_string()
            } else {
                format!("%{:02X}", c as u8)
            }
        })
        .collect()
}

fn randomize_case(s: &str) -> String {
    s.chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_uppercase().to_string()
            } else {
                c.to_lowercase().to_string()
            }
        })
        .collect()
}

fn add_whitespace(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == ' ' {
                "  ".to_string() // Double spaces
            } else {
                c.to_string()
            }
        })
        .collect()
}

fn add_sql_comments(s: &str) -> String {
    s.replace(" OR ", " /*comment*/ OR /*comment*/ ")
        .replace("SELECT", "SEL/**/ECT")
}

fn add_unicode_tricks(s: &str) -> String {
    // Add zero-width spaces and other unicode tricks
    s.chars()
        .flat_map(|c| {
            if c == ' ' {
                vec!['\u{200B}', c] // Zero-width space before regular space
            } else {
                vec![c]
            }
        })
        .collect()
}

// Property composer for unicode attack strings
prop_compose! {
    fn unicode_attack_string()(
        base in prop::string::string_regex("[a-zA-Z0-9]{0,50}").unwrap(),
        attack_type in prop::sample::select(vec![
            "homograph", "bidi", "invisible", "normalization", "mixed"
        ]),
        complexity in 1usize..5,
    ) -> String {
        let mut result = base.clone();
        
        for _ in 0..complexity {
            match attack_type {
                "homograph" => {
                    // Replace ASCII with lookalikes
                    result = result
                        .replace('a', "а") // Cyrillic
                        .replace('o', "о") // Cyrillic
                        .replace('e', "е"); // Cyrillic
                }
                "bidi" => {
                    // Add bidi override characters
                    result = format!("\u{202E}{}\u{202C}", result);
                }
                "invisible" => {
                    // Insert zero-width characters
                    let pos = result.len() / 2;
                    result.insert(pos, '\u{200B}'); // Zero-width space
                    result.insert(pos, '\u{200C}'); // Zero-width non-joiner
                }
                "normalization" => {
                    // Add combining characters
                    result.push('\u{0301}'); // Combining acute accent
                }
                "mixed" => {
                    // Combine multiple techniques
                    result = format!("\u{202E}{}а\u{200B}о\u{202C}", result);
                }
                _ => {}
            }
        }
        
        result
    }
}

// Main property tests
proptest! {
    #[test]
    fn prop_no_injection_bypass(
        input in adversarial_input(),
    ) {
        let runtime = Runtime::new().unwrap();
        
        runtime.block_on(async {
            for neutralizer in get_all_neutralizers() {
                // First scan for threats
                let scanner = create_test_scanner(false).unwrap();
                let threats = scanner.scan_text(&input).unwrap_or_default();
                
                // If threats detected, ensure they're neutralized
                if !threats.is_empty() {
                    for threat in &threats {
                        let result = neutralizer.neutralize(threat, &input).await.unwrap();
                        
                        // Verify threat was handled
                        prop_assert!(
                            result.action_taken != NeutralizeAction::NoAction,
                            "Threat not neutralized: {:?} in input: {:?}",
                            threat.threat_type,
                            input
                        );
                        
                        // If content was sanitized, verify it's safe
                        if let Some(sanitized) = &result.sanitized_content {
                            // Re-scan sanitized content
                            let new_threats = scanner.scan_text(sanitized).unwrap_or_default();
                            
                            // Should not contain the same threat type
                            prop_assert!(
                                !new_threats.iter().any(|t| t.threat_type == threat.threat_type),
                                "Sanitized content still contains threat: {:?}",
                                threat.threat_type
                            );
                        }
                    }
                }
            }
            Ok::<(), TestCaseError>(())
        }).unwrap();
    }

    #[test]
    fn prop_all_malicious_inputs_neutralized(
        inputs in prop::collection::vec(adversarial_input(), 1..10),
    ) {
        let runtime = Runtime::new().unwrap();
        
        runtime.block_on(async {
            for neutralizer in get_all_neutralizers() {
                for input in &inputs {
                    let scanner = create_test_scanner(false).unwrap();
                    let threats = scanner.scan_text(input).unwrap_or_default();
                    
                    if !threats.is_empty() {
                        // Batch neutralize all threats
                        let batch_result = neutralizer.batch_neutralize(&threats, input).await.unwrap();
                        
                        // Verify all threats were addressed
                        prop_assert_eq!(
                            batch_result.individual_results.len(),
                            threats.len(),
                            "Not all threats were processed"
                        );
                        
                        // Verify final content is safe
                        let final_threats = scanner.scan_text(&batch_result.final_content).unwrap_or_default();
                        prop_assert!(
                            final_threats.is_empty() || 
                            final_threats.iter().all(|t| t.severity == Severity::Low),
                            "High severity threats remain in final content"
                        );
                    }
                }
            }
            Ok::<(), TestCaseError>(())
        }).unwrap();
    }

    #[test]
    fn prop_neutralized_content_always_safe(
        base_content in prop::string::string_regex(".{0,1000}").unwrap(),
        threat_count in 1usize..5,
    ) {
        let runtime = Runtime::new().unwrap();
        
        runtime.block_on(async {
            for neutralizer in get_all_neutralizers() {
                // Create synthetic threats
                let threats: Vec<Threat> = (0..threat_count)
                    .map(|i| Threat {
                        threat_type: match i % 3 {
                            0 => ThreatType::SqlInjection,
                            1 => ThreatType::CommandInjection,
                            _ => ThreatType::CrossSiteScripting,
                        },
                        severity: Severity::High,
                        location: Location::Text { 
                            offset: i * 10,
                            length: 5,
                        },
                        description: format!("Test threat {}", i),
                        remediation: None,
                    })
                    .collect();
                
                // Neutralize threats
                let result = neutralizer.batch_neutralize(&threats, &base_content).await.unwrap();
                
                // Verify properties of neutralized content
                prop_assert!(
                    !result.final_content.is_empty() || base_content.is_empty(),
                    "Content was completely removed"
                );
                
                // Ensure no high-severity threats remain
                let scanner = create_test_scanner(false).unwrap();
                let remaining_threats = scanner.scan_text(&result.final_content).unwrap_or_default();
                
                prop_assert!(
                    remaining_threats.iter().all(|t| t.severity != Severity::Critical),
                    "Critical threats remain after neutralization"
                );
            }
            Ok::<(), TestCaseError>(())
        }).unwrap();
    }

    #[test]
    fn prop_unicode_attacks_neutralized(
        input in unicode_attack_string(),
    ) {
        let runtime = Runtime::new().unwrap();
        
        runtime.block_on(async {
            for neutralizer in get_all_neutralizers() {
                let scanner = create_test_scanner(false).unwrap();
                let threats = scanner.scan_text(&input).unwrap_or_default();
                
                // Unicode attacks should be detected
                let unicode_threats: Vec<_> = threats.iter()
                    .filter(|t| matches!(
                        t.threat_type,
                        ThreatType::UnicodeInvisible | 
                        ThreatType::UnicodeBiDi |
                        ThreatType::UnicodeHomograph |
                        ThreatType::UnicodeControl
                    ))
                    .collect();
                
                if !unicode_threats.is_empty() {
                    for threat in unicode_threats {
                        let result = neutralizer.neutralize(threat, &input).await.unwrap();
                        
                        prop_assert!(
                            result.action_taken != NeutralizeAction::NoAction,
                            "Unicode threat not neutralized: {:?}",
                            threat.threat_type
                        );
                        
                        // Verify sanitized content doesn't contain the threat
                        if let Some(sanitized) = &result.sanitized_content {
                            let new_threats = scanner.scan_text(sanitized).unwrap_or_default();
                            prop_assert!(
                                !new_threats.iter().any(|t| 
                                    matches!(t.threat_type, 
                                        ThreatType::UnicodeInvisible | 
                                        ThreatType::UnicodeBiDi |
                                        ThreatType::UnicodeHomograph |
                                        ThreatType::UnicodeControl
                                    )
                                ),
                                "Unicode threat persists after neutralization"
                            );
                        }
                    }
                }
            }
            Ok::<(), TestCaseError>(())
        }).unwrap();
    }

    #[test]
    fn prop_neutralizer_deterministic(
        input in prop::string::string_regex(".{0,500}").unwrap(),
        threat_type in prop::sample::select(vec![
            ThreatType::SqlInjection,
            ThreatType::CommandInjection,
            ThreatType::CrossSiteScripting,
            ThreatType::PathTraversal,
        ]),
    ) {
        let runtime = Runtime::new().unwrap();
        
        runtime.block_on(async {
            for neutralizer in get_all_neutralizers() {
                let threat = Threat {
                    threat_type: threat_type.clone(),
                    severity: Severity::High,
                    location: Location::Text { offset: 0, length: input.len() },
                    description: "Test threat".to_string(),
                    remediation: None,
                };
                
                // Run neutralization multiple times
                let result1 = neutralizer.neutralize(&threat, &input).await.unwrap();
                let result2 = neutralizer.neutralize(&threat, &input).await.unwrap();
                
                // Results should be identical
                prop_assert_eq!(
                    result1.action_taken,
                    result2.action_taken,
                    "Non-deterministic action"
                );
                
                prop_assert_eq!(
                    result1.sanitized_content,
                    result2.sanitized_content,
                    "Non-deterministic sanitization"
                );
            }
            Ok::<(), TestCaseError>(())
        }).unwrap();
    }

    #[test]
    fn prop_extreme_inputs_handled_safely(
        size_mb in 1usize..10,
        pattern in prop::sample::select(vec!["a", "😀", "\u{200B}", "SELECT", "<script>"]),
    ) {
        let runtime = Runtime::new().unwrap();
        
        runtime.block_on(async {
            // Create large input
            let input: String = pattern.repeat(size_mb * 1024 * 1024 / pattern.len());
            
            for neutralizer in get_all_neutralizers() {
                // Should handle large inputs without panic or OOM
                let threat = Threat {
                    threat_type: ThreatType::Custom("Generic".to_string()),
                    severity: Severity::Low,
                    location: Location::Text { offset: 0, length: 100 },
                    description: "Large input test".to_string(),
                    remediation: None,
                };
                
                let result = neutralizer.neutralize(&threat, &input).await;
                prop_assert!(result.is_ok(), "Failed to handle large input");
            }
            Ok::<(), TestCaseError>(())
        }).unwrap();
    }

    #[test]
    fn prop_nested_threats_properly_handled(
        depth in 1usize..5,
        base in prop::string::string_regex("[a-zA-Z0-9]{10,20}").unwrap(),
    ) {
        let runtime = Runtime::new().unwrap();
        
        runtime.block_on(async {
            // Create nested payload
            let mut payload = base.clone();
            for _ in 0..depth {
                payload = format!("' OR '{}'='{}", payload, payload);
            }
            
            for neutralizer in get_all_neutralizers() {
                let scanner = create_test_scanner(false).unwrap();
                let threats = scanner.scan_text(&payload).unwrap_or_default();
                
                if !threats.is_empty() {
                    let result = neutralizer.batch_neutralize(&threats, &payload).await.unwrap();
                    
                    // Verify nested threats are neutralized
                    let final_threats = scanner.scan_text(&result.final_content).unwrap_or_default();
                    prop_assert!(
                        final_threats.len() < threats.len(),
                        "Neutralization didn't reduce threat count"
                    );
                }
            }
            Ok::<(), TestCaseError>(())
        }).unwrap();
    }

    #[test]
    fn prop_polyglot_payloads_neutralized(
        components in prop::collection::vec(
            prop::sample::select(vec![
                "<script>alert(1)</script>",
                "' OR '1'='1",
                "{{7*7}}",
                "${7*7}",
                "=cmd|'/c calc'!A1",
                "../../../etc/passwd",
            ]),
            2..5
        ),
    ) {
        let runtime = Runtime::new().unwrap();
        
        runtime.block_on(async {
            // Create polyglot payload
            let polyglot = components.join("");
            
            for neutralizer in get_all_neutralizers() {
                let scanner = create_test_scanner(false).unwrap();
                let threats = scanner.scan_text(&polyglot).unwrap_or_default();
                
                // Should detect multiple threat types
                prop_assert!(
                    threats.len() >= 2,
                    "Polyglot payload should trigger multiple detections"
                );
                
                // All should be neutralized
                let result = neutralizer.batch_neutralize(&threats, &polyglot).await.unwrap();
                
                // Final content should be significantly different
                prop_assert!(
                    result.final_content != polyglot,
                    "Polyglot payload unchanged after neutralization"
                );
                
                // And safe
                let final_threats = scanner.scan_text(&result.final_content).unwrap_or_default();
                prop_assert!(
                    final_threats.iter().all(|t| t.severity != Severity::High),
                    "High severity threats remain in polyglot neutralization"
                );
            }
            Ok::<(), TestCaseError>(())
        }).unwrap();
    }

    #[test]
    fn prop_capabilities_match_behavior(
        threat_types in prop::collection::vec(
            prop::sample::select(vec![
                ThreatType::SqlInjection,
                ThreatType::CommandInjection,
                ThreatType::CrossSiteScripting,
                ThreatType::PathTraversal,
                ThreatType::UnicodeInvisible,
            ]),
            1..10
        ),
    ) {
        let runtime = Runtime::new().unwrap();
        
        runtime.block_on(async {
            for neutralizer in get_all_neutralizers() {
                let capabilities = neutralizer.get_capabilities();
                
                for threat_type in &threat_types {
                    let can_handle = neutralizer.can_neutralize(threat_type);
                    
                    // Create a threat of this type
                    let threat = Threat {
                        threat_type: threat_type.clone(),
                        severity: Severity::High,
                        location: Location::Text { offset: 0, length: 10 },
                        description: "Test".to_string(),
                        remediation: None,
                    };
                    
                    let result = neutralizer.neutralize(&threat, "test content").await;
                    
                    if can_handle {
                        prop_assert!(
                            result.is_ok(),
                            "Neutralizer claims to handle {:?} but failed",
                            threat_type
                        );
                    }
                    
                    // Verify capabilities are consistent
                    prop_assert!(
                        capabilities.real_time || capabilities.batch_mode,
                        "Neutralizer must support at least one mode"
                    );
                }
            }
            Ok::<(), TestCaseError>(())
        }).unwrap();
    }
}

// Additional security invariant tests
#[cfg(test)]
mod security_invariants {
    use super::*;
    
    #[test]
    fn test_no_content_amplification() {
        let runtime = Runtime::new().unwrap();
        
        runtime.block_on(async {
            for neutralizer in get_all_neutralizers() {
                let test_inputs = vec![
                    "normal text",
                    "text with <script>alert(1)</script>",
                    "SQL: ' OR '1'='1",
                    "Path: ../../../etc/passwd",
                ];
                
                for input in test_inputs {
                    let threat = Threat {
                        threat_type: ThreatType::Custom("Generic".to_string()),
                        severity: Severity::High,
                        location: Location::Text { offset: 0, length: input.len() },
                        description: "Test".to_string(),
                        remediation: None,
                    };
                    
                    let result = neutralizer.neutralize(&threat, input).await.unwrap();
                    
                    if let Some(sanitized) = &result.sanitized_content {
                        // Sanitized content should not be significantly larger
                        assert!(
                            sanitized.len() <= input.len() * 2,
                            "Content amplification detected: {} -> {}",
                            input.len(),
                            sanitized.len()
                        );
                    }
                }
            }
        });
    }
    
    #[test]
    fn test_no_infinite_loops() {
        let runtime = Runtime::new().unwrap();
        
        runtime.block_on(async {
            for neutralizer in get_all_neutralizers() {
                // Create pathological input that might cause loops
                let circular_ref = "{{{{{{{{{{";
                let recursive_payload = "';exec(';exec(';exec(';exec(';exec(";
                
                for input in [circular_ref, recursive_payload] {
                    let threat = Threat {
                        threat_type: ThreatType::Custom("Generic".to_string()),
                        severity: Severity::High,
                        location: Location::Text { offset: 0, length: input.len() },
                        description: "Loop test".to_string(),
                        remediation: None,
                    };
                    
                    // Should complete in reasonable time
                    let result = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        neutralizer.neutralize(&threat, input)
                    ).await;
                    
                    assert!(
                        result.is_ok(),
                        "Neutralization timed out - possible infinite loop"
                    );
                }
            }
        });
    }
    
    #[test]
    fn test_memory_safety() {
        let runtime = Runtime::new().unwrap();
        
        runtime.block_on(async {
            for neutralizer in get_all_neutralizers() {
                // Test with inputs that might cause memory issues
                let null_bytes = "test\0\0\0content";
                let high_unicode = "test\u{10FFFF}content";
                let mixed_encoding = "test\u{202E}\u{200B}\u{202C}content";
                
                for input in [null_bytes, high_unicode, mixed_encoding] {
                    let threat = Threat {
                        threat_type: ThreatType::Custom("Generic".to_string()),
                        severity: Severity::High,
                        location: Location::Text { offset: 0, length: input.len() },
                        description: "Memory safety test".to_string(),
                        remediation: None,
                    };
                    
                    // Should not cause memory errors
                    let result = neutralizer.neutralize(&threat, input).await;
                    assert!(result.is_ok(), "Memory safety issue detected");
                }
            }
        });
    }
}