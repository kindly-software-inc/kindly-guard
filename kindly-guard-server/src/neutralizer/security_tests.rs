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
//! Security-focused tests for the neutralization system
//!
//! These tests ensure the neutralization system is resistant to:
//! - Timing attacks
//! - Resource exhaustion
//! - Malicious patterns
//! - Concurrent access issues
//! - Memory safety violations

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::scanner::{Location, Severity, Threat, ThreatType};
    use proptest::prelude::*;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::sync::Semaphore;

    /// Helper to create a test threat
    fn create_test_threat(threat_type: ThreatType, offset: usize) -> Threat {
        Threat {
            threat_type,
            severity: Severity::High,
            location: Location::Text { offset, length: 10 },
            description: "Test threat".to_string(),
            remediation: None,
        }
    }

    /// Helper to create test neutralizer
    fn create_test_neutralizer() -> Arc<dyn ThreatNeutralizer> {
        let config = NeutralizationConfig::default();
        Arc::new(standard::StandardNeutralizer::new(config))
    }

    #[tokio::test]
    async fn test_timing_attack_resistance() {
        let neutralizer = create_test_neutralizer();
        let threat = create_test_threat(ThreatType::SqlInjection, 0);

        // Measure timing for different content lengths
        let short_content = "SELECT * FROM users";
        let long_content = "SELECT * FROM users WHERE ".repeat(1000);

        let mut short_times = Vec::new();
        let mut long_times = Vec::new();

        // Run multiple iterations to get stable measurements
        for _ in 0..20 {
            // Short content timing
            let start = Instant::now();
            let _ = neutralizer.neutralize(&threat, short_content).await;
            short_times.push(start.elapsed());

            // Long content timing
            let start = Instant::now();
            let _ = neutralizer.neutralize(&threat, &long_content).await;
            long_times.push(start.elapsed());
        }

        // Calculate average times
        let avg_short: Duration = short_times.iter().sum::<Duration>() / short_times.len() as u32;
        let avg_long: Duration = long_times.iter().sum::<Duration>() / long_times.len() as u32;

        // Verify timing is proportional to content size, not revealing secret info
        // The ratio should be roughly proportional to the size difference
        let size_ratio = long_content.len() as f64 / short_content.len() as f64;
        let time_ratio = avg_long.as_nanos() as f64 / avg_short.as_nanos() as f64;

        // Allow for some variance but ensure it's not wildly different
        assert!(
            time_ratio < size_ratio * 2.0,
            "Timing ratio {} exceeds expected bounds for size ratio {}",
            time_ratio,
            size_ratio
        );
    }

    #[tokio::test]
    async fn test_resource_exhaustion_protection() {
        let neutralizer = create_test_neutralizer();

        // Test 1: Extremely large input
        let huge_content = "A".repeat(10_000_000); // 10MB
        let threat = create_test_threat(ThreatType::UnicodeBiDi, 0);

        let start = Instant::now();
        let result = neutralizer.neutralize(&threat, &huge_content).await;
        let elapsed = start.elapsed();

        // Should complete in reasonable time (< 5 seconds)
        assert!(
            elapsed < Duration::from_secs(5),
            "Large input processing took too long: {:?}",
            elapsed
        );
        assert!(result.is_ok(), "Failed to process large input");

        // Test 2: Many small threats
        let content = "test content";
        let threats: Vec<_> = (0..1000)
            .map(|i| create_test_threat(ThreatType::SqlInjection, i % 10))
            .collect();

        let start = Instant::now();
        for threat in &threats {
            let _ = neutralizer.neutralize(threat, content).await;
        }
        let elapsed = start.elapsed();

        // Should handle many operations efficiently
        assert!(
            elapsed < Duration::from_secs(10),
            "Many operations took too long: {:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn test_malicious_pattern_handling() {
        let neutralizer = create_test_neutralizer();

        // Test various malicious patterns
        let buffer_overflow = "A".repeat(65536);
        let malicious_patterns = vec![
            // Nested encoding attacks
            ("SELECT%2520FROM%2520users", ThreatType::SqlInjection),
            // Unicode normalization attacks
            ("DROP\u{0301} TABLE users", ThreatType::SqlInjection),
            // Zero-width space injection
            ("admin\u{200B}@example.com", ThreatType::UnicodeInvisible),
            // Polyglot attacks
            (
                "';alert(String.fromCharCode(88,83,83))//",
                ThreatType::CrossSiteScripting,
            ),
            // Buffer overflow attempts
            (buffer_overflow.as_str(), ThreatType::CommandInjection),
            // Null byte injection
            ("file.txt\0.exe", ThreatType::PathTraversal),
            // Unicode case folding attacks
            (
                "ı", /* Turkish lowercase i */
                ThreatType::UnicodeHomograph,
            ),
        ];

        for (pattern, threat_type) in malicious_patterns {
            let threat = create_test_threat(threat_type, 0);

            let result = neutralizer.neutralize(&threat, pattern).await;
            assert!(
                result.is_ok(),
                "Failed to handle malicious pattern: {:?}",
                pattern
            );

            if let Ok(neutralized) = result {
                // Verify the threat was actually neutralized
                assert!(
                    neutralized.action_taken != NeutralizeAction::NoAction,
                    "Malicious pattern not neutralized: {:?}",
                    pattern
                );
            }
        }
    }

    #[tokio::test]
    async fn test_no_panics_on_malformed_input() {
        let neutralizer = create_test_neutralizer();

        // Test with various malformed inputs
        let long_string = "X".repeat(1_000_000);
        let malformed_inputs = vec![
            // Invalid UTF-8 sequences (as valid Rust strings)
            "\u{FFFD}invalid\u{FFFD}",
            // Extremely long strings
            long_string.as_str(),
            // Empty string
            "",
            // Only whitespace
            "   \t\n\r   ",
            // Control characters
            "\x00\x01\x02\x03\x04\x05",
            // Mixed scripts
            "Hello مرحبا שלום Здравствуйте",
            // Emoji and special characters
            "🚀💣🔥😈👿💀☠️",
            // RTL/LTR mixing
            "Hello \u{202E}dlroW\u{202C} Test",
        ];

        for input in malformed_inputs {
            for threat_type in [
                ThreatType::SqlInjection,
                ThreatType::CommandInjection,
                ThreatType::UnicodeBiDi,
                ThreatType::PathTraversal,
            ] {
                let threat = create_test_threat(threat_type, 0);

                // Should not panic
                let result = neutralizer.neutralize(&threat, input).await;

                // Should return Ok or a proper error, never panic
                match result {
                    Ok(_) => { /* Success */ }
                    Err(e) => {
                        // Error should be informative, not a panic
                        assert!(
                            !format!("{:?}", e).contains("panic"),
                            "Unexpected panic-like error: {:?}",
                            e
                        );
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn test_concurrent_access_safety() {
        let neutralizer = create_test_neutralizer();
        let neutralizer = Arc::new(neutralizer);

        // Test concurrent access from multiple tasks
        let concurrent_tasks = 100;
        let operations_per_task = 50;

        let semaphore = Arc::new(Semaphore::new(concurrent_tasks));
        let mut handles = Vec::new();

        for task_id in 0..concurrent_tasks {
            let neutralizer = neutralizer.clone();
            let sem = semaphore.clone();

            let handle = tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();

                for op in 0..operations_per_task {
                    let content = format!("Task {} operation {}", task_id, op);
                    let threat_type = match op % 4 {
                        0 => ThreatType::SqlInjection,
                        1 => ThreatType::CommandInjection,
                        2 => ThreatType::UnicodeBiDi,
                        _ => ThreatType::PathTraversal,
                    };

                    let threat = create_test_threat(threat_type, 0);
                    let result = neutralizer.neutralize(&threat, &content).await;

                    assert!(
                        result.is_ok(),
                        "Concurrent operation failed: task={}, op={}",
                        task_id,
                        op
                    );
                }
            });

            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_memory_safety() {
        let neutralizer = create_test_neutralizer();

        // Test 1: Self-referential content
        let self_ref = "Content that references itself: ";
        let recursive_content = format!("{}{}{}", self_ref, self_ref, self_ref);

        let threat = create_test_threat(ThreatType::PromptInjection, 0);
        let result = neutralizer.neutralize(&threat, &recursive_content).await;
        assert!(result.is_ok(), "Failed on self-referential content");

        // Test 2: Boundary conditions
        let size_a = "A".repeat(65535);
        let size_b = "B".repeat(65536);
        let size_c = "C".repeat(65537);
        let boundary_tests = vec![
            // Maximum safe integer boundaries
            "9223372036854775807",  // i64::MAX
            "-9223372036854775808", // i64::MIN
            // Unicode boundaries
            "\u{0000}",   // NULL
            "\u{10FFFF}", // Max valid Unicode
            // Size boundaries
            size_a.as_str(), // Just under 64KB
            size_b.as_str(), // Exactly 64KB
            size_c.as_str(), // Just over 64KB
        ];

        for content in boundary_tests {
            let threat = create_test_threat(ThreatType::TokenTheft, 0);
            let result = neutralizer.neutralize(&threat, content).await;

            match result {
                Ok(_) => { /* Success */ }
                Err(e) => {
                    // Should be a controlled error, not memory corruption
                    assert!(
                        format!("{:?}", e).contains("limit")
                            || format!("{:?}", e).contains("size")
                            || format!("{:?}", e).contains("boundary"),
                        "Unexpected error type: {:?}",
                        e
                    );
                }
            }
        }
    }

    // Property-based testing for comprehensive coverage
    proptest! {
        #[test]
        fn test_neutralizer_never_panics(
            content in prop::string::string_regex(".*").unwrap(),
            threat_type_idx in 0..5usize,
            offset in 0..1000usize,
        ) {
            let runtime = tokio::runtime::Runtime::new().unwrap();

            runtime.block_on(async {
                let neutralizer = create_test_neutralizer();

                let threat_type = match threat_type_idx {
                    0 => ThreatType::SqlInjection,
                    1 => ThreatType::CommandInjection,
                    2 => ThreatType::UnicodeBiDi,
                    3 => ThreatType::PathTraversal,
                    _ => ThreatType::CrossSiteScripting,
                };

                let threat = create_test_threat(threat_type, offset);

                // Should never panic, regardless of input
                let _ = neutralizer.neutralize(&threat, &content).await;
            });
        }

        #[test]
        fn test_neutralization_deterministic(
            content in prop::string::string_regex("[A-Za-z0-9 ]{1,100}").unwrap(),
        ) {
            let runtime = tokio::runtime::Runtime::new().unwrap();

            runtime.block_on(async {
                let neutralizer = create_test_neutralizer();
                let threat = create_test_threat(ThreatType::SqlInjection, 0);

                // Run neutralization twice on same input
                let result1 = neutralizer.neutralize(&threat, &content).await;
                let result2 = neutralizer.neutralize(&threat, &content).await;

                // Results should be deterministic
                match (result1, result2) {
                    (Ok(r1), Ok(r2)) => {
                        assert_eq!(r1.action_taken, r2.action_taken);
                        assert_eq!(r1.sanitized_content, r2.sanitized_content);
                    }
                    (Err(_), Err(_)) => { /* Both failed consistently */ }
                    _ => panic!("Non-deterministic results"),
                }
            });
        }
    }

    #[tokio::test]
    async fn test_enhanced_mode_security() {
        // Only run if enhanced feature is enabled
        #[cfg(feature = "enhanced")]
        {
            use crate::neutralizer::enhanced::EnhancedNeutralizer;

            let config = NeutralizationConfig::default();
            let neutralizer = Arc::new(EnhancedNeutralizer::new(config));

            // Test that enhanced mode maintains security properties
            let threat = create_test_threat(ThreatType::SqlInjection, 0);
            let content = "'; DROP TABLE users; --";

            let result = neutralizer.neutralize(&threat, content).await;
            assert!(result.is_ok(), "Enhanced mode failed to neutralize");

            if let Ok(neutralized) = result {
                // Verify threat was neutralized
                assert!(neutralized.action_taken != NeutralizeAction::NoAction);

                // Enhanced mode should provide correlation data
                assert!(
                    neutralized.correlation_data.is_some(),
                    "Enhanced mode should provide correlation data"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_neutralization_validation_bypass_attempts() {
        let neutralizer = create_test_neutralizer();

        // Test various bypass attempts
        let bypass_attempts = vec![
            // Double encoding
            ("SELECT%252520FROM", ThreatType::SqlInjection),
            // Case variation attacks
            ("SeLeCt FrOm", ThreatType::SqlInjection),
            // Comment injection
            ("SELECT/*comment*/FROM", ThreatType::SqlInjection),
            // Concatenation attacks (simulated)
            ("SELECT FROM", ThreatType::SqlInjection),
            // Time-based attacks
            ("SELECT SLEEP(10)", ThreatType::SqlInjection),
            // Boolean-based blind
            ("' OR '1'='1", ThreatType::SqlInjection),
        ];

        for (attempt, threat_type) in bypass_attempts {
            let threat = create_test_threat(threat_type, 0);
            let result = neutralizer.neutralize(&threat, attempt).await;

            assert!(
                result.is_ok(),
                "Failed to handle bypass attempt: {}",
                attempt
            );

            if let Ok(neutralized) = result {
                // Should neutralize bypass attempts
                assert!(
                    neutralized.action_taken != NeutralizeAction::NoAction,
                    "Bypass attempt not neutralized: {}",
                    attempt
                );
            }
        }
    }
}
