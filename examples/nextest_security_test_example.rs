//! Example of writing security tests optimized for nextest execution
//! 
//! This example demonstrates best practices for security test isolation
//! and how to leverage nextest's features for better security testing.

#[cfg(test)]
mod security_tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    
    /// Mock security scanner for demonstration
    struct SecurityScanner {
        threat_count: AtomicU32,
    }
    
    impl SecurityScanner {
        fn new() -> Self {
            Self {
                threat_count: AtomicU32::new(0),
            }
        }
        
        fn scan_text(&self, text: &str) -> Vec<Threat> {
            let mut threats = Vec::new();
            
            // Check for Unicode bidi override attacks
            if text.contains('\u{202E}') || text.contains('\u{202D}') {
                threats.push(Threat {
                    kind: ThreatKind::UnicodeBidi,
                    position: 0,
                    severity: Severity::High,
                });
            }
            
            // Check for zero-width characters
            if text.contains('\u{200B}') || text.contains('\u{200C}') {
                threats.push(Threat {
                    kind: ThreatKind::UnicodeZeroWidth,
                    position: 0,
                    severity: Severity::Medium,
                });
            }
            
            // Track total threats found
            self.threat_count.fetch_add(threats.len() as u32, Ordering::Relaxed);
            
            threats
        }
        
        fn get_stats(&self) -> ScanStats {
            ScanStats {
                total_threats: self.threat_count.load(Ordering::Relaxed),
            }
        }
    }
    
    #[derive(Debug, PartialEq)]
    enum ThreatKind {
        UnicodeBidi,
        UnicodeZeroWidth,
        SqlInjection,
        CommandInjection,
    }
    
    #[derive(Debug, PartialEq)]
    enum Severity {
        Low,
        Medium,
        High,
        Critical,
    }
    
    #[derive(Debug)]
    struct Threat {
        kind: ThreatKind,
        position: usize,
        severity: Severity,
    }
    
    struct ScanStats {
        total_threats: u32,
    }
    
    // Security tests - these will run sequentially with nextest security profile
    
    #[test]
    fn test_security_unicode_bidi_detection() {
        // Each test gets its own scanner instance - no shared state
        let scanner = SecurityScanner::new();
        
        // Test malicious bidi override
        let malicious = "file\u{202E}cod.exe";
        let threats = scanner.scan_text(malicious);
        
        assert_eq!(threats.len(), 1);
        assert_eq!(threats[0].kind, ThreatKind::UnicodeBidi);
        assert_eq!(threats[0].severity, Severity::High);
    }
    
    #[test]
    fn test_security_unicode_zero_width() {
        // Isolated test - no interference from other tests
        let scanner = SecurityScanner::new();
        
        // Test zero-width characters used for fingerprinting
        let fingerprinted = "Hello\u{200B}World\u{200C}!";
        let threats = scanner.scan_text(fingerprinted);
        
        assert_eq!(threats.len(), 2);
        assert!(threats.iter().all(|t| t.kind == ThreatKind::UnicodeZeroWidth));
    }
    
    #[test]
    fn test_security_combined_unicode_attacks() {
        let scanner = SecurityScanner::new();
        
        // Test combination of attacks
        let complex_attack = "admin\u{200B}\u{202E}txt.exe";
        let threats = scanner.scan_text(complex_attack);
        
        // Should detect both types of threats
        assert_eq!(threats.len(), 2);
        assert!(threats.iter().any(|t| t.kind == ThreatKind::UnicodeBidi));
        assert!(threats.iter().any(|t| t.kind == ThreatKind::UnicodeZeroWidth));
    }
    
    #[test]
    fn test_security_scanner_statistics() {
        // Statistics are isolated per scanner instance
        let scanner = SecurityScanner::new();
        
        // Scan multiple texts
        scanner.scan_text("safe text");
        scanner.scan_text("danger\u{202E}ous");
        scanner.scan_text("zero\u{200B}width");
        
        let stats = scanner.get_stats();
        assert_eq!(stats.total_threats, 2);
    }
    
    // Integration tests - limited parallelism with nextest
    
    #[test]
    fn test_integration_scanner_with_normalizer() {
        // Simulated integration test
        let scanner = Arc::new(SecurityScanner::new());
        
        // Simulate multiple components using the scanner
        let scanner_clone = Arc::clone(&scanner);
        std::thread::spawn(move || {
            scanner_clone.scan_text("thread\u{202E}test");
        }).join().unwrap();
        
        // Verify thread-safe operation
        assert!(scanner.get_stats().total_threats > 0);
    }
    
    // Fuzzing tests - extended timeout with nextest
    
    #[test]
    #[ignore = "slow"] // Can be included with --include-ignored
    fn test_fuzz_unicode_scanner() {
        use rand::{thread_rng, Rng};
        
        let scanner = SecurityScanner::new();
        let mut rng = thread_rng();
        
        // Generate random Unicode strings
        for _ in 0..1000 {
            let len = rng.gen_range(1..100);
            let text: String = (0..len)
                .map(|_| {
                    let codepoint = rng.gen_range(0x0000..0x10FFFF);
                    std::char::from_u32(codepoint).unwrap_or('?')
                })
                .collect();
            
            // Should not panic on any input
            let _ = scanner.scan_text(&text);
        }
    }
    
    // Test helpers demonstrating isolation patterns
    
    mod test_helpers {
        use super::*;
        
        /// Create a pre-configured scanner for testing
        /// Each test gets its own instance - no shared state
        pub fn create_test_scanner() -> SecurityScanner {
            SecurityScanner::new()
        }
        
        /// Generate test payloads
        pub fn malicious_payloads() -> Vec<(&'static str, ThreatKind)> {
            vec![
                ("file\u{202E}cod.exe", ThreatKind::UnicodeBidi),
                ("data\u{200B}leak", ThreatKind::UnicodeZeroWidth),
                ("'; DROP TABLE users; --", ThreatKind::SqlInjection),
                ("$(rm -rf /)", ThreatKind::CommandInjection),
            ]
        }
    }
    
    #[test]
    fn test_security_payload_detection() {
        use test_helpers::*;
        
        let scanner = create_test_scanner();
        
        for (payload, expected_kind) in malicious_payloads() {
            let threats = scanner.scan_text(payload);
            
            // Each payload should be detected
            assert!(!threats.is_empty(), 
                "Failed to detect {} in: {:?}", 
                match expected_kind {
                    ThreatKind::UnicodeBidi => "Unicode bidi",
                    ThreatKind::UnicodeZeroWidth => "Zero-width",
                    ThreatKind::SqlInjection => "SQL injection",
                    ThreatKind::CommandInjection => "Command injection",
                },
                payload
            );
        }
    }
}

#[cfg(test)]
mod nextest_features {
    /// Example showing how nextest profiles affect test execution
    
    #[test]
    fn test_runs_in_parallel_by_default() {
        // This test runs in parallel with others by default
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    
    #[test]
    #[should_panic(expected = "deterministic panic")]
    fn test_deterministic_panic() {
        // Nextest properly captures and reports panics
        panic!("deterministic panic for testing");
    }
    
    #[test]
    #[ignore = "slow"]
    fn test_slow_security_analysis() {
        // Marked as slow - skipped by quick profile
        // Has extended timeout in security profile
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
}

fn main() {
    println!("Run tests with: cargo nextest run --example nextest_security_test_example");
    println!("Try different profiles:");
    println!("  cargo nextest run --example nextest_security_test_example --profile=security");
    println!("  cargo nextest run --example nextest_security_test_example --profile=quick");
}