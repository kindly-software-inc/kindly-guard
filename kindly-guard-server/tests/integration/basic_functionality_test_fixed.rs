use kindly_guard_server::{
    config::{Config, ScannerConfig},
    scanner::{SecurityScanner, Threat, ThreatType, Severity, Location},
    neutralizer::{create_neutralizer},
};

/// Test basic scanner functionality
#[test] 
fn test_basic_scanner() {
    let config = ScannerConfig::default();
    let scanner = SecurityScanner::new(config).expect("Failed to create scanner");
    
    // Test safe text
    let safe_text = "Hello, this is a normal text message.";
    let threats = scanner.scan_text(safe_text).expect("Scan should succeed");
    assert!(threats.is_empty(), "Safe text should have no threats");
    
    // Test SQL injection
    let sql_injection = "'; DROP TABLE users; --";
    let threats = scanner.scan_text(sql_injection).expect("Scan should succeed");
    assert!(!threats.is_empty(), "SQL injection should be detected");
    
    // Test XSS
    let xss = "<script>alert('XSS')</script>";
    let threats = scanner.scan_text(xss).expect("Scan should succeed");
    assert!(!threats.is_empty(), "XSS should be detected");
    
    // Test Unicode threats
    let unicode_threat = "Check out pаypal.com"; // Cyrillic 'а'
    let threats = scanner.scan_text(unicode_threat).expect("Scan should succeed");
    assert!(!threats.is_empty(), "Unicode homograph should be detected");
}

/// Test scanner with custom configuration
#[test]
fn test_scanner_with_config() {
    let mut config = ScannerConfig::default();
    config.unicode_detection = false;
    config.injection_detection = true;
    config.xss_detection = Some(true);
    
    let scanner = SecurityScanner::new(config).expect("Failed to create scanner");
    
    // Unicode should not be detected
    let unicode_text = "pаypal.com";
    let threats = scanner.scan_text(unicode_text).expect("Scan should succeed");
    assert!(threats.is_empty(), "Unicode detection is disabled");
    
    // SQL injection should still be detected
    let sql = "'; DROP TABLE users; --";
    let threats = scanner.scan_text(sql).expect("Scan should succeed");
    assert!(!threats.is_empty(), "SQL injection should still be detected");
}

/// Test neutralizer basic functionality
#[tokio::test]
async fn test_basic_neutralizer() {
    let config = Config::default();
    let neutralizer = create_neutralizer(&config.neutralization, None);
    
    // Create a mock threat
    let threats = vec![Threat {
        threat_type: ThreatType::CrossSiteScripting,
        severity: Severity::High,
        location: Location::Text { 
            offset: 0, 
            length: 29
        },
        description: "Script tag detected".to_string(),
        remediation: Some("Remove or encode script tags".to_string()),
    }];
    
    let text = "<script>alert('XSS')</script> Normal text";
    let result = neutralizer.neutralize(&threats[0], text).await;
    
    assert!(result.is_ok(), "Neutralization should succeed");
    let neutralized = result.unwrap();
    
    // Check that some action was taken
    assert!(neutralized.sanitized_content.is_some() || neutralized.extracted_params.is_some(), 
            "Should have sanitized content or extracted params");
}

/// Test JSON scanning
#[test]
fn test_json_scanning() {
    let scanner = SecurityScanner::new(ScannerConfig::default())
        .expect("Failed to create scanner");
    
    let json_with_threat = r#"{
        "name": "John",
        "bio": "<script>alert('XSS')</script>",
        "query": "SELECT * FROM users"
    }"#;
    
    let json_value: serde_json::Value = serde_json::from_str(json_with_threat).unwrap();
    let threats = scanner.scan_json(&json_value);
    assert!(threats.is_ok(), "JSON scanning should succeed");
    
    let threat_list = threats.unwrap();
    assert!(!threat_list.is_empty(), "Should detect threats in JSON");
    
    // Should detect both XSS and SQL patterns
    let threat_types: Vec<_> = threat_list.iter()
        .map(|t| &t.threat_type)
        .collect();
    
    assert!(
        threat_types.iter().any(|t| matches!(t, ThreatType::CrossSiteScripting)),
        "Should detect XSS in JSON"
    );
}

/// Test performance with large input
#[test]
fn test_large_input_performance() {
    let scanner = SecurityScanner::new(ScannerConfig::default())
        .expect("Failed to create scanner");
    
    // Create a 1MB string
    let large_text = "a".repeat(1024 * 1024);
    
    let start = std::time::Instant::now();
    let threats = scanner.scan_text(&large_text).expect("Scan should succeed");
    let duration = start.elapsed();
    
    assert!(duration.as_secs() < 2, "Large input scan took too long: {:?}", duration);
    assert!(threats.is_empty(), "Plain text should have no threats");
}

/// Test concurrent scanning
#[test]
fn test_concurrent_scanning() {
    let scanner = std::sync::Arc::new(
        SecurityScanner::new(ScannerConfig::default())
            .expect("Failed to create scanner")
    );
    
    let mut handles = vec![];
    
    for i in 0..10 {
        let scanner_clone = std::sync::Arc::clone(&scanner);
        let handle = std::thread::spawn(move || {
            let text = format!("Test {} with <script>alert({})</script>", i, i);
            scanner_clone.scan_text(&text).expect("Scan should succeed")
        });
        handles.push(handle);
    }
    
    let results: Vec<_> = handles.into_iter()
        .map(|h| h.join())
        .collect();
    
    for (i, result) in results.iter().enumerate() {
        assert!(result.is_ok(), "Thread {} failed", i);
        let threats = result.as_ref().unwrap();
        assert!(!threats.is_empty(), "Thread {} should detect XSS", i);
    }
}

/// Test mixed content scanning
#[test]
fn test_mixed_content() {
    let scanner = SecurityScanner::new(ScannerConfig::default())
        .expect("Failed to create scanner");
    
    let mixed_content = r#"
        This is a blog post about web security.
        
        Common attacks include SQL injection like: ' OR '1'='1
        
        And XSS attacks such as: <img src=x onerror=alert('XSS')>
        
        Also watch out for unicode attacks: pаypal.com (fake paypal)
        
        Remember to validate all user input!
    "#;
    
    let threats = scanner.scan_text(mixed_content).expect("Scan should succeed");
    
    // Should detect multiple threat types
    assert!(threats.len() >= 3, "Should detect multiple threats");
    
    let threat_types: std::collections::HashSet<_> = threats.iter()
        .map(|t| &t.threat_type)
        .collect();
    
    assert!(threat_types.len() >= 2, "Should detect different threat types");
}

/// Test file scanning via CLI
#[test]
fn test_file_scanning() {
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;
    
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test.txt");
    
    let mut file = File::create(&file_path).unwrap();
    writeln!(file, "Normal content").unwrap();
    writeln!(file, "<script>alert('XSS')</script>").unwrap();
    writeln!(file, "More normal content").unwrap();
    
    let scanner = SecurityScanner::new(ScannerConfig::default())
        .expect("Failed to create scanner");
    let content = std::fs::read_to_string(&file_path).unwrap();
    let threats = scanner.scan_text(&content).expect("Scan should succeed");
    
    assert!(!threats.is_empty(), "Should detect threats in file");
    
    // Check that XSS is among the detected threats
    let has_xss = threats.iter().any(|t| matches!(t.threat_type, ThreatType::CrossSiteScripting));
    assert!(has_xss, "Should detect XSS threat in file");
}