//! Test XSS detection functionality

use kindly_guard_server::{ScannerConfig, SecurityScanner, ThreatType};

#[test]
fn test_xss_detection_simple() {
    // Configure scanner
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
    
    // Test basic XSS patterns
    let xss_payloads = vec![
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<a href=\"javascript:alert('XSS')\">Click</a>",
    ];
    
    for payload in xss_payloads {
        let threats = scanner.scan_text(payload).unwrap();
        
        // Check if any threat was detected
        if threats.is_empty() {
            println!("No threats detected for payload: {}", payload);
            
            // Check if XSS threat type is even being looked for
            let has_xss_type = threats.iter().any(|t| matches!(t.threat_type, ThreatType::CrossSiteScripting));
            println!("Has XSS threat type: {}", has_xss_type);
        } else {
            println!("Detected {} threats for payload: {}", threats.len(), payload);
            for threat in &threats {
                println!("  - Type: {:?}, Description: {}", threat.threat_type, threat.description);
            }
        }
    }
}