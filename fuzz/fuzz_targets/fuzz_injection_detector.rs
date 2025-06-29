#![no_main]

use libfuzzer_sys::fuzz_target;
use kindly_guard_server::{SecurityScanner, ScannerConfig};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    
    // Create scanner with injection detection enabled
    let config = ScannerConfig {
        unicode_detection: false,
        injection_detection: true,
        path_traversal_detection: true,
        custom_patterns: None,
        max_scan_depth: 10,
        enable_event_buffer: false,
    };
    
    if let Ok(scanner) = SecurityScanner::new(config) {
        // Test basic scanning
        let _ = scanner.scan_text(&text);
        
        // Test with common injection prefixes/suffixes
        let sql_test = format!("SELECT * FROM users WHERE name = '{}'", text);
        let _ = scanner.scan_text(&sql_test);
        
        let cmd_test = format!("echo {}", text);
        let _ = scanner.scan_text(&cmd_test);
        
        let path_test = format!("/var/www/{}", text);
        let _ = scanner.scan_text(&path_test);
        
        // Test with URL encoding
        let url_encoded = text.replace(" ", "%20").replace("/", "%2F");
        let _ = scanner.scan_text(&url_encoded);
        
        // Test with HTML context
        let html_test = format!("<div>{}</div>", text);
        let _ = scanner.scan_text(&html_test);
        
        // Test with JSON context
        let json_test = format!(r#"{{"input": "{}"}}"#, text.replace('"', r#"\""#));
        let _ = scanner.scan_text(&json_test);
    }
});