#![no_main]

use libfuzzer_sys::fuzz_target;
use kindly_guard_server::{SecurityScanner, ScannerConfig};
use arbitrary::{Arbitrary, Unstructured};

#[derive(Arbitrary, Debug)]
struct InjectionTestCase {
    // Main payload
    payload: String,
    // Nested depth for testing recursive payloads
    nesting_depth: u8,
    // Whether to include polyglot sequences
    include_polyglot: bool,
    // Whether to test with various encodings
    test_encodings: bool,
}

fuzz_target!(|data: &[u8]| {
    // Try to generate structured test case
    let test_case = match Unstructured::new(data).arbitrary::<InjectionTestCase>() {
        Ok(tc) => tc,
        Err(_) => {
            // Fall back to raw string testing
            let input = String::from_utf8_lossy(data);
            test_injection_scanner(&input);
            return;
        }
    };

    // Test basic payload
    test_injection_scanner(&test_case.payload);

    // Test nested payloads
    if test_case.nesting_depth > 0 {
        let mut nested = test_case.payload.clone();
        for _ in 0..test_case.nesting_depth.min(5) {
            // Create various nested injection patterns
            nested = format!("';{}--", nested);
            test_injection_scanner(&nested);
            
            nested = format!("{{\"payload\": \"{}\"}}", nested.replace('"', "\\\""));
            test_injection_scanner(&nested);
            
            nested = format!("$({})", nested);
            test_injection_scanner(&nested);
        }
    }

    // Test polyglot sequences
    if test_case.include_polyglot {
        let polyglots = vec![
            format!("{}' OR '1'='1", test_case.payload),
            format!("{}\"; echo 'pwned'; #", test_case.payload),
            format!("{}]]><!--", test_case.payload),
            format!("{} %}} {{% raw %}}", test_case.payload),
        ];
        
        for polyglot in polyglots {
            test_injection_scanner(&polyglot);
        }
    }

    // Test various encodings
    if test_case.test_encodings {
        // URL encoding
        let url_encoded = test_case.payload.replace(' ', "%20")
            .replace('"', "%22")
            .replace('\'', "%27");
        test_injection_scanner(&url_encoded);

        // HTML entity encoding
        let html_encoded = test_case.payload.replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;");
        test_injection_scanner(&html_encoded);

        // Unicode encoding
        let unicode_encoded = test_case.payload.chars()
            .map(|c| if c.is_ascii() { c.to_string() } else { format!("\\u{{{:04x}}}", c as u32) })
            .collect::<String>();
        test_injection_scanner(&unicode_encoded);
    }
});

fn test_injection_scanner(input: &str) {
    let config = ScannerConfig {
        unicode_detection: false,
        injection_detection: true,
        path_traversal_detection: true,
        custom_patterns: None,
        max_scan_depth: 10,
        enable_event_buffer: false,
    };

    if let Ok(scanner) = SecurityScanner::new(config) {
        // This should never panic
        let _ = scanner.scan_text(input);
        
        // Also test as JSON
        let json_test = serde_json::json!({
            "method": "test",
            "params": {
                "input": input,
                "nested": {
                    "value": input
                }
            }
        });
        
        let _ = scanner.scan_json(&json_test);
    }
}