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
        crypto_detection: false, // Not needed for XSS testing
        max_content_size: 5_242_880, // 5MB default
        max_input_size: None,
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
            let has_xss_type = threats
                .iter()
                .any(|t| matches!(t.threat_type, ThreatType::CrossSiteScripting));
            println!("Has XSS threat type: {}", has_xss_type);
        } else {
            println!(
                "Detected {} threats for payload: {}",
                threats.len(),
                payload
            );
            for threat in &threats {
                println!(
                    "  - Type: {:?}, Description: {}",
                    threat.threat_type, threat.description
                );
            }
        }
    }
}
