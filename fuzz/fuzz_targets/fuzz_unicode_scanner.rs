#![no_main]

use libfuzzer_sys::fuzz_target;
use kindly_guard_server::{SecurityScanner, ScannerConfig};

fuzz_target!(|data: &[u8]| {
    // Try to interpret the fuzzer input as UTF-8
    let input = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => {
            // Also test with invalid UTF-8
            match String::from_utf8_lossy(data).as_ref() {
                s => s,
            }
        }
    };

    // Create scanner with unicode detection enabled
    let config = ScannerConfig {
        unicode_detection: true,
        injection_detection: false,
        path_traversal_detection: false,
        custom_patterns: None,
        max_scan_depth: 10,
        enable_event_buffer: false,
    };

    if let Ok(scanner) = SecurityScanner::new(config) {
        // This should never panic
        let _ = scanner.scan_text(input);
    }

    // Test edge cases with malformed Unicode
    if data.len() > 0 {
        // Test with zero-width joiners
        let zwj_test = format!("{}\u{200D}{}", input, input);
        if let Ok(scanner) = SecurityScanner::new(config) {
            let _ = scanner.scan_text(&zwj_test);
        }

        // Test with BiDi override characters
        let bidi_test = format!("\u{202E}{}\u{202C}", input);
        if let Ok(scanner) = SecurityScanner::new(config) {
            let _ = scanner.scan_text(&bidi_test);
        }

        // Test with combining characters
        let combining_test = format!("{}\u{0301}\u{0302}\u{0303}", input);
        if let Ok(scanner) = SecurityScanner::new(config) {
            let _ = scanner.scan_text(&combining_test);
        }
    }
});