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
//! Simple performance test without async complexity

use kindly_guard_server::scanner::{InjectionScanner, UnicodeScanner};
use std::time::Instant;

fn main() {
    println!("KindlyGuard Simple Performance Test");
    println!("===================================\n");

    // Test data
    let large_text_sample = format!("Large text: {}", "A".repeat(10000));
    let test_texts = [
        "Hello World",
        "Simple text with unicode: привет мир 你好世界",
        "Text with threats: '; DROP TABLE users; -- <script>alert('xss')</script>",
        "Mixed threats \u{202E}with unicode\u{200B} and injection: SELECT * FROM passwords",
        &large_text_sample,
    ];

    // Test Unicode Scanner
    println!("Unicode Scanner Performance:");
    let unicode_scanner = UnicodeScanner::new();

    for (i, text) in test_texts.iter().enumerate() {
        let start = Instant::now();
        let mut total_threats = 0;

        // Run 1000 iterations
        for _ in 0..1000 {
            match unicode_scanner.scan_text(text) {
                Ok(threats) => total_threats += threats.len(),
                Err(_) => {} // Ignore errors for benchmark
            }
        }

        let elapsed = start.elapsed();
        println!(
            "  Text {}: {} chars, {} threats found, {:?} for 1000 scans ({:.2} μs/scan)",
            i + 1,
            text.len(),
            total_threats / 1000,
            elapsed,
            elapsed.as_micros() as f64 / 1000.0
        );
    }

    // Test Injection Scanner
    println!("\nInjection Scanner Performance:");
    use kindly_guard_server::scanner::ThreatPatterns;
    let patterns = ThreatPatterns::default();
    let injection_scanner = match InjectionScanner::new(&patterns) {
        Ok(scanner) => scanner,
        Err(e) => {
            println!("Failed to create injection scanner: {}", e);
            return;
        }
    };

    for (i, text) in test_texts.iter().enumerate() {
        let start = Instant::now();
        let mut total_threats = 0;

        // Run 1000 iterations
        for _ in 0..1000 {
            match injection_scanner.scan_text(text) {
                Ok(threats) => total_threats += threats.len(),
                Err(_) => {} // Ignore errors for benchmark
            }
        }

        let elapsed = start.elapsed();
        println!(
            "  Text {}: {} chars, {} threats found, {:?} for 1000 scans ({:.2} μs/scan)",
            i + 1,
            text.len(),
            total_threats / 1000,
            elapsed,
            elapsed.as_micros() as f64 / 1000.0
        );
    }

    // Throughput test
    println!("\nThroughput Test:");
    let large_text = "A".repeat(1_000_000); // 1MB of text

    let start = Instant::now();
    let _unicode_threats = unicode_scanner.scan_text(&large_text);
    let unicode_time = start.elapsed();

    let start = Instant::now();
    let _injection_threats = injection_scanner.scan_text(&large_text);
    let injection_time = start.elapsed();

    println!("  1MB text scan:");
    println!(
        "    Unicode scanner: {:?} ({:.2} MB/s)",
        unicode_time,
        1.0 / unicode_time.as_secs_f64()
    );
    println!(
        "    Injection scanner: {:?} ({:.2} MB/s)",
        injection_time,
        1.0 / injection_time.as_secs_f64()
    );
}
