// Copyright 2025 Kindly-Software
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
//! Simple performance comparison between standard and enhanced implementations

use kindly_guard_server::{
    config::{Config, ResilienceConfig},
    neutralizer::{create_neutralizer, NeutralizerMode, NeutralizerTrait},
    scanner::{create_scanner, ScannerTrait},
};
use std::time::Instant;
use tokio;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    println!("KindlyGuard Performance Comparison");
    println!("==================================\n");

    // Test data
    let test_texts = vec![
        "Hello World",
        "Simple text with unicode: привет мир 你好世界",
        "Text with threats: '; DROP TABLE users; -- <script>alert('xss')</script>",
        "Mixed threats \u{202E}with unicode\u{200B} and injection: SELECT * FROM passwords",
    ];

    let large_text = "A".repeat(10000);
    let json_data = serde_json::json!({
        "message": "Test message",
        "user": "'; DROP TABLE users; --",
        "content": "<script>alert(1)</script>",
        "unicode": "Hello\u{202E}World"
    });

    // Standard configuration
    println!("Testing STANDARD implementation:");
    let standard_config = Config::default();
    let standard_scanner = create_scanner(&standard_config).await?;
    let standard_neutralizer = create_neutralizer(&standard_config.neutralizer, None);

    // Benchmark scanning
    let start = Instant::now();
    for _ in 0..1000 {
        for text in &test_texts {
            let _ = standard_scanner.scan_text(text).await?;
        }
    }
    let standard_scan_time = start.elapsed();
    println!("  Scan 4000 texts: {:?}", standard_scan_time);

    // Benchmark large text
    let start = Instant::now();
    for _ in 0..100 {
        let _ = standard_scanner.scan_text(&large_text).await?;
    }
    let standard_large_time = start.elapsed();
    println!("  Scan 100 large texts: {:?}", standard_large_time);

    // Benchmark neutralization
    let start = Instant::now();
    for _ in 0..1000 {
        let _ = standard_neutralizer
            .neutralize_text(&test_texts[2], NeutralizerMode::Standard)
            .await?;
    }
    let standard_neutralize_time = start.elapsed();
    println!("  Neutralize 1000 texts: {:?}", standard_neutralize_time);

    // Benchmark JSON processing
    let start = Instant::now();
    for _ in 0..1000 {
        let _ = standard_scanner.scan_json(&json_data).await?;
        let _ = standard_neutralizer
            .neutralize_json(&json_data, NeutralizerMode::Standard)
            .await?;
    }
    let standard_json_time = start.elapsed();
    println!("  Process 1000 JSON objects: {:?}", standard_json_time);

    // Enhanced configuration (if available)
    #[cfg(feature = "enhanced")]
    {
        println!("\nTesting ENHANCED implementation:");
        let mut enhanced_config = Config::default();
        enhanced_config.resilience.enhanced_mode = true;
        enhanced_config.scanner.enhanced_mode = Some(true);

        let enhanced_scanner = create_scanner(&enhanced_config).await?;
        let enhanced_neutralizer = create_neutralizer(&enhanced_config.neutralizer, None);

        // Benchmark scanning
        let start = Instant::now();
        for _ in 0..1000 {
            for text in &test_texts {
                let _ = enhanced_scanner.scan_text(text).await?;
            }
        }
        let enhanced_scan_time = start.elapsed();
        println!("  Scan 4000 texts: {:?}", enhanced_scan_time);

        // Benchmark large text
        let start = Instant::now();
        for _ in 0..100 {
            let _ = enhanced_scanner.scan_text(&large_text).await?;
        }
        let enhanced_large_time = start.elapsed();
        println!("  Scan 100 large texts: {:?}", enhanced_large_time);

        // Benchmark neutralization
        let start = Instant::now();
        for _ in 0..1000 {
            let _ = enhanced_neutralizer
                .neutralize_text(&test_texts[2], NeutralizerMode::Standard)
                .await?;
        }
        let enhanced_neutralize_time = start.elapsed();
        println!("  Neutralize 1000 texts: {:?}", enhanced_neutralize_time);

        // Benchmark JSON processing
        let start = Instant::now();
        for _ in 0..1000 {
            let _ = enhanced_scanner.scan_json(&json_data).await?;
            let _ = enhanced_neutralizer
                .neutralize_json(&json_data, NeutralizerMode::Standard)
                .await?;
        }
        let enhanced_json_time = start.elapsed();
        println!("  Process 1000 JSON objects: {:?}", enhanced_json_time);

        // Performance comparison
        println!("\nPerformance Improvement:");
        println!(
            "  Scanning: {:.1}x faster",
            standard_scan_time.as_secs_f64() / enhanced_scan_time.as_secs_f64()
        );
        println!(
            "  Large text: {:.1}x faster",
            standard_large_time.as_secs_f64() / enhanced_large_time.as_secs_f64()
        );
        println!(
            "  Neutralization: {:.1}x faster",
            standard_neutralize_time.as_secs_f64() / enhanced_neutralize_time.as_secs_f64()
        );
        println!(
            "  JSON processing: {:.1}x faster",
            standard_json_time.as_secs_f64() / enhanced_json_time.as_secs_f64()
        );
    }

    #[cfg(not(feature = "enhanced"))]
    {
        println!(
            "\nNote: Enhanced mode not available. Compile with --features enhanced to compare."
        );
    }

    Ok(())
}
