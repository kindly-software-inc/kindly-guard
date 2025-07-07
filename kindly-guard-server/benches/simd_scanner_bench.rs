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

//! Benchmarks for SIMD scanner performance

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use kindly_guard_server::{
    config::{Config, ScannerConfig},
    enhanced_impl::EnhancedComponentFactory,
    scanner::SecurityScanner,
    traits::SecurityComponentFactory,
};

fn generate_test_text(size: usize, threat_density: f32) -> String {
    let mut text = String::with_capacity(size);
    let mut chars_added = 0;
    
    while chars_added < size {
        // Add normal text
        let normal_chunk = "The quick brown fox jumps over the lazy dog. ";
        text.push_str(normal_chunk);
        chars_added += normal_chunk.len();
        
        // Occasionally add threats based on density
        if rand::random::<f32>() < threat_density {
            let threats = [
                "\u{200B}",  // Zero-width space
                "\u{202E}",  // Right-to-left override
                "' OR '1'='1",  // SQL injection
                "<script>alert(1)</script>",  // XSS
            ];
            let threat = threats[rand::random::<usize>() % threats.len()];
            text.push_str(threat);
            chars_added += threat.len();
        }
    }
    
    text.truncate(size);
    text
}

#[cfg(feature = "enhanced")]
fn bench_simd_vs_standard(c: &mut Criterion) {
    let mut group = c.benchmark_group("simd_comparison");
    
    // Test different text sizes
    for size in [1_000, 10_000, 100_000, 1_000_000] {
        let text = generate_test_text(size, 0.01); // 1% threat density
        
        // Benchmark standard scanner
        group.bench_with_input(
            BenchmarkId::new("standard", size),
            &text,
            |b, text| {
                let config = ScannerConfig {
                    unicode_detection: true,
                    injection_detection: true,
                    enhanced_mode: Some(false), // Force standard mode
                    ..Default::default()
                };
                let scanner = SecurityScanner::new(config).unwrap();
                
                b.iter(|| {
                    let threats = scanner.scan_text(black_box(text));
                    black_box(threats);
                });
            },
        );
        
        // Benchmark SIMD scanner
        group.bench_with_input(
            BenchmarkId::new("simd", size),
            &text,
            |b, text| {
                let mut config = Config::default();
                config.scanner.unicode_detection = true;
                config.scanner.injection_detection = true;
                config.scanner.enhanced_mode = Some(true); // Enable SIMD
                
                let factory = EnhancedComponentFactory;
                let scanner = factory.create_security_scanner(&config).unwrap();
                
                b.iter(|| {
                    let threats = scanner.scan_text(black_box(text));
                    black_box(threats);
                });
            },
        );
    }
    
    group.finish();
}

#[cfg(feature = "enhanced")]
fn bench_unicode_detection_simd(c: &mut Criterion) {
    let mut group = c.benchmark_group("unicode_detection");
    
    // Create text with many Unicode threats
    let mut text = String::new();
    for _ in 0..10_000 {
        text.push_str("Normal text ");
        text.push('\u{200B}'); // Zero-width space
        text.push_str(" more text ");
        text.push('\u{202E}'); // BiDi override
    }
    
    group.bench_function("simd_unicode", |b| {
        let mut config = Config::default();
        config.scanner.unicode_detection = true;
        config.scanner.enhanced_mode = Some(true);
        
        let factory = EnhancedComponentFactory;
        let scanner = factory.create_security_scanner(&config).unwrap();
        
        b.iter(|| {
            let threats = scanner.scan_text(black_box(&text));
            black_box(threats);
        });
    });
    
    group.finish();
}

#[cfg(feature = "enhanced")]
fn bench_pattern_matching_simd(c: &mut Criterion) {
    let mut group = c.benchmark_group("pattern_matching");
    
    // Create text with SQL injection patterns
    let mut text = String::new();
    for i in 0..1_000 {
        text.push_str(&format!("SELECT * FROM table{} WHERE ", i));
        if i % 10 == 0 {
            text.push_str("id = '1' OR '1'='1'");
        } else {
            text.push_str("id = 123");
        }
        text.push_str(";\n");
    }
    
    group.bench_function("simd_patterns", |b| {
        let mut config = Config::default();
        config.scanner.injection_detection = true;
        config.scanner.enhanced_mode = Some(true);
        
        let factory = EnhancedComponentFactory;
        let scanner = factory.create_security_scanner(&config).unwrap();
        
        b.iter(|| {
            let threats = scanner.scan_text(black_box(&text));
            black_box(threats);
        });
    });
    
    group.finish();
}

#[cfg(not(feature = "enhanced"))]
fn bench_standard_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("standard_scanner");
    
    for size in [1_000, 10_000, 100_000] {
        let text = generate_test_text(size, 0.01);
        
        group.bench_with_input(
            BenchmarkId::new("scan", size),
            &text,
            |b, text| {
                let config = ScannerConfig::default();
                let scanner = SecurityScanner::new(config).unwrap();
                
                b.iter(|| {
                    let threats = scanner.scan_text(black_box(text));
                    black_box(threats);
                });
            },
        );
    }
    
    group.finish();
}

#[cfg(feature = "enhanced")]
criterion_group!(
    benches,
    bench_simd_vs_standard,
    bench_unicode_detection_simd,
    bench_pattern_matching_simd
);

#[cfg(not(feature = "enhanced"))]
criterion_group!(benches, bench_standard_only);

criterion_main!(benches);