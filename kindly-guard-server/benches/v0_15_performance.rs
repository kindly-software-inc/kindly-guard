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

//! KindlyGuard v0.15.0 Performance Benchmarks
//!
//! Measures performance of key components:
//! - Scanner performance (threat detection speed)
//! - Neutralizer performance (threat neutralization speed)
//! - Quarantine encryption/decryption performance
//! - Message formatting performance

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use kindly_guard_server::{
    scanner::{SecurityScanner, ThreatType},
    neutralizer::{ThreatNeutralizer, NeutralizationConfig},
    quarantine::{QuarantineManager, QuarantineConfig},
    messages::{MessageFormatter, FormatConfig},
};
use std::time::Duration;

const KB: usize = 1024;
const MB: usize = 1024 * KB;

/// Benchmark scanner performance with various input sizes
fn bench_scanner_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("scanner_performance");
    group.measurement_time(Duration::from_secs(10));
    
    let scanner = SecurityScanner::new();
    
    // Test different input sizes
    for size in &[1 * KB, 10 * KB, 100 * KB, 1 * MB] {
        let clean_text = "The quick brown fox jumps over the lazy dog. ".repeat(size / 45);
        let clean_text = &clean_text[..=*size];
        
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            format!("clean_text_{}_kb", size / KB),
            &clean_text,
            |b, text| {
                b.iter(|| {
                    let threats = scanner.scan_text(black_box(text));
                    black_box(threats);
                });
            },
        );
        
        // Text with unicode threats
        let unicode_text = format!(
            "{}Hello\u{200B}World\u{202E}Test{}",
            &clean_text[..size / 2],
            &clean_text[size / 2..]
        );
        
        group.bench_with_input(
            format!("unicode_threats_{}_kb", size / KB),
            &unicode_text,
            |b, text| {
                b.iter(|| {
                    let threats = scanner.scan_text(black_box(text));
                    black_box(threats);
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark neutralizer performance
fn bench_neutralizer_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("neutralizer_performance");
    group.measurement_time(Duration::from_secs(10));
    
    let config = NeutralizationConfig::default();
    let neutralizer = ThreatNeutralizer::new(config);
    
    // Test different threat types
    let test_cases = vec![
        ("sql_injection", "SELECT * FROM users WHERE id = '1' OR '1'='1'"),
        ("xss_script", "<script>alert('XSS')</script>"),
        ("unicode_bidi", "Hello\u{202E}World"),
        ("command_injection", "ls -la; rm -rf /"),
    ];
    
    for (name, content) in test_cases {
        group.bench_with_input(
            name,
            &content,
            |b, text| {
                b.iter(|| {
                    let result = neutralizer.neutralize(black_box(text));
                    black_box(result);
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark quarantine encryption/decryption
fn bench_quarantine_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("quarantine_performance");
    group.measurement_time(Duration::from_secs(10));
    
    let config = QuarantineConfig::default();
    let manager = QuarantineManager::new(config).unwrap();
    
    // Test different content sizes
    for size in &[1 * KB, 10 * KB, 100 * KB] {
        let content = vec![0u8; *size];
        
        group.throughput(Throughput::Bytes(*size as u64));
        
        // Benchmark encryption
        group.bench_with_input(
            format!("encrypt_{}_kb", size / KB),
            &content,
            |b, data| {
                b.iter(|| {
                    let encrypted = manager.encrypt(black_box(data));
                    black_box(encrypted);
                });
            },
        );
        
        // Benchmark decryption
        let encrypted = manager.encrypt(&content).unwrap();
        group.bench_with_input(
            format!("decrypt_{}_kb", size / KB),
            &encrypted,
            |b, data| {
                b.iter(|| {
                    let decrypted = manager.decrypt(black_box(data));
                    black_box(decrypted);
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark message formatting performance
fn bench_message_formatting(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_formatting");
    group.measurement_time(Duration::from_secs(5));
    
    let config = FormatConfig::default();
    let formatter = MessageFormatter::new(config);
    
    // Test different message complexities
    let messages = vec![
        ("simple", "This is a simple message"),
        ("with_unicode", "Message with unicode: 🔒 Security Alert"),
        ("long_message", &"A".repeat(1000)),
        ("formatted", "User {} attempted {} at {}"),
    ];
    
    for (name, template) in messages {
        group.bench_with_input(
            name,
            &template,
            |b, msg| {
                b.iter(|| {
                    let formatted = formatter.format(black_box(msg));
                    black_box(formatted);
                });
            },
        );
    }
    
    group.finish();
}

criterion_group!(
    benches,
    bench_scanner_performance,
    bench_neutralizer_performance,
    bench_quarantine_performance,
    bench_message_formatting
);
criterion_main!(benches);