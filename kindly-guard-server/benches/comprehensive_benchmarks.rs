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
//! Comprehensive Performance Benchmark Suite for KindlyGuard
//!
//! This benchmark suite tests:
//! - Scanner performance under various loads (throughput and latency)
//! - Memory usage patterns and leak detection
//! - CPU utilization across different threat types
//! - Enhanced vs Standard mode performance comparison
//! - Multi-threaded performance scaling
//! - Large payload handling (up to 1GB)

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use kindly_guard_server::{
    component_selector::ComponentManager,
    config::{Config, ScannerConfig},
    scanner::{SecurityScanner, Severity, Threat, ThreatType},
    traits::{EnhancedScanner, RateLimitKey, SecurityEvent},
};
use rand::prelude::*;
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
use tokio::runtime::Runtime;

/// Test data generators
mod test_data {
    use super::*;

    /// Generate benign text of specified size
    pub fn generate_benign_text(size: usize) -> String {
        let words = vec![
            "The",
            "quick",
            "brown",
            "fox",
            "jumps",
            "over",
            "the",
            "lazy",
            "dog",
            "Lorem",
            "ipsum",
            "dolor",
            "sit",
            "amet",
            "consectetur",
            "adipiscing",
            "elit",
        ];
        let mut rng = thread_rng();
        let mut result = String::with_capacity(size);

        while result.len() < size {
            result.push_str(words.choose(&mut rng).unwrap());
            result.push(' ');
        }

        result.truncate(size);
        result
    }

    /// Generate text with unicode threats
    pub fn generate_unicode_threats(count: usize) -> String {
        let threats = vec![
            "\u{202E}", // Right-to-left override
            "\u{200B}", // Zero-width space
            "\u{FEFF}", // Zero-width no-break space
            "\u{200C}", // Zero-width non-joiner
            "\u{200D}", // Zero-width joiner
        ];

        let mut result = String::new();
        let mut rng = thread_rng();

        for i in 0..count {
            result.push_str(&format!("Normal text {} ", i));
            result.push_str(threats.choose(&mut rng).unwrap());
            result.push_str(&format!("more text {} ", i));
        }

        result
    }

    /// Generate SQL injection attempts
    pub fn generate_sql_injections(count: usize) -> Vec<String> {
        let patterns = vec![
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'--",
            "1 UNION SELECT * FROM passwords",
            "'; UPDATE users SET admin=1 WHERE username='attacker",
        ];

        patterns
            .into_iter()
            .cycle()
            .take(count)
            .map(String::from)
            .collect()
    }

    /// Generate mixed threat payload
    pub fn generate_mixed_threats(size: usize) -> String {
        let mut result = String::with_capacity(size);
        let mut rng = thread_rng();

        while result.len() < size {
            match rng.gen_range(0..4) {
                0 => {
                    // Add benign text
                    result.push_str("This is normal text. ");
                }
                1 => {
                    // Add unicode threat
                    result.push_str("Hidden\u{202E}text here. ");
                }
                2 => {
                    // Add SQL injection
                    result.push_str("SELECT * FROM users WHERE id = '1' OR '1'='1'. ");
                }
                3 => {
                    // Add XSS attempt
                    result.push_str("<script>alert('xss')</script> ");
                }
                _ => unreachable!(),
            }
        }

        result.truncate(size);
        result
    }

    /// Generate large JSON payload
    pub fn generate_json_payload(depth: usize, breadth: usize) -> serde_json::Value {
        use serde_json::json;

        if depth == 0 {
            return json!({
                "value": thread_rng().gen::<u64>(),
                "text": generate_benign_text(100),
            });
        }

        let mut obj = serde_json::Map::new();
        for i in 0..breadth {
            let key = format!("field_{}", i);
            obj.insert(key, generate_json_payload(depth - 1, breadth));
        }

        serde_json::Value::Object(obj)
    }
}

/// Benchmark scanner throughput with different payload sizes
fn bench_scanner_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("scanner_throughput");
    group.measurement_time(Duration::from_secs(10));

    // Test different payload sizes
    let sizes = vec![
        ("1KB", 1024),
        ("10KB", 10 * 1024),
        ("100KB", 100 * 1024),
        ("1MB", 1024 * 1024),
        ("10MB", 10 * 1024 * 1024),
    ];

    for (name, size) in sizes {
        // Prepare test data
        let benign_data = test_data::generate_benign_text(size);
        let threat_data = test_data::generate_mixed_threats(size);

        // Benchmark standard mode
        let config = ScannerConfig {
            unicode_detection: true,
            injection_detection: true,
            xss_detection: Some(true),
            enhanced_mode: false,
            ..Default::default()
        };
        let scanner = SecurityScanner::new(config).unwrap();

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new(format!("standard_benign_{}", name), size),
            &benign_data,
            |b, data| b.iter(|| scanner.scan_text(data)),
        );

        group.bench_with_input(
            BenchmarkId::new(format!("standard_threats_{}", name), size),
            &threat_data,
            |b, data| b.iter(|| scanner.scan_text(data)),
        );

        // Benchmark enhanced mode
        let enhanced_config = ScannerConfig {
            unicode_detection: true,
            injection_detection: true,
            xss_detection: Some(true),
            enhanced_mode: true,
            ..Default::default()
        };
        let enhanced_scanner = SecurityScanner::new(enhanced_config).unwrap();

        group.bench_with_input(
            BenchmarkId::new(format!("enhanced_benign_{}", name), size),
            &benign_data,
            |b, data| b.iter(|| enhanced_scanner.scan_text(data)),
        );

        group.bench_with_input(
            BenchmarkId::new(format!("enhanced_threats_{}", name), size),
            &threat_data,
            |b, data| b.iter(|| enhanced_scanner.scan_text(data)),
        );
    }

    group.finish();
}

/// Benchmark scanner latency percentiles
fn bench_scanner_latency(c: &mut Criterion) {
    let mut group = c.benchmark_group("scanner_latency");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(1000);

    // Different threat types
    let test_cases = vec![
        ("unicode_threats", test_data::generate_unicode_threats(100)),
        (
            "sql_injection",
            test_data::generate_sql_injections(10).join("\n"),
        ),
        (
            "mixed_threats",
            test_data::generate_mixed_threats(10 * 1024),
        ),
    ];

    for (threat_name, data) in test_cases {
        // Standard mode
        let config = ScannerConfig {
            unicode_detection: true,
            injection_detection: true,
            xss_detection: Some(true),
            enhanced_mode: false,
            ..Default::default()
        };
        let scanner = SecurityScanner::new(config).unwrap();

        group.bench_with_input(
            BenchmarkId::new("standard", threat_name),
            &data,
            |b, data| b.iter(|| scanner.scan_text(data)),
        );

        // Enhanced mode
        let enhanced_config = ScannerConfig {
            unicode_detection: true,
            injection_detection: true,
            xss_detection: Some(true),
            enhanced_mode: true,
            ..Default::default()
        };
        let enhanced_scanner = SecurityScanner::new(enhanced_config).unwrap();

        group.bench_with_input(
            BenchmarkId::new("enhanced", threat_name),
            &data,
            |b, data| b.iter(|| enhanced_scanner.scan_text(data)),
        );
    }

    group.finish();
}

/// Benchmark memory allocation patterns
fn bench_memory_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_usage");
    group.measurement_time(Duration::from_secs(10));

    // Test allocation patterns with different data sizes
    let sizes = vec![
        ("small", 1024),
        ("medium", 100 * 1024),
        ("large", 10 * 1024 * 1024),
    ];

    for (name, size) in sizes {
        group.bench_function(BenchmarkId::new("allocation_pattern", name), |b| {
            b.iter_batched(
                || test_data::generate_mixed_threats(size),
                |data| {
                    let config = ScannerConfig::default();
                    let scanner = SecurityScanner::new(config).unwrap();
                    scanner.scan_text(&data)
                },
                BatchSize::LargeInput,
            );
        });
    }

    // Test for memory leaks with repeated scans
    group.bench_function("leak_detection", |b| {
        let config = ScannerConfig::default();
        let scanner = SecurityScanner::new(config).unwrap();
        let data = test_data::generate_mixed_threats(1024 * 1024);

        b.iter(|| {
            for _ in 0..100 {
                let _ = scanner.scan_text(&data);
            }
        });
    });

    group.finish();
}

/// Benchmark multi-threaded performance scaling
fn bench_multi_threaded_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("multi_threaded_scaling");
    group.measurement_time(Duration::from_secs(15));
    group.sample_size(50);

    let thread_counts = vec![1, 2, 4, 8, 16];
    let data = Arc::new(test_data::generate_mixed_threats(100 * 1024));

    for mode in &["standard", "enhanced"] {
        for thread_count in &thread_counts {
            let config = ScannerConfig {
                unicode_detection: true,
                injection_detection: true,
                xss_detection: Some(true),
                enhanced_mode: *mode == "enhanced",
                ..Default::default()
            };

            group.bench_with_input(
                BenchmarkId::new(mode, thread_count),
                thread_count,
                |b, &thread_count| {
                    b.iter(|| {
                        let mut handles = vec![];
                        let processed = Arc::new(AtomicU64::new(0));

                        for _ in 0..thread_count {
                            let data_clone = data.clone();
                            let processed_clone = processed.clone();
                            let config_clone = config.clone();

                            let handle = thread::spawn(move || {
                                let scanner = SecurityScanner::new(config_clone).unwrap();
                                let start = Instant::now();

                                while start.elapsed() < Duration::from_secs(1) {
                                    let _ = scanner.scan_text(&data_clone);
                                    processed_clone.fetch_add(1, Ordering::Relaxed);
                                }
                            });

                            handles.push(handle);
                        }

                        for handle in handles {
                            handle.join().unwrap();
                        }

                        processed.load(Ordering::Relaxed)
                    });
                },
            );
        }
    }

    group.finish();
}

/// Benchmark large payload handling
fn bench_large_payloads(c: &mut Criterion) {
    let mut group = c.benchmark_group("large_payloads");
    group.measurement_time(Duration::from_secs(20));
    group.sample_size(10);

    // Test increasingly large payloads
    let sizes = vec![
        ("100MB", 100 * 1024 * 1024),
        ("250MB", 250 * 1024 * 1024),
        ("500MB", 500 * 1024 * 1024),
        // Note: 1GB tests are memory intensive, uncomment with caution
        // ("1GB", 1024 * 1024 * 1024),
    ];

    for (name, size) in sizes {
        // Skip if not enough memory
        if size > 500 * 1024 * 1024 {
            eprintln!("Skipping {} test - requires significant memory", name);
            continue;
        }

        group.throughput(Throughput::Bytes(size as u64));

        for mode in &["standard", "enhanced"] {
            group.bench_function(BenchmarkId::new(mode, name), |b| {
                b.iter_batched(
                    || test_data::generate_benign_text(size),
                    |data| {
                        let config = ScannerConfig {
                            unicode_detection: true,
                            injection_detection: true,
                            xss_detection: Some(true),
                            enhanced_mode: *mode == "enhanced",
                            ..Default::default()
                        };
                        let scanner = SecurityScanner::new(config).unwrap();
                        scanner.scan_text(&data)
                    },
                    BatchSize::PerIteration,
                );
            });
        }
    }

    group.finish();
}

/// Benchmark JSON scanning with deep nesting
fn bench_json_scanning(c: &mut Criterion) {
    let mut group = c.benchmark_group("json_scanning");
    group.measurement_time(Duration::from_secs(10));

    // Test different JSON structures
    let test_cases = vec![
        ("shallow_wide", 2, 100), // Shallow but wide
        ("deep_narrow", 10, 3),   // Deep but narrow
        ("balanced", 5, 10),      // Balanced tree
    ];

    for (name, depth, breadth) in test_cases {
        let json_data = test_data::generate_json_payload(depth, breadth);

        for mode in &["standard", "enhanced"] {
            let config = ScannerConfig {
                unicode_detection: true,
                injection_detection: true,
                xss_detection: Some(true),
                enhanced_mode: *mode == "enhanced",
                max_scan_depth: 20,
                ..Default::default()
            };
            let scanner = SecurityScanner::new(config).unwrap();

            group.bench_with_input(BenchmarkId::new(mode, name), &json_data, |b, data| {
                b.iter(|| scanner.scan_json(data))
            });
        }
    }

    group.finish();
}

/// Benchmark CPU utilization patterns
fn bench_cpu_utilization(c: &mut Criterion) {
    let mut group = c.benchmark_group("cpu_utilization");
    group.measurement_time(Duration::from_secs(10));

    // Different workload types
    let workloads = vec![
        ("cpu_light", test_data::generate_benign_text(10 * 1024)),
        ("cpu_moderate", test_data::generate_unicode_threats(100)),
        ("cpu_heavy", test_data::generate_mixed_threats(100 * 1024)),
    ];

    for (name, data) in workloads {
        for mode in &["standard", "enhanced"] {
            let config = ScannerConfig {
                unicode_detection: true,
                injection_detection: true,
                xss_detection: Some(true),
                enhanced_mode: *mode == "enhanced",
                ..Default::default()
            };
            let scanner = SecurityScanner::new(config).unwrap();

            group.bench_with_input(BenchmarkId::new(mode, name), &data, |b, data| {
                b.iter(|| {
                    // Simulate real workload with some processing
                    let threats = scanner.scan_text(data).unwrap();

                    // Process threats (simulating real usage)
                    let high_severity_count = threats
                        .iter()
                        .filter(|t| t.severity >= Severity::High)
                        .count();

                    criterion::black_box(high_severity_count)
                })
            });
        }
    }

    group.finish();
}

/// Benchmark event processing performance
fn bench_event_processing(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_processing");
    group.measurement_time(Duration::from_secs(10));

    let rt = Runtime::new().unwrap();

    // Different event patterns
    let event_patterns = vec![
        ("single_client", 1, 1000),
        ("multi_client", 100, 10),
        ("burst_traffic", 10, 100),
    ];

    for (name, client_count, events_per_client) in event_patterns {
        for mode in &["standard", "enhanced"] {
            let mut config = Config::default();
            config.event_processor.enabled = *mode == "enhanced";

            let manager = ComponentManager::new(&config).unwrap();
            let processor = manager.event_processor();

            group.bench_with_input(
                BenchmarkId::new(mode, name),
                &(client_count, events_per_client),
                |b, &(clients, events)| {
                    b.iter(|| {
                        rt.block_on(async {
                            let mut handles = vec![];

                            for client_id in 0..clients {
                                for event_id in 0..events {
                                    let event = SecurityEvent {
                                        event_type: "request".to_string(),
                                        client_id: format!("client_{}", client_id),
                                        timestamp: event_id as u64,
                                        metadata: serde_json::json!({
                                            "method": "test",
                                            "path": "/api/test",
                                        }),
                                    };

                                    handles.push(processor.process_event(event));
                                }
                            }

                            // Wait for all events to be processed
                            for handle in handles {
                                let _ = handle.await;
                            }
                        });
                    });
                },
            );
        }
    }

    group.finish();
}

/// Benchmark rate limiting performance
fn bench_rate_limiting(c: &mut Criterion) {
    let mut group = c.benchmark_group("rate_limiting");
    group.measurement_time(Duration::from_secs(10));

    let rt = Runtime::new().unwrap();

    // Different access patterns
    let patterns = vec![
        ("steady_rate", 100, 10),
        ("burst_pattern", 10, 100),
        ("distributed", 1000, 1),
    ];

    for (name, client_count, requests_per_client) in patterns {
        for mode in &["standard", "enhanced"] {
            let mut config = Config::default();
            config.event_processor.enabled = *mode == "enhanced";

            let manager = ComponentManager::new(&config).unwrap();
            let rate_limiter = manager.rate_limiter();

            group.bench_with_input(
                BenchmarkId::new(mode, name),
                &(client_count, requests_per_client),
                |b, &(clients, requests)| {
                    b.iter(|| {
                        rt.block_on(async {
                            for client_id in 0..clients {
                                for _ in 0..requests {
                                    let key = RateLimitKey {
                                        client_id: format!("client_{}", client_id),
                                        method: Some("test".to_string()),
                                    };

                                    let _ = rate_limiter.check_rate_limit(&key).await;
                                }
                            }
                        });
                    });
                },
            );
        }
    }

    group.finish();
}

/// Main benchmark groups
criterion_group! {
    name = comprehensive_benches;
    config = Criterion::default()
        .significance_level(0.1)
        .noise_threshold(0.05);
    targets =
        bench_scanner_throughput,
        bench_scanner_latency,
        bench_memory_usage,
        bench_multi_threaded_scaling,
        bench_large_payloads,
        bench_json_scanning,
        bench_cpu_utilization,
        bench_event_processing,
        bench_rate_limiting
}

criterion_main!(comprehensive_benches);
