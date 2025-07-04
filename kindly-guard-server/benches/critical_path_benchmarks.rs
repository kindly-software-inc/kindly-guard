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
//! Critical path performance benchmarks for production readiness

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use kindly_guard_server::{
    metrics::MetricsRegistry,
    scanner::{SecurityScanner, UnicodeScanner},
    security::hardening::CommandRateLimiter,
    Config, McpServer, ScannerConfig,
};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

/// Benchmark unicode threat detection performance
fn bench_unicode_scanning(c: &mut Criterion) {
    let mut group = c.benchmark_group("unicode_scanning");

    // Test different text sizes
    let test_cases = vec![
        ("small", "Hello World".to_string()),
        ("medium", "A".repeat(1000)),
        ("large", "B".repeat(10000)),
        (
            "unicode_threat",
            "Hello\u{202E}World\u{200B}Test\u{FEFF}".to_string(),
        ),
    ];

    let scanner = UnicodeScanner::new();

    for (name, text) in test_cases {
        group.throughput(Throughput::Bytes(text.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), &text, |b, text| {
            b.iter(|| black_box(scanner.scan_text(text)));
        });
    }

    group.finish();
}

/// Benchmark SQL injection detection
fn bench_sql_injection_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("sql_injection");

    let test_cases = vec![
        ("safe", "SELECT * FROM users WHERE id = ?"),
        (
            "simple_injection",
            "SELECT * FROM users WHERE id = 1 OR 1=1",
        ),
        (
            "union_attack",
            "SELECT * FROM users UNION SELECT * FROM passwords",
        ),
        ("complex", "'; DROP TABLE users; --"),
    ];

    let scanner_config = ScannerConfig {
        unicode_detection: true,
        injection_detection: true,
        path_traversal_detection: true,
        xss_detection: Some(true),
        enhanced_mode: Some(false),
        custom_patterns: None,
        max_scan_depth: 10,
        enable_event_buffer: false,
        crypto_detection: true,
        max_content_size: 10_485_760, // 10MB for benchmarks
    };
    let scanner = SecurityScanner::new(scanner_config).unwrap();

    for (name, query) in test_cases {
        group.bench_with_input(BenchmarkId::from_parameter(name), &query, |b, query| {
            b.iter(|| black_box(scanner.scan_text(query)));
        });
    }

    group.finish();
}

/// Benchmark MCP request handling latency
fn bench_mcp_request_handling(c: &mut Criterion) {
    let mut group = c.benchmark_group("mcp_request_handling");
    group.measurement_time(Duration::from_secs(10));

    // Create runtime for async operations
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Test both standard and enhanced modes
    for mode in &["standard", "enhanced"] {
        let enhanced = *mode == "enhanced";

        // Setup server
        let mut config = Config::default();
        config.server.stdio = true;
        config.shield.enabled = false;
        config.auth.enabled = false; // Disable auth for pure request handling benchmark
        config.event_processor.enabled = enhanced;

        let server = Arc::new(McpServer::new(config).unwrap());

        // Initialize server
        rt.block_on(async {
            let init_request = json!({
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {
                        "name": "bench-client",
                        "version": "1.0.0"
                    }
                },
                "id": 1
            });
            server.handle_message(&init_request.to_string()).await;
        });

        // Test different request types
        let test_requests = vec![
            (
                "tools_list",
                json!({
                    "jsonrpc": "2.0",
                    "method": "tools/list",
                    "params": {},
                    "id": 1
                }),
            ),
            (
                "scan_small",
                json!({
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "name": "scan_text",
                        "arguments": {
                            "text": "Hello World"
                        }
                    },
                    "id": 1
                }),
            ),
            (
                "scan_large",
                json!({
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "name": "scan_text",
                        "arguments": {
                            "text": "X".repeat(1000)
                        }
                    },
                    "id": 1
                }),
            ),
        ];

        for (req_name, request) in test_requests {
            let server_clone = server.clone();
            let bench_name = format!("{}/{}", mode, req_name);
            group.bench_function(BenchmarkId::from_parameter(&bench_name), |b| {
                b.iter(|| {
                    let request_str = request.to_string();
                    rt.block_on(async {
                        black_box(server_clone.handle_message(&request_str).await)
                    })
                });
            });
        }
    }

    group.finish();
}

/// Benchmark rate limiting performance
fn bench_rate_limiting(c: &mut Criterion) {
    let mut group = c.benchmark_group("rate_limiting");

    let rate_limiter = CommandRateLimiter::new();

    // Test different scenarios
    let commands = vec!["scan", "status", "dashboard"];

    for command in commands {
        group.bench_function(BenchmarkId::from_parameter(command), |b| {
            let mut counter = 0;
            b.iter(|| {
                // Use different "time" by rotating commands to avoid hitting rate limit
                let test_command = format!("{}_{}", command, counter % 10);
                counter += 1;
                black_box(rate_limiter.check_command(&test_command))
            });
        });
    }

    group.finish();
}

/// Benchmark metrics collection overhead
fn bench_metrics_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("metrics_overhead");

    let registry = Arc::new(MetricsRegistry::new());

    // Create metrics
    let counter = registry.counter("test_counter", "Test counter");
    let gauge = registry.gauge("test_gauge", "Test gauge");
    let histogram = registry.histogram(
        "test_histogram",
        "Test histogram",
        vec![0.1, 0.5, 1.0, 5.0, 10.0],
    );

    group.bench_function("counter_increment", |b| {
        b.iter(|| {
            counter.inc();
        });
    });

    group.bench_function("gauge_set", |b| {
        let mut value = 0.0;
        b.iter(|| {
            gauge.set(value as i64);
            value += 1.0;
        });
    });

    group.bench_function("histogram_observe", |b| {
        let mut value = 0.0;
        b.iter(|| {
            histogram.observe(value);
            value += 0.1;
        });
    });

    group.bench_function("metrics_export", |b| {
        // Add some data
        for i in 0..100 {
            counter.inc();
            gauge.set(i as i64);
            histogram.observe(i as f64 * 0.1);
        }

        b.iter(|| black_box(registry.export_prometheus()));
    });

    group.finish();
}

/// Benchmark memory allocation patterns
fn bench_memory_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_patterns");
    group.measurement_time(Duration::from_secs(5));

    // Test threat allocation patterns
    group.bench_function("threat_vector_allocation", |b| {
        let scanner_config = ScannerConfig {
            unicode_detection: true,
            injection_detection: true,
            path_traversal_detection: true,
            xss_detection: Some(true),
            enhanced_mode: Some(false),
            custom_patterns: None,
            max_scan_depth: 10,
            enable_event_buffer: false,
            crypto_detection: true,
            max_content_size: 10_485_760, // 10MB for benchmarks
        };
        let scanner = SecurityScanner::new(scanner_config).unwrap();
        let text = "A".repeat(1000);

        b.iter(|| {
            // This allocates a new Vec<Threat> each time
            black_box(scanner.scan_text(&text))
        });
    });

    // Test JSON serialization patterns
    group.bench_function("json_serialization", |b| {
        let data = json!({
            "threats": [
                {"type": "unicode", "position": 10},
                {"type": "sql_injection", "pattern": "OR 1=1"},
            ],
            "metadata": {
                "scan_time_ms": 5,
                "scanner_version": "1.0.0"
            }
        });

        b.iter(|| black_box(serde_json::to_string(&data).unwrap()));
    });

    group.finish();
}

/// Benchmark concurrent request handling
fn bench_concurrent_requests(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_requests");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(50);

    let rt = tokio::runtime::Runtime::new().unwrap();

    // Test both standard and enhanced modes
    for mode in &["standard", "enhanced"] {
        let enhanced = *mode == "enhanced";

        // Setup server
        let mut config = Config::default();
        config.server.stdio = true;
        config.shield.enabled = false;
        config.auth.enabled = false;
        config.event_processor.enabled = enhanced;

        let server = Arc::new(McpServer::new(config).unwrap());

        // Initialize
        rt.block_on(async {
            let init_request = json!({
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {
                        "name": "bench-client",
                        "version": "1.0.0"
                    }
                },
                "id": 1
            });
            server.handle_message(&init_request.to_string()).await;
        });

        // Test different concurrency levels
        for concurrency in [1, 10, 50, 100] {
            let server_clone = server.clone();
            let bench_name = format!("{}/{}_concurrent", mode, concurrency);
            group.bench_function(BenchmarkId::from_parameter(&bench_name), |b| {
                b.iter(|| {
                    rt.block_on(async {
                        let tasks: Vec<_> = (0..concurrency)
                            .map(|i| {
                                let server = server_clone.clone();
                                tokio::spawn(async move {
                                    let request = json!({
                                        "jsonrpc": "2.0",
                                        "method": "tools/call",
                                        "params": {
                                            "name": "scan_text",
                                            "arguments": {
                                                "text": format!("Test text {}", i)
                                            }
                                        },
                                        "id": i
                                    });
                                    server.handle_message(&request.to_string()).await
                                })
                            })
                            .collect();

                        for task in tasks {
                            black_box(task.await.unwrap());
                        }
                    })
                });
            });
        }
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_unicode_scanning,
    bench_sql_injection_detection,
    bench_mcp_request_handling,
    bench_rate_limiting,
    bench_metrics_overhead,
    bench_memory_patterns,
    bench_concurrent_requests
);
criterion_main!(benches);
