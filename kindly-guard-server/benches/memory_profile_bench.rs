//! Memory profiling benchmarks to track allocations and identify leaks

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use kindly_guard_server::{
    metrics::{KindlyMetrics, MetricsRegistry},
    Config, McpServer, ScannerConfig, SecurityScanner,
};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

/// Get current memory stats
fn get_memory_stats() -> (usize, usize) {
    // Using jemalloc stats
    let epoch_mib = jemalloc_ctl::epoch::mib().unwrap();
    let allocated_mib = jemalloc_ctl::stats::allocated::mib().unwrap();
    let resident_mib = jemalloc_ctl::stats::resident::mib().unwrap();

    epoch_mib.advance().unwrap();
    let allocated = allocated_mib.read().unwrap();
    let resident = resident_mib.read().unwrap();

    (allocated, resident)
}

/// Benchmark memory usage during threat scanning
fn bench_scanner_memory_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("scanner_memory");
    group.measurement_time(Duration::from_secs(10));

    // Test both standard and enhanced modes
    for mode in &["standard", "enhanced"] {
        let enhanced = *mode == "enhanced";
        let mut config = Config::default();
        config.event_processor.enabled = enhanced;

        let scanner_config = ScannerConfig {
            unicode_detection: true,
            injection_detection: true,
            path_traversal_detection: true,
            xss_detection: Some(true),
            enhanced_mode: Some(enhanced),
            custom_patterns: None,
            max_scan_depth: 10,
            enable_event_buffer: false,
        };
        let scanner = SecurityScanner::new(scanner_config).unwrap();

        // Different input sizes to measure memory scaling
        let test_cases = vec![
            ("1KB", "A".repeat(1024)),
            ("10KB", "B".repeat(10 * 1024)),
            ("100KB", "C".repeat(100 * 1024)),
            ("1MB", "D".repeat(1024 * 1024)),
        ];

        for (size_name, text) in test_cases {
            let bench_name = format!("{}/{}", mode, size_name);
            group.bench_function(BenchmarkId::from_parameter(&bench_name), |b| {
                b.iter_custom(|iters| {
                    let (start_allocated, _) = get_memory_stats();

                    let start = std::time::Instant::now();
                    for _ in 0..iters {
                        black_box(scanner.scan_text(&text));
                    }
                    let elapsed = start.elapsed();

                    let (end_allocated, _) = get_memory_stats();
                    let memory_per_iter = (end_allocated - start_allocated) / iters as usize;

                    eprintln!(
                        "{} {}: ~{} bytes per scan",
                        mode, size_name, memory_per_iter
                    );

                    elapsed
                });
            });
        }
    }

    group.finish();
}

/// Benchmark memory usage during concurrent operations
fn bench_concurrent_memory_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_memory");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(20);

    let rt = tokio::runtime::Runtime::new().unwrap();

    // Test different concurrency levels
    for num_tasks in [10, 50, 100, 500] {
        group.bench_function(
            BenchmarkId::from_parameter(format!("{}_tasks", num_tasks)),
            |b| {
                b.iter_custom(|iters| {
                    let (start_allocated, _) = get_memory_stats();

                    let start = std::time::Instant::now();
                    for _ in 0..iters {
                        rt.block_on(async {
                            let tasks: Vec<_> = (0..num_tasks)
                                .map(|i| {
                                    tokio::spawn(async move {
                                        let scanner_config = ScannerConfig {
                                            unicode_detection: true,
                                            injection_detection: true,
                                            path_traversal_detection: true,
                                            xss_detection: Some(true),
                                            enhanced_mode: Some(false),
                                            custom_patterns: None,
                                            max_scan_depth: 10,
                                            enable_event_buffer: false,
                                        };
                                        let scanner = SecurityScanner::new(scanner_config).unwrap();
                                        let text = format!("Test text {}", i);
                                        scanner.scan_text(&text)
                                    })
                                })
                                .collect();

                            for task in tasks {
                                black_box(task.await.unwrap());
                            }
                        });
                    }
                    let elapsed = start.elapsed();

                    let (end_allocated, _) = get_memory_stats();
                    let memory_per_iter = (end_allocated - start_allocated) / iters as usize;

                    eprintln!(
                        "{} tasks: ~{} KB per iteration",
                        num_tasks,
                        memory_per_iter / 1024
                    );

                    elapsed
                });
            },
        );
    }

    group.finish();
}

/// Benchmark metrics registry memory overhead
fn bench_metrics_memory_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("metrics_memory");

    group.bench_function("registry_with_metrics", |b| {
        b.iter_custom(|iters| {
            let (start_allocated, _) = get_memory_stats();

            let start = std::time::Instant::now();
            for _ in 0..iters {
                let registry = Arc::new(MetricsRegistry::new());
                let metrics = KindlyMetrics::new(&registry);

                // Simulate some metric activity
                for i in 0..100 {
                    metrics.requests_total.inc();
                    if i % 10 == 0 {
                        metrics.threats_detected.inc();
                    }
                    metrics.request_duration.observe(i as f64 * 0.01);
                }

                black_box(registry.export_prometheus());
            }
            let elapsed = start.elapsed();

            let (end_allocated, _) = get_memory_stats();
            let memory_per_iter = (end_allocated - start_allocated) / iters as usize;

            eprintln!(
                "Metrics registry: ~{} KB per instance",
                memory_per_iter / 1024
            );

            elapsed
        });
    });

    group.finish();
}

/// Benchmark server lifecycle memory patterns
fn bench_server_lifecycle_memory(c: &mut Criterion) {
    let mut group = c.benchmark_group("server_lifecycle_memory");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(10);

    let rt = tokio::runtime::Runtime::new().unwrap();

    // Test both standard and enhanced modes
    for mode in &["standard", "enhanced"] {
        let enhanced = *mode == "enhanced";

        group.bench_function(BenchmarkId::from_parameter(format!("{}_mode", mode)), |b| {
            b.iter_custom(|iters| {
                let (start_allocated, _) = get_memory_stats();

                let start = std::time::Instant::now();
                for _ in 0..iters {
                    let mut config = Config::default();
                    config.server.stdio = true;
                    config.shield.enabled = false;
                    config.auth.enabled = false;
                    config.event_processor.enabled = enhanced;

                    let server = Arc::new(McpServer::new(config).unwrap());

                    // Initialize
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
                    rt.block_on(async { server.handle_message(&init_request.to_string()).await });

                    // Perform some operations
                    for i in 0..10 {
                        let request = json!({
                            "jsonrpc": "2.0",
                            "method": "tools/call",
                            "params": {
                                "name": "scan_text",
                                "arguments": {
                                    "text": format!("Test {}", i)
                                }
                            },
                            "id": i
                        });
                        rt.block_on(async {
                            black_box(server.handle_message(&request.to_string()).await)
                        });
                    }

                    // Server drops here
                }
                let elapsed = start.elapsed();

                let (end_allocated, _) = get_memory_stats();
                let memory_per_iter = (end_allocated - start_allocated) / iters as usize;

                eprintln!(
                    "{} server lifecycle: ~{} KB per create/destroy cycle",
                    mode,
                    memory_per_iter / 1024
                );

                elapsed
            });
        });
    }

    group.finish();
}

/// Test for memory leaks during long-running operations
fn bench_memory_leak_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_leak_detection");
    group.measurement_time(Duration::from_secs(30));
    group.sample_size(10);

    let rt = tokio::runtime::Runtime::new().unwrap();

    // Test both standard and enhanced modes
    for mode in &["standard", "enhanced"] {
        let enhanced = *mode == "enhanced";

        group.bench_function(
            BenchmarkId::from_parameter(format!("{}_long_running", mode)),
            |b| {
                b.iter_custom(|iters| {
                    let mut config = Config::default();
                    config.server.stdio = true;
                    config.shield.enabled = false;
                    config.auth.enabled = false;
                    config.event_processor.enabled = enhanced;

                    let server = Arc::new(McpServer::new(config).unwrap());

                    // Initialize once
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
                    rt.block_on(async {
                        server.handle_message(&init_request.to_string()).await
                    });

                    let mut memory_samples = Vec::new();

                    let start = std::time::Instant::now();
                    for i in 0..iters {
                        // Perform operations
                        for j in 0..100 {
                            let request = json!({
                                "jsonrpc": "2.0",
                                "method": "tools/call",
                                "params": {
                                    "name": "scan_text",
                                    "arguments": {
                                        "text": format!("Test iteration {} request {}", i, j)
                                    }
                                },
                                "id": j
                            });
                            rt.block_on(async {
                                black_box(server.handle_message(&request.to_string()).await)
                            });
                        }

                        // Sample memory every 10 iterations
                        if i % 10 == 0 {
                            let (allocated, resident) = get_memory_stats();
                            memory_samples.push((i, allocated, resident));
                        }
                    }
                    let elapsed = start.elapsed();

                    // Analyze memory growth
                    if memory_samples.len() > 2 {
                        let first = memory_samples.first().unwrap();
                        let last = memory_samples.last().unwrap();
                        let growth = last.1 as f64 - first.1 as f64;
                        let growth_per_iter = growth / (last.0 - first.0) as f64;

                        eprintln!(
                            "{} mode - Memory growth: {:.2} KB total, {:.2} bytes/iteration",
                            mode,
                            growth / 1024.0,
                            growth_per_iter
                        );

                        // Warn if significant growth detected
                        if growth_per_iter > 1000.0 {
                            eprintln!("WARNING: Potential memory leak detected in {} mode!", mode);
                        }
                    }

                    elapsed
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_scanner_memory_usage,
    bench_concurrent_memory_usage,
    bench_metrics_memory_overhead,
    bench_server_lifecycle_memory,
    bench_memory_leak_detection
);
criterion_main!(benches);
