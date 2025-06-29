# Performance Testing Guide

## Overview

KindlyGuard includes comprehensive performance benchmarks and regression tests to ensure the security features don't compromise performance.

## Running Benchmarks

### Quick Start

```bash
# Run all performance benchmarks
cargo bench

# Run specific benchmark suite
cargo bench --bench simple_benchmark
cargo bench --bench regression_benchmarks
```

### Performance Regression Testing

Use the performance regression script to detect performance degradations:

```bash
# Create a baseline
./scripts/perf-regression.sh --baseline

# Run tests and compare against baseline
./scripts/perf-regression.sh
```

## Benchmark Suites

### 1. Simple Benchmarks (`simple_benchmark.rs`)

Compares standard vs enhanced modes for core components:
- Event processing throughput
- Rate limiting performance
- Security scanning speed
- Event correlation efficiency

### 2. Regression Benchmarks (`regression_benchmarks.rs`)

Detailed performance tests for regression detection:

#### Unicode Scanning
- Clean ASCII text
- BiDi override characters
- Zero-width spaces
- Homoglyphs
- Combining characters
- Mixed threats

#### Auth Token Validation
- Valid tokens
- Expired tokens
- Malformed tokens

#### Permission Checking
- Various authentication states
- Different threat levels
- Complex permission rules

#### MCP Protocol Parsing
- Simple requests
- Complex requests with nested data
- Batch requests

#### JSON Scanning
- Simple objects
- Deeply nested structures
- Large arrays
- Threat-containing JSON

#### Large Payload Handling
- 1KB to 1MB payloads
- Throughput measurements

#### Concurrent Request Handling
- 1 to 100 concurrent requests
- Server scalability testing

## Performance Targets

### Response Time Targets

| Operation | Target | Maximum |
|-----------|--------|---------|
| Unicode scan (1KB) | < 100μs | 500μs |
| Token validation | < 50μs | 200μs |
| Permission check | < 10μs | 50μs |
| MCP request parse | < 100μs | 500μs |
| JSON scan (simple) | < 200μs | 1ms |

### Throughput Targets

| Component | Target | Minimum |
|-----------|--------|---------|
| Event processing | > 100k/sec | 50k/sec |
| Rate limiting checks | > 1M/sec | 500k/sec |
| Text scanning | > 100MB/sec | 50MB/sec |

## Optimization Guidelines

### 1. Profile First

```bash
# CPU profiling
cargo build --release
perf record --call-graph=dwarf target/release/kindly-guard
perf report

# Memory profiling
valgrind --tool=massif target/release/kindly-guard
```

### 2. Common Optimizations

#### String Operations
```rust
// Good: Borrow when possible
fn scan_text(&self, text: &str) -> Vec<Threat>

// Bad: Unnecessary allocation
fn scan_text(&self, text: String) -> Vec<Threat>
```

#### Collections
```rust
// Good: Pre-allocate when size is known
let mut results = Vec::with_capacity(estimated_size);

// Good: Use SmallVec for small collections
use smallvec::SmallVec;
let threats: SmallVec<[Threat; 4]> = SmallVec::new();
```

#### Async Operations
```rust
// Good: Batch operations
let results = futures::future::join_all(operations).await;

// Bad: Sequential awaits
for op in operations {
    let _ = op.await;
}
```

### 3. SIMD Optimizations

For unicode scanning, consider SIMD when available:

```rust
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

// Use SIMD for parallel character checking
```

## Regression Detection

The regression script automatically detects performance degradations:

1. **Baseline Creation**: Run with `--baseline` to establish performance baseline
2. **Threshold**: 5% regression triggers a warning
3. **Reporting**: Color-coded output shows regressions, improvements, and stable performance

## Continuous Monitoring

### CI Integration

The GitHub Actions workflow runs benchmarks on:
- Every PR to detect regressions early
- Nightly builds to track long-term trends
- Release candidates for final validation

### Metrics Collection

Performance metrics are collected for:
- Response time percentiles (p50, p95, p99)
- Throughput (requests/second)
- Memory usage
- CPU utilization

## Benchmark Development

When adding new benchmarks:

1. **Representative Workloads**: Use realistic data and scenarios
2. **Stable Measurements**: Ensure consistent results across runs
3. **Meaningful Comparisons**: Compare similar operations
4. **Documentation**: Explain what each benchmark measures

Example benchmark structure:

```rust
fn bench_new_feature(c: &mut Criterion) {
    let mut group = c.benchmark_group("new_feature");
    group.measurement_time(Duration::from_secs(10));
    
    for scenario in scenarios {
        group.bench_with_input(
            BenchmarkId::from_parameter(&scenario.name),
            &scenario,
            |b, scenario| {
                b.iter(|| {
                    // Benchmark code
                });
            },
        );
    }
    
    group.finish();
}
```

## Troubleshooting

### Inconsistent Results

- Ensure system is idle
- Disable CPU frequency scaling
- Use `--release` builds
- Increase sample size

### Memory Issues

- Monitor with `htop` during benchmarks
- Check for memory leaks with valgrind
- Use bounded collections

### Slow Benchmarks

- Reduce measurement time for quick iterations
- Use smaller datasets during development
- Profile to find bottlenecks

## Tools

### Required
- `cargo bench` - Built into Cargo
- `criterion` - Benchmarking framework

### Recommended
- `critcmp` - Compare benchmark results
- `perf` - Linux profiling
- `flamegraph` - Visualization
- `cargo-flamegraph` - Easy flamegraph generation

Install tools:
```bash
cargo install critcmp
cargo install flamegraph
```

## Best Practices

1. **Run on consistent hardware** - Use the same machine for comparisons
2. **Multiple runs** - Average results across multiple runs
3. **Document changes** - Note any optimizations in commit messages
4. **Test edge cases** - Include worst-case scenarios
5. **Monitor trends** - Track performance over time