# KindlyGuard Performance Benchmarks

This directory contains performance benchmarks for KindlyGuard to ensure production readiness.

## Available Benchmarks

### 1. Critical Path Benchmarks (`critical_path_benchmarks.rs`)
Tests the performance of critical code paths:
- **Unicode Scanning**: Tests threat detection performance for various text sizes
- **SQL Injection Detection**: Benchmarks pattern matching for SQL injection attempts
- **MCP Request Handling**: Measures request latency for both standard and enhanced modes
- **Rate Limiting**: Tests rate limiter performance under load
- **Metrics Collection**: Measures the overhead of metrics instrumentation
- **Memory Patterns**: Analyzes memory allocation patterns
- **Concurrent Requests**: Tests server performance under concurrent load

### 2. Memory Profile Benchmarks (`memory_profile_bench.rs`)
Tracks memory usage and detects potential leaks:
- **Scanner Memory Usage**: Measures memory consumption for different scan sizes
- **Concurrent Memory Usage**: Tests memory behavior under concurrent operations
- **Metrics Memory Overhead**: Quantifies the memory cost of metrics collection
- **Server Lifecycle Memory**: Tracks memory during server creation/teardown
- **Memory Leak Detection**: Long-running tests to detect memory leaks

### 3. Simple Benchmarks (`simple_benchmark.rs`)
Basic performance comparison between standard and enhanced modes:
- Event processing throughput
- Rate limiting performance
- Scanner performance
- Correlation engine efficiency

### 4. Regression Benchmarks (`regression_benchmarks.rs`)
Ensures performance doesn't degrade across versions.

## Running Benchmarks

### Run all benchmarks:
```bash
cargo bench
```

### Run specific benchmark suite:
```bash
cargo bench --bench critical_path_benchmarks
```

### Run specific test within a suite:
```bash
cargo bench --bench critical_path_benchmarks unicode_scanning
```

### Quick test (verify compilation):
```bash
cargo bench --bench critical_path_benchmarks -- --test
```

### Generate HTML reports:
```bash
cargo bench --bench critical_path_benchmarks -- --save-baseline main
```

## Performance Targets

Based on 2025 best practices for production-ready security software:

### Latency Requirements:
- Unicode scanning: < 1ms for 1KB text
- MCP request handling: < 10ms p99 latency
- Rate limiting check: < 100μs

### Memory Requirements:
- Memory per request: < 10KB
- No memory leaks over 1M requests
- Stable memory usage under concurrent load

### Throughput Requirements:
- 10,000+ requests/second (standard mode)
- 5,000+ requests/second (enhanced mode)
- Linear scaling up to 100 concurrent connections

## Comparing Standard vs Enhanced Mode

All benchmarks test both modes to help users understand the performance trade-offs:

- **Standard Mode**: Baseline security with minimal overhead
- **Enhanced Mode**: Advanced threat detection with proprietary optimizations

The benchmarks will show the performance difference between modes, typically:
- Standard mode: Baseline performance
- Enhanced mode: 20-50% better threat detection at 10-30% performance cost

## Analyzing Results

Benchmark results are saved in `target/criterion/`. Look for:
- `report/index.html`: Visual comparison of benchmark results
- Performance regressions between runs
- Memory growth patterns indicating potential leaks

## CI Integration

Add to your CI pipeline:
```yaml
- name: Run benchmarks
  run: |
    cargo bench --bench critical_path_benchmarks -- --save-baseline pr
    cargo bench --bench memory_profile_bench -- --save-baseline pr
```

## Tips for Accurate Benchmarking

1. Run on a quiet system (close other applications)
2. Use `--release` mode (automatic with `cargo bench`)
3. Run multiple times for consistent results
4. Compare against baselines, not absolute numbers
5. Test both cold and warm scenarios

## Contributing

When adding new features, include relevant benchmarks to ensure performance doesn't regress.