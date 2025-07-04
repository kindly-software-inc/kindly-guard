# KindlyGuard Performance Benchmark Guide

## Overview

The comprehensive benchmark suite (`comprehensive_benchmarks.rs`) provides detailed performance analysis of KindlyGuard's security scanning capabilities. It measures:

1. **Scanner Throughput** - How much data can be processed per second
2. **Scanner Latency** - Response time percentiles for different threat types
3. **Memory Usage** - Allocation patterns and leak detection
4. **Multi-threaded Scaling** - Performance across different core counts
5. **Large Payload Handling** - Performance with payloads up to 1GB
6. **Enhanced vs Standard Mode** - Performance comparison between modes

## Running Benchmarks

### Quick Start

```bash
# Run all comprehensive benchmarks
./run-comprehensive-benchmarks.sh

# Run specific benchmark groups
cargo bench --bench comprehensive_benchmarks scanner_throughput
cargo bench --bench comprehensive_benchmarks memory_usage
cargo bench --bench comprehensive_benchmarks multi_threaded_scaling
```

### Benchmark Groups

- `scanner_throughput` - Tests scanning speed with various payload sizes (1KB to 10MB)
- `scanner_latency` - Measures response time for different threat types
- `memory_usage` - Analyzes memory allocation patterns and detects leaks
- `multi_threaded_scaling` - Tests performance scaling from 1 to 16 threads
- `large_payloads` - Handles payloads from 100MB to 500MB (1GB optional)
- `json_scanning` - Tests performance with nested JSON structures
- `cpu_utilization` - Measures CPU usage patterns
- `event_processing` - Benchmarks security event handling
- `rate_limiting` - Tests rate limiter performance

## Analyzing Results

### Automated Analysis

```bash
# Generate performance report and visualizations
python3 analyze-benchmarks.py

# View HTML reports
cd kindly-guard-server/target/criterion
python3 -m http.server 8000
# Open http://localhost:8000 in browser
```

### Key Metrics

1. **Throughput** (MB/s)
   - Standard mode target: >100 MB/s for benign data
   - Enhanced mode target: >50 MB/s with full threat detection

2. **Latency** (microseconds)
   - P50: <100 μs
   - P99: <1000 μs
   - Maximum: <10ms for 1MB payloads

3. **Memory Usage**
   - Peak memory: <2x input size
   - No memory leaks over 1000 iterations

4. **Scaling Efficiency**
   - 80%+ efficiency up to 8 threads
   - 60%+ efficiency at 16 threads

## Performance Tuning

### CPU Governor

For best results, set CPU governor to performance mode:

```bash
sudo cpupower frequency-set -g performance
```

### Memory Allocator

The benchmarks use jemalloc for better performance:

```bash
export MALLOC_CONF="background_thread:true,metadata_thp:auto"
```

### Benchmark Environment

- Disable CPU frequency scaling
- Close unnecessary applications
- Run on a dedicated machine for consistent results
- Use `nice -n -20` for benchmark priority

## Interpreting Results

### Standard vs Enhanced Mode

Enhanced mode typically shows:
- 20-50% overhead for additional security checks
- Better threat detection coverage
- Improved correlation capabilities

### Threat Type Performance

Different threat types have varying performance impacts:
- Unicode detection: Minimal overhead (<5%)
- SQL injection: Moderate overhead (10-20%)
- XSS detection: Higher overhead (20-30%)
- Combined threats: Cumulative overhead

### Memory Patterns

Expected memory usage patterns:
- Linear growth with input size
- Temporary spikes during parsing
- Quick deallocation after scanning
- No long-term memory growth

## Optimization Opportunities

1. **SIMD Optimizations**
   - Enable with `RUSTFLAGS="-C target-cpu=native"`
   - Provides 2-8x speedup for Unicode scanning

2. **Pattern Caching**
   - Pre-compile regex patterns
   - Cache frequently used patterns
   - Batch similar scans

3. **Parallel Processing**
   - Split large inputs into chunks
   - Process independent chunks in parallel
   - Merge results efficiently

## Troubleshooting

### Out of Memory

For large payload tests (>500MB):
```bash
# Increase system limits
ulimit -v unlimited
ulimit -m unlimited

# Run with memory profiling
RUST_LOG=warn cargo bench --bench comprehensive_benchmarks large_payloads
```

### Inconsistent Results

- Check CPU throttling: `cat /proc/cpuinfo | grep MHz`
- Verify no background processes: `htop`
- Run multiple times and average results
- Use `--sample-size 100` for more samples

### Enhanced Mode Not Available

Ensure the enhanced feature is enabled:
```bash
cargo bench --bench comprehensive_benchmarks --features enhanced
```

## Continuous Performance Monitoring

### Regression Detection

Set baseline measurements:
```bash
cargo bench --bench comprehensive_benchmarks -- --save-baseline main
```

Compare against baseline:
```bash
cargo bench --bench comprehensive_benchmarks -- --baseline main
```

### CI Integration

Add to CI pipeline:
```yaml
- name: Run Performance Benchmarks
  run: |
    cargo bench --bench comprehensive_benchmarks -- --output-format bencher | tee output.txt
    # Fail if performance degrades >10%
    python3 check_regression.py output.txt --threshold 0.1
```