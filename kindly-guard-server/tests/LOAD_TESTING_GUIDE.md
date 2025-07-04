# Load Testing Guide for KindlyGuard

## Overview

This document describes the comprehensive load testing suite for KindlyGuard, designed to ensure the system maintains security and stability under various load patterns.

## Test Scenarios

### 1. Steady Load Test (`test_steady_load`)
- **Purpose**: Verify system stability under constant load
- **Pattern**: 1000 requests/second for 10 seconds
- **Metrics**: Success rate, average latency, memory usage
- **Pass Criteria**: 
  - Success rate > 95%
  - Average latency < 50ms

### 2. Burst Load Test (`test_burst_load`)
- **Purpose**: Test system resilience to traffic spikes
- **Pattern**: 3 bursts of 5000 requests over 2 seconds, with 3-second quiet periods
- **Threats**: 10% of requests contain various threat types
- **Metrics**: Threat detection rate, rate limiting effectiveness
- **Pass Criteria**: 
  - System handles bursts without crashing
  - Threats are detected accurately

### 3. Gradual Ramp Test (`test_gradual_ramp`)
- **Purpose**: Find system capacity limits gracefully
- **Pattern**: Ramp from 100 to 2000 req/s over 30 seconds, then sustain for 10 seconds
- **Metrics**: Performance degradation curve
- **Pass Criteria**: 
  - Average latency remains < 100ms
  - No sudden performance cliff

### 4. Mixed Workload Test (`test_mixed_workload`)
- **Purpose**: Simulate realistic traffic patterns
- **Pattern**: 10,000 requests with mixed threat types:
  - 40% benign traffic
  - 20% SQL injection attempts
  - 15% XSS attempts
  - 15% Unicode attacks
  - 10% Command injection
- **Metrics**: Threat detection accuracy per type
- **Pass Criteria**: 
  - Detect > 90% of all threats
  - Correctly identify threat types

### 5. Rate Limiting Test (`test_rate_limiting_under_load`)
- **Purpose**: Verify rate limiting works under stress
- **Pattern**: Attempt 10x the configured rate limit
- **Configuration**: 100 req/s limit with 200 burst
- **Metrics**: Requests allowed vs rejected
- **Pass Criteria**: 
  - Rate limiting constrains throughput effectively
  - No bypass under load

### 6. Performance Degradation Test (`test_performance_degradation`)
- **Purpose**: Map system performance at various load levels
- **Pattern**: Test at 100, 500, 1000, 2000, 5000, 10000 req/s
- **Metrics**: Throughput, latency, success rate at each level
- **Output**: Performance degradation curve and breaking point
- **Pass Criteria**: 
  - Graceful degradation (no exponential latency increase)
  - Clear identification of maximum capacity

### 7. Sustained Load Test (`test_sustained_load`) - Extended
- **Purpose**: Detect memory leaks and performance degradation over time
- **Pattern**: 500 req/s sustained for 5 minutes
- **Metrics**: Memory usage trend, performance stability
- **Pass Criteria**: 
  - Memory growth < 50%
  - Performance remains stable

## Key Metrics Collected

### LoadTestStats Structure
```rust
- total_requests: Total number of requests sent
- successful_requests: Requests that completed successfully
- failed_requests: Requests that failed or timed out
- threats_detected: Number of threats identified
- threats_neutralized: Number of threats successfully neutralized
- rate_limited_requests: Requests rejected by rate limiting
- total_latency_us: Sum of all request latencies
- max_latency_us: Maximum observed latency
- memory_peak_bytes: Peak memory usage during test
```

### Calculated Metrics
- **Throughput**: Requests per second achieved
- **Average Latency**: Mean response time across all requests
- **Success Rate**: Percentage of successful requests
- **Threat Detection Rate**: Percentage of threats correctly identified

## Running the Tests

### Quick Test Suite (Default)
```bash
./run-load-tests.sh
```
Runs all tests except the long-running sustained load test.

### Full Test Suite
```bash
./run-load-tests.sh --all
```
Includes the 5-minute sustained load test.

### Individual Tests
```bash
cd kindly-guard-server
cargo test --test load_testing test_steady_load -- --nocapture
```

### With Enhanced Mode
```bash
cargo test --test load_testing --features enhanced -- --nocapture
```

## Interpreting Results

### Example Output
```
=== Load Test Results: Steady Load ===
Duration: 10.05s
Total Requests: 9847
Successful: 9732
Failed: 115
Rate Limited: 0
Threats Detected: 0
Threats Neutralized: 0
Throughput: 979.31 req/s
Average Latency: 12.45 ms
Max Latency: 156.23 ms
Peak Memory: 87.50 MB
```

### Key Indicators

1. **Healthy System**:
   - Success rate > 95%
   - Average latency < 50ms
   - Consistent throughput near target
   - Low memory growth

2. **Warning Signs**:
   - Success rate 90-95%
   - Average latency 50-100ms
   - Throughput significantly below target
   - Memory growth > 20%

3. **Critical Issues**:
   - Success rate < 90%
   - Average latency > 100ms
   - Exponential latency growth
   - Memory growth > 50%

## Configuration Tuning

Based on load test results, you may need to adjust:

1. **Rate Limiting**:
   ```toml
   [rate_limit]
   requests_per_second = 1000  # Adjust based on capacity
   burst_size = 2000          # Handle traffic spikes
   ```

2. **Connection Limits**:
   ```toml
   [transport]
   max_connections = 500      # Based on concurrent load
   ```

3. **Scanner Settings**:
   ```toml
   [scanner]
   max_scan_depth = 10       # Balance security vs performance
   enhanced_mode = true      # Enable for better detection
   ```

## Memory Profiling

The tests include memory monitoring when compiled with jemalloc:

```bash
cargo test --test load_testing --features "jemalloc" -- --nocapture
```

This provides accurate memory usage statistics for leak detection.

## CI/CD Integration

Add to your CI pipeline:

```yaml
load-tests:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v3
    - uses: actions-rs/toolchain@v1
    - name: Run load tests
      run: |
        cd kindly-guard-server
        cargo test --test load_testing --release -- --test-threads=1
    - name: Check performance regression
      run: |
        # Compare with baseline metrics
        # Fail if performance degrades > 10%
```

## Best Practices

1. **Run tests in isolation**: Use `--test-threads=1` to avoid interference
2. **Use release builds**: Add `--release` for realistic performance
3. **Monitor system resources**: Watch CPU, memory, and network during tests
4. **Establish baselines**: Record metrics for each release
5. **Test after changes**: Run load tests for any performance-critical changes

## Troubleshooting

### High Latency
- Check rate limiting configuration
- Verify scanner settings aren't too aggressive
- Look for lock contention in logs

### Memory Growth
- Enable detailed logging to identify leaks
- Check for unbounded collections
- Verify cleanup in error paths

### Failed Requests
- Check for timeout settings
- Verify authentication isn't bottlenecking
- Look for panic messages in logs

## Future Enhancements

1. **Distributed Load Testing**: Support for multi-node load generation
2. **Automated Performance Regression**: CI integration with baseline comparison
3. **Chaos Engineering**: Add fault injection during load tests
4. **Protocol-Specific Tests**: HTTP, WebSocket, and stdio-specific scenarios
5. **Resource Exhaustion Tests**: Test behavior at absolute limits