# Performance Regression Testing Guide

This guide explains how to use KindlyGuard's performance regression testing system to maintain performance standards across releases.

## Overview

The performance regression testing system helps:
- Establish performance baselines for critical operations
- Detect performance regressions (>20% slowdown)
- Compare standard vs enhanced implementations
- Generate actionable reports for CI/CD

## Running Tests Locally

### Basic Usage

```bash
# Run performance tests
cd kindly-guard-server
cargo test --test performance_regression

# Run with detailed output
cargo test --test performance_regression -- --nocapture --test-threads=1
```

### Using the Helper Script

```bash
# Run standard implementation tests
./scripts/run-performance-tests.sh

# Run both standard and enhanced tests
./scripts/run-performance-tests.sh --enhanced

# Update baselines (careful!)
./scripts/run-performance-tests.sh --update-baselines

# Verbose output
./scripts/run-performance-tests.sh --verbose
```

## Understanding Results

### Performance Metrics

Each test reports:
- **Mean**: Average operation time
- **Std Dev**: Standard deviation (consistency)
- **P50**: Median time (50th percentile)
- **P95**: 95th percentile (most operations)
- **P99**: 99th percentile (worst case)

### Regression Detection

The system detects regressions when:
1. Current performance is >20% slower than baseline
2. The change is statistically significant (>2 standard deviations)

Example output:
```
Performance regression detected: 25.3% slower than baseline
  Baseline: 1.2ms ± 0.1ms
  Current:  1.5ms ± 0.1ms
```

## Test Coverage

### Operations Tested

1. **Neutralization Performance**
   - Individual threat neutralization
   - Batch neutralization
   - Various threat types

2. **Scanning Performance**
   - Text scanning
   - Large content handling
   - Pattern matching

3. **Batch Operations**
   - Concurrent processing
   - Resource utilization

### Implementation Coverage

- Standard implementation (always tested)
- Enhanced implementation (when feature enabled)

## CI/CD Integration

### GitHub Actions

The workflow runs:
- On every push to main/develop
- On pull requests
- Daily at 2 AM UTC

### PR Comments

Performance results are automatically commented on PRs:
```markdown
### Performance Test Results - Standard

- Mean: 1.2ms
- P50: 1.1ms
- P95: 1.5ms
- P99: 2.0ms
```

### Regression Alerts

If regression detected on main branch:
- GitHub issue created automatically
- Team notified via labels
- Workflow fails to prevent merge

## Managing Baselines

### Baseline Storage

Baselines stored in: `tests/performance_baselines.json`

Format:
```json
{
  "neutralization_standard": {
    "operation": "neutralization",
    "implementation": "standard",
    "mean_duration_ns": 1200000,
    "std_deviation_ns": 100000,
    "samples": 1000,
    "timestamp": "2024-01-15T10:30:00Z",
    "rust_version": "1.75.0",
    "os": "linux"
  }
}
```

### Updating Baselines

**Caution**: Only update baselines when:
- Performance improvements are intentional
- After fixing false positives
- Major refactoring with expected changes

```bash
# Backup current baselines
cp tests/performance_baselines.json tests/performance_baselines.backup.json

# Update baselines
./scripts/run-performance-tests.sh --update-baselines
```

## Troubleshooting

### False Positives

Reduce false positives by:
1. Running with `--test-threads=1` for consistency
2. Ensuring system is idle during tests
3. Increasing sample size in code

### Inconsistent Results

If results vary significantly:
1. Check system load
2. Disable CPU frequency scaling
3. Run in release mode: `cargo test --release`

### Missing Baselines

First run creates baselines automatically:
```bash
cargo test --test performance_regression
```

## Best Practices

1. **Regular Testing**
   - Run before commits
   - Monitor CI results
   - Update baselines quarterly

2. **Investigation Process**
   - Check recent commits
   - Profile specific operations
   - Compare flamegraphs

3. **Performance Goals**
   - Standard: Acceptable baseline
   - Enhanced: 5x+ faster where applicable
   - Both: Consistent, predictable performance

## Advanced Usage

### Custom Regression Threshold

Modify in code:
```rust
let detector = RegressionDetector {
    regression_threshold: 0.15, // 15% instead of 20%
    ..Default::default()
};
```

### Adding New Benchmarks

1. Add measurement function in `BenchmarkRunner`
2. Create test case with baseline management
3. Update CI workflow if needed

### Statistical Analysis

The system uses:
- Multiple samples for accuracy
- Standard deviation for significance
- Percentiles for distribution analysis

This ensures reliable regression detection while minimizing false positives.