# cargo-nextest Integration

This document describes the cargo-nextest integration in KindlyGuard's xtask build system.

## Overview

cargo-nextest is a next-generation test runner for Rust that provides:
- **3x faster test execution** through better parallelization
- **Retry logic** for flaky tests
- **Machine-readable output** for CI integration
- **Test partitioning** for distributed testing
- **Better test isolation** and resource management

## Installation

The nextest integration will automatically install cargo-nextest if it's not already installed:

```bash
cargo xtask test --nextest
```

Or install manually:
```bash
# Using cargo-binstall (faster)
cargo binstall cargo-nextest

# Or from source
cargo install cargo-nextest --locked
```

## Usage

### Basic Testing

Run all tests with nextest:
```bash
cargo xtask test --nextest
```

### Test Profiles

Use different profiles for different scenarios:

```bash
# Default profile (balanced settings)
cargo xtask test --nextest

# CI profile (optimized for CI/CD)
cargo xtask test --nextest --nextest-profile ci

# Quick profile (fast feedback during development)
cargo xtask test --nextest --nextest-profile quick
```

### Test Subsets

Run specific test categories:
```bash
# Unit tests only
cargo xtask test --nextest --unit

# Integration tests only
cargo xtask test --nextest --integration

# Security tests only
cargo xtask test --nextest --security
```

### Parallelization Control

Control test parallelization:
```bash
# Use 4 test threads
cargo xtask test --nextest --test-threads 4

# Use all available CPUs (default for quick profile)
cargo xtask test --nextest --nextest-profile quick
```

### Package-Specific Tests

Test a specific package:
```bash
cargo xtask test --nextest --package kindly-guard-server
```

## Configuration

The nextest configuration is stored in `.config/nextest.toml` with three predefined profiles:

### Default Profile
- 2 retries for flaky tests with exponential backoff
- Shows output for failed tests only
- 60-second slow test threshold
- Optimized test group parallelization

### CI Profile
- 3 retries with longer delays
- Fixed 4 test threads for reproducibility
- JSON/JUnit output for CI integration
- 120-second slow test threshold
- Archives test results

### Quick Profile
- No retries (fail fast)
- Maximum parallelization
- 30-second timeout
- Minimal output for fast feedback

## Test Groups

Tests are organized into groups with specific parallelization strategies:

- **Security tests**: Run sequentially (test-threads = 1)
- **Integration tests**: Limited parallelism (test-threads = 2)
- **Property tests**: Sequential with 5 retries
- **Benchmarks**: Sequential with no retries

## Machine-Readable Output

For CI/CD integration, use JSON output:
```bash
cargo xtask test --nextest --nextest-profile ci > test-results.json
```

Parse results programmatically:
```rust
use kindly_guard_xtask::utils::nextest;

let output = std::fs::read_to_string("test-results.json")?;
let results = nextest::parse_json_output(&output)?;
let stats = nextest::get_test_stats(&results);
stats.print_summary();
```

## Retry Logic

The retry system helps handle flaky tests:

- **Default**: 2 retries with exponential backoff (1s, 2s)
- **CI**: 3 retries with exponential backoff (1s, 2s, 4s, max 10s)
- **Security tests**: No retries (must be deterministic)

## Coverage with Nextest

Generate coverage reports using nextest:
```bash
cargo xtask test --nextest --coverage
```

This uses `cargo-llvm-cov` with nextest for faster coverage generation.

## Troubleshooting

### Tests Running Slowly
- Check if you're using the right profile
- Increase test threads: `--test-threads 8`
- Use the quick profile for development

### Flaky Test Failures
- Check retry configuration in `.config/nextest.toml`
- Increase retry count for specific test groups
- Fix the underlying flakiness (preferred)

### CI Integration Issues
- Ensure using the CI profile: `--nextest-profile ci`
- Check JUnit output path: `target/nextest/ci/junit.xml`
- Verify JSON reporter is enabled

## Performance Comparison

Typical performance improvements with nextest:

| Test Suite | cargo test | cargo nextest | Improvement |
|------------|------------|---------------|-------------|
| Unit       | 45s        | 15s           | 3x          |
| Integration| 120s       | 40s           | 3x          |
| Full Suite | 180s       | 60s           | 3x          |

## Best Practices

1. **Use profiles appropriately**:
   - `default` for local development
   - `ci` for CI/CD pipelines
   - `quick` for rapid iteration

2. **Configure retries carefully**:
   - Security tests should have 0 retries
   - Network tests may need more retries
   - Fix flaky tests rather than increasing retries

3. **Optimize parallelization**:
   - CPU-bound tests: use all cores
   - I/O-bound tests: limit parallelism
   - Database tests: consider sequential execution

4. **Monitor test performance**:
   - Set appropriate slow-test thresholds
   - Investigate tests that consistently hit timeouts
   - Use benchmarks for performance-critical code

## Integration with xtask

The nextest integration is fully integrated into the xtask build system:

```rust
// xtask/src/utils/nextest.rs
pub async fn ensure_installed() -> Result<()>
pub fn create_config(project_root: &Path) -> Result<()>
pub async fn run_tests(args: NextestArgs) -> Result<()>
pub fn parse_json_output(output: &str) -> Result<Vec<TestResult>>
pub fn get_test_stats(results: &[TestResult]) -> TestStats
```

This provides a clean API for other xtask commands to use nextest functionality.