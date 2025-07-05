# Flaky Test Management System

The xtask flaky test management system provides intelligent tracking and handling of unreliable tests.

## Features

- **Automatic Flaky Test Detection**: Tracks test execution history and identifies tests with inconsistent results
- **Smart Retry Policies**: Configures retry strategies based on test flakiness scores
- **Test Quarantine**: Isolate problematic tests to prevent CI failures
- **Comprehensive Reporting**: Generate detailed reports in JSON and HTML formats
- **Nextest Integration**: Automatic configuration generation for cargo-nextest

## Usage

### Basic Test Execution with Flaky Tracking

```bash
# Run tests with flaky test tracking enabled
cargo xtask test --flaky-retries

# Run with nextest (recommended for better retry handling)
cargo xtask test --nextest --flaky-retries
```

### Managing Quarantined Tests

```bash
# View quarantined tests
cargo xtask test --show-quarantined

# Quarantine a specific test
cargo xtask test --quarantine "test::module::flaky_test_name"

# Un-quarantine a test
cargo xtask test --unquarantine "test::module::flaky_test_name"
```

### Generating Reports

```bash
# Generate flaky test report
cargo xtask test --flaky-report

# Reports are saved to:
# - target/flaky-tests.json (machine-readable)
# - target/flaky-tests.html (human-readable)
```

### Nextest Configuration

```bash
# Generate nextest configuration with retry policies
cargo xtask test --generate-nextest-config

# This creates .config/nextest.toml with:
# - Custom retry counts for flaky tests
# - Exponential backoff strategies
# - Test-specific overrides
```

## How It Works

### Flakiness Detection

The system tracks each test execution and calculates a flakiness score based on:
- Failure rate over time
- Recent execution patterns
- Consistency of results

Tests are considered flaky if they:
- Have a failure rate above 10%
- Show inconsistent results in recent runs
- Fail intermittently despite no code changes

### Retry Strategies

The system supports multiple backoff strategies:

1. **None**: No delay between retries
2. **Fixed**: Constant delay between retries
3. **Linear**: Delay increases linearly (base × attempt)
4. **Exponential**: Delay doubles each attempt
5. **Exponential with Jitter**: Adds randomization to prevent thundering herd

### Auto-Quarantine

Tests are automatically quarantined when:
- Flakiness score exceeds 50%
- Consistent failures across multiple runs
- Manual quarantine via CLI

Quarantined tests:
- Still run but don't fail the build
- Are tracked separately in reports
- Can be un-quarantined when fixed

## Configuration

The flaky test database is stored at `.xtask/flaky-tests.json` and includes:
- Test execution history (last 100 runs per test)
- Statistics and metrics
- Custom retry policies
- Quarantine status

## Best Practices

1. **Regular Monitoring**: Generate flaky test reports weekly
2. **Fix Don't Ignore**: Use quarantine as temporary measure while fixing
3. **Root Cause Analysis**: Investigate why tests are flaky
4. **CI Integration**: Use `--flaky-retries` in CI pipelines

## Example Workflow

```bash
# 1. Run tests with flaky tracking
cargo xtask test --nextest --flaky-retries

# 2. Check for new flaky tests
cargo xtask test --flaky-report

# 3. Quarantine problematic tests temporarily
cargo xtask test --quarantine "test::integration::timing_sensitive_test"

# 4. Generate nextest config for CI
cargo xtask test --generate-nextest-config

# 5. Fix the flaky test, then un-quarantine
cargo xtask test --unquarantine "test::integration::timing_sensitive_test"
```

## Integration with CI

For GitHub Actions:

```yaml
- name: Run tests with flaky handling
  run: |
    cargo xtask test --nextest --flaky-retries
    cargo xtask test --flaky-report
    
- name: Upload flaky test report
  uses: actions/upload-artifact@v3
  if: always()
  with:
    name: flaky-test-report
    path: target/flaky-tests.html
```