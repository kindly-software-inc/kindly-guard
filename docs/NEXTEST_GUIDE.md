# KindlyGuard Nextest Configuration Guide

## Overview

KindlyGuard uses [cargo-nextest](https://nexte.st/) for faster, more reliable test execution with enhanced security test isolation. This guide explains our configuration and how it benefits security-critical testing.

## Why Nextest for Security Testing?

1. **Test Isolation**: Each test runs in its own process, preventing security tests from interfering with each other
2. **Parallel Execution**: Faster feedback loops encourage frequent security testing
3. **Deterministic Ordering**: Helps identify test dependencies and race conditions
4. **Better Failure Reporting**: Immediate visibility of security test failures
5. **Retry Logic**: Distinguishes between flaky tests and real security issues

## Installation

```bash
# Using cargo
cargo install cargo-nextest

# Or using the installer (faster)
curl -LsSf https://get.nexte.st/latest/linux | tar zxf - -C ${CARGO_HOME:-~/.cargo}/bin
```

## Test Profiles

### Default Profile
Balanced settings for local development:
- Parallel execution using all CPU cores
- Retries for transient failures (2 attempts)
- Security tests run sequentially
- 30-second timeout for slow tests

```bash
cargo nextest run
```

### Security Profile
Maximum isolation for security testing:
- **Sequential execution only** - prevents race conditions
- **No retries** - security tests must be deterministic
- **Extended timeouts** - thorough security checks take time
- **Full output capture** - audit trail for security reviews

```bash
cargo nextest run --profile=security
```

### CI Profile
Optimized for continuous integration:
- Fixed thread count (4) for reproducibility
- JUnit XML output for CI integration
- Test archival for debugging
- Fail-fast to save CI resources

```bash
cargo nextest run --profile=ci
```

### Quick Profile
Rapid feedback during development:
- Maximum parallelism
- Fail-fast on first error
- Skips slow tests
- Minimal output

```bash
cargo nextest run --profile=quick
```

### Release Profile
Thorough validation before releases:
- Conservative parallelism (2 threads)
- No retries - must be stable
- Extended timeouts (3 minutes)
- Complete result archival

```bash
cargo nextest run --profile=release
```

## Security Test Organization

### Test Naming Convention

Security tests should be marked for proper isolation:

```rust
#[test]
fn test_security_unicode_homograph_detection() {
    // This test will run sequentially due to "security" in the name
}

#[test]
fn test_unicode_bidi_override_attack() {
    // This test will run sequentially due to "unicode" in the name
}
```

### Test Groups

Our nextest configuration recognizes these test groups:
- `security` - General security tests (sequential)
- `unicode` - Unicode security tests (sequential)
- `integration` - Integration tests (limited parallelism)
- `fuzz` - Fuzzing tests (extended timeouts)
- `slow` - Long-running tests (skipped in quick profile)

## Usage Examples

### Run All Tests
```bash
# Using our test runner script
./scripts/run-tests-nextest.sh

# Or directly with nextest
cargo nextest run
```

### Run Security Tests Only
```bash
# With isolation
./scripts/run-tests-nextest.sh -p security -f security

# List security tests without running
./scripts/run-tests-nextest.sh -l -f security
```

### Debug Failing Tests
```bash
# Show output for all tests
./scripts/run-tests-nextest.sh -s

# Run specific test with output
cargo nextest run -E 'test(test_unicode_normalization)' --no-capture
```

### CI Integration
```bash
# Generate JUnit report
cargo nextest run --profile=ci

# The report will be at: target/nextest/junit.xml
```

## Configuration Details

The nextest configuration is located at `.config/nextest.toml`. Key settings:

### Thread Management
```toml
# Security tests must run sequentially
[[profile.default.overrides]]
filter = "test(security)"
test-threads = 1
```

### Retry Policy
```toml
# Default: retry transient failures
retries = { count = 2, backoff = "exponential", delay = "1s" }

# Security: no retries
[[profile.security.overrides]]
retries = { count = 0 }
```

### Timeout Configuration
```toml
# Normal timeout
slow-timeout = { period = "30s", terminate-after = 3 }

# Fuzzing timeout
[[profile.security.overrides]]
filter = "test(fuzz)"
slow-timeout = { period = "300s", terminate-after = 1 }
```

## Best Practices

1. **Name Security Tests Clearly**: Include "security", "unicode", or "injection" in test names for automatic isolation

2. **Avoid Test Dependencies**: Each test should be independent
   ```rust
   // Bad: depends on external state
   #[test]
   fn test_after_config_loaded() { ... }
   
   // Good: self-contained
   #[test]
   fn test_config_validation() {
       let config = TestConfig::new();
       // ...
   }
   ```

3. **Use Test Fixtures**: For consistent test environments
   ```rust
   #[test]
   fn test_unicode_scanner() {
       let scanner = test_fixtures::create_unicode_scanner();
       // ...
   }
   ```

4. **Profile Selection**: 
   - Development: `default` or `quick`
   - Pre-commit: `default`
   - CI: `ci`
   - Security review: `security`
   - Release: `release`

## Troubleshooting

### Tests Pass with `cargo test` but Fail with Nextest
This usually indicates test interdependencies. Run with the security profile to isolate tests:
```bash
cargo nextest run --profile=security
```

### Timeout Errors
Increase timeout in the profile or mark test as slow:
```rust
#[test]
#[ignore = "slow"]
fn test_large_payload_scanning() { ... }
```

### Flaky Tests
Use the retry mechanism to identify truly flaky tests:
```bash
cargo nextest run --profile=default --retries 5
```
If a test needs 5 retries, it's genuinely flaky and needs fixing.

## Security Benefits

1. **Process Isolation**: Each test runs in a separate process, preventing:
   - Memory corruption spreading between tests
   - Global state pollution
   - File descriptor leaks

2. **Deterministic Execution**: Sequential security tests ensure:
   - Consistent results
   - Easier debugging
   - No race conditions in security validations

3. **Audit Trail**: Full output capture provides:
   - Complete test execution logs
   - Failure analysis for security reviews
   - Compliance documentation

4. **Fast Feedback**: Parallel execution means:
   - Developers run tests more often
   - Security issues caught earlier
   - Reduced cost of security fixes

## Integration with CI/CD

Our GitHub Actions workflow uses nextest for all platforms:

```yaml
- name: Install cargo-nextest
  uses: taiki-e/install-action@v2
  with:
    tool: nextest

- name: Run tests
  run: cargo nextest run --profile=ci
```

The CI profile generates JUnit XML for test reporting and archives all test artifacts for security reviews.

## Future Enhancements

1. **Distributed Testing**: Use nextest's partition feature for large test suites
2. **Custom Test Reporters**: Security-specific test report formats
3. **Integration with Security Tools**: Combine with cargo-audit, cargo-fuzz
4. **Performance Baselines**: Track test execution times for regression detection