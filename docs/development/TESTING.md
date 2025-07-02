# KindlyGuard Testing Guide

## Overview

KindlyGuard uses a comprehensive test suite to ensure security, reliability, and performance. The test suite is organized into unit tests, integration tests, and performance benchmarks.

## Test Architecture

### Async vs Sync Tests

KindlyGuard's scanner includes async components (like the XSS scanner), which requires special handling in tests:

1. **Unit Tests** - Run synchronously using the sync_wrapper module
2. **Integration Tests** - Use `#[tokio::test]` for async runtime
3. **Property Tests** - Wrap in `tokio::runtime::Runtime::new()` blocks

### Test Organization

```
kindly-guard/
├── run-all-tests.sh          # Master test runner
├── run-unit-tests.sh         # Unit tests only
├── run-integration-tests.sh  # Integration tests only
├── kindly-guard-server/
│   ├── src/
│   │   └── scanner/
│   │       └── sync_wrapper.rs  # Sync scanner for testing
│   └── tests/
│       ├── common/
│       │   └── mod.rs           # Shared test utilities
│       ├── security_tests.rs    # Core security tests
│       ├── unicode_tag_injection_tests.rs
│       ├── enhanced_prompt_injection_tests.rs
│       └── ...
└── kindly-guard-cli/
    └── tests/
        └── cli_wrapper_security_tests.rs
```

## Running Tests

### Quick Start

```bash
# Run all tests
./run-all-tests.sh

# Run only unit tests (fast)
./run-unit-tests.sh

# Run only integration tests
./run-integration-tests.sh

# Run with coverage
./run-all-tests.sh --coverage

# Run with benchmarks
./run-all-tests.sh --bench
```

### Individual Test Commands

```bash
# Run specific test file
cargo test --test security_tests

# Run specific test function
cargo test test_sql_injection_detection

# Run with output
cargo test --test security_tests -- --nocapture

# Run with specific number of threads
cargo test -- --test-threads=1
```

## Writing Tests

### Async Test Pattern

For tests that use the SecurityScanner:

```rust
#[tokio::test]
async fn test_sql_injection() {
    let config = ScannerConfig::default();
    let scanner = SecurityScanner::new(config).unwrap();
    
    let threats = scanner.scan_text("' OR '1'='1").unwrap();
    assert!(!threats.is_empty());
}
```

### Sync Test Pattern

For unit tests that don't need async:

```rust
#[test]
fn test_unicode_detection() {
    use crate::scanner::sync_wrapper::create_sync_scanner;
    
    let config = ScannerConfig::default();
    let scanner = create_sync_scanner(config).unwrap();
    
    let threats = scanner.scan_text("Hello\u{202E}World").unwrap();
    assert!(!threats.is_empty());
}
```

### Property Test Pattern

For property-based testing with proptest:

```rust
proptest! {
    #[test]
    fn test_no_panics(input in ".*") {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let scanner = SecurityScanner::new(config).unwrap();
            let _ = scanner.scan_text(&input);
        });
    }
}
```

### Using Test Utilities

```rust
use common::{payloads, assertions, create_test_scanner};

#[tokio::test]
async fn test_sql_payloads() {
    let scanner = create_test_scanner().unwrap();
    
    for payload in payloads::SQL_INJECTIONS {
        let threats = scanner.scan_text(payload).unwrap();
        assertions::assert_contains_threat_type(
            &threats, 
            &ThreatType::SqlInjection
        );
    }
}
```

## Test Categories

### 1. Security Tests (`security_tests.rs`)
- Timing attack resistance
- DoS protection
- Resource exhaustion prevention
- Input validation

### 2. Unicode Tests (`unicode_tag_injection_tests.rs`)
- CVE-2024-5184 detection
- Unicode tag injection
- BiDi override attacks
- Zero-width character detection

### 3. Prompt Injection Tests (`enhanced_prompt_injection_tests.rs`)
- Neural Exec patterns
- Multi-turn attacks
- Context window manipulation
- AI-specific attack vectors

### 4. Protocol Tests (`multi_protocol_security_tests.rs`)
- HTTP API security
- HTTPS proxy functionality
- WebSocket security
- Cross-protocol attacks

### 5. CLI Tests (`cli_wrapper_security_tests.rs`)
- Command injection prevention
- Environment variable security
- Signal handling
- I/O stream protection

## Debugging Failed Tests

### Common Issues

1. **Async Runtime Errors**
   ```
   "there is no reactor running"
   ```
   Solution: Ensure test is marked with `#[tokio::test]`

2. **Timeout in Tests**
   ```
   test timed out after 60s
   ```
   Solution: Use `#[tokio::test(flavor = "multi_thread")]`

3. **Compilation Errors**
   Check that all async tests use proper runtime setup

### Debug Commands

```bash
# Run with debug logging
RUST_LOG=debug cargo test test_name

# Run with backtrace
RUST_BACKTRACE=1 cargo test test_name

# Run single test with full output
cargo test test_name -- --exact --nocapture

# Check for test flakiness
for i in {1..10}; do cargo test test_name || break; done
```

## Performance Testing

### Running Benchmarks

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark
cargo bench scanner_throughput

# Compare with baseline
cargo bench -- --save-baseline main
cargo bench -- --baseline main
```

### Benchmark Categories

1. **Scanner Throughput** - MB/s processing speed
2. **Latency Percentiles** - p50, p95, p99
3. **Memory Usage** - Allocation patterns
4. **Concurrent Performance** - Multi-threaded scaling

## Continuous Integration

### GitHub Actions

Tests run automatically on:
- Push to main branch
- Pull requests
- Release tags

### Local CI Simulation

```bash
# Run tests as CI would
./run-all-tests.sh
cargo fmt -- --check
cargo clippy -- -D warnings
```

## Test Coverage

### Generate Coverage Report

```bash
# Install tarpaulin
cargo install cargo-tarpaulin

# Generate coverage
cargo tarpaulin --out Html --output-dir coverage

# View report
open coverage/index.html
```

### Coverage Goals

- Overall: >80%
- Security modules: >90%
- Scanner core: >95%

## Best Practices

1. **Test Naming**
   - Use descriptive names: `test_sql_injection_in_json_field`
   - Group related tests with common prefixes

2. **Test Independence**
   - Each test should be self-contained
   - Use fresh scanner instances
   - Don't rely on test execution order

3. **Assertions**
   - Use specific assertions from test utilities
   - Check both positive and negative cases
   - Verify severity levels match expectations

4. **Performance**
   - Keep unit tests fast (<100ms)
   - Use smaller inputs for unit tests
   - Save large payload tests for integration suite

## Troubleshooting

### Test Hanging

If tests hang, check for:
- Deadlocks in async code
- Infinite loops in scanners
- Missing timeouts

### Flaky Tests

For intermittent failures:
- Add retries for network-dependent tests
- Use deterministic test data
- Avoid time-based assertions

### Memory Issues

For out-of-memory errors:
- Reduce test payload sizes
- Run tests with limited parallelism
- Check for memory leaks with valgrind

## Contributing Tests

When adding new features:

1. Write unit tests first (TDD)
2. Add integration tests for user scenarios
3. Include edge cases and error conditions
4. Update this documentation if needed

Remember: A feature without tests is not complete!