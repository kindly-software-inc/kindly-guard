# KindlyGuard Testing Guide

## Overview

KindlyGuard implements a comprehensive dual-implementation testing strategy to ensure both security and performance. Our testing infrastructure validates that standard and enhanced implementations maintain security parity while allowing performance optimizations. The test suite includes unit tests, integration tests, performance benchmarks, and specialized security validation.

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

## Comprehensive Test Suites

### 1. Trait Compliance Tests (`tests/trait_compliance.rs`)
Validates that all implementations correctly implement required traits:

```bash
cargo test --test trait_compliance
```

Features:
- Verifies trait method signatures
- Tests default implementations
- Validates error handling
- Ensures Send + Sync bounds

### 2. Behavioral Equivalence Tests (`tests/behavioral_equivalence.rs`)
Ensures standard and enhanced implementations produce identical security outcomes:

```bash
cargo test --test behavioral_equivalence
```

Tests:
- Same threats detected for identical inputs
- Equivalent severity assessments
- Consistent neutralization results
- Performance metrics collection

Example:
```rust
#[tokio::test]
async fn test_scanner_equivalence() {
    let input = "malicious\u{202E}content";
    
    let standard_threats = test_standard_scanner(input).await;
    let enhanced_threats = test_enhanced_scanner(input).await;
    
    assert_eq!(standard_threats.len(), enhanced_threats.len());
    for (std_threat, enh_threat) in standard_threats.iter().zip(enhanced_threats.iter()) {
        assert_eq!(std_threat.threat_type, enh_threat.threat_type);
        assert_eq!(std_threat.severity, enh_threat.severity);
    }
}
```

### 3. Performance Regression Tests (`tests/performance_regression.rs`)
Tracks performance metrics across versions:

```bash
cargo test --test performance_regression
```

Metrics tracked:
- Throughput (MB/s)
- Latency percentiles (p50, p95, p99, p99.9)
- Memory allocations
- CPU utilization

### 4. Security Properties Tests (`tests/security_properties.rs`)
Property-based testing for security invariants:

```bash
cargo test --test security_properties
```

Properties tested:
- No false negatives on known threats
- Monotonic threat detection (more context = same or more threats)
- Safe neutralization (no data corruption)
- Consistent behavior across runs

### 5. Integration Scenarios (`tests/integration_scenarios.rs`)
Real-world usage patterns:

```bash
cargo test --test integration_scenarios
```

Scenarios:
- Multi-client concurrent access
- Mixed protocol usage (HTTP + WebSocket)
- Authentication flows
- Rate limiting behavior
- Circuit breaker activation

### 6. Comparative Benchmarks (`benches/comparative_benchmarks.rs`)
Side-by-side performance analysis:

```bash
cargo bench --bench comparative_benchmarks
```

Comparisons:
- Standard vs Enhanced throughput
- Memory efficiency ratios
- Latency distribution analysis
- Scalability under load

### 7. Chaos Engineering Tests (`tests/chaos_engineering.rs`)
Fault injection and resilience testing:

```bash
cargo test --test chaos_engineering -- --test-threads=1
```

Fault scenarios:
- Random component failures
- Network delays and partitions
- Resource exhaustion
- Cascading failure recovery

### 8. Load Testing (`tests/load_testing.rs`)
Stress and capacity testing:

```bash
cargo test --test load_testing -- --release
```

Load patterns:
- Sustained high throughput
- Burst traffic handling
- Connection limit testing
- Memory pressure scenarios

## Running the Complete Test Suite

### Quick Test Run
```bash
# Run all tests with optimal settings
./run-all-tests.sh
```

### Comprehensive Test Run
```bash
# Run all tests including slow tests and benchmarks
./run-all-tests.sh --comprehensive
```

### CI/CD Test Pipeline
```bash
# Run tests as CI would
./run-all-tests.sh --ci
```

## Test Configuration

### Environment Variables
```bash
# Control test behavior
RUST_TEST_THREADS=1              # Sequential execution
RUST_LOG=debug                   # Enable debug logging
PROPTEST_CASES=10000            # More property test cases
KINDLY_TEST_ENHANCED=true       # Test enhanced implementations
```

### Test Features
```toml
[dev-dependencies]
kindly-guard-server = { path = ".", features = ["test-utils", "enhanced"] }
```

## Performance Testing Best Practices

### Baseline Comparison
```bash
# Save baseline
cargo bench -- --save-baseline main

# Compare against baseline
cargo bench -- --baseline main
```

### Performance Regression Detection
```bash
# Run performance regression tests
cargo test --test performance_regression -- --nocapture

# Analyze results
python analyze-benchmarks.py --baseline main --threshold 10
```

## Security Testing Guidelines

### Threat Coverage
Ensure tests cover all threat categories:
- Unicode exploits (homographs, bidi, zero-width)
- Injection attacks (SQL, command, LDAP, path)
- XSS variants (HTML, JS, CSS contexts)
- Authentication bypasses
- Rate limit evasion

### Security Test Pattern
```rust
#[test]
fn test_security_invariant() {
    // Test both implementations
    for implementation in &[Implementation::Standard, Implementation::Enhanced] {
        let scanner = create_scanner(*implementation);
        
        // Test known threats
        for (input, expected_threat) in KNOWN_THREATS.iter() {
            let threats = scanner.scan(input).unwrap();
            assert!(threats.iter().any(|t| t.threat_type == *expected_threat),
                   "Failed to detect {} in {:?}", expected_threat, implementation);
        }
    }
}
```

## Continuous Integration

### GitHub Actions Integration
```yaml
name: Comprehensive Testing

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run all tests
        run: ./run-all-tests.sh --ci
        
      - name: Run benchmarks
        run: cargo bench -- --save-baseline ${{ github.sha }}
        
      - name: Check performance regression
        run: python analyze-benchmarks.py --threshold 10
        
      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: test-results
          path: |
            target/criterion
            test-results.json
```

## Contributing Tests

When adding new features:

1. Write trait compliance tests for new traits
2. Add behavioral equivalence tests for dual implementations
3. Include performance benchmarks
4. Add security property tests
5. Create integration scenarios
6. Document test patterns

Remember: Every feature must maintain security parity between implementations!