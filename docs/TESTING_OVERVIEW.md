# KindlyGuard Testing Overview

## Test Infrastructure

KindlyGuard employs a comprehensive testing strategy to ensure security, reliability, and performance.

### Test Categories

1. **Unit Tests** - Component-level testing with mocks
2. **Integration Tests** - Cross-component interaction testing
3. **E2E Tests** - Complete workflow validation
4. **Security Tests** - Threat detection and prevention
5. **Property Tests** - Edge case discovery with proptest
6. **Fuzz Tests** - Automated vulnerability discovery
7. **Performance Tests** - Regression detection and benchmarking
8. **Mock Tests** - Isolated component testing

## Running Tests

### Quick Start

```bash
# Run all tests
cargo test

# Run with cargo-nextest (60% faster)
cargo nextest run

# Run with coverage
./scripts/coverage.sh

# Run specific test category
cargo nextest run --test security_tests
cargo nextest run --test e2e_tests
```

### Advanced Testing

```bash
# Run fuzz tests
cd fuzz && cargo fuzz run fuzz_unicode_scanner

# Run benchmarks
cargo bench --bench regression_benchmarks

# Run performance regression tests
./scripts/perf-regression.sh

# Run property tests
cargo test --test property_tests
```

## CI/CD Workflows

### 1. CI Workflow (`ci.yml`)
- Runs on every push and PR
- Basic tests, formatting, clippy
- Security audit
- Coverage reporting

### 2. Comprehensive Tests (`comprehensive-tests.yml`)
- Full test suite execution
- MCP protocol compliance
- Mock and security tests
- Performance benchmarks

### 3. PR Tests (`pr-tests.yml`)
- Fast feedback for pull requests
- Format and clippy checks
- Quick test subset
- Basic coverage enforcement

### 4. Nightly Tests (`nightly-tests.yml`)
- Extended fuzzing (1 hour per target)
- Memory leak detection
- Stress testing
- Compatibility matrix

## Test Organization

```
kindly-guard/
├── tests/                     # Integration tests
│   ├── helpers/              # Test utilities
│   │   └── mod.rs           # Common test helpers
│   ├── mcp_protocol_tests.rs # MCP compliance
│   ├── e2e_tests.rs         # End-to-end scenarios
│   ├── security_tests.rs    # Security validation
│   ├── mock_tests.rs        # Mock usage examples
│   └── property_tests.rs    # Property-based tests
├── benches/                  # Performance benchmarks
│   ├── simple_benchmark.rs   # Basic benchmarks
│   └── regression_benchmarks.rs # Detailed regression tests
├── fuzz/                     # Fuzzing targets
│   └── fuzz_targets/
│       ├── fuzz_unicode_scanner.rs
│       ├── fuzz_injection_detector.rs
│       ├── fuzz_json_scanner.rs
│       ├── fuzz_mcp_protocol.rs
│       ├── fuzz_auth_token.rs
│       └── fuzz_permission_check.rs
└── src/
    └── */mod.rs             # Unit tests in modules

```

## Coverage Requirements

- **Minimum Coverage**: 70% (enforced in CI)
- **Target Coverage**: 80%+ for critical paths
- **Security Code**: 90%+ coverage required

View coverage reports:
```bash
# Generate HTML report
cargo llvm-cov test --html

# Open report
open target/llvm-cov/html/index.html
```

## Testing Best Practices

### 1. Test Naming
```rust
#[test]
fn test_scanner_detects_unicode_bidi_override() { }
//  ^---- descriptive name explaining what is tested
```

### 2. Test Structure
```rust
#[test]
fn test_feature() {
    // Arrange
    let config = create_test_config();
    
    // Act
    let result = function_under_test(config);
    
    // Assert
    assert_eq!(result, expected);
}
```

### 3. Async Tests
```rust
#[tokio::test]
async fn test_async_operation() {
    let server = create_test_server().await;
    // test implementation
}
```

### 4. Serial Tests
```rust
#[test]
#[serial]
fn test_requiring_exclusive_access() {
    // Tests that can't run in parallel
}
```

## Mock Testing

All major traits support mocking:

```rust
let mut mock = MockSecurityEventProcessor::new();
mock.expect_process_event()
    .times(1)
    .returning(|_| Ok(EventHandle::default()));
```

See [MOCKING.md](MOCKING.md) for detailed mock usage.

## Performance Testing

Monitor performance with benchmarks:

```bash
# Run benchmarks
cargo bench

# Compare with baseline
./scripts/perf-regression.sh

# Create new baseline
./scripts/perf-regression.sh --baseline
```

See [PERFORMANCE_TESTING.md](PERFORMANCE_TESTING.md) for details.

## Security Testing

Security is validated through:

1. **Unit tests** for specific threats
2. **Property tests** for edge cases
3. **Fuzz tests** for unknown vulnerabilities
4. **Integration tests** for attack scenarios

## Debugging Tests

### Failed Tests
```bash
# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_name -- --exact

# Debug with nextest
cargo nextest run -E 'test(test_name)'
```

### Coverage Gaps
```bash
# Find untested code
cargo llvm-cov test --show-missing-lines
```

### Performance Issues
```bash
# Profile tests
cargo test --release -- --profile-time
```

## Adding New Tests

1. **Identify category** - unit, integration, e2e, etc.
2. **Use helpers** - leverage existing test utilities
3. **Mock dependencies** - isolate code under test
4. **Add to CI** - ensure tests run automatically
5. **Document** - explain complex test scenarios

## Test Maintenance

- Review and update tests with code changes
- Remove obsolete tests
- Keep test data minimal and focused
- Ensure tests remain fast and reliable

## Continuous Improvement

- Monitor test execution time
- Track coverage trends
- Review flaky tests
- Update test infrastructure
- Add new test categories as needed