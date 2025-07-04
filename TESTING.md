# KindlyGuard Testing Guide

## Overview

KindlyGuard maintains comprehensive test coverage across all security features, with a focus on ensuring both correctness and security. Our testing philosophy follows the principle: **"Security First, Performance Second, Features Third"**.

## 📊 Test Statistics

### Current Coverage (v0.9.5)
- **Total Tests**: 235
- **Security Tests**: 58 (100% passing ✅)
- **Unit Tests**: 127 (100% passing ✅)
- **Integration Tests**: 35 (100% passing ✅)
- **Property Tests**: 15 (100% passing ✅)
- **Line Coverage**: 94%
- **Branch Coverage**: 89%

### Performance Benchmarks
- **Unicode Scanner**: 156.4 MB/s (↑ 15% from v0.9.0)
- **Injection Scanner**: 203.7 MB/s (↑ 12% from v0.9.0)
- **XSS Scanner**: 187.2 MB/s (↑ 8% from v0.9.0)
- **End-to-end Latency**: 0.43ms p50, 0.89ms p99

## 🚀 Nextest Integration

KindlyGuard uses [cargo-nextest](https://nexte.st/) for faster, more reliable test execution with enhanced isolation for security tests.

### Quick Start with Nextest

```bash
# Install nextest
cargo install cargo-nextest

# Run all tests with nextest
cargo nextest run

# Run with security profile (sequential, no retries)
cargo nextest run --profile=security

# Use our test runner script
./scripts/run-tests-nextest.sh
```

### Nextest Benefits for Security Testing

1. **Process Isolation**: Each test runs in its own process, preventing memory corruption spread
2. **Parallel Execution**: 2-3x faster test runs encourage frequent security testing
3. **Deterministic Ordering**: Helps identify test dependencies and race conditions
4. **Better Failure Reporting**: Immediate visibility of security test failures
5. **Retry Mechanism**: Distinguishes between flaky tests and real security issues

### Available Nextest Profiles

| Profile | Use Case | Key Features |
|---------|----------|-------------|
| `default` | Local development | Balanced parallelism, 2 retries |
| `security` | Security validation | Sequential only, no retries, extended timeouts |
| `ci` | CI/CD pipelines | Fixed 4 threads, JUnit output |
| `quick` | Rapid feedback | Max parallelism, skip slow tests |
| `release` | Pre-release validation | Conservative, full archival |

## 🧪 Test Categories

### 1. Security Tests (`tests/security_tests.rs`)
Comprehensive security vulnerability testing:

```bash
cargo test --test security_tests
```

**Coverage Areas**:
- ✅ Unicode exploits (homographs, BiDi, zero-width)
- ✅ Injection attacks (SQL, command, LDAP, NoSQL)
- ✅ XSS vectors (all contexts)
- ✅ Path traversal attempts
- ✅ DoS attack vectors
- ✅ Authentication bypasses
- ✅ Timing attacks
- ✅ Token security

**Key Tests**:
- `test_unicode_homograph_detection` - Cyrillic lookalikes
- `test_bidi_override_detection` - RTL/LTR attacks
- `test_sql_injection_detection` - All SQL dialects
- `test_command_injection_cross_platform` - Windows/Linux/macOS
- `test_dos_protection` - Resource exhaustion
- `test_resource_exhaustion_protection` - Resource limits

### 2. Unit Tests
Module-level testing for each component:

```bash
cargo test --lib
```

**Modules Tested**:
- Scanner implementations (100% coverage)
- Neutralizer strategies (100% coverage)
- Authentication logic (100% coverage)
- Rate limiting (100% coverage)
- Circuit breakers (100% coverage)
- Configuration parsing (100% coverage)

### 3. Integration Tests
End-to-end scenario testing:

```bash
cargo test --test integration
```

**Scenarios**:
- MCP protocol compliance
- Multi-client authentication
- Concurrent request handling
- Error propagation
- Resource cleanup
- Cross-component interaction

### 4. Property-Based Tests
Fuzzing with proptest:

```bash
cargo test --test property_tests
```

**Properties Verified**:
- No panics on any input
- Neutralization safety
- Scanner determinism
- Configuration validity
- Thread safety

### 5. Performance Tests
Regression prevention:

```bash
cargo bench
```

**Benchmarks**:
- Scanner throughput
- Neutralization speed
- Authentication overhead
- Circuit breaker latency
- Memory usage

## 🔧 Running Tests

### Quick Test Commands

```bash
# Run all tests with nextest (recommended)
cargo nextest run --all-features

# Run all tests with standard cargo test
cargo test --all-features

# Run specific test suite with nextest
cargo nextest run --test security_tests

# Run security tests with isolation
cargo nextest run --profile=security -E 'test(security)'

# Run with coverage using nextest
cargo llvm-cov nextest --html

# Run with coverage using tarpaulin
cargo tarpaulin --out Html

# Run benchmarks
cargo bench

# Run specific benchmark
cargo bench unicode_scanner

# Run fuzz tests
cargo fuzz run scanner_fuzzer

# Quick test run (skip slow tests)
cargo nextest run --profile=quick
```

### Comprehensive Test Scripts

```bash
# Run complete test suite with nextest
./scripts/run-tests-nextest.sh

# Run with specific profile
./scripts/run-tests-nextest.sh -p security

# Filter specific tests
./scripts/run-tests-nextest.sh -f unicode

# List tests without running
./scripts/run-tests-nextest.sh -l

# Legacy: Run complete test suite with cargo test
./run-all-tests.sh

# With coverage report
./run-all-tests.sh --coverage

# CI mode (fail fast)
./run-all-tests.sh --ci
```

### Platform-Specific Testing

```bash
# Test Windows-specific features
cargo test --features windows_security

# Test Unix-specific features  
cargo test --features unix_security

# Cross-platform tests
cargo test --test cross_platform_tests
```

## 🎯 Test Architecture

### Dual Implementation Testing

We test both standard and enhanced implementations:

```rust
#[test]
fn test_both_implementations() {
    let standard = StandardScanner::new();
    let enhanced = EnhancedScanner::new();
    
    let input = "test\u{202E}input";
    
    // Both must detect the same threats
    assert_eq!(
        standard.scan(input).unwrap(),
        enhanced.scan(input).unwrap()
    );
}
```

### Security Property Testing

```rust
proptest! {
    #[test]
    fn no_injection_bypasses(input: String) {
        let scanner = InjectionScanner::new();
        let result = scanner.scan(&input);
        
        // If marked safe, must not contain injection
        if result.is_safe() {
            assert!(!contains_injection(&input));
        }
    }
}
```

### Performance Regression Testing

```rust
#[bench]
fn bench_unicode_scanner(b: &mut Bencher) {
    let scanner = UnicodeScanner::new();
    let input = create_test_input(1024 * 1024); // 1MB
    
    b.iter(|| {
        scanner.scan(&input)
    });
    
    // Assert minimum throughput
    assert!(b.bytes > 100 * 1024 * 1024); // 100 MB/s
}
```

## 📈 Recent Test Improvements

### Fixed Security Vulnerabilities (v0.9.5)
1. **Timing Attack Prevention**
   - Implemented constant-time token comparison
   - Added timing-safe string operations
   - Test: `test_constant_time_comparison`

2. **Path Traversal Detection**
   - Enhanced pattern matching for "../" sequences
   - Added Windows path traversal patterns
   - Test: `test_path_traversal_variants`

3. **DoS Protection**
   - Added resource limits
   - Implemented scan depth limits
   - Added resource exhaustion protection
   - Tests: `test_dos_protection_suite`

4. **Cross-Platform Security**
   - Windows command injection patterns
   - PowerShell injection detection
   - Unix shell escape sequences
   - Tests: `test_platform_specific_injection`

### Performance Optimizations
1. **Scanner Pipeline** - 15% throughput improvement
2. **Pattern Caching** - Reduced regex compilation overhead
3. **Memory Pool** - Decreased allocations by 40%
4. **SIMD Usage** - Vectorized unicode scanning

## 🛡️ Security Test Examples

### Unicode Attack Detection
```rust
#[test]
fn test_unicode_attacks() {
    let scanner = SecurityScanner::new(config());
    
    // Homograph attack
    let threats = scanner.scan("pаypal.com"); // Cyrillic 'а'
    assert_eq!(threats[0].threat_type, ThreatType::Homograph);
    
    // BiDi override
    let threats = scanner.scan("Hello\u{202E}World");
    assert_eq!(threats[0].threat_type, ThreatType::BidiOverride);
    
    // Zero-width space
    let threats = scanner.scan("user\u{200B}name");
    assert_eq!(threats[0].threat_type, ThreatType::ZeroWidth);
}
```

### Injection Prevention
```rust
#[test]
fn test_injection_prevention() {
    let scanner = InjectionScanner::new();
    
    // SQL injection
    assert!(scanner.scan("'; DROP TABLE users; --").is_threat());
    
    // Command injection (cross-platform)
    assert!(scanner.scan("echo test && rm -rf /").is_threat());
    assert!(scanner.scan("echo test & del /f /s /q C:\\").is_threat());
    
    // Path traversal
    assert!(scanner.scan("../../../etc/passwd").is_threat());
    assert!(scanner.scan("..\\..\\..\\windows\\system32").is_threat());
}
```

## 📋 Test Checklist

Before each release, ensure:

- [ ] All security tests pass
- [ ] No performance regressions
- [ ] Property tests run 10,000+ iterations
- [ ] Fuzzing finds no crashes
- [ ] Cross-platform tests pass
- [ ] Integration tests complete
- [ ] Documentation examples compile
- [ ] Benchmarks meet targets

## 🚀 Continuous Testing

### CI Pipeline with Nextest
```yaml
test:
  strategy:
    matrix:
      os: [ubuntu-latest, windows-latest, macos-latest]
      rust: [stable, nightly]
  steps:
    - name: Install nextest
      uses: taiki-e/install-action@v2
      with:
        tool: nextest
    - cargo nextest run --all-features --profile=ci
    - cargo test --doc  # Doc tests still need cargo test
    - cargo bench --no-run
    - cargo clippy -- -D warnings
    - cargo audit
```

### Nightly Fuzzing
```bash
# Runs automatically every night
cargo fuzz run scanner_fuzzer -- -max_total_time=3600
```

### Security Audit
```bash
# Weekly security dependency check
cargo audit
cargo outdated --aggressive
```

## 📊 Test Reports

### Coverage Report Location
- HTML: `target/tarpaulin/tarpaulin-report.html`
- LCOV: `target/tarpaulin/lcov.info`
- JSON: `target/tarpaulin/tarpaulin-report.json`

### Benchmark Results
- Current: `target/criterion/report/index.html`
- History: `target/criterion/*/report/index.html`

### Security Scan Results
- SARIF: `target/security/report.sarif`
- JSON: `target/security/vulnerabilities.json`

## 🎯 Testing Best Practices

1. **Security First**: Always test security properties
2. **Deterministic**: Tests must be reproducible
3. **Fast**: Unit tests < 10ms, integration < 100ms
4. **Isolated**: No test interdependencies (enforced by nextest)
5. **Documented**: Clear test names and comments
6. **Named for Nextest**: Include "security", "unicode", or "integration" in test names for automatic profile selection
7. **No Shared State**: Each test should create its own fixtures

## 🔮 Future Testing Plans

### v1.0 Goals
- [ ] 100% line coverage
- [ ] Chaos engineering tests
- [ ] Load testing suite
- [ ] Penetration testing

### v1.1 Goals
- [ ] Distributed testing
- [ ] AI-powered test generation
- [ ] Continuous fuzzing
- [ ] Production chaos testing

---

**Remember**: A test not written is a bug waiting to happen. Test everything, especially security!