# Testing Guide for KindlyGuard

## Overview

KindlyGuard uses a comprehensive testing strategy to ensure security, reliability, and performance. Our test suite includes unit tests, integration tests, property-based tests, security-specific tests, and end-to-end scenarios.

## Test Organization

```
tests/
├── helpers/              # Shared test utilities
├── integration_test.rs   # Basic integration tests
├── property_tests.rs     # Property-based testing with proptest
├── mcp_protocol_tests.rs # MCP protocol compliance tests
├── mcp_error_tests.rs    # Error handling tests
├── mcp_auth_tests.rs     # Authentication and authorization tests
├── mcp_advanced_tests.rs # Advanced MCP features
├── e2e_tests.rs         # End-to-end scenarios
└── security_tests.rs    # Security-specific tests
```

## Running Tests

### Quick Test Commands

```bash
# Run all tests with cargo-nextest (fastest)
make test

# Run tests without enhanced features
make test-fast

# Run tests with coverage reporting
make test-coverage

# Run security-specific tests
make test-security

# Run property-based tests
make test-property

# Run comprehensive test suite
./scripts/test-all.sh
```

### Using Cargo Directly

```bash
# Run all tests
cargo test --all-features

# Run specific test file
cargo test --test mcp_protocol_tests

# Run tests matching pattern
cargo nextest run test_auth

# Run tests with output
cargo test -- --nocapture

# Run benchmarks
cargo bench
```

## Test Categories

### 1. Unit Tests
Located in `src/` modules under `#[cfg(test)]` blocks.

**Focus**: Individual components in isolation
- Scanner modules (unicode, injection, patterns)
- Authentication logic
- Rate limiting
- Configuration parsing

### 2. Integration Tests

**`integration_test.rs`**: Tests interaction between components
- Standard vs Enhanced mode switching
- Component manager functionality
- Cross-module interactions

### 3. MCP Protocol Tests

**`mcp_protocol_tests.rs`**: Core protocol compliance
- All MCP methods (initialize, tools/*, resources/*, prompts/*)
- JSON-RPC 2.0 compliance
- Batch requests
- Notifications

**`mcp_error_tests.rs`**: Error handling
- Parse errors
- Invalid requests
- Method not found
- Invalid parameters
- Internal errors

**`mcp_auth_tests.rs`**: Security features
- OAuth 2.0 bearer tokens
- Message signing
- Permission checks
- Rate limiting

**`mcp_advanced_tests.rs`**: Advanced features
- Completion support
- Progress notifications
- Cancellation
- Logging

### 4. Property-Based Tests

**`property_tests.rs`**: Using proptest for exhaustive testing
- Scanner never panics
- Threat locations are valid
- Deterministic results
- JSON depth limits
- Mixed threat detection

### 5. Security Tests

**`security_tests.rs`**: Security-specific scenarios
- Timing attack resistance
- DoS protection
- ReDoS prevention
- Memory exhaustion
- Path traversal
- Command injection
- Unicode normalization

### 6. End-to-End Tests

**`e2e_tests.rs`**: Complete user workflows
- Full security scanning workflow
- Multi-client scenarios
- Attack detection patterns
- Rate limiting behavior
- Performance under load

## Coverage Requirements

- **Minimum Coverage**: 70% overall
- **Critical Paths**: 80% for security modules
- **New Code**: 80% for pull requests

Check coverage with:
```bash
./scripts/coverage.sh
# or
make test-coverage
```

## Writing New Tests

### Test Helpers

Use the helpers module for common functionality:

```rust
mod helpers;
use helpers::*;

// Create standard init request
let init = create_init_request(1);

// Validate JSON-RPC response
validate_jsonrpc_response(&response, expected_id);

// Validate error response
validate_jsonrpc_error(&response, -32602);
```

### Best Practices

1. **Test Naming**: Use descriptive names
   ```rust
   #[test]
   fn test_scanner_detects_unicode_bidi_override() { }
   ```

2. **Isolation**: Tests should not depend on external state
   ```rust
   #[tokio::test]
   #[serial] // For tests that need exclusive access
   async fn test_rate_limiting() { }
   ```

3. **Property Testing**: Use for edge cases
   ```rust
   proptest! {
       #[test]
       fn test_scanner_handles_any_input(s in ".*") {
           let scanner = create_scanner();
           prop_assert!(scanner.scan(&s).is_ok());
       }
   }
   ```

4. **Security Testing**: Always test both positive and negative cases
   ```rust
   // Test that valid tokens work
   assert!(auth_with_valid_token().is_ok());
   
   // Test that invalid tokens fail
   assert!(auth_with_invalid_token().is_err());
   
   // Test timing attacks
   assert_constant_time_comparison();
   ```

## Continuous Integration

Tests run automatically on:
- Every push to main/develop
- All pull requests
- Nightly security scans

CI includes:
- Multiple Rust versions (stable, beta, nightly)
- Coverage reporting to Codecov
- Security audit with cargo-audit
- Clippy lints
- Format checking

## Performance Testing

Run benchmarks:
```bash
cargo bench
```

Key benchmarks:
- Scanner throughput
- Unicode detection performance
- Pattern matching speed
- Auth token validation

## Fuzzing

For security-critical components:

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run fuzzer (requires nightly)
cargo +nightly fuzz run fuzz_scanner
```

## Debugging Tests

```bash
# Run single test with output
cargo test test_name -- --nocapture

# Run with backtrace
RUST_BACKTRACE=1 cargo test

# Run with debug logging
RUST_LOG=debug cargo test

# Use nextest for better output
cargo nextest run --failure-output immediate
```

## Test Maintenance

1. **Keep tests fast**: Use mocking where appropriate
2. **Update tests**: When changing behavior
3. **Remove flaky tests**: Fix or remove unreliable tests
4. **Document complex tests**: Add comments explaining why
5. **Review test coverage**: Regularly check uncovered code

## Security Test Checklist

When adding security features, ensure tests for:
- [ ] Input validation
- [ ] Boundary conditions  
- [ ] Error handling
- [ ] Resource limits
- [ ] Timing attacks
- [ ] Injection attempts
- [ ] Authentication bypass
- [ ] Authorization checks