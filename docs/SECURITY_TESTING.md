# KindlyGuard Security Testing Guide

This document describes our comprehensive security testing approach for KindlyGuard.

## Overview

KindlyGuard employs multiple layers of security testing to ensure robustness against attacks:

1. **Property-Based Testing** - Validates invariants across random inputs
2. **Fuzzing** - Discovers edge cases and crashes through guided randomness
3. **Static Analysis** - Detects unsafe code and vulnerability patterns
4. **Dependency Auditing** - Monitors for known vulnerabilities

## 1. Property-Based Testing

Located in `kindly-guard-server/tests/property_tests.rs`

### Running Property Tests
```bash
cd kindly-guard-server
cargo test --test property_tests
```

### Key Properties Tested

- **Scanner Never Panics**: Any input should be handled gracefully
- **Deterministic Results**: Same input produces same threats
- **Valid Threat Locations**: All locations point to valid positions
- **Depth Limit Enforcement**: JSON scanning respects depth limits

### Adding New Properties

```rust
proptest! {
    #[test]
    fn my_property(input in strategy()) {
        // Property assertion
        prop_assert!(invariant_holds(input));
    }
}
```

## 2. Fuzzing

Located in `fuzz/` directory

### Quick Start
```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run unicode scanner fuzzing for 1 hour
./scripts/fuzz.sh run fuzz_unicode_scanner -t 3600

# Run all fuzzers
./scripts/fuzz.sh run-all
```

### Fuzz Targets

| Target | Description | Focus Areas |
|--------|-------------|-------------|
| fuzz_unicode_scanner | Unicode threat detection | Malformed UTF-8, combining chars, BiDi |
| fuzz_injection_detector | Injection pattern matching | Nested payloads, polyglots, encodings |
| fuzz_mcp_protocol | MCP protocol parsing | Malformed JSON-RPC, batch requests |
| fuzz_event_buffer | Concurrent buffer access | Race conditions, memory safety |

### Interpreting Results

- **Crashes**: Saved to `fuzz/artifacts/<target>/`
- **Timeouts**: May indicate algorithmic complexity issues
- **Coverage**: Use `cargo fuzz coverage` to analyze

## 3. Static Analysis

### Unsafe Code Detection
```bash
# Install cargo-geiger
cargo install cargo-geiger

# Check for unsafe code
cargo geiger --all-features
```

Expected output: Zero unsafe code in public API

### Clippy Lints
```bash
# Run with all lints enabled
cargo clippy -- -W clippy::all -W clippy::pedantic
```

### Security-Specific Lints
```toml
# In Cargo.toml
[lints.rust]
unsafe_code = "forbid"
missing_debug_implementations = "warn"

[lints.clippy]
unwrap_used = "warn"
expect_used = "warn"
panic = "warn"
unimplemented = "warn"
todo = "warn"
```

## 4. Dependency Auditing

### Cargo Audit
```bash
# Install cargo-audit
cargo install cargo-audit

# Run audit
cargo audit
```

### Cargo Deny
```bash
# Install cargo-deny
cargo install cargo-deny

# Check dependencies
cargo deny check
```

Configuration in `deny.toml`:
- Banned heavy dependencies
- License compliance
- Source verification

## 5. Performance Security

### Benchmarking
```bash
cargo bench
```

Key metrics:
- Scan latency < 1ms
- Memory usage stable under load
- No algorithmic complexity attacks

### Stress Testing
```rust
#[test]
fn stress_test_scanner() {
    let scanner = SecurityScanner::new(config).unwrap();
    
    // Test with pathological input
    let evil_input = "a".repeat(1_000_000);
    let start = Instant::now();
    let _ = scanner.scan_text(&evil_input);
    
    assert!(start.elapsed() < Duration::from_secs(1));
}
```

## 6. CI Security Pipeline

Our GitHub Actions workflow includes:

1. **Security Audit**: `cargo audit` on every push
2. **Unsafe Detection**: `cargo geiger` verification
3. **Property Tests**: Full test suite
4. **Fuzz Smoke Tests**: 60-second fuzz runs
5. **Coverage Analysis**: 90%+ target

## 7. Manual Security Review Checklist

Before each release:

- [ ] Run full fuzzing suite (1+ hour per target)
- [ ] Review all `unsafe` blocks (should be none)
- [ ] Audit new dependencies
- [ ] Check for timing side-channels
- [ ] Verify error messages don't leak sensitive info
- [ ] Test with malicious MCP clients
- [ ] Benchmark worst-case performance

## 8. Threat Model

### In Scope
- Malicious text input (Unicode attacks)
- Injection attempts (SQL, command, prompt)
- Protocol attacks (malformed JSON-RPC)
- DoS attempts (resource exhaustion)
- Concurrent access issues

### Out of Scope
- Physical access attacks
- Supply chain beyond direct dependencies
- Zero-day vulnerabilities in Rust std

## 9. Security Guarantees

After passing all tests:

1. **No Panics**: Fuzz-tested for 24+ hours
2. **No Unsafe**: Zero unsafe in public API
3. **No Known Vulnerabilities**: cargo-audit clean
4. **Performance Bounded**: <1ms scan latency
5. **Memory Safe**: No leaks or corruption

## 10. Reporting Security Issues

Found a security issue? Please report to:
- Email: security@kindlyguard.dev
- GitHub Security Advisories

## Quick Security Test

Run this before any commit:
```bash
#!/bin/bash
# Save as scripts/security-check.sh

echo "Running security checks..."

# Property tests
cargo test --test property_tests || exit 1

# Quick fuzz
./scripts/fuzz.sh run fuzz_unicode_scanner -t 60 || exit 1

# Audit
cargo audit || exit 1

# Unsafe check
cargo geiger --all-features || exit 1

echo "All security checks passed!"
```