# KindlyGuard Final Test Fix Plan

## Priority 0 (P0) - Critical Security Functionality

### 1. Fix Pattern Matcher SQL Injection Detection
**Issue**: The pattern matcher test is failing because it's using `contains()` instead of regex matching.
**File**: `kindly-guard-core/src/pattern_matcher.rs`
**Fix**: 
```rust
// Line 116 - Replace string contains with regex matching
use regex::Regex;

pub fn scan(&self, text: &str) -> Vec<PatternMatch> {
    let mut matches = Vec::new();
    
    for (name, compiled) in &self.patterns {
        let re = Regex::new(&compiled.pattern).unwrap_or_else(|_| {
            // Fallback to literal match if regex fails
            Regex::new(&regex::escape(&compiled.pattern)).unwrap()
        });
        
        if let Some(mat) = re.find(text) {
            matches.push(PatternMatch {
                threat_type: compiled.threat_type,
                location: mat.start(),
                pattern_name: name.clone(),
                confidence: compiled.confidence_base,
            });
        }
    }
    
    matches
}
```
**Expected Outcome**: SQL injection patterns like "UNION SELECT" will be properly detected.

### 2. Fix WebSocket Test Compilation Errors
**Issue**: Missing `SinkExt` trait import for WebSocket stream operations.
**File**: `kindly-guard-server/tests/multi_protocol_security_tests_standalone.rs`
**Fix**:
```rust
// Add at the top of the file
use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;

// Replace ws.send() with proper sink operations
// Line 277
let _ = ws.send(msg).await;

// Replace ws.receive() with proper stream operations  
// Line 279
if let Some(Ok(response)) = ws.next().await {
    // Handle response
}
```
**Expected Outcome**: WebSocket tests will compile and run properly.

## Priority 1 (P1) - Core Functionality

### 3. Fix Async Runtime Issues in Integration Tests
**Issue**: Tests are missing proper async runtime setup and error type conversions.
**File**: `kindly-guard-server/tests/chaos_engineering_tests.rs`
**Fix**:
```rust
// Add proper error conversion for anyhow::Error to KindlyError
// In the error handling sections (lines 675, 735, 819)
chaos_clone.inject_failure().await
    .map_err(|e| KindlyError::Internal(e.to_string()))?;

// Fix the circuit breaker trait method calls
// The trait methods need to match the actual trait definition
```
**Expected Outcome**: Chaos engineering tests will compile with proper error handling.

### 4. Fix Scanner Configuration in Tests
**Issue**: `SecurityScanner::new()` requires a `ScannerConfig` parameter.
**File**: `kindly-guard-server/tests/chaos_engineering_tests.rs`
**Fix**:
```rust
// Line 357
let scanner = SecurityScanner::new(ScannerConfig::default())?;
```
**Expected Outcome**: Scanner will be properly initialized in tests.

### 5. Fix Missing Dependencies in Tests
**Issue**: `tower_http::limit` module not found.
**File**: `kindly-guard-server/tests/multi_protocol_security_tests_standalone.rs`
**Fix**:
```rust
// Either add the feature flag to Cargo.toml
[dev-dependencies]
tower-http = { version = "0.6", features = ["limit"] }

// Or remove the body limit layer if not critical for the test
```
**Expected Outcome**: Test dependencies will resolve correctly.

## Priority 2 (P2) - Non-Critical Improvements

### 6. Fix String Type Mismatches
**Issue**: String literals need `.to_string()` conversion.
**Files**: Various test files
**Fix**: Add `.to_string()` to string literals where needed.

### 7. Fix Temporary Value Borrowing
**Issue**: Temporary strings being borrowed in test vectors.
**File**: `kindly-guard-server/tests/multi_protocol_security_tests_standalone.rs`
**Fix**:
```rust
// Create owned strings before the vec
let medium_input = "a".repeat(100);
let long_input = "a".repeat(1000);
let test_inputs = vec![
    ("short", "abc"),
    ("medium", medium_input.as_str()),
    ("long", long_input.as_str()),
    // ...
];
```

### 8. Add Missing Test Helper Functions
**Issue**: `create_invisible_text` function not found.
**File**: `kindly-guard-server/tests/enhanced_prompt_injection_tests.rs`
**Fix**: Either implement the helper function or remove tests that depend on it.

## Implementation Order

1. **First Wave (P0 fixes)**:
   - Fix pattern matcher regex implementation
   - Add WebSocket trait imports
   - Run core tests to verify fixes

2. **Second Wave (P1 fixes)**:
   - Fix async/error handling in chaos tests
   - Fix scanner initialization
   - Update test dependencies

3. **Third Wave (P2 fixes)**:
   - Clean up string conversions
   - Fix temporary borrowing issues
   - Add missing helper functions

## Success Criteria

After implementing these fixes:
- All core security tests should pass (pattern matching, threat detection)
- WebSocket tests should compile and run
- Integration tests should have proper async runtime setup
- No compilation errors in the test suite
- Core MCP server functionality remains intact

## Testing Commands

```bash
# Test pattern matcher fix
cargo test -p kindly-guard-core test_pattern_matcher

# Test WebSocket functionality
cargo test -p kindly-guard-server --features websocket multi_protocol

# Test all integration tests
cargo test -p kindly-guard-server --all-features

# Run full test suite
cargo test --workspace --all-features
```

## Notes

- The pattern matcher fix is the most critical as it affects core security functionality
- WebSocket support is important for real-time threat monitoring
- Some tests may need feature flags enabled in Cargo.toml
- Consider adding regression tests for each fix