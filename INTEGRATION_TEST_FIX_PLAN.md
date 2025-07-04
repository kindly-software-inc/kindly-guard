# Integration Test Fix Plan

## Overview
After production readiness improvements, we need to fix several integration test compilation errors before the codebase is fully ready.

## Identified Issues

### 1. CLI Wrapper Tests (`cli_wrapper_security_tests.rs`)
- **Error**: Unicode escape in byte string
- **Error**: `does_not_contain` function not found in `predicate::str`
- **Error**: `TestWebSocketServer` type not found
- **Fix**: 
  - Use regular strings instead of byte strings for unicode
  - Use correct predicate functions
  - Import or define missing test infrastructure

### 2. Enhanced Prompt Injection Tests (`enhanced_prompt_injection_tests.rs`)
- **Error**: String type mismatches (expected String, found &str)
- **Error**: Missing `create_invisible_text` function
- **Fix**:
  - Add `.to_string()` to string literals
  - Implement or import the missing helper function

### 3. Chaos Engineering Tests (`chaos_engineering_tests.rs`)
- **Error**: `SecurityScanner::new()` requires `ScannerConfig` argument
- **Error**: `scan_text` method not found (should be `scan`)
- **Error**: Circuit breaker trait methods don't match implementation
- **Error**: `anyhow::Error` to `KindlyError` conversion
- **Fix**:
  - Pass config to scanner constructor
  - Use correct method names
  - Update trait method calls
  - Add error conversion implementations

### 4. AI Service Integration Tests (`ai_service_integration_tests.rs`)
- **Error**: `create_test_websocket_server` function not found
- **Fix**: Implement test helper or import from common module

### 5. OWASP ASVS Compliance Tests (`owasp_asvs_compliance_tests.rs`)
- **Error**: `SigningKey::generate` not found
- **Fix**: Use correct API for key generation

### 6. Multi-Protocol Security Tests
- **Error**: WebSocket test infrastructure issues
- **Fix**: Already partially fixed, may need additional imports

## Implementation Plan

### Phase 1: Quick Fixes (String & Import Issues)
1. Fix string type mismatches in enhanced_prompt_injection_tests.rs
2. Fix predicate imports in cli_wrapper_security_tests.rs
3. Add missing helper functions

### Phase 2: API Compatibility
1. Update SecurityScanner constructor calls with config
2. Fix method names (scan_text → scan)
3. Update circuit breaker trait method calls
4. Fix signing key generation

### Phase 3: Test Infrastructure
1. Create missing test helper functions
2. Import or implement WebSocket test server
3. Add error conversion implementations

### Phase 4: Validation
1. Run all integration tests
2. Fix any remaining issues
3. Ensure all tests pass

## Commands to Test Each Fix

```bash
# Test individual suites
cargo test --test cli_wrapper_security_tests
cargo test --test enhanced_prompt_injection_tests
cargo test --test chaos_engineering_tests
cargo test --test ai_service_integration_tests
cargo test --test owasp_asvs_compliance_tests
cargo test --test multi_protocol_security_tests

# Test all integration tests
cargo test --workspace --test '*'
```

## Success Criteria
- All integration tests compile without errors
- All integration tests pass
- No regression in unit tests
- CI/CD pipeline ready for deployment