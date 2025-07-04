# Security Error Handling Guide

This document provides comprehensive guidance on handling security-critical errors in KindlyGuard.

## Core Security Principles

### 1. Fail Closed
- **Always deny by default** when a security decision cannot be made
- Never allow operations to proceed when security state is uncertain
- Example: If threat scanner fails to initialize, block all requests

### 2. Information Hiding
- **Never expose internal details** in external error messages
- Use generic messages for all security-related errors
- Log detailed information internally for security team only

### 3. Audit Everything
- All security errors **MUST** generate audit events
- Include: timestamp, client ID, IP address, action attempted
- Preserve evidence for forensic analysis

### 4. Constant-Time Operations
- Use constant-time comparisons for all security decisions
- Prevent timing attacks on authentication/authorization

## Security-Critical Error Types

### 1. ThreatDetected - CRITICAL

**When it occurs:**
- Unicode attacks (invisible characters, RTL override)
- Injection attempts (SQL, command, path traversal)
- Known malicious patterns detected

**Security implications:**
- Active attack in progress
- Potential system compromise attempt
- Data exfiltration risk

**Handling:**
```rust
use kindly_guard_server::error::{KindlyError, security_patterns::handle_threat};

// ALWAYS fail closed
match scanner.scan_text(input) {
    Ok(threats) if !threats.is_empty() => {
        // Log full details internally
        audit_log.critical(AuditEvent::ThreatDetected {
            client_id,
            threat_type: threats[0].threat_type.clone(),
            input_hash: sha256(input),
        });
        
        // Return generic error
        return Err(handle_threat(&threats[0], input));
    }
    Ok(_) => proceed(),
    Err(_) => {
        // Scanner failure = fail closed
        return Err(KindlyError::Internal("Security check failed".into()));
    }
}
```

**Recovery:**
- Block request immediately
- Increment threat counter for client
- Consider temporary IP ban after N attempts
- Alert security team for severe threats

### 2. AuthError/Unauthorized - CRITICAL

**When it occurs:**
- Invalid credentials
- Expired tokens
- Missing authentication
- Failed authorization checks

**Security implications:**
- Unauthorized access attempt
- Credential stuffing attack
- Privilege escalation attempt

**Handling:**
```rust
use kindly_guard_server::error::security_patterns::{handle_auth_error, constant_time_compare};

// Use constant-time comparison
if !constant_time_compare(provided_token.as_bytes(), expected_token.as_bytes()) {
    // Apply progressive delay
    let delay = 2u64.pow(failure_count);
    tokio::time::sleep(Duration::from_secs(delay)).await;
    
    return handle_auth_error(
        anyhow!("Token mismatch"),
        &client_id
    );
}
```

**Progressive penalties:**
- 1st attempt: No delay
- 2nd attempt: 2 second delay
- 3rd attempt: 4 second delay
- 4th attempt: 8 second delay
- 5th attempt: Account lockout

**Logging requirements:**
```rust
audit_log.critical(AuditEvent::AuthFailure {
    timestamp: SystemTime::now(),
    client_id: hash_client_id(&client_id),
    ip_address: client_ip,
    failure_count,
    lockout_triggered: failure_count >= 5,
});
```

### 3. ValidationError/InvalidInput - HIGH

**When it occurs:**
- Malformed input data
- Invalid parameters
- Failed schema validation
- Suspicious patterns

**Security implications:**
- Potential injection probe
- Fuzzing attempt
- API abuse

**Handling:**
```rust
// Never echo back invalid input
match validate_input(&params) {
    Err(e) => {
        warn!(
            target: "security.validation",
            error = %e,
            client_id = %client_id,
            "Input validation failed"
        );
        
        // Generic error message
        return Err(KindlyError::InvalidInput {
            reason: "Invalid request parameters".to_string()
        });
    }
    Ok(validated) => validated,
}
```

### 4. ResourceError/TimeoutError - HIGH

**When it occurs:**
- Rate limit exceeded
- Memory limit reached
- Connection pool exhausted
- Operation timeout

**Security implications:**
- DoS attack in progress
- Resource exhaustion attack
- Slowloris attack

**Handling:**
```rust
use kindly_guard_server::error::security_patterns::{handle_resource_limit, handle_timeout};

// Rate limiting with circuit breaker
if !rate_limiter.check_limit(&client_id).await? {
    circuit_breaker.record_failure(&client_id);
    
    return handle_resource_limit("rate_limit", &client_id);
}

// Timeout with jitter
match timeout(Duration::from_secs(30), operation()).await {
    Ok(result) => result?,
    Err(_) => return handle_timeout(30), // Adds random jitter
}
```

## Error Response Examples

### Safe External Response
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32004,
    "message": "Request blocked by security policy"
  }
}
```

### Internal Audit Log
```json
{
  "timestamp": "2024-01-20T15:30:45Z",
  "severity": "CRITICAL",
  "event_type": "threat_detected",
  "client_id": "abc123hash",
  "threat": {
    "type": "sql_injection",
    "pattern": "'; DROP TABLE users; --",
    "location": "params.query",
    "confidence": 0.95
  },
  "action_taken": "request_blocked",
  "ip_address": "192.168.1.100"
}
```

## Best Practices

### 1. Error Message Guidelines
```rust
// BAD: Reveals internal information
Err(KindlyError::AuthError {
    reason: "User 'admin' not found in database".to_string()
})

// GOOD: Generic message
Err(KindlyError::AuthError {
    reason: "Authentication failed".to_string()
})
```

### 2. Timing Attack Prevention
```rust
// BAD: Early return reveals information
if !user_exists(&username) {
    return Err(AuthError);
}
if !verify_password(&password) {
    return Err(AuthError);
}

// GOOD: Constant time regardless of failure point
let user_valid = user_exists(&username);
let pass_valid = verify_password(&password);
if !user_valid || !pass_valid {
    return Err(AuthError);
}
```

### 3. Resource Cleanup
```rust
// Always clean up on security errors
let result = match security_check() {
    Ok(_) => process_request().await,
    Err(e) => {
        // Clean up resources
        connection_pool.release();
        temp_files.cleanup();
        
        // Then propagate error
        Err(e)
    }
};
```

## Security Error Metrics

Monitor these metrics for security insights:

1. **auth_failures_total**: Authentication failure rate
2. **threats_detected_total**: Active threats blocked
3. **validation_errors_total**: Input validation failures
4. **resource_exhaustion_total**: DoS attempt indicators
5. **error_response_time**: Ensure consistent timing

## Testing Security Errors

```rust
#[cfg(test)]
mod security_tests {
    #[test]
    fn test_no_information_leakage() {
        let err1 = handle_auth_error("user_not_found");
        let err2 = handle_auth_error("invalid_password");
        
        // Both should return identical messages
        assert_eq!(err1.to_string(), err2.to_string());
    }
    
    #[test]
    fn test_constant_time_comparison() {
        let start = Instant::now();
        constant_time_compare(b"short", b"very_long_string");
        let dur1 = start.elapsed();
        
        let start = Instant::now();
        constant_time_compare(b"equal", b"equal");
        let dur2 = start.elapsed();
        
        // Timing should be similar regardless of match
        assert!((dur1.as_nanos() as i64 - dur2.as_nanos() as i64).abs() < 1000);
    }
}
```

## Incident Response

When security errors spike:

1. **Immediate Actions:**
   - Check audit logs for patterns
   - Enable enhanced monitoring
   - Consider emergency rate limiting

2. **Investigation:**
   - Correlate IPs with known threat lists
   - Analyze attack patterns
   - Check for zero-day indicators

3. **Mitigation:**
   - Deploy additional rate limits
   - Update threat patterns
   - Consider IP blocking for severe cases

## Remember

> "Security is only as strong as the weakest error message" 

Always err on the side of caution. When in doubt:
- Fail closed
- Log internally
- Return generic error
- Alert security team