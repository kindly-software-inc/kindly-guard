# Mocking Guide for KindlyGuard

## Overview

KindlyGuard uses `mockall` for creating mock implementations of traits during testing. This enables testing components in isolation and simulating error conditions that would be difficult to reproduce with real implementations.

## Setup

All major traits in KindlyGuard are configured to support mocking:

```rust
#[async_trait]
#[cfg_attr(test, automock)]
pub trait SecurityEventProcessor: Send + Sync {
    // trait methods...
}
```

This generates a `MockSecurityEventProcessor` type automatically in test builds.

## Available Mocks

### Core Traits

- `MockSecurityEventProcessor` - Event processing and correlation
- `MockEnhancedScanner` - Threat scanning
- `MockCorrelationEngine` - Pattern detection
- `MockRateLimiter` - Rate limiting
- `MockToolPermissionManager` - Authorization

### Using Mocks in Tests

#### Basic Mock Setup

```rust
use kindly_guard_server::traits::*;
use mockall::predicate::*;

#[tokio::test]
async fn test_with_mock() {
    let mut mock = MockSecurityEventProcessor::new();
    
    // Set expectation
    mock.expect_process_event()
        .times(1)
        .returning(|_| Ok(EventHandle { 
            event_id: 1, 
            processed: true 
        }));
    
    // Use mock
    let event = create_test_event();
    let result = mock.process_event(event).await;
    assert!(result.is_ok());
}
```

#### Advanced Expectations

##### Matching Arguments

```rust
// Exact match
mock.expect_check_permission()
    .with(eq("user1"), eq("scan_text"), always())
    .returning(|_, _, _| Ok(Permission::Allow));

// Custom predicate
mock.expect_enhanced_scan()
    .withf(|data| {
        let text = String::from_utf8_lossy(data);
        text.contains("malware")
    })
    .returning(|_| Ok(vec![create_threat()]));
```

##### Sequences

```rust
let mut seq = mockall::Sequence::new();

// First call returns success
mock.expect_process_event()
    .times(1)
    .in_sequence(&mut seq)
    .returning(|_| Ok(create_handle()));

// Second call returns error
mock.expect_process_event()
    .times(1)
    .in_sequence(&mut seq)
    .returning(|_| Err(anyhow!("Buffer full")));
```

##### Times and Cardinality

```rust
// Exactly once
mock.expect_method().times(1);

// Never called
mock.expect_method().times(0);

// Any number of times
mock.expect_method().times(..);

// At least once
mock.expect_method().times(1..);

// Between 2 and 5 times
mock.expect_method().times(2..=5);
```

## Common Patterns

### Testing Error Conditions

```rust
#[tokio::test]
async fn test_scanner_network_failure() {
    let mut mock = MockEnhancedScanner::new();
    
    mock.expect_enhanced_scan()
        .returning(|_| Err(anyhow!("Network timeout")));
    
    // Test component handles error gracefully
    let scanner: Arc<dyn EnhancedScanner> = Arc::new(mock);
    let result = scanner.enhanced_scan(b"test data");
    
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Network timeout"));
}
```

### Testing Rate Limiting

```rust
#[tokio::test]
async fn test_progressive_rate_limiting() {
    let mut mock = MockRateLimiter::new();
    let mut seq = mockall::Sequence::new();
    
    // Allow first 5 requests
    for i in 0..5 {
        mock.expect_check_rate_limit()
            .times(1)
            .in_sequence(&mut seq)
            .returning(move |_| Ok(RateLimitDecision {
                allowed: true,
                tokens_remaining: (5 - i) as f64,
                tokens_used: 1.0,
                retry_after: None,
            }));
    }
    
    // Then deny
    mock.expect_check_rate_limit()
        .returning(|_| Ok(RateLimitDecision {
            allowed: false,
            tokens_remaining: 0.0,
            tokens_used: 0.0,
            retry_after: Some(60),
        }));
    
    // Test rate limit behavior
}
```

### Testing Permission Hierarchies

```rust
#[tokio::test]
async fn test_role_based_permissions() {
    let mut mock = MockToolPermissionManager::new();
    
    // Admin can do everything
    mock.expect_check_permission()
        .withf(|client_id, _, _| client_id == "admin")
        .returning(|_, _, _| Ok(Permission::Allow));
    
    // Users have limited access
    mock.expect_check_permission()
        .withf(|client_id, tool, _| {
            client_id == "user" && tool != "update_config"
        })
        .returning(|_, _, _| Ok(Permission::Allow));
    
    mock.expect_check_permission()
        .withf(|client_id, tool, _| {
            client_id == "user" && tool == "update_config"
        })
        .returning(|_, _, _| Ok(Permission::Deny(
            "Insufficient privileges".to_string()
        )));
}
```

### Component Factory Pattern

```rust
struct TestComponentFactory {
    scanner: Arc<MockEnhancedScanner>,
    processor: Arc<MockSecurityEventProcessor>,
}

impl TestComponentFactory {
    fn new() -> Self {
        let mut scanner = MockEnhancedScanner::new();
        scanner.expect_enhanced_scan()
            .returning(|_| Ok(vec![]));
        
        let mut processor = MockSecurityEventProcessor::new();
        processor.expect_process_event()
            .returning(|_| Ok(create_handle()));
        
        Self {
            scanner: Arc::new(scanner),
            processor: Arc::new(processor),
        }
    }
}
```

## Best Practices

### 1. Mock at the Right Level

Mock external dependencies and trait boundaries, not internal implementation details:

```rust
// Good: Mock external service
let mut mock_oauth = MockOAuthProvider::new();

// Bad: Mock internal helper function
// Don't mock private methods or internal structs
```

### 2. Use Descriptive Expectations

```rust
// Good: Clear what's being tested
mock.expect_check_permission()
    .withf(|client, tool, ctx| {
        client == "attacker" && 
        ctx.threat_level >= ThreatLevel::High
    })
    .times(1)
    .returning(|_, _, _| Ok(Permission::Deny(
        "High threat level detected".to_string()
    )));

// Bad: Unclear expectations
mock.expect_check_permission()
    .returning(|_, _, _| Ok(Permission::Deny("".to_string())));
```

### 3. Verify Important Interactions

```rust
// Ensure cleanup is called
mock.expect_cleanup()
    .times(1)
    .returning(|| Ok(()));

// Test code...

// Mock automatically verifies expectations
```

### 4. Use Predicates for Flexible Matching

```rust
use mockall::predicate::*;

// Match any string containing "admin"
mock.expect_method()
    .with(str::contains("admin"));

// Match values in range
mock.expect_method()
    .with(in_range(10..=20));

// Custom predicate
mock.expect_method()
    .withf(|x: &i32| x % 2 == 0); // Even numbers
```

### 5. Handle Async Properly

```rust
// For async traits
mock.expect_async_method()
    .returning(|_| Box::pin(async {
        // Async work here
        Ok(())
    }));

// Or simpler
mock.expect_async_method()
    .returning(|_| Ok(()));
```

## Testing Error Scenarios

### Network Failures

```rust
mock.expect_fetch_data()
    .returning(|_| Err(anyhow!("Connection refused")));
```

### Timeouts

```rust
mock.expect_process()
    .returning(|_| {
        // In real test, would use tokio::time::sleep
        Err(anyhow!("Operation timed out"))
    });
```

### Resource Exhaustion

```rust
mock.expect_allocate()
    .times(10)
    .returning(|_| Ok(Resource::new()))
    .times(1)
    .returning(|_| Err(anyhow!("Out of memory")));
```

## Debugging Mock Tests

### Enable Mock Debug Output

```rust
let mut mock = MockSecurityEventProcessor::new();
mock.checkpoint(); // Prints expectation status
```

### Common Issues

1. **Expectation Not Met**: Check times() and argument matchers
2. **Unexpected Call**: Add catch-all expectation or adjust times()
3. **Wrong Return Type**: Ensure returning() closure matches trait signature

## Integration with Test Infrastructure

Use mocks with our test helpers:

```rust
use helpers::*;

fn create_mock_server() -> Arc<McpServer> {
    let mut mock_scanner = MockEnhancedScanner::new();
    mock_scanner.expect_enhanced_scan()
        .returning(|_| Ok(vec![]));
    
    // Inject mock into server
    // ...
}
```

## Performance Considerations

Mocks have minimal overhead but:
- Don't create unnecessary expectations
- Use `times(..)` for methods called many times
- Consider real implementations for performance tests

## Examples

See these test files for comprehensive examples:
- `tests/mock_tests.rs` - Basic mock usage
- `tests/mock_auth_tests.rs` - Auth component mocking
- Individual unit tests throughout the codebase