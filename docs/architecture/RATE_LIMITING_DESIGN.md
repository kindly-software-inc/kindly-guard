# Rate Limiting in KindlyGuard

## Overview

KindlyGuard implements advanced rate limiting to protect against various types of abuse and ensure fair resource allocation. The rate limiting system is designed for high performance and scalability.

## Architecture

### Token Bucket Algorithm

The rate limiter uses a token bucket algorithm with the following properties:

- **Capacity**: Maximum burst size
- **Refill Rate**: Tokens added per second
- **Fair Sharing**: Resources distributed fairly among clients

### Performance Characteristics

- **Complexity**: O(1) amortized time complexity
- **Scalability**: Linear scaling with CPU cores
- **Memory**: Minimal memory footprint per client

## Configuration

### Basic Configuration

```toml
[rate_limiting]
# Global rate limit
global_limit = 1000  # requests per second
burst_size = 100     # burst capacity

# Per-client limits
[rate_limiting.per_client]
default_limit = 100  # requests per second
burst_size = 20      # burst capacity
```

### Advanced Configuration

```toml
[rate_limiting.advanced]
# Enable advanced features
mode = "enhanced"

# Granular control
[rate_limiting.endpoints]
"/api/scan" = { limit = 50, burst = 10 }
"/api/status" = { limit = 1000, burst = 100 }
```

## Usage Examples

### Basic Rate Limiting

```rust
use kindly_guard_server::create_rate_limiter;

let rate_limiter = create_rate_limiter(&config)?;

// Check if request is allowed
if rate_limiter.check_rate("client_id", 1).await? {
    // Process request
} else {
    // Rate limit exceeded
}
```

### With Circuit Breaker

```rust
let rate_limiter = create_rate_limiter(&config)?;
let circuit_breaker = create_circuit_breaker(&config)?;

// Combined protection
let result = circuit_breaker.call("api", || async {
    if rate_limiter.check_rate("client", 1).await? {
        // Make API call
        api_client.request().await
    } else {
        Err(RateLimitExceeded)
    }
}).await?;
```

## Integration Points

### MCP Protocol

Rate limiting is automatically applied to all MCP requests:

- Tool invocations
- Resource access
- Notification handling

### HTTP API

When using HTTP transport, rate limiting includes:

- IP-based limiting
- API key-based limiting
- Endpoint-specific limits

## Monitoring

### Metrics

The rate limiter exposes the following metrics:

- `rate_limit_allowed_total` - Allowed requests
- `rate_limit_rejected_total` - Rejected requests
- `rate_limit_tokens_available` - Current token count

### Logging

Enable debug logging to monitor rate limiting:

```bash
RUST_LOG=kindly_guard::rate_limit=debug cargo run
```

## Best Practices

1. **Set Reasonable Limits**: Start conservative and adjust based on monitoring
2. **Use Burst Capacity**: Allow short bursts while preventing sustained abuse
3. **Monitor Metrics**: Track rejection rates to identify legitimate vs abusive traffic
4. **Client Identification**: Use appropriate client identifiers (API keys, IPs, etc.)
5. **Graceful Degradation**: Return proper error codes when limits are exceeded

## Error Handling

Rate limit errors include:

- `RateLimitExceeded` - Client exceeded their limit
- `GlobalLimitExceeded` - System-wide limit reached
- `InvalidConfiguration` - Configuration error

Example error response:

```json
{
  "error": "rate_limit_exceeded",
  "retry_after": 5,
  "limit": 100,
  "remaining": 0,
  "reset": 1234567890
}
```

## Performance Tuning

### Memory Usage

Each rate limiter instance uses approximately:
- Base overhead: ~1KB
- Per-client state: ~128 bytes

### CPU Usage

- Checking rate: <1μs typical
- Token refill: Performed lazily on check

### Scalability

The rate limiter scales linearly with:
- Number of CPU cores
- Number of clients
- Request rate

## Advanced Features

When using enhanced mode (`--features enhanced`), additional capabilities include:

- Distributed rate limiting across multiple servers
- Persistent state for rate limit recovery
- Advanced analytics and reporting
- Custom rate limit strategies

## Troubleshooting

### Common Issues

1. **All requests rejected**
   - Check configuration values
   - Verify client identification
   - Review logs for errors

2. **Inconsistent limiting**
   - Ensure proper client identification
   - Check for clock skew
   - Verify configuration reload

3. **Performance degradation**
   - Monitor client count
   - Check for memory leaks
   - Profile with `cargo flamegraph`

### Debug Commands

```bash
# Check current rate limit status
kindly-guard debug rate-limit --client "client_id"

# Reset rate limits
kindly-guard admin reset-limits --confirm

# Export rate limit stats
kindly-guard export rate-limits --format json
```

## See Also

- [Circuit Breaker Pattern](./architecture/ARCHITECTURE.md#circuit-breaker)
- [Performance Tuning](./PERFORMANCE_TUNING.md)
- [Monitoring Guide](./MONITORING.md)