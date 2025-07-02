# KindlyGuard API Documentation

## Overview

KindlyGuard is a security-focused MCP (Model Context Protocol) server that provides comprehensive threat detection and protection against unicode attacks, injection attempts, and other security threats.

## Core Components

### 1. McpServer

The main server implementation that handles MCP protocol communication.

```rust
use kindly_guard_server::{McpServer, Config};

// Create server with default config
let config = Config::default();
let server = McpServer::new(config)?;

// Handle MCP messages
let response = server.handle_message(&request_json).await;
```

### 2. SecurityScanner

Comprehensive security scanner for detecting various threats.

```rust
use kindly_guard_server::{SecurityScanner, ScannerConfig};

let config = ScannerConfig::default();
let scanner = SecurityScanner::new(config)?;

// Scan text for threats
let threats = scanner.scan_text("potentially dangerous text");

// Scan JSON data
let threats = scanner.scan_json(&json_value)?;
```

#### Threat Types Detected:
- **Unicode threats**: Invisible characters, BiDi overrides, homoglyphs
- **Injection attacks**: SQL, command, path traversal, prompt injection
- **Data leaks**: API keys, passwords, session tokens
- **Pattern-based threats**: Custom regex patterns

### 3. Configuration

#### Config Structure
```rust
pub struct Config {
    pub server: ServerConfig,
    pub scanner: ScannerConfig,
    pub shield: ShieldConfig,
    pub auth: AuthConfig,
    pub rate_limit: RateLimitConfig,
    pub telemetry: TelemetryConfig,
    pub audit: AuditConfig,
}
```

#### Loading Configuration
```rust
// From file
let config = Config::from_file("config.toml")?;

// From environment
let config = Config::from_env()?;

// Default with modifications
let mut config = Config::default();
config.scanner.unicode_detection = true;
config.rate_limit.default_rpm = 100;
```

### 4. Error Handling

All operations return `KindlyResult<T>` which provides rich error context.

```rust
use kindly_guard_server::{KindlyError, KindlyResult};

fn process_request() -> KindlyResult<String> {
    // Automatic error conversion with ?
    let scanner = SecurityScanner::new(config)?;
    let threats = scanner.scan_text(input)?;
    
    if !threats.is_empty() {
        return Err(KindlyError::ThreatDetected {
            threat_type: threats[0].threat_type.to_string(),
            location: threats[0].location.to_string(),
        });
    }
    
    Ok("Safe".to_string())
}
```

#### Error Types:
- `ThreatDetected`: Security threat found
- `AuthError`: Authentication failure
- `RateLimitExceeded`: Too many requests
- `ValidationError`: Invalid input
- `ConfigError`: Configuration issues

### 5. Authentication & Authorization

```rust
// JWT-based authentication
config.auth.enabled = true;
config.auth.validation_endpoint = "https://auth.example.com/validate";
config.auth.required_scopes = vec!["read".to_string()];

// Client authentication
let token = "Bearer eyJ...";
let is_valid = server.validate_token(token).await?;
```

### 6. Rate Limiting

```rust
// Global rate limiting
config.rate_limit.enabled = true;
config.rate_limit.default_rpm = 60;

// Per-method limits
config.rate_limit.method_limits.insert(
    "scan_text".to_string(), 
    100
);

// Per-client limits
config.rate_limit.client_limits.insert(
    "premium_client".to_string(),
    1000
);
```

### 7. Metrics & Monitoring

```rust
use kindly_guard_server::MetricsRegistry;

let registry = MetricsRegistry::new();

// Access built-in metrics
let metrics = registry.export_prometheus();

// Custom metrics
let counter = registry.counter("custom_events", "Custom event counter");
counter.inc();
```

Available metrics:
- `kindlyguard_requests_total`: Total requests
- `kindlyguard_requests_failed`: Failed requests
- `kindlyguard_request_duration`: Request latency histogram
- `kindlyguard_threats_detected`: Threats found
- `kindlyguard_rate_limit_hits`: Rate limit violations

### 8. Shield (UI Display)

```rust
use kindly_guard_server::Shield;

// Create shield display
let shield = Shield::new(config)?;

// Run interactive shield
shield.run().await?;

// Get current status
let status = shield.status();
println!("Threats blocked: {}", status.threats_blocked);
```

### 9. MCP Protocol Tools

Available MCP tools:
- `scan_text`: Scan text for security threats
- `scan_file`: Scan file contents
- `scan_url`: Scan URL content
- `monitor_start`: Start threat monitoring
- `monitor_stop`: Stop threat monitoring
- `shield_status`: Get shield status

### 10. Advanced Features

#### Event Processing (Enhanced Mode)
```rust
// Enable enhanced event processing
config.event_processor.enabled = true;
config.event_processor.buffer_size_mb = 100;
config.event_processor.correlation_window_secs = 60;
```

#### Audit Logging
```rust
// Enable audit logging
config.audit.enabled = true;
config.audit.file_path = Some("/var/log/kindlyguard/audit.log");
config.audit.rotation_size_mb = 100;
```

#### Graceful Shutdown
```rust
// Handle shutdown signals
let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

// In signal handler
shutdown_tx.send(()).ok();

// In server
server.run_until_shutdown(shutdown_rx).await?;
```

## Example: Complete MCP Server

```rust
use kindly_guard_server::{McpServer, Config, Shield};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize configuration
    let mut config = Config::from_env()?;
    config.scanner.unicode_detection = true;
    config.scanner.injection_detection = true;
    config.rate_limit.enabled = true;
    config.auth.enabled = true;
    
    // Create server
    let server = Arc::new(McpServer::new(config.clone())?);
    
    // Optional: Start shield UI
    if config.shield.enabled {
        let shield = Shield::new(config.shield)?;
        tokio::spawn(async move {
            shield.run().await
        });
    }
    
    // Run server with graceful shutdown
    let server_handle = tokio::spawn(async move {
        server.run().await
    });
    
    // Wait for shutdown signal
    signal::ctrl_c().await?;
    println!("Shutting down gracefully...");
    
    server_handle.abort();
    Ok(())
}
```

## Security Best Practices

1. **Always enable authentication in production**
   ```rust
   config.auth.enabled = true;
   ```

2. **Configure rate limiting**
   ```rust
   config.rate_limit.enabled = true;
   config.rate_limit.default_rpm = 60;
   ```

3. **Enable audit logging**
   ```rust
   config.audit.enabled = true;
   ```

4. **Use secure defaults**
   ```rust
   let config = Config::secure_defaults();
   ```

5. **Monitor metrics**
   - Set up Prometheus scraping for `/metrics`
   - Alert on high threat detection rates
   - Monitor rate limit violations

## Performance Tuning

### Standard Mode
- Lower memory usage
- Good for most use cases
- ~10,000 requests/second

### Enhanced Mode
- Advanced threat correlation
- Pattern learning
- ~5,000 requests/second
- Requires `enhanced` feature flag

```rust
// Enable enhanced mode
config.event_processor.enabled = true;
```

## Integration Examples

### With AI Assistant Applications
```json
{
  "mcpServers": {
    "kindly-guard": {
      "command": "kindly-guard",
      "args": ["--stdio"],
      "env": {
        "KINDLY_GUARD_AUTH_ENABLED": "true",
        "KINDLY_GUARD_SCANNER_UNICODE": "true"
      }
    }
  }
}
```

### With Docker
```dockerfile
FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/kindly-guard /usr/local/bin/
ENV KINDLY_GUARD_CONFIG=/etc/kindlyguard/config.toml
CMD ["kindly-guard", "--stdio"]
```

### With Kubernetes
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kindly-guard
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: kindly-guard
        image: kindlyguard:latest
        resources:
          requests:
            memory: "256Mi"
            cpu: "500m"
          limits:
            memory: "512Mi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /metrics
            port: 9090
```

## Troubleshooting

### Common Issues

1. **Rate limit errors**
   - Increase `default_rpm` or add client-specific limits
   - Check metrics for patterns

2. **Memory usage**
   - Reduce `event_processor.buffer_size_mb`
   - Disable shield UI in headless environments

3. **Authentication failures**
   - Verify JWT issuer configuration
   - Check token expiration
   - Ensure required scopes match

### Debug Mode
```bash
RUST_LOG=kindly_guard=debug kindly-guard --stdio
```

### Health Check
```bash
curl http://localhost:9090/metrics | grep kindlyguard_up
```

## API Stability

- Core scanner API: Stable
- MCP protocol: Stable (follows spec)
- Configuration: Stable with backwards compatibility
- Metrics: Stable Prometheus format
- Enhanced features: Beta (may change)

## License

See LICENSE file in the repository.