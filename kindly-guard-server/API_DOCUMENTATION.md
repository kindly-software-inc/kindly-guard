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
    pub event_processor: EventProcessorConfig,
}

pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub pool_size: usize,  // Session pool size
    // ... other fields
}

pub struct EventProcessorConfig {
    pub enabled: bool,
    pub buffer_size: usize,  // Event buffer size
    pub buffer_size_mb: usize,
    pub correlation_window_secs: u64,
}

pub struct TelemetryConfig {
    pub enabled: bool,
    pub export_interval: Duration,  // Metrics export interval
    pub export_interval_secs: u64,
    // ... other fields
}

pub struct RateLimitConfig {
    pub enabled: bool,
    pub burst_size: u32,  // Rate limit burst size
    pub default_rpm: u32,
    pub method_limits: HashMap<String, u32>,
    pub client_limits: HashMap<String, u32>,
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

// Configure component settings
config.server.pool_size = 100;
config.event_processor.buffer_size = 1000;
config.telemetry.export_interval = Duration::from_secs(60);
config.rate_limit.burst_size = 10;
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

### 10. Trait-Based Components

KindlyGuard uses a trait-based architecture for extensibility and modularity.

#### EventBufferTrait

The `EventBufferTrait` defines the interface for event buffering systems:

```rust
use kindly_guard_server::{EventBufferTrait, EventType, create_event_buffer};
use std::sync::Arc;

// Create an event buffer using the factory function
let buffer: Arc<dyn EventBufferTrait> = create_event_buffer(
    config.event_processor.buffer_size_mb,
    config.event_processor.enabled
)?;

// Add events to the buffer
buffer.add_event(EventType::ThreatDetected {
    threat_type: "SQL_INJECTION".to_string(),
    severity: "HIGH".to_string(),
    details: serde_json::json!({
        "query": "SELECT * FROM users WHERE id = '1' OR '1'='1'",
        "location": "request_body"
    })
})?;

// Get recent events
let recent_events = buffer.get_recent_events(100)?;

// Get events in a time range
let start = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
let end = std::time::SystemTime::now();
let events_in_range = buffer.get_events_in_range(start, end)?;

// Get buffer statistics
let stats = buffer.get_stats();
println!("Events buffered: {}", stats.total_events);
println!("Buffer size: {} MB", stats.memory_usage_mb);
```

#### MetricsProvider

The `MetricsProvider` trait provides a unified interface for metrics collection:

```rust
use kindly_guard_server::{MetricsProvider, create_metrics_provider};
use std::sync::Arc;

// Create a metrics provider using the factory function
let metrics: Arc<dyn MetricsProvider> = create_metrics_provider(
    config.telemetry.enabled
)?;

// Register and use metrics
let requests_counter = metrics.counter("kindlyguard_requests_total", "Total requests");
requests_counter.inc();

let request_duration = metrics.histogram(
    "kindlyguard_request_duration",
    "Request duration in seconds"
);
request_duration.observe(0.023);

let active_connections = metrics.gauge(
    "kindlyguard_active_connections",
    "Number of active connections"
);
active_connections.set(42.0);

// Export metrics in Prometheus format
let prometheus_output = metrics.export_prometheus();
```

#### Factory Functions

KindlyGuard provides factory functions that automatically select the appropriate implementation based on feature flags and configuration:

```rust
use kindly_guard_server::{
    create_event_buffer,
    create_metrics_provider,
    create_session_pool,
    create_rate_limiter,
};

// Event buffer - creates standard implementation
let event_buffer = create_event_buffer(
    buffer_size_mb: 100
)?;

// Metrics provider - creates standard provider
let metrics = create_metrics_provider(
    export_interval: config.telemetry.export_interval
)?;

// Session pool - creates standard pool
let session_pool = create_session_pool(
    max_sessions: config.server.pool_size
)?;

// Rate limiter - creates standard limiter
let rate_limiter = create_rate_limiter(
    config: &config.rate_limit
)?;
```

### 11. Advanced Features

#### Event Processing
```rust
// Configure event processing
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

## Example: Using Trait-Based Components

```rust
use kindly_guard_server::{
    Config, SecurityScanner, 
    create_event_buffer, create_metrics_provider,
    create_rate_limiter, create_session_pool,
    EventType, KindlyResult
};
use std::sync::Arc;

#[tokio::main]
async fn main() -> KindlyResult<()> {
    // Load configuration
    let mut config = Config::from_env()?;
    config.server.enabled = true;
    config.event_processor.enabled = true;
    config.telemetry.enabled = true;
    
    // Create trait-based components
    let event_buffer = create_event_buffer(
        config.event_processor.buffer_size_mb,
        config.event_processor.enabled
    )?;
    
    let metrics = create_metrics_provider(
        config.telemetry.enabled
    )?;
    
    let rate_limiter = create_rate_limiter(
        &config.rate_limit,
        config.rate_limit.enabled
    )?;
    
    let session_pool = create_session_pool(
        1000, // max sessions
        config.server.enabled
    )?;
    
    // Use components
    let scanner = SecurityScanner::new(config.scanner)?;
    
    // Process a request
    let client_id = "user_123";
    let session = session_pool.get_or_create(client_id).await?;
    
    // Check rate limit
    if !rate_limiter.check_and_increment(client_id, "scan_text").await? {
        let rate_limit_counter = metrics.counter(
            "kindlyguard_rate_limit_exceeded",
            "Rate limit exceeded events"
        );
        rate_limit_counter.inc();
        return Err(KindlyError::RateLimitExceeded);
    }
    
    // Scan for threats
    let input = "SELECT * FROM users WHERE id = '1' OR '1'='1'";
    let threats = scanner.scan_text(input)?;
    
    // Record events
    if !threats.is_empty() {
        event_buffer.add_event(EventType::ThreatDetected {
            threat_type: threats[0].threat_type.to_string(),
            severity: "HIGH".to_string(),
            details: serde_json::json!({
                "input": input,
                "client_id": client_id,
                "session_id": session.id,
                "threats": threats
            })
        })?;
        
        let threat_counter = metrics.counter(
            "kindlyguard_threats_detected",
            "Threats detected"
        );
        threat_counter.inc();
    }
    
    // Get recent security events for analysis
    let recent_events = event_buffer.get_recent_events(1000)?;
    println!("Recent security events: {}", recent_events.len());
    
    // Export metrics
    let prometheus_metrics = metrics.export_prometheus();
    println!("{}", prometheus_metrics);
    
    Ok(())
}
```

## Example: Custom Event Buffer Implementation

```rust
use kindly_guard_server::{EventBufferTrait, EventType, BufferStats, KindlyResult};
use std::sync::RwLock;
use std::collections::VecDeque;
use std::time::SystemTime;

// Custom implementation of EventBufferTrait
pub struct CustomEventBuffer {
    events: RwLock<VecDeque<(SystemTime, EventType)>>,
    max_size: usize,
}

impl CustomEventBuffer {
    pub fn new(max_size: usize) -> Self {
        Self {
            events: RwLock::new(VecDeque::with_capacity(max_size)),
            max_size,
        }
    }
}

impl EventBufferTrait for CustomEventBuffer {
    fn add_event(&self, event: EventType) -> KindlyResult<()> {
        let mut events = self.events.write().unwrap();
        
        // Remove oldest if at capacity
        if events.len() >= self.max_size {
            events.pop_front();
        }
        
        events.push_back((SystemTime::now(), event));
        Ok(())
    }
    
    fn get_recent_events(&self, count: usize) -> KindlyResult<Vec<EventType>> {
        let events = self.events.read().unwrap();
        let recent: Vec<EventType> = events
            .iter()
            .rev()
            .take(count)
            .map(|(_, event)| event.clone())
            .collect();
        Ok(recent)
    }
    
    fn get_events_in_range(
        &self,
        start: SystemTime,
        end: SystemTime
    ) -> KindlyResult<Vec<EventType>> {
        let events = self.events.read().unwrap();
        let filtered: Vec<EventType> = events
            .iter()
            .filter(|(timestamp, _)| *timestamp >= start && *timestamp <= end)
            .map(|(_, event)| event.clone())
            .collect();
        Ok(filtered)
    }
    
    fn clear(&self) -> KindlyResult<()> {
        let mut events = self.events.write().unwrap();
        events.clear();
        Ok(())
    }
    
    fn get_stats(&self) -> BufferStats {
        let events = self.events.read().unwrap();
        BufferStats {
            total_events: events.len(),
            memory_usage_mb: (events.len() * std::mem::size_of::<(SystemTime, EventType)>()) as f64 / 1_048_576.0,
            oldest_event: events.front().map(|(timestamp, _)| *timestamp),
            newest_event: events.back().map(|(timestamp, _)| *timestamp),
        }
    }
}

// Use the custom implementation
let custom_buffer: Arc<dyn EventBufferTrait> = Arc::new(CustomEventBuffer::new(10000));
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
- Standard implementations of all components


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
        "KINDLY_GUARD_SCANNER_UNICODE": "true",
        "KINDLY_GUARD_SERVER_ENHANCED_MODE": "true",
        "KINDLY_GUARD_EVENT_PROCESSOR_ENHANCED_MODE": "true"
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
# Build for production
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/kindly-guard /usr/local/bin/
ENV KINDLY_GUARD_CONFIG=/etc/kindlyguard/config.toml
ENV KINDLY_GUARD_SERVER_ENHANCED_MODE=true
ENV KINDLY_GUARD_EVENT_PROCESSOR_ENHANCED_MODE=true
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