# KindlyGuard Threat Neutralization System

## Overview

The KindlyGuard Threat Neutralization System provides actual threat remediation capabilities beyond just detection. Both standard and optimized implementations provide full protection, with the optimized version offering superior performance through advanced algorithms.

## Architecture

The neutralization system uses a layered architecture with trait-based abstractions:

```
┌─────────────────────────────────────┐
│         API Consumer                │
└─────────────────┬───────────────────┘
                  │
┌─────────────────▼───────────────────┐
│      Distributed Tracing            │ (Optional)
└─────────────────┬───────────────────┘
                  │
┌─────────────────▼───────────────────┐
│       Health Monitoring             │ (Always enabled)
└─────────────────┬───────────────────┘
                  │
┌─────────────────▼───────────────────┐
│        Rate Limiting                │ (Optional)
└─────────────────┬───────────────────┘
                  │
┌─────────────────▼───────────────────┐
│      Rollback Support               │ (Optional)
└─────────────────┬───────────────────┘
                  │
┌─────────────────▼───────────────────┐
│    Recovery & Resilience            │ (Optional)
└─────────────────┬───────────────────┘
                  │
┌─────────────────▼───────────────────┐
│   Core Neutralizer Implementation   │
│  (Standard or Optimized)            │
└─────────────────────────────────────┘
```

## Core Trait

```rust
#[async_trait]
pub trait ThreatNeutralizer: Send + Sync {
    /// Neutralize a specific threat in content
    async fn neutralize(&self, threat: &Threat, content: &str) -> Result<NeutralizeResult>;
    
    /// Check if this neutralizer can handle a threat type
    fn can_neutralize(&self, threat_type: &ThreatType) -> bool;
    
    /// Get neutralizer capabilities
    fn get_capabilities(&self) -> NeutralizerCapabilities;
    
    /// Batch neutralize multiple threats
    async fn batch_neutralize(&self, threats: &[Threat], content: &str) -> Result<BatchNeutralizeResult>;
}
```

## Quick Start

### Basic Usage

```rust
use kindly_guard_server::neutralizer::{
    create_neutralizer, NeutralizationConfig, NeutralizationMode,
};
use kindly_guard_server::scanner::{Threat, ThreatType, Severity, Location};

// Configure neutralization
let config = NeutralizationConfig {
    mode: NeutralizationMode::Automatic,
    backup_originals: true,
    audit_all_actions: true,
    ..Default::default()
};

// Create neutralizer
let neutralizer = create_neutralizer(&config, None);

// Neutralize a threat
let threat = Threat {
    threat_type: ThreatType::SqlInjection,
    severity: Severity::High,
    location: Location::Text { offset: 28, length: 15 },
    description: "SQL injection detected".to_string(),
    remediation: Some("Use parameterized queries".to_string()),
};

let result = neutralizer.neutralize(&threat, "SELECT * FROM users WHERE id='1' OR '1'='1'").await?;

println!("Action: {}", result.action_taken);
println!("Sanitized: {:?}", result.sanitized_content);
```

### With Rate Limiting

```rust
use kindly_guard_server::traits::RateLimiter;
use std::sync::Arc;

// Assume you have a rate limiter
let rate_limiter: Arc<dyn RateLimiter> = create_rate_limiter();

// Create neutralizer with rate limiting
let neutralizer = create_neutralizer(&config, Some(rate_limiter));
```

### With Distributed Tracing

```rust
use kindly_guard_server::neutralizer::create_neutralizer_with_telemetry;
use kindly_guard_server::telemetry::{
    DistributedTracingProvider, ProbabilitySampler, W3CTraceContextPropagator,
};

// Create tracing provider
let tracing_provider = Arc::new(DistributedTracingProvider::new(
    base_telemetry_provider,
    Arc::new(ProbabilitySampler::new(0.1)), // 10% sampling
    Arc::new(W3CTraceContextPropagator),
));

// Create neutralizer with tracing
let neutralizer = create_neutralizer_with_telemetry(
    &config,
    rate_limiter,
    Some(tracing_provider),
);
```

## Configuration

### NeutralizationConfig

The main configuration structure controls neutralization behavior:

```rust
pub struct NeutralizationConfig {
    /// Neutralization mode
    pub mode: NeutralizationMode,
    
    /// Backup original content
    pub backup_originals: bool,
    
    /// Audit all actions
    pub audit_all_actions: bool,
    
    /// Unicode-specific settings
    pub unicode: UnicodeNeutralizationConfig,
    
    /// Injection-specific settings
    pub injection: InjectionNeutralizationConfig,
    
    /// Recovery configuration
    pub recovery: Option<RecoveryConfig>,
}
```

### Neutralization Modes

- `ReportOnly`: Only report threats, don't modify content
- `Interactive`: Ask user for each threat (requires UI integration)
- `Automatic`: Automatically neutralize threats (recommended for production)

### Unicode Configuration

```rust
pub struct UnicodeNeutralizationConfig {
    /// How to handle BiDi characters
    pub bidi_replacement: BiDiReplacement,
    
    /// Action for zero-width characters
    pub zero_width_action: ZeroWidthAction,
    
    /// Action for homographs
    pub homograph_action: HomographAction,
}
```

Options:
- `BiDiReplacement`: Remove, Marker, or Escape
- `ZeroWidthAction`: Remove or Escape
- `HomographAction`: Ascii, Warn, or Block

### Injection Configuration

```rust
pub struct InjectionNeutralizationConfig {
    /// SQL injection action
    pub sql_action: SqlAction,
    
    /// Command injection action
    pub command_action: CommandAction,
    
    /// Path traversal action
    pub path_action: PathAction,
    
    /// Prompt injection action
    pub prompt_action: PromptAction,
}
```

Options:
- `SqlAction`: Block, Escape, or Parameterize
- `CommandAction`: Block, Escape, or Sandbox
- `PathAction`: Block or Normalize
- `PromptAction`: Block, Escape, or Wrap

## Neutralization Actions

The system can take various actions to neutralize threats:

```rust
pub enum NeutralizeAction {
    /// Content was sanitized
    Sanitized,
    
    /// Query was parameterized
    Parameterized,
    
    /// Path was normalized
    Normalized,
    
    /// Content was escaped
    Escaped,
    
    /// Threat was removed
    Removed,
    
    /// Content was quarantined
    Quarantined,
    
    /// No action needed
    NoAction,
}
```

## Result Types

### NeutralizeResult

```rust
pub struct NeutralizeResult {
    /// Action taken to neutralize threat
    pub action_taken: NeutralizeAction,
    
    /// Sanitized content (if modified)
    pub sanitized_content: Option<String>,
    
    /// Confidence in neutralization (0.0 - 1.0)
    pub confidence_score: f64,
    
    /// Processing time in microseconds
    pub processing_time_us: u64,
    
    /// Correlation data
    pub correlation_data: Option<CorrelationData>,
    
    /// Any parameters extracted (e.g., SQL params)
    pub extracted_params: Option<Vec<String>>,
}
```

### BatchNeutralizeResult

```rust
pub struct BatchNeutralizeResult {
    /// Final sanitized content after all neutralizations
    pub final_content: String,
    
    /// Individual results for each threat
    pub individual_results: Vec<NeutralizeResult>,
}
```

## Advanced Features

### Rollback Support

The rollback feature maintains a history of neutralization operations:

```rust
// Rollback is automatically enabled when backup_originals is true
let config = NeutralizationConfig {
    backup_originals: true,
    ..Default::default()
};

// The rollback wrapper maintains history internally
// Access via health monitoring or custom extensions
```

### Health Monitoring

Health monitoring is always enabled and provides:

- Performance metrics (response times, throughput)
- Error rate tracking
- Resource usage monitoring
- Synthetic probes for validation

```rust
// Cast to access health monitoring
if let Some(health_monitored) = neutralizer.as_any()
    .downcast_ref::<HealthMonitoredNeutralizer>() {
    
    let report = health_monitored.get_health_report().await;
    println!("Health status: {:?}", report.status);
}
```

### Recovery and Resilience

The recovery system provides automatic retry and fallback:

```rust
let config = NeutralizationConfig {
    recovery: Some(RecoveryConfig {
        enabled: true,
        max_retries: 3,
        retry_delay: Duration::from_millis(100),
        exponential_backoff: true,
        circuit_breaker: true,
        ..Default::default()
    }),
    ..Default::default()
};
```

## Performance Characteristics

### Standard Implementation
- Average neutralization time: 5-10ms
- Memory efficient
- Suitable for most applications

### Optimized Implementation (Feature-gated)
- Significantly faster neutralization times
- Uses advanced optimization techniques
- Ideal for high-throughput scenarios

## Security Considerations

1. **Input Validation**: All inputs are validated before processing
2. **Resource Limits**: Built-in protection against resource exhaustion
3. **Audit Trail**: All actions are logged for security review
4. **Rate Limiting**: Optional rate limiting prevents abuse
5. **Health Monitoring**: Continuous validation of system health

## Best Practices

1. **Always use Automatic mode in production**
   ```rust
   config.mode = NeutralizationMode::Automatic;
   ```

2. **Enable auditing for compliance**
   ```rust
   config.audit_all_actions = true;
   ```

3. **Configure appropriate actions for your use case**
   ```rust
   config.injection.sql_action = SqlAction::Parameterize; // Safest
   config.unicode.bidi_replacement = BiDiReplacement::Marker; // Visible
   ```

4. **Use batch neutralization for multiple threats**
   ```rust
   let results = neutralizer.batch_neutralize(&threats, content).await?;
   ```

5. **Monitor health in production**
   ```rust
   // Set up health check endpoint
   // Monitor neutralization metrics
   ```

## Integration Examples

### With MCP Server

```rust
// In your MCP request handler
async fn handle_request(&self, method: &str, params: Value) -> Result<Value> {
    // Scan for threats
    let threats = self.scanner.scan_json(&params)?;
    
    // Neutralize if threats found
    if !threats.is_empty() {
        let content = serde_json::to_string(&params)?;
        let result = self.neutralizer.batch_neutralize(&threats, &content).await?;
        
        // Parse sanitized content back to JSON
        params = serde_json::from_str(&result.final_content)?;
    }
    
    // Continue processing with sanitized params
    self.process_request(method, params).await
}
```

### With Web API

```rust
// In your web handler
async fn handle_api_request(
    neutralizer: Arc<dyn ThreatNeutralizer>,
    body: String,
) -> Result<Response> {
    // Scan request body
    let threats = scan_content(&body)?;
    
    // Neutralize threats
    let safe_body = if threats.is_empty() {
        body
    } else {
        let result = neutralizer.batch_neutralize(&threats, &body).await?;
        result.final_content
    };
    
    // Process safe content
    process_request(safe_body).await
}
```

## Troubleshooting

### Common Issues

1. **High latency**: Check health metrics, consider enabling performance optimizations
2. **Memory usage**: Monitor rollback history size, adjust retention
3. **False positives**: Tune threat detection sensitivity
4. **Rate limiting**: Adjust rate limits based on traffic patterns

### Debug Logging

Enable debug logging for detailed information:

```bash
RUST_LOG=kindly_guard::neutralizer=debug cargo run
```

## API Stability

The neutralization API is stable and follows semantic versioning:

- Trait methods are stable and won't change in minor versions
- Configuration fields may be added but not removed
- New neutralization actions may be added
- Result fields may be added but not removed

## Performance Benchmarks

Run benchmarks to measure performance:

```bash
cargo bench --bench neutralization
```

Typical results vary based on implementation:
- SQL injection: microseconds to milliseconds
- Unicode threats: very fast processing
- Batch operations: scales linearly with threat count

## Contributing

When adding new neutralization strategies:

1. Implement in both standard and optimized modules
2. Add comprehensive tests including security tests
3. Update benchmarks
4. Document configuration options
5. Ensure backward compatibility