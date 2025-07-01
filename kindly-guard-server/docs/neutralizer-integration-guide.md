# KindlyGuard Neutralizer Integration Guide

This guide provides step-by-step instructions for integrating the KindlyGuard threat neutralization system into your application.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Basic Integration](#basic-integration)
3. [Advanced Integration](#advanced-integration)
4. [Production Deployment](#production-deployment)
5. [Monitoring and Observability](#monitoring-and-observability)
6. [Performance Tuning](#performance-tuning)
7. [Security Best Practices](#security-best-practices)

## Prerequisites

- Rust 1.70 or later
- Tokio runtime
- Understanding of async Rust
- KindlyGuard scanner configured

## Basic Integration

### Step 1: Add Dependencies

Add to your `Cargo.toml`:

```toml
[dependencies]
kindly-guard-server = { version = "0.1", features = ["default"] }
tokio = { version = "1.35", features = ["full"] }
anyhow = "1.0"
```

### Step 2: Create a Neutralizer

```rust
use kindly_guard_server::{
    neutralizer::{
        create_neutralizer,
        NeutralizationConfig,
        NeutralizationMode,
    },
    scanner::{SecurityScanner, ScannerConfig},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create scanner
    let scanner_config = ScannerConfig::default();
    let scanner = SecurityScanner::new(scanner_config)?;
    
    // Create neutralizer
    let neutralizer_config = NeutralizationConfig {
        mode: NeutralizationMode::Automatic,
        ..Default::default()
    };
    let neutralizer = create_neutralizer(&neutralizer_config, None);
    
    // Your application code here
    Ok(())
}
```

### Step 3: Scan and Neutralize

```rust
async fn process_user_input(
    scanner: &SecurityScanner,
    neutralizer: Arc<dyn ThreatNeutralizer>,
    input: String,
) -> anyhow::Result<String> {
    // Scan for threats
    let threats = scanner.scan_text(&input);
    
    if threats.is_empty() {
        // No threats found
        return Ok(input);
    }
    
    // Neutralize threats
    let result = neutralizer.batch_neutralize(&threats, &input).await?;
    
    // Log what was done
    tracing::info!(
        "Neutralized {} threats in user input",
        result.individual_results.len()
    );
    
    Ok(result.final_content)
}
```

## Advanced Integration

### Custom Configuration

```rust
use kindly_guard_server::neutralizer::{
    NeutralizationConfig,
    NeutralizationMode,
    UnicodeNeutralizationConfig,
    BiDiReplacement,
    ZeroWidthAction,
    HomographAction,
    InjectionNeutralizationConfig,
    SqlAction,
    CommandAction,
    PathAction,
    PromptAction,
    recovery::RecoveryConfig,
};
use std::time::Duration;

fn create_production_config() -> NeutralizationConfig {
    NeutralizationConfig {
        mode: NeutralizationMode::Automatic,
        backup_originals: true,
        audit_all_actions: true,
        
        // Unicode handling
        unicode: UnicodeNeutralizationConfig {
            bidi_replacement: BiDiReplacement::Marker,
            zero_width_action: ZeroWidthAction::Remove,
            homograph_action: HomographAction::Ascii,
        },
        
        // Injection handling
        injection: InjectionNeutralizationConfig {
            sql_action: SqlAction::Parameterize,
            command_action: CommandAction::Escape,
            path_action: PathAction::Normalize,
            prompt_action: PromptAction::Wrap,
        },
        
        // Recovery configuration
        recovery: Some(RecoveryConfig {
            enabled: true,
            max_retries: 3,
            retry_delay: Duration::from_millis(100),
            exponential_backoff: true,
            circuit_breaker: true,
            ..Default::default()
        }),
    }
}
```

### Rate Limiting Integration

```rust
use kindly_guard_server::{
    rate_limit::{create_rate_limiter, RateLimitConfig},
    neutralizer::create_neutralizer,
};

async fn create_rate_limited_neutralizer() -> Arc<dyn ThreatNeutralizer> {
    // Configure rate limiting
    let rate_limit_config = RateLimitConfig {
        enabled: true,
        requests_per_second: 100.0,
        burst_size: 200,
        ..Default::default()
    };
    
    // Create rate limiter
    let storage = create_storage_provider().await?;
    let rate_limiter = create_rate_limiter(&rate_limit_config, storage)?;
    
    // Create neutralizer with rate limiting
    let config = create_production_config();
    create_neutralizer(&config, Some(rate_limiter))
}
```

### Distributed Tracing Integration

```rust
use kindly_guard_server::{
    neutralizer::create_neutralizer_with_telemetry,
    telemetry::{
        TelemetryConfig,
        StandardTelemetryProvider,
        DistributedTracingProvider,
        ProbabilitySampler,
        W3CTraceContextPropagator,
    },
};

async fn create_traced_neutralizer() -> Arc<dyn ThreatNeutralizer> {
    // Configure telemetry
    let telemetry_config = TelemetryConfig {
        enabled: true,
        service_name: "my-service".to_string(),
        service_version: env!("CARGO_PKG_VERSION").to_string(),
        export_endpoint: Some("http://localhost:4317".to_string()),
        tracing_enabled: true,
        sampling_rate: 0.1, // 10% sampling
        ..Default::default()
    };
    
    // Create tracing provider
    let base_provider = Arc::new(StandardTelemetryProvider::new(telemetry_config));
    let sampler = Arc::new(ProbabilitySampler::new(0.1));
    let propagator = Arc::new(W3CTraceContextPropagator);
    
    let tracing_provider = Arc::new(DistributedTracingProvider::new(
        base_provider,
        sampler,
        propagator,
    ));
    
    // Create neutralizer with tracing
    let config = create_production_config();
    create_neutralizer_with_telemetry(&config, None, Some(tracing_provider))
}
```

## Production Deployment

### Health Check Endpoint

```rust
use axum::{
    extract::State,
    response::Json,
    http::StatusCode,
};
use serde_json::json;

async fn health_check(
    State(neutralizer): State<Arc<dyn ThreatNeutralizer>>,
) -> Result<Json<Value>, StatusCode> {
    // Cast to health monitored neutralizer
    let health_monitored = neutralizer
        .as_any()
        .downcast_ref::<HealthMonitoredNeutralizer>()
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    
    // Get health report
    let report = health_monitored
        .get_health_report()
        .await
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    
    // Convert to HTTP status
    let status_code = match report.status {
        HealthStatus::Healthy => StatusCode::OK,
        HealthStatus::Degraded => StatusCode::OK,
        HealthStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
        HealthStatus::Critical => StatusCode::SERVICE_UNAVAILABLE,
    };
    
    Ok((
        status_code,
        Json(json!({
            "status": format!("{:?}", report.status),
            "performance": report.performance,
            "error_metrics": report.error_metrics,
            "capabilities": report.capabilities,
        }))
    ))
}
```

### Graceful Shutdown

```rust
use tokio::signal;

async fn run_server(neutralizer: Arc<dyn ThreatNeutralizer>) -> anyhow::Result<()> {
    // Set up shutdown signal
    let shutdown = signal::ctrl_c();
    
    // Run server
    tokio::select! {
        _ = run_application(neutralizer) => {},
        _ = shutdown => {
            tracing::info!("Shutting down gracefully...");
        }
    }
    
    // Cleanup
    if let Some(health_monitored) = neutralizer
        .as_any()
        .downcast_ref::<HealthMonitoredNeutralizer>() {
        // Export final metrics
        let report = health_monitored.get_health_report().await;
        tracing::info!("Final health report: {:?}", report);
    }
    
    Ok(())
}
```

## Monitoring and Observability

### Metrics Collection

```rust
use prometheus::{Registry, Counter, Histogram, HistogramOpts};

struct NeutralizationMetrics {
    threats_neutralized: Counter,
    neutralization_duration: Histogram,
    neutralization_errors: Counter,
}

impl NeutralizationMetrics {
    fn new(registry: &Registry) -> anyhow::Result<Self> {
        let threats_neutralized = Counter::new(
            "kindly_guard_threats_neutralized_total",
            "Total number of threats neutralized"
        )?;
        
        let neutralization_duration = Histogram::with_opts(
            HistogramOpts::new(
                "kindly_guard_neutralization_duration_seconds",
                "Neutralization duration in seconds"
            )
        )?;
        
        let neutralization_errors = Counter::new(
            "kindly_guard_neutralization_errors_total",
            "Total number of neutralization errors"
        )?;
        
        registry.register(Box::new(threats_neutralized.clone()))?;
        registry.register(Box::new(neutralization_duration.clone()))?;
        registry.register(Box::new(neutralization_errors.clone()))?;
        
        Ok(Self {
            threats_neutralized,
            neutralization_duration,
            neutralization_errors,
        })
    }
    
    async fn record_neutralization(
        &self,
        neutralizer: Arc<dyn ThreatNeutralizer>,
        threat: &Threat,
        content: &str,
    ) -> anyhow::Result<NeutralizeResult> {
        let timer = self.neutralization_duration.start_timer();
        
        match neutralizer.neutralize(threat, content).await {
            Ok(result) => {
                self.threats_neutralized.inc();
                timer.observe_duration();
                Ok(result)
            }
            Err(e) => {
                self.neutralization_errors.inc();
                timer.observe_duration();
                Err(e)
            }
        }
    }
}
```

### Logging Integration

```rust
use tracing::{info, warn, error, debug, instrument};

#[instrument(skip(neutralizer, content), fields(threat_type = ?threat.threat_type))]
async fn neutralize_with_logging(
    neutralizer: Arc<dyn ThreatNeutralizer>,
    threat: &Threat,
    content: &str,
) -> anyhow::Result<NeutralizeResult> {
    debug!("Starting neutralization");
    
    let start = std::time::Instant::now();
    let result = neutralizer.neutralize(threat, content).await;
    let duration = start.elapsed();
    
    match &result {
        Ok(res) => {
            info!(
                action = ?res.action_taken,
                confidence = res.confidence_score,
                duration_ms = duration.as_millis(),
                "Threat neutralized successfully"
            );
        }
        Err(e) => {
            error!(
                error = %e,
                duration_ms = duration.as_millis(),
                "Neutralization failed"
            );
        }
    }
    
    result
}
```

## Performance Tuning

### Batch Processing

```rust
use futures::stream::{self, StreamExt};

async fn process_batch(
    neutralizer: Arc<dyn ThreatNeutralizer>,
    scanner: Arc<SecurityScanner>,
    items: Vec<String>,
) -> Vec<anyhow::Result<String>> {
    const BATCH_SIZE: usize = 100;
    
    stream::iter(items)
        .chunks(BATCH_SIZE)
        .map(|batch| {
            let neutralizer = neutralizer.clone();
            let scanner = scanner.clone();
            
            async move {
                // Process batch concurrently
                let mut handles = Vec::new();
                
                for item in batch {
                    let neutralizer = neutralizer.clone();
                    let scanner = scanner.clone();
                    
                    let handle = tokio::spawn(async move {
                        let threats = scanner.scan_text(&item);
                        if threats.is_empty() {
                            Ok(item)
                        } else {
                            let result = neutralizer
                                .batch_neutralize(&threats, &item)
                                .await?;
                            Ok(result.final_content)
                        }
                    });
                    
                    handles.push(handle);
                }
                
                // Collect results
                let mut results = Vec::new();
                for handle in handles {
                    results.push(handle.await?);
                }
                
                results
            }
        })
        .buffer_unordered(4) // Process up to 4 batches concurrently
        .flat_map(stream::iter)
        .collect()
        .await
}
```

### Caching

```rust
use moka::future::Cache;
use std::time::Duration;

struct CachedNeutralizer {
    inner: Arc<dyn ThreatNeutralizer>,
    cache: Cache<String, String>,
}

impl CachedNeutralizer {
    fn new(inner: Arc<dyn ThreatNeutralizer>) -> Self {
        let cache = Cache::builder()
            .max_capacity(10_000)
            .time_to_live(Duration::from_secs(300)) // 5 minutes
            .build();
        
        Self { inner, cache }
    }
    
    async fn neutralize_with_cache(
        &self,
        threat: &Threat,
        content: &str,
    ) -> anyhow::Result<String> {
        // Create cache key
        let key = format!("{:?}:{}", threat.threat_type, content);
        
        // Check cache
        if let Some(cached) = self.cache.get(&key).await {
            return Ok(cached);
        }
        
        // Neutralize
        let result = self.inner.neutralize(threat, content).await?;
        let safe_content = result.sanitized_content
            .unwrap_or_else(|| content.to_string());
        
        // Cache result
        self.cache.insert(key, safe_content.clone()).await;
        
        Ok(safe_content)
    }
}
```

## Security Best Practices

### Input Validation

```rust
fn validate_content(content: &str) -> anyhow::Result<()> {
    const MAX_SIZE: usize = 10 * 1024 * 1024; // 10MB
    
    if content.len() > MAX_SIZE {
        anyhow::bail!("Content exceeds maximum size of {} bytes", MAX_SIZE);
    }
    
    if content.is_empty() {
        anyhow::bail!("Content cannot be empty");
    }
    
    Ok(())
}

async fn secure_neutralize(
    neutralizer: Arc<dyn ThreatNeutralizer>,
    threat: &Threat,
    content: &str,
) -> anyhow::Result<NeutralizeResult> {
    // Validate input
    validate_content(content)?;
    
    // Apply timeout
    tokio::time::timeout(
        Duration::from_secs(30),
        neutralizer.neutralize(threat, content)
    )
    .await?
}
```

### Audit Logging

```rust
use kindly_guard_server::audit::{AuditEvent, AuditEventBuilder};

async fn neutralize_with_audit(
    neutralizer: Arc<dyn ThreatNeutralizer>,
    audit_logger: Arc<dyn AuditLogger>,
    threat: &Threat,
    content: &str,
    user_id: &str,
) -> anyhow::Result<NeutralizeResult> {
    let start = std::time::Instant::now();
    
    // Perform neutralization
    let result = neutralizer.neutralize(threat, content).await;
    
    // Create audit event
    let event = AuditEventBuilder::new("neutralization")
        .client_id(user_id)
        .add_detail("threat_type", &format!("{:?}", threat.threat_type))
        .add_detail("severity", &format!("{:?}", threat.severity))
        .add_detail("success", &result.is_ok().to_string())
        .add_detail("duration_ms", &start.elapsed().as_millis().to_string())
        .build();
    
    // Log audit event
    audit_logger.log(event).await?;
    
    result
}
```

### Error Handling

```rust
use thiserror::Error;

#[derive(Error, Debug)]
enum NeutralizationError {
    #[error("Neutralization failed: {0}")]
    NeutralizationFailed(String),
    
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    #[error("Service unavailable")]
    ServiceUnavailable,
}

async fn handle_neutralization_error(
    error: anyhow::Error,
) -> Result<String, NeutralizationError> {
    // Check for specific error types
    if let Some(rate_limit_error) = error.downcast_ref::<RateLimitError>() {
        return Err(NeutralizationError::RateLimitExceeded);
    }
    
    // Check for circuit breaker open
    if error.to_string().contains("Circuit breaker is open") {
        return Err(NeutralizationError::ServiceUnavailable);
    }
    
    // Generic error
    Err(NeutralizationError::NeutralizationFailed(error.to_string()))
}
```

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use kindly_guard_server::scanner::{Location};

    #[tokio::test]
    async fn test_neutralization() {
        let config = NeutralizationConfig::default();
        let neutralizer = create_neutralizer(&config, None);
        
        let threat = Threat {
            threat_type: ThreatType::SqlInjection,
            severity: Severity::High,
            location: Location::Text { offset: 0, length: 10 },
            description: "Test threat".to_string(),
            remediation: None,
        };
        
        let result = neutralizer
            .neutralize(&threat, "'; DROP TABLE users;")
            .await
            .unwrap();
        
        assert_eq!(result.action_taken, NeutralizeAction::Parameterized);
        assert!(result.sanitized_content.is_some());
    }
}
```

### Integration Tests

```rust
#[tokio::test]
async fn test_full_integration() {
    // Create all components
    let scanner = SecurityScanner::new(ScannerConfig::default()).unwrap();
    let neutralizer = create_neutralizer(&Default::default(), None);
    
    // Test content with multiple threats
    let content = "SELECT * FROM users WHERE id='1' OR '1'='1'; echo \u{202E}test";
    
    // Scan
    let threats = scanner.scan_text(content);
    assert!(!threats.is_empty());
    
    // Neutralize
    let result = neutralizer.batch_neutralize(&threats, content).await.unwrap();
    
    // Verify all threats were handled
    assert_eq!(threats.len(), result.individual_results.len());
    
    // Verify content is safe
    let rescan_threats = scanner.scan_text(&result.final_content);
    assert!(rescan_threats.is_empty());
}
```

## Troubleshooting

### Common Issues

1. **High Memory Usage**
   - Check rollback history size
   - Reduce `sample_window_size` in health config
   - Enable periodic cleanup

2. **Slow Performance**
   - Enable performance optimizations if available
   - Use batch neutralization
   - Add caching layer
   - Check health metrics

3. **Rate Limiting Issues**
   - Adjust rate limits based on traffic
   - Implement client-specific limits
   - Add bypass for trusted clients

4. **False Positives**
   - Tune scanner sensitivity
   - Add allowlist for known-safe patterns
   - Implement context-aware neutralization

### Debug Mode

Enable detailed logging:

```bash
RUST_LOG=kindly_guard=debug,kindly_guard::neutralizer=trace cargo run
```

### Performance Profiling

```bash
# CPU profiling
cargo flamegraph --bench neutralization

# Memory profiling
cargo run --features jemalloc -- --memory-profile
```

## Conclusion

The KindlyGuard neutralization system provides comprehensive threat remediation with production-ready features. By following this guide, you can integrate it into your application with confidence, knowing that security threats will be properly handled while maintaining performance and reliability.