# KindlyGuard Symbol Index

This document provides a comprehensive index of all public symbols (traits, structs, enums, functions) in the KindlyGuard codebase.

## Traits

### Core Security Traits

| Trait | Module | Description |
|-------|--------|-------------|
| `SecurityScannerTrait` | `traits` | Main scanner interface for threat detection |
| `EnhancedScanner` | `traits` | Extended scanner with context and insights |
| `PatternMatcherTrait` | `security/enhanced` | Pattern matching for threats |
| `ThreatClassifierTrait` | `security/enhanced` | ML-based threat classification |

### Resilience Traits

| Trait | Module | Description |
|-------|--------|-------------|
| `CircuitBreakerTrait` | `traits` | Circuit breaker pattern interface |
| `RetryStrategyTrait` | `traits` | Retry logic with backoff |
| `RecoveryStrategyTrait` | `traits` | Recovery handling for failures |
| `HealthCheckTrait` | `traits` | Health monitoring interface |
| `BulkheadTrait` | `resilience/bulkhead` | Resource isolation |

### Event Processing Traits

| Trait | Module | Description |
|-------|--------|-------------|
| `EventBufferTrait` | `traits` | Event buffering interface |
| `SecurityEventProcessor` | `traits` | Event processing logic |
| `CorrelationEngine` | `traits` | Event correlation |
| `EventProcessorTrait` | `core/standard` | Tauri event processing |

### Infrastructure Traits

| Trait | Module | Description |
|-------|--------|-------------|
| `RateLimiter` | `traits` | Rate limiting interface |
| `MetricsProvider` | `traits` | Metrics collection |
| `CounterTrait` | `traits` | Counter metric |
| `GaugeTrait` | `traits` | Gauge metric |
| `HistogramTrait` | `traits` | Histogram metric |
| `PluginManagerTrait` | `plugins/mod` | Plugin management |

### Protocol Traits

| Trait | Module | Description |
|-------|--------|-------------|
| `WebSocketHandlerTrait` | `websocket/enhanced` | WebSocket handling |
| `BinaryProtocolTrait` | `websocket/enhanced` | Binary protocol |
| `MessageCompressorTrait` | `websocket/enhanced` | Message compression |

## Structs

### Configuration Structs

| Struct | Module | Description |
|-------|--------|-------------|
| `Config` | `config` | Main configuration |
| `ScannerConfig` | `config` | Scanner settings |
| `ShieldConfig` | `protocol/claude_code` | Shield configuration |
| `RetryContext` | `traits` | Retry context data |
| `RecoveryContext` | `traits` | Recovery context |

### Security Structs

| Struct | Module | Description |
|-------|--------|-------------|
| `Threat` | `scanner` | Threat representation |
| `SecurityEvent` | `traits` | Security event data |
| `ThreatPattern` | `traits` | Pattern definition |
| `PatternRule` | `traits` | Pattern matching rule |
| `ScannerStats` | `traits` | Scanner statistics |
| `SecurityInsights` | `traits` | Security analysis |

### Protocol Structs

| Struct | Module | Description |
|-------|--------|-------------|
| `ShieldStatusNotification` | `protocol/claude_code` | Status update |
| `ShieldStatistics` | `protocol/claude_code` | Shield stats |
| `PerformanceMetrics` | `protocol/claude_code` | Performance data |
| `LastThreatInfo` | `protocol/claude_code` | Last threat details |
| `BinaryMessageHeader` | `protocol/claude_code` | Binary protocol header |

### Resilience Structs

| Struct | Module | Description |
|-------|--------|-------------|
| `CircuitStats` | `traits` | Circuit breaker stats |
| `RetryStats` | `traits` | Retry statistics |
| `RecoveryStats` | `traits` | Recovery statistics |
| `HealthReport` | `traits` | Health check report |
| `BulkheadStats` | `resilience/bulkhead` | Bulkhead statistics |

### Metrics Structs

| Struct | Module | Description |
|-------|--------|-------------|
| `EndpointStats` | `traits` | Endpoint statistics |
| `ProcessorStats` | `traits` | Processor statistics |
| `RateLimiterStats` | `traits` | Rate limiter stats |
| `HistogramStats` | `traits` | Histogram statistics |

## Enums

### Core Enums

| Enum | Module | Description |
|-------|--------|-------------|
| `ThreatType` | `scanner` | Types of threats |
| `Severity` | `scanner` | Threat severity levels |
| `Priority` | `traits` | Task priority |
| `ErrorType` | `traits` | Error categories |

### State Enums

| Enum | Module | Description |
|-------|--------|-------------|
| `CircuitState` | `traits` | Circuit breaker states |
| `HealthStatus` | `traits` | Health check status |
| `RecoveryState` | `traits` | Recovery states |
| `ShieldState` | `protocol/claude_code` | Shield states |

### Protocol Enums

| Enum | Module | Description |
|-------|--------|-------------|
| `ThreatSeverity` | `protocol/claude_code` | Claude-specific severity |
| `ShieldControlAction` | `protocol/claude_code` | Control actions |
| `ClaudeCodeErrorCode` | `protocol/claude_code` | Error codes |

### CLI Enums

| Enum | Module | Description |
|-------|--------|-------------|
| `Commands` | `cli/main` | CLI commands |
| `ShieldCommands` | `cli/main` | Shield subcommands |
| `OutputFormat` | `cli/output` | Output formats |

## Public Functions

### Factory Functions (lib.rs)

| Function | Returns | Description |
|----------|---------|-------------|
| `create_scanner` | `Arc<dyn SecurityScannerTrait>` | Create configured scanner |
| `create_transport` | `Arc<dyn Transport>` | Create transport layer |
| `create_event_buffer` | `Arc<dyn EventBufferTrait>` | Create event buffer |
| `create_storage` | `Arc<dyn Storage>` | Create storage backend |
| `create_rate_limiter` | `Arc<dyn RateLimiter>` | Create rate limiter |
| `create_telemetry` | `Arc<dyn TelemetryProvider>` | Create telemetry |
| `create_audit_logger` | `Arc<dyn AuditLogger>` | Create audit logger |

### Protocol Functions

| Function | Module | Description |
|----------|--------|-------------|
| `create_status_notification` | `protocol/claude_code` | Create status notification |
| `threat_to_severity` | `protocol/claude_code` | Convert threat to severity |

### CLI Functions

| Function | Module | Description |
|----------|--------|-------------|
| `scan_command` | `cli/main` | Execute scan command |
| `monitor_command` | `cli/main` | Execute monitor command |
| `shield_command` | `cli/main` | Execute shield command |
| `wrap_command` | `cli/main` | Execute wrap command |

## Type Aliases

| Alias | Definition | Module |
|-------|------------|--------|
| `Result<T>` | `std::result::Result<T, KindlyError>` | `error` |
| `ThreatVec` | `Vec<Threat>` | `scanner` |
| `EventHandle` | `u64` | `traits` |

## Constants

| Constant | Value | Module | Description |
|----------|-------|--------|-------------|
| `DEFAULT_MAX_SCAN_DEPTH` | `20` | `config` | Max JSON recursion |
| `DEFAULT_BUFFER_SIZE` | `10000` | `event_processor` | Event buffer size |
| `DEFAULT_FAILURE_THRESHOLD` | `5` | `resilience` | Circuit breaker threshold |
| `MAX_RETRY_ATTEMPTS` | `3` | `resilience` | Max retry attempts |

## Feature-Gated Symbols

### Enhanced Feature

Available with `--features enhanced`:

| Symbol | Type | Module |
|--------|------|--------|
| `EnhancedScanner` | Trait | `scanner/enhanced` |
| `EnhancedEventBuffer` | Struct | `enhanced_impl` |
| `EnhancedRateLimiter` | Struct | `enhanced_impl` |
| `BinaryProtocol` | Struct | `protocol/claude_code` |
| `EnhancedCircuitBreaker` | Struct | `resilience/enhanced` |

## Module Paths

### Public Modules

```rust
pub mod audit;
pub mod cli;
pub mod config;
pub mod error;
pub mod metrics;
pub mod neutralizer;
pub mod permissions;
pub mod protocol;
pub mod resilience;
pub mod scanner;
pub mod shield;
pub mod storage;
pub mod telemetry;
pub mod traits;
pub mod transport;
```

### Re-exports

```rust
// From protocol module
pub use protocol::{
    ShieldStatusNotification,
    ShieldState,
    ShieldStatistics,
    ThreatSeverity,
    // ... more
};

// From scanner module
pub use scanner::{
    SecurityScanner,
    Threat,
    ThreatType,
    Severity,
};

// From traits module
pub use traits::{
    SecurityScannerTrait,
    CircuitBreakerTrait,
    EventBufferTrait,
    // ... more
};
```

## Implementation Matrix

### Standard Implementations

| Trait | Implementation | Module |
|-------|----------------|--------|
| `SecurityScannerTrait` | `SecurityScanner` | `scanner/mod` |
| `CircuitBreakerTrait` | `StandardCircuitBreaker` | `resilience/standard` |
| `RetryStrategyTrait` | `StandardRetryStrategy` | `resilience/standard` |
| `EventBufferTrait` | `SimpleEventBuffer` | `event_processor` |
| `RateLimiter` | `TokenBucket` | `rate_limit` |

### Enhanced Implementations

| Trait | Implementation | Module |
|-------|----------------|--------|
| `SecurityScannerTrait` | `EnhancedScanner` | `scanner/enhanced` |
| `CircuitBreakerTrait` | `EnhancedCircuitBreaker` | `resilience/enhanced` |
| `RetryStrategyTrait` | `EnhancedRetryStrategy` | `resilience/enhanced` |
| `EventBufferTrait` | `EnhancedEventBuffer` | `enhanced_impl` |
| `RateLimiter` | `EnhancedRateLimiter` | `enhanced_impl` |

## Usage Examples

### Creating a Scanner

```rust
use kindly_guard_server::{create_scanner, Config};

let config = Config::from_file("config.toml")?;
let scanner = create_scanner(&config)?;
let threats = scanner.scan_text("suspicious text").await?;
```

### Using Circuit Breaker

```rust
use kindly_guard_server::traits::CircuitBreakerTrait;

let breaker = create_circuit_breaker(&config)?;
let result = breaker.call("api_call", || async {
    // Potentially failing operation
    api_client.fetch().await
}).await?;
```

### Event Processing

```rust
use kindly_guard_server::traits::{EventBufferTrait, SecurityEvent};

let buffer = create_event_buffer(&config)?;
let event = SecurityEvent::new(threat);
let handle = buffer.push(event).await?;
```

This index provides a complete reference to all public symbols in KindlyGuard for easy navigation and API discovery.