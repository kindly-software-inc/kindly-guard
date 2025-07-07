# KindlyGuard API Documentation

This document provides a comprehensive overview of KindlyGuard's public API surfaces, trait definitions, and architectural components.

## Quick Start

### Installation
```bash
# Instant installation via npm (recommended)
npm install -g kindlyguard

# Alternative: Install via Cargo
cargo install kindlyguard
```

### Basic Usage
```bash
# Start MCP server
kindlyguard serve

# Scan files
kindlyguard scan file.txt

# Monitor threats
kindlyguard monitor
```

## Table of Contents

1. [Unified Binary Architecture](#unified-binary-architecture)
2. [Core Traits](#core-traits)
3. [Public Modules](#public-modules)
4. [Factory Functions](#factory-functions)
5. [MCP Protocol Integration](#mcp-protocol-integration)
6. [Security Components](#security-components)
7. [Resilience Architecture](#resilience-architecture)

## Unified Binary Architecture

KindlyGuard v0.15.0 introduces a unified binary that combines all functionality:

### Binary: `kindlyguard`

The single executable includes:
- **MCP Server** (`serve` command) - Full MCP protocol support with multiple tools
- **CLI Scanner** (`scan` command) - Command-line security scanning
- **Monitor** (`monitor` command) - Real-time threat monitoring
- **Shield** (`shield` command) - Interactive security dashboard
- **MCP Management** (`mcp` command) - Configure and manage MCP integration

### MCP Multi-Tool Support

When running as an MCP server, KindlyGuard exposes multiple security tools:

```typescript
// Available MCP tools
interface KindlyGuardTools {
  scan_text: (text: string, protection_mode?: string) => ScanResult;
  scan_file: (path: string, quarantine?: boolean) => FileResult;
  check_url: (url: string) => URLResult;
  neutralize: (text: string, threat_id?: string) => CleanResult;
  quarantine_list: (filter?: string) => QuarantineEntry[];
  get_statistics: () => SecurityStats;
}
```

## Core Traits

KindlyGuard follows a trait-based architecture for maximum flexibility and testability. All major components are defined as traits with standard and enhanced implementations.

### Security Scanner Traits

#### `SecurityScannerTrait`
```rust
pub trait SecurityScannerTrait: Send + Sync {
    async fn scan_text(&self, text: &str) -> Result<Vec<Threat>>;
    async fn scan_json(&self, json: &Value) -> Result<Vec<Threat>>;
}
```

The main security scanning interface for detecting threats in text and JSON inputs.

#### `EnhancedScanner`
```rust
pub trait EnhancedScanner: SecurityScannerTrait {
    async fn scan_with_context(&self, text: &str, context: ScanContext) -> Result<Vec<Threat>>;
    async fn get_insights(&self) -> Result<SecurityInsights>;
}
```

Extended scanner interface with context-aware scanning and security insights.

### Resilience Traits

#### `CircuitBreakerTrait`
```rust
pub trait CircuitBreakerTrait: Send + Sync {
    async fn call<F, T, Fut>(&self, name: &str, f: F) -> Result<T, CircuitBreakerError>
    where
        F: FnOnce() -> Fut + Send,
        Fut: Future<Output = Result<T>> + Send,
        T: Send;
        
    fn state(&self) -> CircuitState;
    fn stats(&self) -> CircuitStats;
}
```

Circuit breaker pattern for fault tolerance.

#### `RetryStrategyTrait`
```rust
pub trait RetryStrategyTrait: Send + Sync {
    async fn execute<F, T, Fut>(&self, context: RetryContext, f: F) -> Result<T>
    where
        F: Fn() -> Fut + Send,
        Fut: Future<Output = Result<T>> + Send,
        T: Send;
        
    fn should_retry(&self, error: &Error, attempt: u32) -> RetryDecision;
    fn stats(&self) -> RetryStats;
}
```

Retry logic with configurable backoff strategies.

#### `RecoveryStrategyTrait`
```rust
pub trait RecoveryStrategyTrait: Send + Sync {
    async fn recover(&self, context: RecoveryContext) -> Result<RecoveryState>;
    fn can_recover(&self, error: &Error) -> bool;
    fn stats(&self) -> RecoveryStats;
}
```

Recovery strategies for handling failures.

### Event Processing Traits

#### `EventBufferTrait`
```rust
pub trait EventBufferTrait: Send + Sync {
    async fn push(&self, event: SecurityEvent) -> Result<EventHandle>;
    async fn flush(&self) -> Result<Vec<SecurityEvent>>;
    fn capacity(&self) -> usize;
    fn stats(&self) -> EndpointStats;
}
```

Event buffering for asynchronous threat processing.

#### `SecurityEventProcessor`
```rust
pub trait SecurityEventProcessor: Send + Sync {
    async fn process(&self, event: SecurityEvent) -> Result<()>;
    async fn process_batch(&self, events: Vec<SecurityEvent>) -> Result<ProcessorStats>;
}
```

Event processing interface for security events.

### Rate Limiting

#### `RateLimiter`
```rust
pub trait RateLimiter: Send + Sync {
    async fn check(&self, key: RateLimitKey) -> Result<RateLimitDecision>;
    async fn report(&self, key: RateLimitKey, outcome: bool);
    fn stats(&self) -> RateLimiterStats;
}
```

Rate limiting interface for API protection.

### Metrics and Telemetry

#### `MetricsProvider`
```rust
pub trait MetricsProvider: Send + Sync {
    fn counter(&self, name: &str) -> Arc<dyn CounterTrait>;
    fn gauge(&self, name: &str) -> Arc<dyn GaugeTrait>;
    fn histogram(&self, name: &str) -> Arc<dyn HistogramTrait>;
}
```

Metrics collection interface.

## Public Modules

### Scanner Module (`scanner`)

The scanner module provides comprehensive threat detection:

- **Unicode Scanner** (`unicode`): Detects Unicode-based attacks
  - Invisible characters (zero-width spaces, joiners)
  - BiDi override attacks
  - Homograph attacks
  - Control characters

- **Injection Scanner** (`injection`): Detects injection attacks
  - SQL injection
  - Command injection
  - Prompt injection (LLM-specific)
  - Path traversal
  - LDAP/XML/NoSQL injections

- **XSS Scanner** (`xss_scanner`): Cross-site scripting detection
  - Script tags and event handlers
  - JavaScript URLs
  - Data URIs
  - HTML entity bypasses

- **Pattern Scanner** (`patterns`): Custom threat patterns
  - MCP-specific threats
  - Tool poisoning attempts
  - Configuration-based patterns

- **Crypto Scanner** (`crypto`): Cryptographic weakness detection
  - Deprecated algorithms (MD5, SHA1, DES)
  - Weak key sizes
  - Insecure modes (ECB)
  - Bad key derivation

### Protocol Module (`protocol`)

MCP protocol implementation with Claude Code extensions:

```rust
pub mod types;  // Core MCP types
pub mod claude_code;  // Claude-specific extensions

// Key types exported:
pub use claude_code::{
    ShieldStatusNotification,
    ShieldState,
    ShieldStatistics,
    ThreatSeverity,
    ShieldConfig,
    // ... more
};
```

### Shield Module (`shield`)

UI and display components:

- **Display** (`display`): Terminal UI components
- **Universal Display** (`universal_display`): Cross-platform display
- **CLI** (`cli`): Command-line interface helpers

### Storage Module (`storage`)

Persistence and caching:

- **Memory Storage**: In-memory threat storage
- **Enhanced Storage**: Persistent storage with SQLite

### Resilience Module (`resilience`)

Fault tolerance components:

- **Circuit Breaker**: Prevents cascading failures
- **Retry**: Configurable retry strategies
- **Bulkhead**: Resource isolation
- **Health Checks**: System health monitoring

## Factory Functions

KindlyGuard provides factory functions for creating configured components:

```rust
// Create scanner based on configuration
pub fn create_scanner(config: &Config) -> Result<Arc<dyn SecurityScannerTrait>>;

// Create transport based on configuration
pub fn create_transport(config: &Config) -> Result<Arc<dyn Transport>>;

// Create event buffer
pub fn create_event_buffer(config: &Config) -> Result<Arc<dyn EventBufferTrait>>;

// Create storage
pub fn create_storage(config: &Config) -> Result<Arc<dyn Storage>>;

// Create rate limiter
pub fn create_rate_limiter(config: &Config) -> Result<Arc<dyn RateLimiter>>;

// Create telemetry
pub fn create_telemetry(config: &Config) -> Result<Arc<dyn TelemetryProvider>>;

// Create audit logger
pub fn create_audit_logger(config: &Config) -> Result<Arc<dyn AuditLogger>>;
```

## MCP Protocol Integration

KindlyGuard implements the Model Context Protocol (MCP) with security extensions:

### Tool Registration

```rust
// Scanner tool
Tool {
    name: "scan_text",
    description: "Scan text for security threats",
    input_schema: {
        "text": { "type": "string", "description": "Text to scan" }
    }
}

// Shield status tool
Tool {
    name: "shield_status",
    description: "Get current shield status and statistics",
    input_schema: {}
}

// Shield control tool
Tool {
    name: "shield_control",
    description: "Control shield behavior",
    input_schema: {
        "action": { "type": "string", "enum": ["enable", "disable", "reset"] }
    }
}
```

### Claude Code Extensions

Special notifications for Claude Code integration:

```rust
pub struct ShieldStatusNotification {
    pub state: ShieldState,
    pub threats_blocked: u64,
    pub last_threat: Option<LastThreatInfo>,
    pub performance: PerformanceMetrics,
}
```

## Security Components

### Threat Types

```rust
#[derive(Debug, Clone, PartialEq)]
pub enum ThreatType {
    // Unicode threats
    UnicodeInvisible { position: usize },
    UnicodeBiDi { position: usize },
    UnicodeHomograph { similar_to: String },
    
    // Injection threats
    SqlInjection { pattern: String },
    CommandInjection { pattern: String },
    PromptInjection { pattern: String },
    
    // XSS threats
    XssScript { context: String },
    XssEventHandler { handler: String },
    
    // Crypto threats
    WeakCrypto { algorithm: String },
    InsecureRandom { source: String },
}
```

### Severity Levels

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}
```

## Resilience Architecture

### Circuit Breaker States

```rust
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CircuitState {
    Closed,      // Normal operation
    Open,        // Failing, reject calls
    HalfOpen,    // Testing recovery
}
```

### Health Check System

```rust
pub trait HealthCheckTrait: Send + Sync {
    async fn check(&self) -> Result<HealthCheckResult>;
    fn metadata(&self) -> HealthCheckMetadata;
}

#[derive(Debug, Clone)]
pub struct HealthCheckResult {
    pub status: HealthStatus,
    pub message: Option<String>,
    pub details: HashMap<String, Value>,
}
```

## Configuration

KindlyGuard uses a hierarchical configuration system:

```toml
[scanner]
unicode_detection = true
injection_detection = true
xss_detection = true
max_scan_depth = 20

[resilience]
[resilience.circuit_breaker]
failure_threshold = 5
recovery_timeout = "30s"

[resilience.retry]
max_attempts = 3
initial_delay = "100ms"
max_delay = "10s"

[telemetry]
enabled = true
export_interval = "10s"
```

## Error Handling

All fallible operations return `Result<T, E>` with appropriate error types:

```rust
#[derive(Debug, thiserror::Error)]
pub enum KindlyError {
    #[error("Scanner error: {0}")]
    Scanner(String),
    
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("Circuit breaker open")]
    CircuitBreakerOpen,
    
    // ... more variants
}
```

## Thread Safety

All public traits require `Send + Sync` for thread-safe usage across async boundaries. Components use:

- `Arc<T>` for shared ownership
- `Mutex` or `RwLock` for interior mutability
- Lock-free atomics for statistics

## Performance Considerations

- Scanner uses zero-copy operations where possible
- SIMD optimizations available for Unicode scanning
- Event buffering reduces lock contention
- Circuit breakers prevent resource exhaustion

## Security Guarantees

1. **No unwrap() in production code**: All operations handle errors explicitly
2. **Input validation**: All external inputs are validated
3. **Constant-time comparisons**: Security-sensitive comparisons use constant-time algorithms
4. **Memory safety**: No unsafe code in public APIs
5. **Resource limits**: Configurable limits prevent DoS attacks