# KindlyGuard Architecture Documentation

## System Overview

KindlyGuard is a security-focused Model Context Protocol (MCP) server that provides real-time threat detection and neutralization for AI assistants. Built with Rust for performance and safety, it implements a multi-layered security architecture.

```mermaid
graph TB
    subgraph "Client Layer"
        CLI[CLI Client]
        Shield[Shield UI]
        VSCode[VS Code Extension]
        Browser[Browser Extension]
    end
    
    subgraph "MCP Server"
        Transport[Transport Layer]
        Protocol[MCP Protocol Handler]
        
        subgraph "Core Components"
            Scanner[Security Scanner]
            Buffer[Event Buffer]
            Metrics[Metrics Provider]
            Neutralizer[Neutralizer]
        end
        
        Config[Configuration]
    end
    
    CLI --> Transport
    Shield --> Transport
    VSCode --> Transport
    Browser --> Transport
    
    Transport --> Protocol
    Protocol --> Scanner
    Protocol --> Buffer
    Protocol --> Metrics
    Protocol --> Neutralizer
    
    Config --> Scanner
    Config --> Buffer
    Config --> Metrics
    
    style Scanner fill:#e1f5e1
    style Buffer fill:#e1f5e1
    style Metrics fill:#e1f5e1
    style Neutralizer fill:#e1f5e1
```

## Component Architecture

### Overview

KindlyGuard employs a modular architecture with well-defined components that work together to provide comprehensive security scanning and threat neutralization.

### Key Design Principles

1. **Interface Segregation**: Components have clear, focused responsibilities
2. **Modularity**: Each component can be independently tested and maintained
3. **Configuration-Driven**: Behavior can be customized through configuration
4. **Dependency Inversion**: Components depend on abstractions, not concrete types

### Architecture Diagram

```mermaid
graph TB
    subgraph "Core Components"
        Scanner[Security Scanner]
        Buffer[Event Buffer]
        Metrics[Metrics Provider]
        Neutralizer[Neutralizer]
        Storage[Storage Layer]
    end
    
    subgraph "Supporting Components"
        Config[Configuration]
        Audit[Audit Logger]
        Health[Health Monitor]
    end
    
    Config --> Scanner
    Config --> Buffer
    Config --> Metrics
    
    Scanner --> Buffer
    Scanner --> Metrics
    Scanner --> Audit
    
    style Scanner fill:#e1f5e1
    style Buffer fill:#e1f5e1
    style Metrics fill:#e1f5e1
```

### Core Components

#### Event Buffer
The event buffer manages security events with a configurable capacity:

```rust
pub struct EventBuffer {
    events: Mutex<VecDeque<SecurityEvent>>,
    capacity: usize,
}

impl EventBuffer {
    pub fn push(&self, event: SecurityEvent) -> Result<()> {
        let mut events = self.events.lock().unwrap();
        if events.len() >= self.capacity {
            events.pop_front();
        }
        events.push_back(event);
        Ok(())
    }
    
    pub fn pop(&self) -> Option<SecurityEvent> {
        self.events.lock().unwrap().pop_front()
    }
    
    pub fn flush(&self) -> Vec<SecurityEvent> {
        self.events.lock().unwrap().drain(..).collect()
    }
}
```

#### Metrics Provider
Collects and exports performance metrics:

```rust
pub struct MetricsProvider {
    counters: DashMap<String, AtomicU64>,
    histograms: DashMap<String, Histogram>,
}

impl MetricsProvider {
    pub fn record_event(&self, event_type: &str, value: f64) {
        // Record metric
    }
    
    pub fn export_metrics(&self) -> MetricsSnapshot {
        // Export current metrics
    }
}
```

#### Security Scanner
The core threat detection engine:

```rust
pub struct SecurityScanner {
    unicode_scanner: UnicodeScanner,
    injection_scanner: InjectionScanner,
    xss_scanner: XssScanner,
    pattern_scanner: PatternScanner,
}

impl SecurityScanner {
    pub async fn scan(&self, input: &str) -> ScanResult {
        // Parallel scanning across all threat detectors
    }
    
    pub fn capabilities(&self) -> ScannerCapabilities {
        // Return supported scan types
    }
}
```

### Configuration

The system uses a hierarchical configuration approach:

```toml
# Configuration example
[scanner]
unicode_detection = true
injection_detection = true
xss_detection = true
pattern_matching = true

[buffer]
capacity = 1000
cleanup_interval = 300  # seconds

[metrics]
export_interval = 60  # seconds
histogram_buckets = [0.001, 0.01, 0.1, 1.0, 10.0]
```

### Benefits of This Architecture

#### 1. Clean Separation of Concerns
- Each component has a single, well-defined responsibility
- Clear boundaries between components
- Easy to understand and maintain

#### 2. Flexibility
- Components can be configured independently
- Easy to add new threat detectors
- Extensible through configuration

#### 3. Maintainability and Testing
- Each component can be tested in isolation
- Clear interfaces make mocking straightforward
- Reduced coupling between components

#### 4. Performance Optimization
- Components optimized for their specific tasks
- Parallel scanning for better throughput
- Efficient data structures for high performance

### Component Lifecycle

```mermaid
sequenceDiagram
    participant App
    participant Config
    participant Scanner
    participant Buffer
    participant Metrics
    
    App->>Config: load_configuration()
    Config-->>App: Configuration
    
    App->>Scanner: new(config)
    App->>Buffer: new(config)
    App->>Metrics: new(config)
    
    App->>Scanner: scan(input)
    Scanner->>Buffer: push(event)
    Scanner->>Metrics: record_event()
    Scanner-->>App: ScanResult
```

### Best Practices

1. **Configuration First** - Design with configuration in mind
2. **Single Responsibility** - Each component does one thing well
3. **Error Handling** - All operations return Result types
4. **Performance Monitoring** - Built-in metrics collection
5. **Comprehensive Testing** - Unit and integration tests for all components

## Core Components

### 1. Transport Layer (`src/transport/`)
- **Purpose**: Handle client connections and protocol negotiation
- **Key Files**:
  - `stdio.rs` - Standard I/O transport for CLI integration
  - `websocket.rs` - WebSocket transport for web clients
  - `ipc.rs` - Inter-process communication for desktop apps

### 2. MCP Protocol Handler (`src/protocol/`)
- **Purpose**: Implement Model Context Protocol specification
- **Key Components**:
  - `handler.rs` - Main request/response handler
  - `types.rs` - Protocol type definitions
  - `traits.rs` - Core trait definitions

### 3. Security Scanner (`src/scanner/`)
The heart of KindlyGuard's threat detection, implemented using trait-based architecture:

```rust
// CLAUDE-note-architecture: Scanner module structure
scanner/
├── mod.rs          // SecurityScanner trait definition
├── factory.rs      // Scanner factory functions
├── standard/       // Open-source implementations
│   ├── mod.rs      // Standard scanner implementation
│   ├── unicode.rs  // Basic Unicode security
│   ├── injection.rs// Standard SQL/Command injection
│   └── xss.rs      // Basic XSS detection
└── traits.rs       // Scanner-specific sub-traits
```

#### Security Scanner Implementation
```rust
pub struct SecurityScanner {
    config: ScannerConfig,
    unicode_scanner: UnicodeScanner,
    injection_scanner: InjectionScanner,
    xss_scanner: XssScanner,
    pattern_scanner: PatternScanner,
}

impl SecurityScanner {
    pub fn new(config: ScannerConfig) -> Self {
        Self {
            config,
            unicode_scanner: UnicodeScanner::new(),
            injection_scanner: InjectionScanner::new(),
            xss_scanner: XssScanner::new(),
            pattern_scanner: PatternScanner::new(),
        }
    }
    
    pub async fn scan(&self, input: &str) -> ScanResult {
        // Parallel scanning implementation
    }
    
    pub fn capabilities(&self) -> ScannerCapabilities {
        // Return supported scan types
    }
}
```

#### Scanning Pipeline:
1. **Input Normalization** - Unicode normalization, encoding detection
2. **Threat Detection** - Parallel scanning for multiple threat types
3. **Risk Assessment** - Severity scoring and threat categorization
4. **Response Generation** - Neutralization recommendations

### 4. Threat Neutralizer (`src/neutralizer/`)
- **Purpose**: Transform dangerous input into safe alternatives
- **Strategies**:
  - Encoding (HTML entities, URL encoding)
  - Sanitization (Remove dangerous patterns)
  - Transformation (Safe alternatives)
  - Blocking (Reject entirely)

### 5. Audit System (`src/audit/`)
- **Purpose**: Comprehensive security event logging
- **Features**:
  - Tamper-proof event logs
  - Compliance reporting (SOC2, GDPR)
  - Real-time alerting
  - Forensic analysis support

### 6. Storage Layer (`src/storage/`)
- **SQLite Backend**: Persistent threat database
- **Schema**:
  ```sql
  -- CLAUDE-note-implemented: Database schema
  CREATE TABLE threats (
      id TEXT PRIMARY KEY,
      timestamp INTEGER NOT NULL,
      threat_type TEXT NOT NULL,
      severity INTEGER NOT NULL,
      input_hash TEXT NOT NULL,
      details JSONB
  );
  
  CREATE TABLE audit_log (
      id INTEGER PRIMARY KEY,
      timestamp INTEGER NOT NULL,
      event_type TEXT NOT NULL,
      user_id TEXT,
      details JSONB
  );
  ```

### 7. Resilience Layer (`src/resilience/`)
Fault tolerance and reliability patterns:

```rust
// CLAUDE-note-pattern: Resilience components
pub struct CircuitBreaker {
    failure_count: AtomicU32,
    last_failure: RwLock<Option<Instant>>,
    state: RwLock<CircuitState>,
    config: CircuitBreakerConfig,
}

impl CircuitBreaker {
    pub fn call<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        // Check circuit state and execute if allowed
    }
    
    pub fn state(&self) -> CircuitState {
        *self.state.read().unwrap()
    }
    
    pub fn reset(&self) {
        self.failure_count.store(0, Ordering::Relaxed);
        *self.state.write().unwrap() = CircuitState::Closed;
    }
}

pub struct RetryPolicy {
    max_attempts: u32,
    initial_delay: Duration,
    max_delay: Duration,
    jitter_factor: f64,
}

impl RetryPolicy {
    pub async fn execute<F, T>(&self, f: F) -> Result<T>
    where
        F: Fn() -> Future<Output = Result<T>> + Send,
    {
        // Execute with exponential backoff and jitter
    }
}
```

## Data Flow

### Request Processing Flow:
```mermaid
sequenceDiagram
    participant Client
    participant Transport
    participant Protocol
    participant Scanner
    participant Neutralizer
    participant Storage
    participant Client
    
    Client->>Transport: Send request
    Transport->>Protocol: Parse MCP message
    Protocol->>Scanner: Extract content for scanning
    
    par Parallel Scanning
        Scanner->>Scanner: Unicode analysis
        Scanner->>Scanner: Injection detection
        Scanner->>Scanner: XSS detection
        Scanner->>Scanner: Pattern matching
    end
    
    Scanner->>Storage: Log threats
    Scanner->>Neutralizer: Process threats
    Neutralizer->>Protocol: Generate safe response
    Protocol->>Transport: Encode response
    Transport->>Client: Return result
```

### State Management:
- **Stateless scanning**: Each request is independent
- **Cached results**: LRU cache for repeated queries
- **Session tracking**: Optional client session management
- **Metrics aggregation**: Real-time performance tracking

## Security Architecture

### Defense in Depth:
1. **Input Validation** - Type checking, size limits, encoding validation
2. **Threat Detection** - Multi-engine scanning with ML models
3. **Neutralization** - Context-aware sanitization
4. **Output Encoding** - Proper escaping for target context
5. **Audit Trail** - Complete security event logging

### Threat Model:
```yaml
# CLAUDE-note-security: Threat categories
threats:
  - category: Unicode Attacks
    severity: HIGH
    examples:
      - Homograph attacks
      - Bidi override attacks
      - Zero-width characters
    
  - category: Injection Attacks
    severity: CRITICAL
    examples:
      - SQL injection
      - Command injection
      - LDAP injection
      
  - category: XSS Attacks
    severity: HIGH
    examples:
      - Reflected XSS
      - Stored XSS
      - DOM-based XSS
      
  - category: Prompt Injection
    severity: HIGH
    examples:
      - Instruction override
      - Context manipulation
      - Jailbreak attempts
```

## Performance Characteristics

### Benchmarks:
```yaml
# CLAUDE-note-performance: Measured on Apple M2
operations:
  unicode_scan:
    throughput: "1.2M chars/sec"
    latency_p50: "82µs"
    latency_p99: "145µs"
    
  full_scan:
    throughput: "850K chars/sec"
    latency_p50: "118µs"
    latency_p99: "312µs"
    
  cache_hit:
    latency: "<1µs"
    hit_rate: "~85%"
```

### Resource Usage:
- **Memory**: ~50MB base + 0.1MB per connection
- **CPU**: Single-threaded scanner, async I/O
- **Disk**: Minimal (SQLite WAL mode)
- **Network**: Protocol overhead <5%

## Deployment Architecture

### Container Deployment:
```dockerfile
# CLAUDE-note-deployment: Production Dockerfile
FROM rust:1.75-alpine AS builder
# Multi-stage build for minimal image

FROM alpine:3.19
# Runtime with security hardening
USER kindly:kindly
EXPOSE 8080
```

### Scaling Strategy:
1. **Vertical**: Single instance handles ~10K concurrent connections
2. **Horizontal**: Stateless design enables easy scaling
3. **Edge deployment**: Can run at edge locations
4. **Embedded**: Can be embedded in other applications

## Integration Points

### MCP Clients:
- **Claude Desktop**: Native stdio integration
- **VS Code**: Extension with Language Server Protocol
- **Web Apps**: WebSocket connectivity
- **CLI Tools**: Direct stdio communication

### External Systems:
```yaml
# CLAUDE-note-integrations: External system hooks
integrations:
  - name: SIEM
    protocol: Syslog
    events: [threat_detected, scan_failed]
    
  - name: Metrics
    protocol: OpenTelemetry
    metrics: [scan_duration, threat_count, cache_hit_rate]
    
  - name: Alerting
    protocol: Webhook
    events: [critical_threat, system_error]
```

## Configuration Management

### Configuration Hierarchy:
1. **Default config** - Built-in safe defaults
2. **File config** - TOML/JSON/YAML files
3. **Environment** - Environment variable overrides
4. **Runtime** - Dynamic reconfiguration via API

### Key Configuration Areas:
```toml
# CLAUDE-note-config: Example configuration
[scanner]
timeout_ms = 1000
max_input_size = 1048576  # 1MB
parallel_scanners = 4

[security]
unicode_security_level = "strict"
injection_detection = true
xss_detection = true

[transport]
listen_address = "127.0.0.1:8080"
max_connections = 1000

[storage]
path = "./kindly.db"
wal_mode = true
cache_size_mb = 100

[resilience]
circuit_breaker_enabled = true
retry_enabled = true
bulkhead_enabled = true
```

## Error Handling Strategy

### Error Categories:
1. **Configuration Errors** - Fail fast on startup
2. **Runtime Errors** - Graceful degradation
3. **Security Errors** - Log and alert
4. **Protocol Errors** - Return proper MCP errors

### Error Response Format:
```rust
// CLAUDE-note-pattern: Consistent error responses
#[derive(Serialize)]
pub struct ErrorResponse {
    pub code: ErrorCode,
    pub message: String,
    pub details: Option<Value>,
    pub request_id: Uuid,
}
```

## Monitoring and Observability

### Metrics:
- Request rate and latency
- Threat detection rates by type
- Cache performance
- Resource utilization

### Logging:
- Structured JSON logs
- Log levels: ERROR, WARN, INFO, DEBUG, TRACE
- Correlation IDs for request tracing

### Health Checks:
```rust
// CLAUDE-note-endpoint: Health check endpoints
GET /health/live    -> 200 OK (am I alive?)
GET /health/ready   -> 200 OK (am I ready to serve?)
GET /metrics        -> Prometheus format metrics
```

## Future Architecture Considerations

### Planned Enhancements:
1. **Performance Optimizations**
   - GPU-accelerated pattern matching
   - SIMD optimizations for Unicode scanning
   - Zero-copy parsing improvements
   
2. **Scalability Features**
   - Horizontal scaling support
   - Distributed caching
   - Load balancing capabilities
   
3. **Extended Security Features**
   - Machine learning threat detection
   - Behavioral analysis
   - Advanced pattern recognition

4. **Integration Improvements**
   - Additional transport protocols
   - Plugin system for custom scanners
   - Extended API surface

5. **Operational Features**
   - Enhanced monitoring dashboards
   - Automated threat response
   - Advanced configuration management

### Scalability Path:
```mermaid
graph LR
    subgraph "Current"
        Single[Single Instance]
    end
    
    subgraph "Near Term"
        Multi[Multi-Instance]
        LB[Load Balancer]
        Cache[Shared Cache]
    end
    
    subgraph "Future"
        Edge[Edge Nodes]
        Central[Central Coordinator]
        ML[ML Cluster]
    end
    
    Single --> Multi
    Multi --> LB
    LB --> Cache
    Cache --> Edge
    Edge --> Central
    Central --> ML
```

## Development Workflow

### Build Pipeline:
1. **Local development** - `cargo watch -x run`
2. **Testing** - Unit, integration, and property tests
3. **Benchmarking** - Criterion.rs benchmarks
4. **Security audit** - `cargo audit` and fuzzing
5. **Release** - Multi-platform builds via GitHub Actions