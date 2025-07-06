# KindlyGuard Architecture

## Overview

KindlyGuard is a security-focused MCP (Model Context Protocol) server designed to protect against unicode attacks, injection attempts, and other security threats. It provides real-time threat detection and neutralization while maintaining high performance and reliability.

## Core Principles

1. **Security First**: Every architectural decision prioritizes security over features
2. **Zero Trust**: All input is considered potentially malicious until validated
3. **Defense in Depth**: Multiple layers of protection throughout the system
4. **Fail Secure**: System fails closed, denying access rather than allowing threats
5. **Performance**: Security without sacrificing usability

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        MCP Client (LLM)                         │
└──────────────────────────────┬──────────────────────────────────┘
                               │ MCP Protocol (JSON-RPC)
┌──────────────────────────────▼──────────────────────────────────┐
│                      Protocol Handler                           │
│  • Request validation                                           │
│  • Rate limiting                                                │
│  • Authentication                                               │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                    Security Scanner Layer                       │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌─────────────┐ │
│  │  Unicode   │ │ Injection  │ │    XSS     │ │   Pattern   │ │
│  │  Scanner   │ │  Scanner   │ │  Scanner   │ │   Scanner   │ │
│  └────────────┘ └────────────┘ └────────────┘ └─────────────┘ │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                      Neutralizer Layer                          │
│  • Threat mitigation                                            │
│  • Content sanitization                                         │
│  • Safe encoding                                                │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                    Resilience Components                        │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌─────────────┐ │
│  │  Circuit   │ │   Retry    │ │  Bulkhead  │ │   Health    │ │
│  │  Breaker   │ │  Handler   │ │ Isolation  │ │   Check     │ │
│  └────────────┘ └────────────┘ └────────────┘ └─────────────┘ │
└──────────────────────────────┬──────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────┐
│                      Supporting Services                        │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌─────────────┐ │
│  │   Audit    │ │  Storage   │ │ Telemetry  │ │   Shield    │ │
│  │   Logger   │ │  (SQLite)  │ │  Metrics   │ │    (TUI)    │ │
│  └────────────┘ └────────────┘ └────────────┘ └─────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Component Architecture

### 1. Protocol Handler (`src/protocol/`)

The protocol handler is the entry point for all MCP requests:

- **Request Validation**: Validates JSON-RPC format and method names
- **Rate Limiting**: Prevents DoS attacks through configurable limits
- **Authentication**: Token-based authentication with expiry
- **Routing**: Dispatches requests to appropriate handlers

Key traits:
```rust
pub trait ProtocolHandler: Send + Sync {
    async fn handle_request(&self, request: Request) -> Result<Response>;
}
```

### 2. Security Scanner Layer (`src/scanner/`)

The scanner layer implements a pluggable architecture for threat detection:

#### Unicode Scanner (`src/scanner/unicode.rs`)
- Detects homograph attacks (e.g., Cyrillic 'а' vs Latin 'a')
- Identifies BiDi override characters
- Finds zero-width characters used for hiding content
- Validates unicode normalization

#### Injection Scanner (`src/scanner/injection.rs`)
- SQL injection patterns
- Command injection detection
- LDAP injection prevention
- Path traversal attacks

#### XSS Scanner (`src/scanner/xss.rs`)
- Context-aware XSS detection
- HTML, JavaScript, CSS, and URL contexts
- DOM-based XSS patterns
- Event handler injection

#### Pattern Scanner (`src/scanner/patterns.rs`)
- Regex-based pattern matching
- Fuzzy pattern detection
- ML-enhanced pattern recognition
- Custom pattern definitions

### 3. Neutralizer Layer (`src/neutralizer/`)

Transforms potentially dangerous content into safe forms:

- **HTML Encoding**: Entity encoding for HTML contexts
- **URL Encoding**: Percent encoding and punycode conversion
- **JavaScript Escaping**: Safe string escaping for JS contexts
- **SQL Escaping**: Parameterized query generation

### 4. Resilience Components (`src/resilience/`)

Ensures system reliability under adverse conditions:

#### Circuit Breaker
- Prevents cascade failures
- Automatic recovery with half-open state
- Configurable failure thresholds

#### Retry Handler
- Exponential backoff with jitter
- Configurable retry limits
- Idempotency support

#### Bulkhead Isolation
- Resource pool isolation
- Prevents resource exhaustion
- Concurrent request limiting

### 5. Storage Layer (`src/storage/`)

Persistent storage with multiple backends:

- **SQLite**: Default storage for audit logs and threat history
- **In-Memory Cache**: LRU cache with TTL for performance
- **File-based**: JSON/YAML storage for configuration

### 6. Shield UI (`src/shield/`)

Real-time monitoring dashboard built with ratatui:

- Live threat visualization
- Performance metrics
- Configuration management
- Alert notifications

## Data Flow

1. **Request Reception**: MCP client sends JSON-RPC request
2. **Authentication**: Token validation and rate limit check
3. **Threat Scanning**: Parallel scanning across all enabled scanners
4. **Threat Assessment**: Aggregation and severity calculation
5. **Neutralization**: Apply appropriate mitigation strategies
6. **Audit Logging**: Record all security events
7. **Response**: Return sanitized response or error

## Security Architecture

### Threat Model

KindlyGuard defends against:

1. **Unicode Attacks**
   - Homograph/homoglyph attacks
   - BiDi text spoofing
   - Zero-width character hiding

2. **Injection Attacks**
   - SQL injection
   - Command injection
   - LDAP injection
   - XSS (all contexts)

3. **Protocol Attacks**
   - Request flooding
   - Malformed requests
   - Authentication bypass attempts

### Security Layers

1. **Input Validation**: All external input validated at entry
2. **Type Safety**: Rust's type system prevents memory corruption
3. **Least Privilege**: Each component has minimal permissions
4. **Secure Defaults**: Security features enabled by default
5. **Audit Trail**: Complete logging of security events

## Performance Architecture

### Optimization Strategies

1. **Zero-Copy Operations**: Use borrowed data wherever possible
2. **Parallel Scanning**: Concurrent threat detection
3. **SIMD Optimization**: Hardware acceleration for pattern matching
4. **Lazy Evaluation**: Compute only when necessary
5. **Connection Pooling**: Reuse database connections

### Benchmarks

Key performance metrics:

- Unicode scanning: ~10,000 req/sec
- Full security scan: ~5,000 req/sec
- P99 latency: <10ms
- Memory usage: <100MB baseline

## Extensibility

### Plugin Architecture

KindlyGuard supports plugins through:

1. **Scanner Plugins**: Custom threat detection logic
2. **Neutralizer Plugins**: Custom sanitization strategies
3. **Storage Plugins**: Alternative storage backends
4. **Transport Plugins**: Alternative protocol support

### Trait-Based Design

All major components are trait-based for extensibility:

```rust
pub trait Scanner: Send + Sync {
    async fn scan(&self, input: &str) -> Result<Vec<Threat>>;
}

pub trait Neutralizer: Send + Sync {
    async fn neutralize(&self, threat: &Threat) -> Result<String>;
}

pub trait Storage: Send + Sync {
    async fn store(&self, event: &SecurityEvent) -> Result<()>;
}
```

## Configuration Management

### Configuration Sources (Priority Order)

1. Command-line arguments
2. Environment variables
3. Configuration files (TOML/YAML)
4. Default values

### Hot Reloading

Configuration changes can be applied without restart:

- Scanner thresholds
- Rate limits
- Logging levels
- Feature toggles

## Error Handling

### Error Philosophy

- No `unwrap()` in production code
- All errors are recoverable or fail secure
- Detailed error context for debugging
- User-friendly error messages

### Error Types

```rust
pub enum KindlyError {
    SecurityThreat(ThreatDetails),
    Configuration(ConfigError),
    Protocol(ProtocolError),
    Storage(StorageError),
    Internal(String),
}
```

## Testing Architecture

### Test Levels

1. **Unit Tests**: Component-level testing
2. **Integration Tests**: Cross-component workflows
3. **Property Tests**: Fuzzing with proptest
4. **Performance Tests**: Benchmark critical paths
5. **Security Tests**: Penetration testing scenarios

### Test Infrastructure

- Mock implementations for all traits
- Test fixtures for common scenarios
- Deterministic random generation
- Parallel test execution

## Deployment Architecture

### Deployment Options

1. **Standalone Binary**: Single executable with embedded assets
2. **Docker Container**: Isolated container deployment
3. **Kubernetes**: Scalable cloud deployment
4. **NPM Package**: JavaScript ecosystem integration

### Monitoring

- OpenTelemetry integration
- Prometheus metrics export
- Structured logging (JSON)
- Health check endpoints

## Future Architecture Considerations

### Planned Enhancements

1. **Clustering Support**: Multi-node deployments
2. **External Storage**: PostgreSQL, Redis support
3. **Machine Learning**: Advanced pattern detection
4. **WebAssembly Plugins**: Safe plugin execution
5. **gRPC Support**: Alternative transport protocol

### Scalability Path

1. Horizontal scaling through stateless design
2. Read replicas for audit logs
3. Caching layer expansion
4. Load balancer integration

## Architecture Decisions Record (ADR)

### ADR-001: Rust Language Choice
- **Status**: Accepted
- **Context**: Need memory safety without GC overhead
- **Decision**: Use Rust for entire codebase
- **Consequences**: Higher initial development time, better long-term reliability

### ADR-002: Trait-Based Architecture
- **Status**: Accepted
- **Context**: Need extensibility without compromising security
- **Decision**: All major components behind traits
- **Consequences**: Clean plugin architecture, slight runtime overhead

### ADR-003: SQLite Default Storage
- **Status**: Accepted
- **Context**: Need embedded database without dependencies
- **Decision**: SQLite as default, trait allows alternatives
- **Consequences**: Simple deployment, limited concurrent writes

### ADR-004: MCP Protocol Support
- **Status**: Accepted
- **Context**: Integration with AI assistants
- **Decision**: Implement full MCP specification
- **Consequences**: Wide compatibility, protocol overhead

## Conclusion

KindlyGuard's architecture prioritizes security while maintaining performance and extensibility. The trait-based design allows for future enhancements without breaking existing functionality, while Rust's safety guarantees provide a solid foundation for security-critical operations.