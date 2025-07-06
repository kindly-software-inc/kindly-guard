# KindlyGuard Module Documentation

This document provides detailed documentation for each module in the KindlyGuard codebase.

## Project Structure

```
kindly-guard/
├── kindly-guard-server/     # Main MCP server implementation
├── kindly-guard-cli/        # Command-line interface
├── kindly-guard-shield/     # Desktop UI (Tauri app)
├── kindly-tools/            # Additional CLI tools
└── crates-io-package/       # Crates.io publishing package
```

## kindly-guard-server

The core MCP server providing security scanning and threat detection.

### Entry Points

- `src/main.rs` - Server binary entry point
- `src/lib.rs` - Library interface with factory functions

### Core Modules

#### `scanner/` - Threat Detection Engine

- **`mod.rs`** - Scanner trait and orchestration (~200 lines)
  - `SecurityScanner` struct coordinating sub-scanners
  - Factory function for creating scanners
  - Threat aggregation and deduplication

- **`unicode.rs`** - Unicode threat detection (~350 lines)
  - Homograph attack detection
  - BiDi override detection
  - Zero-width character detection
  - Unicode normalization attacks

- **`injection.rs`** - Injection attack prevention (~300 lines)
  - SQL injection patterns
  - Command injection detection
  - LDAP injection detection
  - Path traversal prevention

- **`xss_scanner.rs`** - Cross-site scripting prevention (~400 lines)
  - HTML context XSS
  - JavaScript context XSS
  - CSS context XSS
  - Event handler detection

- **`patterns.rs`** - Pattern-based detection (~250 lines)
  - Regex pattern matching
  - ML-based pattern detection
  - Custom pattern loading

- **`crypto.rs`** - Cryptographic weakness detection
  - Weak algorithm detection (MD5, SHA1, DES)
  - Insecure random detection
  - Weak key size detection
  - Bad encryption modes (ECB)

#### `neutralizer/` - Threat Neutralization

- **`mod.rs`** - Neutralization strategies (~150 lines)
- **`standard.rs`** - Basic neutralization
- **`enhanced.rs`** - Advanced neutralization with ML
- **`health.rs`** - Health monitoring for neutralizer
- **`metrics.rs`** - Performance metrics
- **`validation.rs`** - Input/output validation

#### `protocol/` - MCP Protocol Implementation

- **`mod.rs`** - Module exports
- **`types.rs`** - Core MCP types
- **`claude_code.rs`** - Claude Code extensions
  - Shield status notifications
  - Binary protocol for performance
  - Custom tool definitions

#### `shield/` - UI Components

- **`display.rs`** - Terminal UI with ratatui (~300 lines)
- **`universal_display.rs`** - Cross-platform display
- **`cli.rs`** - CLI-specific display helpers

#### `resilience/` - Fault Tolerance

- **`circuit_breaker.rs`** - Circuit breaker pattern (~200 lines)
- **`retry.rs`** - Retry with exponential backoff (~150 lines)
- **`bulkhead.rs`** - Resource isolation
- **`standard.rs`** - Standard implementations
- **`enhanced.rs`** - Enhanced implementations

#### `storage/` - Data Persistence

- **`memory.rs`** - In-memory storage with TTL (~250 lines)
- **`enhanced.rs`** - SQLite-based persistence (~400 lines)

#### `metrics/` - Telemetry

- **`mod.rs`** - Metrics traits
- **`standard.rs`** - Basic metrics (counters, gauges, histograms)
- **`enhanced_interface.rs`** - Advanced metrics with tags

#### `transport/` - Communication Layers

- **`stdio.rs`** - Standard I/O transport
- **`http.rs`** - HTTP/HTTPS transport
- **`websocket.rs`** - WebSocket transport
- **`claude_code.rs`** - Claude Code specific transport

#### `traits.rs` - Core Trait Definitions

All major component traits:
- `SecurityScannerTrait`
- `CircuitBreakerTrait`
- `RetryStrategyTrait`
- `EventBufferTrait`
- `RateLimiter`
- `MetricsProvider`
- And many more...

### Test Organization

- `tests/unit/` - Unit tests colocated with modules
- `tests/integration/` - End-to-end integration tests
- `tests/property/` - Property-based tests with proptest
- `benches/` - Performance benchmarks with criterion

## kindly-guard-cli

Command-line interface for KindlyGuard.

### Commands

#### `scan` - Scan files for threats
```bash
kindly-guard scan <file_or_directory>
```
Options:
- `--format`: Output format (json, text, table)
- `--recursive`: Scan directories recursively
- `--parallel`: Number of parallel workers

#### `monitor` - Monitor server status
```bash
kindly-guard monitor [--interval <seconds>]
```
Shows real-time threat statistics and performance metrics.

#### `shield` - Shield management
```bash
kindly-guard shield <subcommand>
```
Subcommands:
- `start`: Start shield service
- `stop`: Stop shield service
- `status`: Show shield status

#### `wrap` - Wrap commands with protection
```bash
kindly-guard wrap -- <command>
```
Executes commands with KindlyGuard protection.

#### `install` - Install shell integration
```bash
kindly-guard install [--shell <bash|zsh|fish>]
```

### Shell Integration

- `scripts/shell-init.bash` - Bash integration
- `scripts/shell-init.zsh` - Zsh integration
- `scripts/shell-init.fish` - Fish integration

## kindly-guard-shield

Desktop UI application built with Tauri.

### Frontend (TypeScript/React)

- `src/main.ts` - Application entry
- `src/shield.ts` - Shield component logic
- `src/styles/` - CSS styles

### Backend (Rust)

#### `src-tauri/src/`

- **`main.rs`** - Tauri application entry
- **`lib.rs`** - Library interface
- **`config.rs`** - Configuration handling

#### Core Components

- **`core/`** - Core business logic
  - `standard.rs` - Standard event processor
  - `enhanced.rs` - Enhanced event processor

- **`websocket/`** - WebSocket communication
  - `standard.rs` - Basic WebSocket handler
  - `enhanced.rs` - Binary protocol handler

- **`security/`** - Security components
  - Pattern matching
  - Threat classification

### Binary Protocol

For enhanced mode, uses a binary protocol for efficiency:
- Message compression
- Shared memory communication
- Zero-copy serialization

## kindly-tools

Additional CLI tools for KindlyGuard ecosystem.

### Commands

- **`monitor`** - Advanced monitoring
- **`scan`** - Extended scanning capabilities
- **`shield`** - Shield control
- **`wrap`** - Command wrapping

### Features

- MCP environment detection
- Platform-specific optimizations
- Configuration management

## Feature Flags

### Standard Features (Default)

- Basic scanning capabilities
- Standard resilience patterns
- Memory storage
- Text-based protocols

### Enhanced Features

Enable with `--features enhanced`:
- Advanced ML-based detection
- Binary protocols
- Persistent storage
- Distributed tracing
- Advanced rate limiting

## Configuration Schema

### Scanner Configuration

```toml
[scanner]
unicode_detection = true
injection_detection = true
xss_detection = true
crypto_detection = true
max_scan_depth = 20
enhanced_mode = false
```

### Resilience Configuration

```toml
[resilience.circuit_breaker]
failure_threshold = 5
recovery_timeout = "30s"
half_open_max_requests = 3

[resilience.retry]
max_attempts = 3
initial_delay = "100ms"
max_delay = "10s"
jitter_factor = 0.1
```

### Telemetry Configuration

```toml
[telemetry]
enabled = true
export_interval = "10s"
max_batch_size = 1000
```

## Security Boundaries

### Input Validation

All external inputs pass through:
1. Size validation
2. Character encoding validation
3. Threat scanning
4. Rate limiting

### Memory Safety

- No `unsafe` blocks in public APIs
- All indexing operations checked
- Buffer sizes limited
- Stack depth controlled

### Cryptographic Security

- Constant-time comparisons for secrets
- Secure random number generation
- No weak algorithms allowed
- Key rotation support

## Performance Characteristics

### Scanner Performance

- O(n) complexity for text scanning
- SIMD optimizations for Unicode
- Parallel scanning for multiple files
- Memory usage: ~100MB baseline

### Latency Targets

- Text scanning: <10ms for 1KB
- JSON scanning: <50ms for 10KB
- Pattern matching: <5ms per pattern
- Circuit breaker: <1μs overhead

## Integration Points

### MCP Clients

- Claude Desktop
- VS Code MCP extension
- Custom MCP clients

### Monitoring

- Prometheus metrics endpoint
- OpenTelemetry traces
- Custom dashboards

### Deployment

- Docker containers
- Systemd services
- Kubernetes operators
- Binary distributions

## Debugging and Troubleshooting

### Logging

```bash
RUST_LOG=kindly_guard=debug cargo run
```

Levels:
- `error`: Critical errors only
- `warn`: Warnings and errors
- `info`: General information
- `debug`: Detailed debugging
- `trace`: Very verbose tracing

### Common Issues

1. **High memory usage**: Check max_scan_depth
2. **Slow scanning**: Enable parallel scanning
3. **Circuit breaker trips**: Adjust thresholds
4. **Rate limiting**: Check client identification

## Contributing

See CONTRIBUTING.md for:
- Code style guidelines
- Testing requirements
- PR process
- Security reporting