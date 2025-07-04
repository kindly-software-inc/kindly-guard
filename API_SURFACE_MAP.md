# KindlyGuard API Surface Map

This document provides a comprehensive reference of all public APIs exposed by KindlyGuard, including MCP protocol methods, CLI commands, HTTP endpoints, and configuration options.

## Table of Contents

1. [MCP Protocol API](#mcp-protocol-api)
2. [MCP Tools](#mcp-tools)
3. [CLI Commands](#cli-commands)
4. [HTTP/WebSocket Endpoints](#httpwebsocket-endpoints)
5. [Public Traits](#public-traits)
6. [Configuration](#configuration)
7. [Security Events](#security-events)

## MCP Protocol API

KindlyGuard implements the Model Context Protocol (MCP) v2024-11-05 with security-focused extensions.

### Core MCP Methods

#### `initialize`
Initializes the MCP connection and returns server capabilities.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": {
      "roots": { "listChanged": true },
      "sampling": {}
    },
    "clientInfo": {
      "name": "example-client",
      "version": "1.0.0"
    }
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "2024-11-05",
    "capabilities": {
      "tools": {},
      "resources": {},
      "prompts": {},
      "logging": {}
    },
    "serverInfo": {
      "name": "kindly-guard",
      "version": "0.1.0"
    }
  }
}
```

#### `initialized`
Signals that the client has finished initialization.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "initialized",
  "params": {}
}
```

#### `shutdown`
Gracefully shuts down the server.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "shutdown",
  "params": {}
}
```

### Tools API

#### `tools/list`
Lists all available security tools.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "tools/list",
  "params": {}
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "result": {
    "tools": [
      {
        "name": "scan_text",
        "description": "Scan text for security threats including unicode attacks and injection attempts",
        "inputSchema": {
          "type": "object",
          "properties": {
            "text": {
              "type": "string",
              "description": "Text to scan for threats"
            }
          },
          "required": ["text"]
        }
      }
    ]
  }
}
```

#### `tools/call`
Executes a security tool.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "tools/call",
  "params": {
    "name": "scan_text",
    "arguments": {
      "text": "Hello\u202EWorld"
    }
  }
}
```

### Resources API

#### `resources/list`
Lists available security resources.

**Response includes:**
- `threat-patterns://default` - Built-in threat detection patterns
- `security-report://latest` - Current security status and recent threats
- `config://security` - Security configuration and settings
- `threat-db://current` - Current threat database and patterns

#### `resources/read`
Reads a specific security resource.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "method": "resources/read",
  "params": {
    "uri": "security-report://latest"
  }
}
```

### Custom Security Methods

#### `security/status`
Returns current security system status.

#### `security/threats`
Returns recent threat information.

#### `security/rate_limit_status`
Returns rate limiting status for the client.

## MCP Tools

### `scan_text`
Scans text for security threats.

**Input:**
```json
{
  "text": "SELECT * FROM users WHERE id = '1' OR '1'='1'"
}
```

**Output:**
```json
{
  "content": [{
    "type": "text",
    "text": "[{\"threat_type\":\"sql_injection\",\"severity\":\"high\",\"description\":\"SQL injection attempt detected\"}]"
  }]
}
```

### `scan_file`
Scans a file for security threats.

**Input:**
```json
{
  "path": "/path/to/file.txt"
}
```

### `scan_json`
Scans JSON data for threats in all string values.

**Input:**
```json
{
  "data": {
    "user": "admin",
    "query": "'; DROP TABLE users; --"
  }
}
```

### `get_security_info`
Returns comprehensive security statistics.

**Output includes:**
- Scanner statistics (threats detected by type)
- Shield information (active status, uptime, threats blocked)
- Rate limit statistics
- Authentication statistics
- Permission check statistics

### `verify_signature`
Verifies message signatures for integrity.

**Input:**
```json
{
  "message": "{\"data\":\"example\"}",
  "signature": "base64-encoded-signature"
}
```

### `get_shield_status`
Returns current shield protection status.

**Output:**
```json
{
  "content": [{
    "type": "text",
    "text": "{\"active\":true,\"protection_level\":\"high\",\"threats_blocked\":42,\"uptime_seconds\":3600}"
  }]
}
```

## CLI Commands

KindlyGuard provides a comprehensive CLI interface via the `/kindlyguard` command.

### Main Binary Options

```bash
# Run as MCP server (default stdio mode)
kindly-guard [--stdio]

# Run as HTTP API server
kindly-guard --http --bind 127.0.0.1:8080

# Run as HTTPS proxy
kindly-guard --proxy --bind 127.0.0.1:8443

# Run as daemon
kindly-guard --daemon [--pid-file /var/run/kindly-guard.pid]

# Enable shield display
kindly-guard --shield

# Specify config file
kindly-guard --config /etc/kindly-guard/config.toml
```

### Command Interface

```bash
# Show security status
/kindlyguard status [--format json|text|minimal] [--no-color]

# Scan for threats
/kindlyguard scan <FILE_OR_TEXT> [--text] [--format json]

# Example: Scan text directly
/kindlyguard scan "SELECT * FROM users" --text

# Example: Scan a file
/kindlyguard scan /path/to/file.txt

# Show telemetry
/kindlyguard telemetry [--detailed]

# Manage advanced security features
/kindlyguard advancedsecurity status
/kindlyguard advancedsecurity enable
/kindlyguard advancedsecurity disable

# Show feature information
/kindlyguard info [unicode|injection|path|advanced]

# Start web dashboard
/kindlyguard dashboard [--port 3000]
```

### Output Formats

- **text** (default) - Human-readable colored output
- **json** - Machine-readable JSON format
- **minimal** - Minimal output for scripts
- **dashboard** - Interactive dashboard mode

## HTTP/WebSocket Endpoints

### HTTP API (when running with `--http`)

#### `POST /rpc`
JSON-RPC endpoint for MCP protocol messages.

**Request:**
```http
POST /rpc HTTP/1.1
Content-Type: application/json

{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/list",
  "params": {}
}
```

### Web Dashboard API

#### `GET /`
Serves the web dashboard HTML interface.

#### `GET /api/status`
Returns current security status as JSON.

**Response:**
```json
{
  "shield_active": true,
  "protection_mode": "enhanced",
  "threats_blocked": 156,
  "current_threat_level": "low",
  "recent_threats": []
}
```

#### `POST /api/shield/toggle`
Toggles shield active state.

#### `POST /api/mode/toggle`
Toggles between standard and enhanced protection modes.

## Public Traits

KindlyGuard exposes several trait-based APIs for extensibility and customization.

### Core Security Traits

#### `SecurityScannerTrait`
```rust
pub trait SecurityScannerTrait: Send + Sync {
    fn scan_text(&self, text: &str) -> Vec<Threat>;
    fn scan_json(&self, value: &serde_json::Value) -> Vec<Threat>;
    fn scan_with_depth(&self, text: &str, max_depth: usize) -> Vec<Threat>;
    fn get_stats(&self) -> ScannerStats;
    fn reset_stats(&self);
}
```

#### `SecurityEventProcessor`
```rust
pub trait SecurityEventProcessor: Send + Sync {
    async fn process_event(&self, event: SecurityEvent) -> Result<EventHandle>;
    fn get_stats(&self) -> ProcessorStats;
    fn is_monitored(&self, endpoint: &str) -> bool;
    async fn get_insights(&self, client_id: &str) -> Result<SecurityInsights>;
    async fn cleanup(&self) -> Result<()>;
}
```

### Resilience Traits

#### `CircuitBreakerTrait`
```rust
pub trait CircuitBreakerTrait: Send + Sync {
    async fn call<F, T, Fut>(&self, name: &str, f: F) -> Result<T, CircuitBreakerError>
    where 
        F: FnOnce() -> Fut + Send,
        Fut: Future<Output = Result<T>> + Send,
        T: Send;
    
    fn state(&self, name: &str) -> CircuitState;
    fn stats(&self, name: &str) -> CircuitStats;
    async fn trip(&self, name: &str, reason: &str);
    async fn reset(&self, name: &str);
}
```

#### `RetryStrategyTrait`
```rust
pub trait RetryStrategyTrait: Send + Sync {
    async fn execute<F, T, Fut>(&self, operation: &str, f: F) -> Result<T>
    where
        F: Fn() -> Fut + Send + Sync,
        Fut: Future<Output = Result<T>> + Send,
        T: Send;
    
    fn should_retry(&self, error: &anyhow::Error, context: &RetryContext) -> RetryDecision;
    fn stats(&self) -> RetryStats;
}
```

### Metrics Traits

#### `MetricsProvider`
```rust
pub trait MetricsProvider: Send + Sync {
    fn counter(&self, name: &str, help: &str) -> Arc<dyn CounterTrait>;
    fn gauge(&self, name: &str, help: &str) -> Arc<dyn GaugeTrait>;
    fn histogram(&self, name: &str, help: &str, buckets: Vec<f64>) -> Arc<dyn HistogramTrait>;
    fn export_prometheus(&self) -> String;
    fn export_json(&self) -> serde_json::Value;
    fn uptime_seconds(&self) -> u64;
}
```

## Configuration

KindlyGuard uses TOML configuration with environment variable overrides.

### Configuration Hierarchy

1. Environment: `KINDLY_GUARD_CONFIG=/path/to/config.toml`
2. Default: `./kindly-guard.toml`
3. Built-in secure defaults

### Core Configuration Sections

#### Server Configuration
```toml
[server]
port = 8080                    # HTTP/proxy port
stdio = true                   # Enable stdio mode (default)
max_connections = 100          # Connection limit
request_timeout_secs = 30      # Request timeout
```

#### Scanner Configuration
```toml
[scanner]
unicode_detection = true       # Detect unicode attacks
injection_detection = true     # Detect injection attempts
path_traversal_detection = true # Detect path traversal
xss_detection = true          # Detect XSS attempts
enhanced_mode = false         # Enable enhanced detection (if available)
max_scan_depth = 10           # Maximum nesting depth
enable_event_buffer = false   # Enable event correlation
max_content_size = 5242880    # 5MB max content size
custom_patterns = "/etc/kindly-guard/patterns.toml"
```

#### Authentication Configuration
```toml
[auth]
enabled = false               # Enable authentication
validation_endpoint = "https://auth.example.com/oauth2/introspect"
trusted_issuers = ["https://auth.example.com"]
cache_ttl_seconds = 300
jwt_secret = "base64-encoded-secret"  # For JWT validation
require_signature_verification = true

[auth.required_scopes]
default = ["kindlyguard:access"]

[auth.required_scopes.tools]
"scan" = ["security:read"]
"neutralize" = ["security:write"]
```

#### Rate Limiting Configuration
```toml
[rate_limit]
enabled = true
default_rpm = 60              # Requests per minute
burst_capacity = 10           # Burst allowance
cleanup_interval_secs = 300
adaptive = true               # Adaptive rate limiting
threat_penalty_multiplier = 0.5

[rate_limit.method_limits]
"tools/list" = { rpm = 120, burst = 20 }
"tools/call" = { rpm = 30, burst = 5 }
```

#### Shield Display Configuration
```toml
[shield]
enabled = false               # Enable visual shield
update_interval_ms = 1000     # Update frequency
detailed_stats = false        # Show detailed stats
color = true                  # Enable color output
```

#### Neutralization Configuration
```toml
[neutralization]
mode = "monitor"              # monitor|automatic|manual
backup_originals = true       # Keep original content
audit_all_actions = true      # Log all neutralizations

[neutralization.unicode]
bidi_replacement = "marker"   # marker|remove|escape
zero_width_action = "remove"  # remove|escape|marker
homograph_action = "ascii"    # ascii|punycode|marker

[neutralization.injection]
sql_action = "parameterize"   # parameterize|escape|reject
command_action = "escape"     # escape|reject|sanitize
path_action = "normalize"     # normalize|reject|sanitize
```

### Enhanced vs Standard Mode

KindlyGuard supports two operational modes:

**Standard Mode** (default):
- Open-source threat detection
- Basic pattern matching
- Standard performance

**Enhanced Mode** (when available):
- Advanced pattern correlation
- ML-based threat detection
- Event correlation engine
- "Purple shield" visual indicator
- ~10-20% performance overhead

Enable enhanced mode:
```toml
[scanner]
enhanced_mode = true
enable_event_buffer = true

[event_processor]
enabled = true
```

## Security Events

KindlyGuard tracks various security events that can be monitored:

### Event Types

- **auth.success** - Successful authentication
- **auth.failure** - Failed authentication attempt
- **rate_limit.allowed** - Request allowed by rate limiter
- **rate_limit.exceeded** - Rate limit exceeded
- **threat.detected** - Security threat detected
- **threat.neutralized** - Threat successfully neutralized
- **scan.completed** - Security scan completed
- **circuit.open** - Circuit breaker opened
- **circuit.closed** - Circuit breaker closed

### Event Format

```json
{
  "event_type": "threat.detected",
  "client_id": "example-client",
  "timestamp": 1234567890,
  "metadata": {
    "threat_type": "sql_injection",
    "severity": "high",
    "location": "request.params.query"
  }
}
```

## API Stability

### Stable APIs ✅
- MCP protocol core methods
- CLI commands and arguments
- Configuration file format
- Core security traits
- Standard mode features

### Experimental APIs ⚠️
- Enhanced mode features
- Event correlation API
- Plugin system
- Custom pattern language
- WebSocket transport

### Deprecated APIs ❌
None currently.

## Examples

### Complete MCP Session Example

```python
import json
import subprocess

# Start KindlyGuard server
server = subprocess.Popen(
    ["kindly-guard", "--stdio"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    text=True
)

# Initialize connection
request = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "example", "version": "1.0"}
    }
}
server.stdin.write(json.dumps(request) + "\n")
server.stdin.flush()

# Scan text for threats
request = {
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
        "name": "scan_text",
        "arguments": {
            "text": "SELECT * FROM users WHERE id = '1' OR '1'='1'"
        }
    }
}
server.stdin.write(json.dumps(request) + "\n")
server.stdin.flush()
```

### HTTP API Example

```bash
# Start HTTP server
kindly-guard --http --bind 127.0.0.1:8080 &

# Call MCP method via HTTP
curl -X POST http://localhost:8080/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/list",
    "params": {}
  }'

# Get dashboard status
curl http://localhost:8080/api/status
```

### Configuration Example

```toml
# /etc/kindly-guard/production.toml

[server]
stdio = false
max_connections = 1000
request_timeout_secs = 30

[auth]
enabled = true
jwt_secret = "YOUR-BASE64-SECRET-HERE"
validation_endpoint = "https://auth.company.com/validate"

[scanner]
unicode_detection = true
injection_detection = true
path_traversal_detection = true
xss_detection = true
enhanced_mode = true
max_scan_depth = 20

[rate_limit]
enabled = true
default_rpm = 100
adaptive = true

[shield]
enabled = true
detailed_stats = true
```

## Version History

- **0.1.0** - Initial release with core MCP support
- **0.2.0** - Added enhanced mode and event correlation
- **0.3.0** - Added neutralization capabilities
- **0.4.0** - Added resilience features (circuit breaker, retry)
- **0.5.0** - Current version with full API surface

## Security Considerations

1. **Authentication**: Always enable in production
2. **Rate Limiting**: Essential for DoS protection
3. **TLS**: Use HTTPS/WSS for network transports
4. **Secrets**: Never commit secrets to config files
5. **Permissions**: Restrict config file access (chmod 600)
6. **Monitoring**: Enable audit logging and telemetry
7. **Updates**: Keep KindlyGuard updated for latest security patches

For security issues, contact: security@kindlyguard.dev