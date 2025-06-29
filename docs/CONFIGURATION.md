# KindlyGuard Configuration Guide

This guide covers all configuration options for KindlyGuard, including standard and enhanced modes.

## Table of Contents

- [Configuration File](#configuration-file)
- [Scanner Settings](#scanner-settings)
- [Shield Display](#shield-display)
- [Authentication](#authentication)
- [Rate Limiting](#rate-limiting)
- [Message Signing](#message-signing)
- [Event Processor (Enhanced Mode)](#event-processor-enhanced-mode)
- [Tool Permissions](#tool-permissions)
- [Logging](#logging)
- [Environment Variables](#environment-variables)
- [Configuration Examples](#configuration-examples)

## Configuration File

KindlyGuard looks for configuration in these locations (in order):

1. Path specified by `KINDLY_GUARD_CONFIG` environment variable
2. `./kindly-guard.yaml` (current directory)
3. `~/.config/kindly-guard/config.yaml` (user config)
4. `/etc/kindly-guard/config.yaml` (system config)

### Minimal Configuration

```yaml
# Minimal working configuration
scanner:
  unicode_detection: true
  injection_detection: true

auth:
  enabled: false  # Disable for testing only!
```

### Full Configuration Template

```yaml
# Complete configuration with all options
scanner:
  unicode_detection: true
  injection_detection: true
  max_scan_depth: 10
  enable_event_buffer: false
  custom_patterns: null

shield:
  display_enabled: true
  update_interval_ms: 1000
  show_timestamp: true
  show_stats: true
  color_mode: "auto"  # auto, always, never

auth:
  enabled: true
  token_lifetime_secs: 3600
  refresh_token_lifetime_secs: 86400
  require_resource_indicators: true
  allowed_resources:
    - "kindlyguard:v0.1.0"
  allowed_clients: []

rate_limit:
  enabled: true
  default_rpm: 60
  default_burst: 10
  cleanup_interval_secs: 300
  per_method_limits: {}
  per_client_limits: {}
  threat_penalty_multiplier: 2.0

signing:
  enabled: false
  algorithm: "Ed25519"
  private_key_path: null
  public_key_path: null
  require_signed_requests: false
  timestamp_tolerance_secs: 300

event_processor:
  enabled: false
  buffer_size_mb: 10
  endpoint_limit: 1000
  event_rate_limit: 10000.0
  circuit_breaker_threshold: 5
  pattern_detection: true
  correlation_window_secs: 300

permissions:
  default_permissions:
    allowed_tools: []
    denied_tools: []
    max_threat_level: "medium"
    require_signing: false
  tool_definitions: {}
  global_deny_list: []

log_level: "info"
log_format: "pretty"  # pretty, json, compact
```

## Scanner Settings

The scanner detects security threats in text and JSON content.

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `unicode_detection` | bool | `true` | Detect unicode-based attacks |
| `injection_detection` | bool | `true` | Detect injection attempts |
| `max_scan_depth` | int | `10` | Maximum JSON nesting depth |
| `enable_event_buffer` | bool | `false` | Enable enhanced scanning (purple shield) |
| `custom_patterns` | string | `null` | Path to custom threat patterns file |

### Custom Patterns File

Create custom threat patterns in YAML:

```yaml
# custom_patterns.yaml
patterns:
  - name: "api_key_exposure"
    regex: "api[_-]?key\\s*[:=]\\s*['\"]?[a-zA-Z0-9]{32,}"
    severity: "high"
    description: "Potential API key exposure"
    
  - name: "base64_executable"
    regex: "data:application/x-executable;base64"
    severity: "critical"
    description: "Base64 encoded executable"
```

### Performance Tuning

```yaml
scanner:
  # For high-throughput environments
  enable_event_buffer: true  # Enables purple shield mode
  max_scan_depth: 5         # Reduce for faster scanning
```

## Shield Display

Visual security indicator configuration.

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `display_enabled` | bool | `true` | Show shield in terminal |
| `update_interval_ms` | int | `1000` | Update frequency |
| `show_timestamp` | bool | `true` | Display timestamp |
| `show_stats` | bool | `true` | Show threat statistics |
| `color_mode` | string | `"auto"` | Color output mode |

### Color Modes

- `"auto"` - Detect terminal capability
- `"always"` - Force color output
- `"never"` - Disable colors

### Shield States

- 🟢 Green - Standard mode, active protection
- 🟣 Purple - Enhanced mode with AtomicEventBuffer
- 🔴 Red - Threat detected
- ⚫ Gray - Inactive/disabled

## Authentication

OAuth 2.0 implementation with Resource Indicators (RFC 8707).

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `true` | Enable authentication |
| `token_lifetime_secs` | int | `3600` | Access token lifetime |
| `refresh_token_lifetime_secs` | int | `86400` | Refresh token lifetime |
| `require_resource_indicators` | bool | `true` | Require resource parameter |
| `allowed_resources` | array | `[]` | Allowed resource indicators |
| `allowed_clients` | array | `[]` | Client configurations |

### Client Configuration

```yaml
auth:
  enabled: true
  allowed_clients:
    - client_id: "production-app"
      secret: "$2b$10$..."  # bcrypt hashed secret
      allowed_scopes:
        - "tools:execute"
        - "resources:read"
      rate_limit_override: 120  # Custom rate limit
      require_signing: true     # Require signed requests
      
    - client_id: "monitoring-app"
      secret: "$2b$10$..."
      allowed_scopes:
        - "resources:read"
        - "security:status"
      read_only: true  # No write operations
```

### Generating Client Secrets

```bash
# Generate bcrypt hash for client secret
htpasswd -bnBC 10 "" "your-secret-here" | tr -d ':\n' | sed 's/$2y/$2b/'
```

### Scope Definitions

- `tools:execute` - Execute security tools
- `resources:read` - Read resources
- `admin:write` - Administrative operations
- `security:scan` - Perform scans
- `security:verify` - Verify signatures
- `security:status` - Read security status
- `info:read` - Read information

## Rate Limiting

Protect against abuse with configurable rate limits.

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `true` | Enable rate limiting |
| `default_rpm` | int | `60` | Default requests per minute |
| `default_burst` | int | `10` | Burst capacity |
| `cleanup_interval_secs` | int | `300` | Cleanup interval |
| `per_method_limits` | map | `{}` | Method-specific limits |
| `per_client_limits` | map | `{}` | Client-specific limits |
| `threat_penalty_multiplier` | float | `2.0` | Penalty for threats |

### Method-Specific Limits

```yaml
rate_limit:
  enabled: true
  default_rpm: 60
  per_method_limits:
    "tools/call": 30        # Limit tool execution
    "resources/read": 120   # Allow more reads
    "admin/*": 10          # Strict admin limits
```

### Client-Specific Limits

```yaml
rate_limit:
  per_client_limits:
    "high-volume-app": 300
    "internal-monitor": 600
    "untrusted-app": 20
```

### Threat Penalties

When threats are detected, rate limits are reduced:

```yaml
rate_limit:
  threat_penalty_multiplier: 2.0  # Halve the rate limit
  # After threat: 60 RPM → 30 RPM
```

## Message Signing

Cryptographic message authentication using Ed25519.

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable message signing |
| `algorithm` | string | `"Ed25519"` | Signature algorithm |
| `private_key_path` | string | `null` | Path to private key |
| `public_key_path` | string | `null` | Path to public key |
| `require_signed_requests` | bool | `false` | Require client signatures |
| `timestamp_tolerance_secs` | int | `300` | Timestamp tolerance |

### Generating Keys

```bash
# Generate Ed25519 keypair
openssl genpkey -algorithm ed25519 -out private_key.pem
openssl pkey -in private_key.pem -pubout -out public_key.pem
```

### Configuration Example

```yaml
signing:
  enabled: true
  private_key_path: "/etc/kindly-guard/keys/private_key.pem"
  public_key_path: "/etc/kindly-guard/keys/public_key.pem"
  require_signed_requests: true
  timestamp_tolerance_secs: 60  # Strict timing
```

## Event Processor (Enhanced Mode)

Enable advanced threat detection with AtomicEventBuffer.

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable enhanced mode |
| `buffer_size_mb` | int | `10` | Event buffer size |
| `endpoint_limit` | int | `1000` | Max tracked endpoints |
| `event_rate_limit` | float | `10000.0` | Events per second |
| `circuit_breaker_threshold` | int | `5` | Failure threshold |
| `pattern_detection` | bool | `true` | Detect attack patterns |
| `correlation_window_secs` | int | `300` | Event correlation window |

### Enabling Enhanced Mode

```yaml
event_processor:
  enabled: true  # Activates purple shield
  buffer_size_mb: 50  # More buffer for high traffic
  pattern_detection: true
  correlation_window_secs: 600  # 10-minute correlation
```

### Performance Impact

Enhanced mode provides:
- 🟣 Purple shield indicator
- Advanced pattern detection
- Event correlation
- Circuit breaker protection
- ~10-15% CPU overhead

## Tool Permissions

Fine-grained access control for MCP tools.

### Permission Structure

```yaml
permissions:
  default_permissions:
    allowed_tools: []  # Empty = all allowed
    denied_tools: ["admin_shell", "file_write"]
    max_threat_level: "medium"
    require_signing: false
    
  tool_definitions:
    scan_text:
      category: "security"
      required_scopes: ["security:scan"]
      min_threat_level: "safe"
      require_signing: false
      
    update_config:
      category: "administrative"
      required_scopes: ["admin:write"]
      min_threat_level: "safe"
      require_signing: true
      
  global_deny_list:
    - "dangerous_tool"
    - "legacy_endpoint"
    
  per_client_permissions:
    "untrusted-app":
      allowed_tools: ["scan_text", "get_info"]
      denied_tools: []
      max_threat_level: "low"
```

### Threat Levels

1. `safe` - No threats detected
2. `low` - Minor threats
3. `medium` - Moderate threats  
4. `high` - Serious threats
5. `critical` - Severe threats

## Logging

Configure logging output and verbosity.

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `log_level` | string | `"info"` | Logging verbosity |
| `log_format` | string | `"pretty"` | Output format |

### Log Levels

- `trace` - Very verbose debugging
- `debug` - Debugging information
- `info` - General information
- `warn` - Warning messages
- `error` - Error messages only

### Log Formats

- `pretty` - Human-readable with colors
- `json` - Structured JSON logs
- `compact` - Minimal output

### Example Configurations

Development:
```yaml
log_level: "debug"
log_format: "pretty"
```

Production:
```yaml
log_level: "info"
log_format: "json"
```

## Environment Variables

Override configuration with environment variables:

| Variable | Description | Example |
|----------|-------------|---------|
| `KINDLY_GUARD_CONFIG` | Config file path | `/etc/kg/config.yaml` |
| `RUST_LOG` | Rust log configuration | `kindly_guard=debug` |
| `KINDLY_GUARD_AUTH_ENABLED` | Enable/disable auth | `false` |
| `KINDLY_GUARD_RATE_LIMIT_RPM` | Default rate limit | `120` |
| `KINDLY_GUARD_SHIELD_ENABLED` | Enable/disable shield | `true` |
| `KINDLY_GUARD_LOG_FORMAT` | Log format | `json` |

### Precedence

1. Command-line arguments (highest)
2. Environment variables
3. Configuration file
4. Default values (lowest)

## Configuration Examples

### Development Setup

```yaml
# config.dev.yaml
scanner:
  unicode_detection: true
  injection_detection: true
  
auth:
  enabled: false  # Disable for local dev
  
rate_limit:
  enabled: false  # No limits for testing
  
shield:
  display_enabled: true
  update_interval_ms: 500  # Faster updates
  
log_level: "debug"
log_format: "pretty"
```

### Production Setup

```yaml
# config.prod.yaml
scanner:
  unicode_detection: true
  injection_detection: true
  enable_event_buffer: true  # Enhanced mode
  
auth:
  enabled: true
  require_resource_indicators: true
  allowed_clients:
    - client_id: "production-app"
      secret: "$2b$10$..."
      allowed_scopes: ["tools:execute", "resources:read"]
      
rate_limit:
  enabled: true
  default_rpm: 60
  threat_penalty_multiplier: 3.0  # Strict penalties
  
signing:
  enabled: true
  require_signed_requests: true
  
event_processor:
  enabled: true
  pattern_detection: true
  
log_level: "info"
log_format: "json"
```

### High-Security Setup

```yaml
# config.secure.yaml
scanner:
  unicode_detection: true
  injection_detection: true
  enable_event_buffer: true
  max_scan_depth: 5  # Limit complexity
  
auth:
  enabled: true
  token_lifetime_secs: 900  # 15 minutes
  require_resource_indicators: true
  
rate_limit:
  enabled: true
  default_rpm: 30  # Conservative limit
  default_burst: 5
  threat_penalty_multiplier: 5.0  # Heavy penalties
  
signing:
  enabled: true
  require_signed_requests: true
  timestamp_tolerance_secs: 60  # Strict timing
  
permissions:
  default_permissions:
    denied_tools: ["*"]  # Deny all by default
    max_threat_level: "low"
    require_signing: true
    
event_processor:
  enabled: true
  circuit_breaker_threshold: 3  # Quick protection
  
log_level: "info"
log_format: "json"
```

### Monitoring Setup

```yaml
# config.monitor.yaml
scanner:
  unicode_detection: true
  injection_detection: true
  
auth:
  enabled: true
  allowed_clients:
    - client_id: "prometheus-exporter"
      secret: "$2b$10$..."
      allowed_scopes: ["resources:read", "security:status"]
      read_only: true
      
rate_limit:
  enabled: true
  per_client_limits:
    "prometheus-exporter": 600  # 10 req/sec for metrics
    
shield:
  display_enabled: false  # No UI for monitoring
  
log_level: "warn"  # Only problems
log_format: "json"
```

## Validation

Validate configuration before deployment:

```bash
# Validate configuration file
kindly-guard validate-config --config /path/to/config.yaml

# Test configuration loading
kindly-guard --config /path/to/config.yaml --dry-run
```

## Best Practices

1. **Start with defaults** - Modify only what you need
2. **Use environment variables** - For secrets and deployment-specific values
3. **Separate environments** - Different configs for dev/staging/prod
4. **Monitor logs** - Watch for configuration warnings
5. **Test changes** - Validate before deploying
6. **Document changes** - Keep configuration changelog
7. **Secure secrets** - Use proper secret management
8. **Regular reviews** - Audit configuration quarterly