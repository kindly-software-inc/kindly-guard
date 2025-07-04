# KindlyGuard Configuration Guide

This guide provides comprehensive documentation for all configuration options available in KindlyGuard. Configuration can be provided via TOML files, YAML files, or environment variables.

## Table of Contents

1. [Configuration Overview](#configuration-overview)
2. [Configuration Sources](#configuration-sources)
3. [Server Configuration](#server-configuration)
4. [Scanner Configuration](#scanner-configuration)
5. [Authentication Configuration](#authentication-configuration)
6. [Rate Limiting Configuration](#rate-limiting-configuration)
7. [Neutralization Configuration](#neutralization-configuration)
8. [Audit Configuration](#audit-configuration)
9. [Shield Display Configuration](#shield-display-configuration)
10. [Resilience Configuration](#resilience-configuration)
11. [Storage Configuration](#storage-configuration)
12. [Signing Configuration](#signing-configuration)
13. [Telemetry Configuration](#telemetry-configuration)
14. [Transport Configuration](#transport-configuration)
15. [Plugin Configuration](#plugin-configuration)
16. [Environment Variables](#environment-variables)
17. [Example Configurations](#example-configurations)
18. [Configuration Validation](#configuration-validation)
19. [Hot Reloading](#hot-reloading)

## Configuration Overview

KindlyGuard uses a hierarchical configuration system with the following precedence:

1. **Environment Variables** (highest priority)
2. **Configuration File** (specified by `KINDLY_GUARD_CONFIG`)
3. **Default Configuration** (built-in secure defaults)

### Security Philosophy

All configuration defaults follow these principles:
- **Secure by Default**: Conservative settings that prioritize security
- **Defense in Depth**: Multiple security layers that can be configured independently
- **Least Privilege**: Features are disabled by default and must be explicitly enabled
- **Transparency**: Security implications of each setting are clearly documented

### Configuration File Formats

KindlyGuard supports both TOML and YAML configuration files:

```toml
# kindly-guard.toml
[server]
port = 8080
stdio = true

[scanner]
unicode_detection = true
```

```yaml
# kindly-guard.yaml
server:
  port: 8080
  stdio: true

scanner:
  unicode_detection: true
```

## Configuration Sources

### 1. Configuration File Location

The configuration file is loaded from (in order):
1. Path specified in `KINDLY_GUARD_CONFIG` environment variable
2. `kindly-guard.toml` in the current directory
3. Built-in defaults if no file is found

### 2. File Permissions

**Security Warning**: Configuration files should have restricted permissions:
- Linux/macOS: `600` or `640` (readable by owner/group only)
- Windows: Remove read permissions for other users

```bash
# Set secure permissions on Linux/macOS
chmod 600 kindly-guard.toml
```

### 3. Secrets Management

**Never store secrets directly in configuration files**. Use:
- Environment variables for sensitive values
- Secret management systems (HashiCorp Vault, AWS Secrets Manager)
- Encrypted configuration files with runtime decryption

## Server Configuration

Controls network exposure and connection handling.

```toml
[server]
# Port to listen on (for HTTP transport)
# Default: 8080
# Security: Use non-standard ports to reduce automated scanning
# Range: 1-65535 (ports < 1024 require root/admin privileges)
port = 8080

# Enable stdio transport (default for MCP)
# Default: true (secure by default)
# Security: stdio is the most secure transport (no network exposure)
stdio = true

# Maximum concurrent connections
# Default: 100
# Security: Lower values prevent resource exhaustion attacks
# Range: 1-10000 (recommend 10-500 for most deployments)
max_connections = 100

# Request timeout in seconds
# Default: 30
# Security: Shorter timeouts prevent slow loris attacks
# Range: 1-300 (recommend 10-60 for most use cases)
request_timeout_secs = 30
```

### Security Implications

| Setting | Security Impact | Recommendation |
|---------|----------------|----------------|
| `stdio = true` | No network exposure, most secure | Use for local integrations |
| `port` | Standard ports attract scanners | Use non-standard ports |
| `max_connections` | Lower = more DoS resistant | 10-500 for most deployments |
| `request_timeout_secs` | Shorter = less attack window | 10-60 seconds |

## Scanner Configuration

Configures threat detection capabilities.

```toml
[scanner]
# Enable unicode threat detection
# Default: true
# Security: Detects BiDi overrides, zero-width chars, homoglyphs
unicode_detection = true

# Enable injection detection
# Default: true
# Security: Detects SQL, NoSQL, command, and LDAP injection
injection_detection = true

# Enable path traversal detection
# Default: true
# Security: Prevents unauthorized file access
path_traversal_detection = true

# Enable XSS detection
# Default: true
# Security: Detects cross-site scripting attempts
xss_detection = true

# Enable cryptographic security detection
# Default: true
# Security: Detects weak crypto patterns (MD5, SHA1, DES)
crypto_detection = true

# Enable enhanced mode (if available)
# Default: false
# Security: Better detection at performance cost
enhanced_mode = false

# Custom threat patterns file
# Default: none
# Security: Add organization-specific patterns
custom_patterns = "/etc/kindly-guard/patterns.toml"

# Maximum scan depth for nested structures
# Default: 10
# Security: Prevents algorithmic complexity attacks
# Range: 1-100 (recommend 5-20)
max_scan_depth = 10

# Enable high-performance event buffer
# Default: false
# Security: Enables "purple shield" enhanced detection
enable_event_buffer = false

# Maximum content size to scan (bytes)
# Default: 5242880 (5MB)
# Security: Prevents DoS through large payloads
# Range: 1024-104857600 (1KB-100MB)
max_content_size = 5242880
```

### Custom Patterns Format

```toml
# custom-patterns.toml
[[patterns]]
name = "Internal API Keys"
pattern = "(?i)(api[_-]?key|apikey)\\s*[:=]\\s*['\"]?([a-zA-Z0-9]{32,})"
severity = "high"
description = "Detects exposed API keys"

[[patterns]]
name = "AWS Credentials"
pattern = "AKIA[0-9A-Z]{16}"
severity = "critical"
description = "AWS access key IDs"
```

## Authentication Configuration

OAuth 2.0 with Resource Indicators (RFC 8707) support.

```toml
[auth]
# Enable authentication
# Default: false (for easier testing)
# Security: MUST be true in production
enabled = true

# Token validation endpoint (for remote validation)
# Default: none
# Security: Use HTTPS endpoints only
validation_endpoint = "https://auth.example.com/oauth2/introspect"

# Trusted token issuers
# Default: [] (no issuers trusted)
# Security: Only accept tokens from these issuers
trusted_issuers = ["https://auth.example.com"]

# Token cache TTL in seconds
# Default: 300 (5 minutes)
# Security: Shorter TTLs reduce compromised token window
# Range: 60-3600 (recommend 300-900)
cache_ttl_seconds = 300

# Validate resource indicators (RFC 8707)
# Default: true
# Security: Prevents token reuse across services
validate_resource_indicators = true

# JWT signing secret (base64 encoded)
# Default: none
# Security: Use 256-bit (32 byte) secret minimum
# Generation: openssl rand -base64 32
jwt_secret = "YOUR-BASE64-ENCODED-256-BIT-SECRET"

# Require JWT signature verification
# Default: false
# Security: Essential for preventing token tampering
require_signature_verification = true

# Required scopes configuration
[auth.required_scopes]
# Default scopes for any operation
default = ["kindlyguard:access"]

# Tool-specific scope requirements
[auth.required_scopes.tools]
"security/scan" = ["security:read"]
"security/neutralize" = ["security:write", "security:admin"]

# Resource-specific scope requirements
[auth.required_scopes.resources]
"sensitive/*" = ["admin"]
```

### Security Best Practices

1. **Always enable in production**: `enabled = true`
2. **Use strong secrets**: At least 256 bits (32 bytes)
3. **Short cache TTLs**: 5-15 minutes maximum
4. **Validate resource indicators**: Prevents cross-service attacks
5. **Define granular scopes**: Implement least privilege

## Rate Limiting Configuration

Prevents abuse and DoS attacks.

```toml
[rate_limit]
# Enable rate limiting
# Default: false
# Security: MUST be true in production
enabled = true

# Default requests per minute
# Default: 60
# Security: Lower = more secure but less scalable
# Range: 10-600 (recommend 30-120)
default_rpm = 60

# Burst capacity (immediate tokens)
# Default: 10
# Security: Allows bursts while preventing abuse
# Range: 1-50 (should be < default_rpm/6)
burst_capacity = 10

# Cleanup interval for expired buckets (seconds)
# Default: 300
# Security: Regular cleanup prevents memory exhaustion
cleanup_interval_secs = 300

# Enable adaptive rate limiting
# Default: false
# Security: Auto-adjusts under attack conditions
adaptive = true

# Threat penalty multiplier
# Default: 0.5 (halve the limit)
# Security: Reduces limits for threat sources
# Range: 0.1-1.0
threat_penalty_multiplier = 0.5

# Method-specific limits
[rate_limit.method_limits]
"tools/list" = { rpm = 120, burst = 20 }      # Read operations
"tools/call" = { rpm = 30, burst = 5 }        # Execute operations
"security/neutralize" = { rpm = 10, burst = 2 } # Sensitive operations

# Client-specific limits
[rate_limit.client_limits]
"trusted-app" = { rpm = 300, burst = 50, priority = "high" }
"public-api" = { rpm = 30, burst = 5, priority = "low" }
```

### Priority Levels

- `low`: First to be rate limited under load
- `normal`: Standard rate limiting
- `high`: Protected from rate limiting
- `premium`: Highest priority, last to be limited

## Neutralization Configuration

Controls how detected threats are handled.

```toml
[neutralization]
# Neutralization mode
# Default: "report_only"
# Options: "report_only", "interactive", "automatic"
mode = "automatic"

# Backup original content
# Default: true
# Security: Enables recovery from false positives
backup_originals = true

# Audit all neutralization actions
# Default: true
# Security: Creates forensic trail
audit_all_actions = true

# Unicode-specific settings
[neutralization.unicode]
# BiDi character handling
# Default: "marker"
# Options: "remove", "marker", "escape"
bidi_replacement = "marker"

# Zero-width character action
# Default: "remove"
# Options: "remove", "escape"
zero_width_action = "remove"

# Homograph character action
# Default: "ascii"
# Options: "ascii", "warn", "block"
homograph_action = "ascii"

# Injection-specific settings
[neutralization.injection]
# SQL injection action
# Default: "parameterize"
# Options: "block", "escape", "parameterize"
sql_action = "parameterize"

# Command injection action
# Default: "escape"
# Options: "block", "escape", "sandbox"
command_action = "escape"

# Path traversal action
# Default: "normalize"
# Options: "block", "normalize"
path_action = "normalize"

# Prompt injection action
# Default: "wrap"
# Options: "block", "wrap", "sanitize"
prompt_action = "wrap"

# Recovery configuration
[neutralization.recovery]
enabled = true
max_retries = 3
backoff_ms = 100
```

### Neutralization Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `report_only` | Detect but don't modify | Testing, monitoring |
| `interactive` | Require user confirmation | Sensitive data |
| `automatic` | Immediate remediation | Production systems |

## Audit Configuration

Security event logging and compliance.

```toml
[audit]
# Enable audit logging
# Default: false
# Security: Required for compliance
enabled = true

# Audit backend type
# Default: "memory"
# Options: "memory", "file", "enhanced" (with feature), "custom"
backend = "file"

# Retention period in days
# Default: 90
# Compliance: Check regulatory requirements
# GDPR: 30-90 days, PCI DSS: 1 year minimum
retention_days = 365

# Maximum events to keep
# Default: 1000000
# Security: Prevents unbounded growth
max_events = 10000000

# Buffer size for batch operations
# Default: 1000
# Performance: Higher = better throughput
buffer_size = 1000

# File path (for file backend)
# Default: "./audit.log"
# Security: Use secure directory with proper permissions
file_path = "/var/log/kindly-guard/audit.log"

# Enable compression
# Default: false
# Trade-off: Saves space but uses more CPU
compress = true

# Enable encryption
# Default: false
# Security: Required for sensitive environments
encrypt = true

# Rotation settings (for file backend)
[audit.rotation]
# Maximum file size in MB
max_size_mb = 100

# Maximum number of files to keep
max_files = 10

# Rotation frequency
# Options: "daily", "hourly", "size"
frequency = "daily"
```

### Compliance Requirements

| Standard | Retention | Encryption | Requirements |
|----------|-----------|------------|--------------|
| GDPR | 30-90 days | Recommended | Data minimization |
| PCI DSS | 1 year | Required | Daily review |
| HIPAA | 6 years | Required | Access controls |
| SOC2 | 1 year | Recommended | Monitoring |

## Shield Display Configuration

Visual security status indicator.

```toml
[shield]
# Enable shield display
# Default: false
# Purpose: Visual security monitoring
enabled = true

# Update interval in milliseconds
# Default: 1000 (1 second)
# Range: 100-10000 (recommend 500-2000)
update_interval_ms = 1000

# Show detailed statistics
# Default: false
# Shows: Threat counts, types, neutralization stats
detailed_stats = true

# Enable color output
# Default: true
# Accessibility: Set false for screen readers
color = true
```

### Shield States

- 🟢 **Green**: Normal operation, no threats
- 🟣 **Purple**: Enhanced mode active (better detection)
- 🔴 **Red**: Active threat detected
- ⚫ **Gray**: Disabled or error state

## Resilience Configuration

Circuit breakers and retry logic for fault tolerance.

```toml
[resilience]
# Enable enhanced resilience mode
# Default: false
# Benefits: Optimized algorithms, predictive features
enhanced_mode = false

# Circuit breaker configuration
[resilience.circuit_breaker]
# Failures before opening circuit
# Default: 5
# Range: 1-20 (recommend 3-10)
failure_threshold = 5

# Time window for counting failures
# Default: "60s"
# Format: Duration string (e.g., "30s", "5m")
failure_window = "60s"

# Successes in half-open before closing
# Default: 3
# Range: 1-10
success_threshold = 3

# Recovery timeout before half-open
# Default: "30s"
# Trade-off: Longer = safer but slower recovery
recovery_timeout = "30s"

# Request timeout
# Default: "10s"
# Security: Prevents resource holding
request_timeout = "10s"

# Max requests in half-open state
# Default: 3
# Range: 1-10
half_open_max_requests = 3

# Retry configuration
[resilience.retry]
# Maximum retry attempts
# Default: 3
# Range: 1-10 (recommend 3-5)
max_attempts = 3

# Initial retry delay
# Default: "100ms"
# Pattern: Exponential backoff
initial_delay = "100ms"

# Maximum delay between retries
# Default: "10s"
# Prevents excessive delays
max_delay = "10s"

# Exponential backoff multiplier
# Default: 2.0
# Formula: delay = initial * (multiplier ^ attempt)
multiplier = 2.0

# Jitter factor (0.0 to 1.0)
# Default: 0.1
# Purpose: Prevents thundering herd
jitter_factor = 0.1

# Overall retry timeout
# Default: "60s"
# Limits total retry duration
timeout = "60s"

# Health check configuration
[resilience.health_check]
# Check interval
# Default: "30s"
interval = "30s"

# Check timeout
# Default: "5s"
timeout = "5s"

# Failures before unhealthy
# Default: 3
unhealthy_threshold = 3

# Successes before healthy
# Default: 2
healthy_threshold = 2

# Enable predictive monitoring (enhanced only)
# Default: false
predictive_monitoring = false

# Recovery configuration
[resilience.recovery]
# Enable cache-based recovery
# Default: true
cache_enabled = true

# Cache TTL
# Default: "300s" (5 minutes)
cache_ttl = "300s"

# Max recovery attempts
# Default: 3
max_attempts = 3

# Recovery timeout
# Default: "30s"
timeout = "30s"

# Enable predictive recovery (enhanced only)
# Default: false
predictive_recovery = false
```

## Storage Configuration

Persistence for security events and state.

```toml
[storage]
# Enable persistence
# Default: false
# Purpose: Survive restarts, forensics
enabled = true

# Storage type
# Default: "memory"
# Options: "memory", "sqlite", "redis" (enhanced), "s3" (enhanced)
storage_type = "sqlite"

# Data directory (file-based storage)
# Default: none
# Security: Ensure proper permissions
data_dir = "/var/lib/kindly-guard"

# Connection string (remote storage)
# Default: none
# Format: Database-specific
connection_string = "redis://localhost:6379/0"

# Retention period in days
# Default: 30
# Compliance: Check regulatory requirements
retention_days = 90

# Archive older than days
# Default: none
# Purpose: Long-term storage
archive_after_days = 30

# Maximum storage size in MB
# Default: 1024 (1GB)
# Prevents unbounded growth
max_storage_mb = 10240

# Enable compression
# Default: true
# Trade-off: Space vs CPU
compression = true

# Enable encryption at rest
# Default: false
# Security: Required for sensitive data
encryption_at_rest = true
```

## Signing Configuration

Message integrity and authenticity.

```toml
[signing]
# Enable message signing
# Default: false
# Security: Prevents tampering
enabled = true

# Signing algorithm
# Default: "hmac-sha256"
# Options: "hmac-sha256", "ed25519"
algorithm = "ed25519"

# HMAC secret (base64, for hmac-sha256)
# Minimum: 256 bits (32 bytes)
# Generation: openssl rand -base64 32
hmac_secret = "YOUR-BASE64-SECRET"

# Ed25519 private key (base64, for ed25519)
# Size: Exactly 32 bytes
# Generation: Use ed25519 key generation tool
ed25519_private_key = "YOUR-BASE64-PRIVATE-KEY"

# Require signatures on incoming messages
# Default: false
# Security: Enforce message authenticity
require_signatures = true

# Grace period for unsigned messages (seconds)
# Default: 86400 (24 hours)
# Purpose: Migration period
grace_period_seconds = 3600

# Include timestamp in signatures
# Default: true
# Security: Prevents replay attacks
include_timestamp = true

# Maximum clock skew (seconds)
# Default: 300 (5 minutes)
# Trade-off: Security vs clock sync issues
max_clock_skew_seconds = 300
```

## Telemetry Configuration

Observability and monitoring.

```toml
[telemetry]
# Enable telemetry
# Default: false
# Purpose: Performance monitoring, debugging
enabled = true

# Service name
# Default: "kindly-guard"
service_name = "kindly-guard-prod"

# Service version
# Default: Current version
service_version = "1.0.0"

# Export endpoint (OTLP)
# Default: none
# Example: "http://localhost:4318"
export_endpoint = "http://otel-collector:4318"

# Export interval (seconds)
# Default: 60
# Trade-off: Freshness vs overhead
export_interval_seconds = 60

# Enable tracing
# Default: true
# Purpose: Request flow tracking
tracing_enabled = true

# Enable metrics
# Default: true
# Purpose: Performance monitoring
metrics_enabled = true

# Sampling rate (0.0 to 1.0)
# Default: 0.1 (10%)
# Trade-off: Detail vs overhead
sampling_rate = 0.1
```

## Transport Configuration

Communication protocol settings.

```toml
[transport]
# Enable transport multiplexing
# Default: false
# Purpose: Support multiple transports
multiplexing = false

# Transport configurations
[[transport.transports]]
transport_type = "stdio"
enabled = true
config = {}

[[transport.transports]]
transport_type = "http"
enabled = false
config = { port = 8080, tls = true }

[[transport.transports]]
transport_type = "websocket"
enabled = false
config = { port = 8081, path = "/ws" }

# Timeout configuration
[transport.timeouts]
# Connection timeout (ms)
# Default: 5000
connect_ms = 5000

# Read timeout (ms)
# Default: 30000
read_ms = 30000

# Write timeout (ms)
# Default: 30000
write_ms = 30000

# Keep-alive interval (ms)
# Default: 60000
keepalive_ms = 60000

# Security configuration
[transport.security]
# Require TLS for network transports
# Default: true
# Security: Always use in production
require_tls = true

# Minimum TLS version
# Default: "1.2"
# Options: "1.2", "1.3"
min_tls_version = "1.3"

# Client authentication
[transport.security.client_auth]
# Require client certificates
# Default: false
required = true

# Trusted CA certificates
trusted_cas = ["/etc/kindly-guard/ca.crt"]

# Buffer configuration
[transport.buffers]
# Read buffer size (bytes)
# Default: 65536 (64KB)
read_buffer = 65536

# Write buffer size (bytes)
# Default: 65536 (64KB)
write_buffer = 65536
```

## Plugin Configuration

Extensibility through plugins.

```toml
[plugins]
# Enable plugin system
# Default: false
# Security: Only load trusted plugins
enabled = true

# Plugin directories
# Default: ["./plugins"]
# Security: Use secure directories
plugin_dirs = ["/etc/kindly-guard/plugins", "./plugins"]

# Auto-load plugins on startup
# Default: true
auto_load = true

# Plugin allowlist (empty = all allowed)
# Default: []
# Security: Explicitly allow plugins
allowlist = ["official-*", "company-scanner"]

# Plugin denylist
# Default: []
# Security: Block known bad plugins
denylist = ["deprecated-*"]

# Max plugin execution time (ms)
# Default: 5000
# Security: Prevent DoS
max_execution_time_ms = 5000

# Plugin isolation level
# Default: "standard"
# Options: "none", "standard", "strong"
isolation_level = "standard"
```

## Environment Variables

All configuration options can be overridden via environment variables:

```bash
# General pattern: KINDLY_GUARD_<SECTION>_<KEY>
export KINDLY_GUARD_SERVER_PORT=8443
export KINDLY_GUARD_AUTH_ENABLED=true
export KINDLY_GUARD_AUTH_JWT_SECRET="base64-secret"
export KINDLY_GUARD_SCANNER_ENHANCED_MODE=true

# Special variables
export KINDLY_GUARD_CONFIG="/etc/kindly-guard/config.toml"
export RUST_LOG="kindly_guard=debug"
```

### Environment Variable Mapping

| Config Path | Environment Variable |
|------------|---------------------|
| `server.port` | `KINDLY_GUARD_SERVER_PORT` |
| `auth.enabled` | `KINDLY_GUARD_AUTH_ENABLED` |
| `auth.jwt_secret` | `KINDLY_GUARD_AUTH_JWT_SECRET` |
| `scanner.enhanced_mode` | `KINDLY_GUARD_SCANNER_ENHANCED_MODE` |
| `rate_limit.default_rpm` | `KINDLY_GUARD_RATE_LIMIT_DEFAULT_RPM` |

## Example Configurations

### Minimal Secure Configuration

```toml
# Minimum configuration for production security
[auth]
enabled = true
jwt_secret = "YOUR-BASE64-SECRET-HERE"

[rate_limit]
enabled = true

[scanner]
# All scanners enabled by default

[neutralization]
mode = "automatic"
```

### Development Configuration

```toml
# Development-friendly configuration
[server]
port = 8080
stdio = true

[auth]
enabled = false  # Only for local development!

[rate_limit]
enabled = false  # Easier testing

[scanner]
# Keep all scanners enabled for testing

[neutralization]
mode = "report_only"  # See threats without modification

[shield]
enabled = true
detailed_stats = true

[telemetry]
enabled = true
sampling_rate = 1.0  # Sample everything in dev
```

### High-Security Production Configuration

```toml
# Maximum security configuration
[server]
port = 8443
stdio = false
max_connections = 100
request_timeout_secs = 10

[auth]
enabled = true
validation_endpoint = "https://auth.company.com/validate"
trusted_issuers = ["https://auth.company.com"]
cache_ttl_seconds = 300
validate_resource_indicators = true
jwt_secret = "YOUR-STRONG-BASE64-SECRET"
require_signature_verification = true

[auth.required_scopes]
default = ["kindlyguard:access"]

[rate_limit]
enabled = true
default_rpm = 30
burst_capacity = 5
adaptive = true
threat_penalty_multiplier = 0.2

[scanner]
unicode_detection = true
injection_detection = true
path_traversal_detection = true
xss_detection = true
crypto_detection = true
enhanced_mode = true
max_scan_depth = 20
enable_event_buffer = true
custom_patterns = "/etc/kindly-guard/patterns.toml"

[neutralization]
mode = "automatic"
backup_originals = true
audit_all_actions = true

[audit]
enabled = true
backend = "file"
retention_days = 365
file_path = "/var/log/kindly-guard/audit.log"
compress = true
encrypt = true

[signing]
enabled = true
algorithm = "ed25519"
ed25519_private_key = "YOUR-ED25519-KEY"
require_signatures = true
include_timestamp = true

[storage]
enabled = true
storage_type = "sqlite"
data_dir = "/var/lib/kindly-guard"
retention_days = 90
encryption_at_rest = true

[resilience]
enhanced_mode = true

[resilience.circuit_breaker]
failure_threshold = 3
recovery_timeout = "60s"

[transport.security]
require_tls = true
min_tls_version = "1.3"

[transport.security.client_auth]
required = true
```

### Cloud-Native Configuration

```toml
# Configuration for Kubernetes/cloud deployments
[server]
port = 8080  # Behind ingress
stdio = false
max_connections = 1000

[auth]
enabled = true
validation_endpoint = "http://auth-service.auth.svc.cluster.local/validate"
cache_ttl_seconds = 600

[storage]
enabled = true
storage_type = "redis"
connection_string = "redis://redis.storage.svc.cluster.local:6379"

[telemetry]
enabled = true
export_endpoint = "http://otel-collector.monitoring.svc.cluster.local:4318"
service_name = "kindly-guard"

[audit]
enabled = true
backend = "enhanced"  # Sends to central logging
```

## Configuration Validation

KindlyGuard validates configuration on startup:

```rust
// Automatic validation checks:
- Authentication enabled in production
- Strong JWT secrets (256+ bits)
- Rate limiting enabled
- All scanners properly configured
- Valid file paths and permissions
- Network settings within acceptable ranges
```

### Manual Validation

```bash
# Validate configuration without starting server
kindly-guard validate-config --config kindly-guard.toml

# Test configuration with dry-run
kindly-guard --config kindly-guard.toml --dry-run
```

## Hot Reloading

KindlyGuard supports hot configuration reloading for certain settings:

### Reloadable Settings

- ✅ Scanner settings (all)
- ✅ Rate limit settings (all)
- ✅ Shield display settings
- ✅ Audit settings (enabled/disabled)
- ✅ Plugin settings (enabled/disabled)
- ✅ Telemetry settings

### Non-Reloadable Settings

- ❌ Server port/transport settings
- ❌ Authentication core settings
- ❌ Storage backend type
- ❌ Signing keys

### Triggering Reload

```bash
# Send SIGHUP to reload configuration
kill -HUP <kindly-guard-pid>

# Or use the CLI
kindly-guard reload-config
```

### Reload Events

Configuration changes are logged to the audit system:

```json
{
  "event_type": "config_changed",
  "severity": "info",
  "changed_fields": ["scanner.enhanced_mode", "rate_limit.default_rpm"],
  "changed_by": "hot-reload",
  "timestamp": "2025-01-10T12:00:00Z"
}
```

## Security Best Practices

1. **File Permissions**: Always use restrictive permissions (600/640)
2. **Secrets Management**: Never commit secrets to version control
3. **Environment Separation**: Use different configs for dev/staging/prod
4. **Regular Reviews**: Audit configuration quarterly
5. **Change Control**: Track all configuration changes
6. **Validation**: Always validate before deploying
7. **Monitoring**: Set up alerts for configuration changes

## Troubleshooting

### Common Issues

**Issue**: "JWT secret too short"
- **Solution**: Use at least 32 bytes: `openssl rand -base64 32`

**Issue**: "Configuration file not found"
- **Solution**: Check `KINDLY_GUARD_CONFIG` or place in current directory

**Issue**: "Permission denied reading config"
- **Solution**: Check file permissions and user running KindlyGuard

**Issue**: "Invalid TOML/YAML syntax"
- **Solution**: Validate with online TOML/YAML validators

**Issue**: "Hot reload not working"
- **Solution**: Check if setting is reloadable, check audit logs

### Debug Logging

Enable detailed configuration logging:

```bash
export RUST_LOG="kindly_guard::config=debug"
```

## Need Help?

- Configuration examples: [/examples/configs/](../examples/configs/)
- Security guide: [SECURITY_CONFIG_GUIDE.md](../kindly-guard-server/src/config/SECURITY_CONFIG_GUIDE.md)
- API documentation: [API_DOCUMENTATION.md](API_DOCUMENTATION.md)
- Community forum: [https://github.com/kindly-software/kindly-guard/discussions](https://github.com/kindly-software/kindly-guard/discussions)