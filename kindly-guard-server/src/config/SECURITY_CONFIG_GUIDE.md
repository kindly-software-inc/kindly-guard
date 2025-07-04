# KindlyGuard Security Configuration Guide

This guide provides a comprehensive overview of all security-related configuration options in KindlyGuard, their implications, and best practices.

## Table of Contents

1. [Security Philosophy](#security-philosophy)
2. [Configuration Overview](#configuration-overview)
3. [Authentication Configuration](#authentication-configuration)
4. [Rate Limiting Configuration](#rate-limiting-configuration)
5. [Scanner Configuration](#scanner-configuration)
6. [Neutralization Configuration](#neutralization-configuration)
7. [Server Configuration](#server-configuration)
8. [Security Best Practices](#security-best-practices)
9. [Common Security Scenarios](#common-security-scenarios)

## Security Philosophy

KindlyGuard follows these security principles:

1. **Secure by Default**: Conservative defaults that prioritize security
2. **Defense in Depth**: Multiple independent security layers
3. **Least Privilege**: Features must be explicitly enabled
4. **Transparency**: Clear documentation of security implications

## Configuration Overview

Security features work together in this priority order:

1. **Authentication** - Blocks unauthenticated requests (highest priority)
2. **Rate Limiting** - Prevents abuse from authenticated clients
3. **Scanner** - Detects threats in all requests
4. **Neutralization** - Remediates detected threats

## Authentication Configuration

### Overview

Authentication prevents unauthorized access to your MCP server using OAuth 2.0 with Resource Indicators (RFC 8707).

### Critical Settings

```toml
[auth]
enabled = true                    # MUST be true in production
jwt_secret = "base64-secret"      # Generate: openssl rand -base64 32
require_signature_verification = true
validate_resource_indicators = true
```

### Security Implications

| Setting | Default | Security Impact | Recommendation |
|---------|---------|----------------|----------------|
| `enabled` | `false` | When false, ANYONE can access all operations | **Always true in production** |
| `jwt_secret` | `None` | Weak/missing secrets enable token forgery | Use 256-bit (32 byte) secret |
| `cache_ttl_seconds` | `300` | Longer TTL = larger window for compromised tokens | 300-900 seconds |
| `validate_resource_indicators` | `true` | Prevents token reuse across services | Keep enabled |

### Example: Secure Production Config

```toml
[auth]
enabled = true
validation_endpoint = "https://auth.example.com/oauth2/introspect"
trusted_issuers = ["https://auth.example.com"]
cache_ttl_seconds = 300
validate_resource_indicators = true
jwt_secret = "YOUR-BASE64-ENCODED-256-BIT-SECRET"
require_signature_verification = true

[auth.required_scopes]
default = ["kindlyguard:access"]

[auth.required_scopes.tools]
"security/scan" = ["security:read"]
"security/neutralize" = ["security:write", "security:admin"]
```

## Rate Limiting Configuration

### Overview

Rate limiting prevents DoS attacks, brute force attempts, and resource exhaustion.

### Critical Settings

```toml
[rate_limit]
enabled = true                    # Essential for production
default_rpm = 60                  # Requests per minute
threat_penalty_multiplier = 0.5   # Reduce limits for threats
```

### Security Implications

| Setting | Default | Security Impact | Recommendation |
|---------|---------|----------------|----------------|
| `enabled` | `false` | No protection against DoS/brute force | **Always true in production** |
| `default_rpm` | `60` | Lower = more secure, less scalable | 30-120 for most APIs |
| `burst_capacity` | `10` | Too high enables rapid attacks | 5-20 (< rpm/6) |
| `threat_penalty_multiplier` | `0.5` | Automatic restriction of suspicious clients | 0.1-0.5 |

### Example: Tiered Rate Limiting

```toml
[rate_limit]
enabled = true
default_rpm = 60
burst_capacity = 10
adaptive = true
threat_penalty_multiplier = 0.5

# Different limits for different operations
[rate_limit.method_limits]
"tools/list" = { rpm = 120, burst = 20 }      # Read operations
"tools/call" = { rpm = 30, burst = 5 }        # Execute operations
"security/neutralize" = { rpm = 10, burst = 2 } # Sensitive operations

# Client-specific limits
[rate_limit.client_limits]
"trusted-app" = { rpm = 300, burst = 50, priority = "high" }
"public-api" = { rpm = 30, burst = 5, priority = "low" }
```

## Scanner Configuration

### Overview

The scanner is your first line of defense, detecting threats before they can cause harm.

### Critical Settings

```toml
[scanner]
unicode_detection = true          # Detect unicode attacks
injection_detection = true        # Detect SQL/command injection
path_traversal_detection = true   # Detect directory traversal
xss_detection = true             # Detect XSS attempts
```

### Security Implications

| Setting | Default | Security Impact | Recommendation |
|---------|---------|----------------|----------------|
| `unicode_detection` | `true` | Detects BiDi, zero-width, homoglyphs | Keep enabled |
| `injection_detection` | `true` | Prevents code execution | Keep enabled |
| `path_traversal_detection` | `true` | Prevents file access | Keep enabled |
| `xss_detection` | `true` | Prevents script injection | Keep enabled |
| `max_scan_depth` | `10` | Prevents algorithmic complexity attacks | 5-20 |
| `enhanced_mode` | `false` | Better detection at performance cost | Enable if available |

### Example: Maximum Security Scanner

```toml
[scanner]
unicode_detection = true
injection_detection = true
path_traversal_detection = true
xss_detection = true
enhanced_mode = true              # If available
max_scan_depth = 20               # Deep scanning
enable_event_buffer = true        # Purple shield mode
custom_patterns = "/etc/kindly-guard/patterns.toml"
```

## Neutralization Configuration

### Overview

Neutralization transforms detected threats into safe content while preserving functionality.

### Critical Settings

```toml
[neutralization]
mode = "automatic"                # Active protection
backup_originals = true           # Enable recovery
audit_all_actions = true          # Forensic trail
```

### Security Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| `ReportOnly` | Detect but don't modify | Testing/monitoring |
| `Interactive` | Require confirmation | Sensitive data |
| `Automatic` | Immediate remediation | Production |

### Unicode Threat Handling

```toml
[neutralization.unicode]
bidi_replacement = "marker"       # Visible markers for BiDi
zero_width_action = "remove"      # Remove invisible chars
homograph_action = "ascii"        # Convert lookalikes
```

| Action | Security | Usability | Recommendation |
|--------|----------|-----------|----------------|
| `Remove` | Highest | May break RTL text | High security |
| `Marker` | High | Visible indication | **Balanced** |
| `Escape` | Medium | Preserves data | Data integrity |

### Injection Handling

```toml
[neutralization.injection]
sql_action = "parameterize"       # Convert to prepared statements
command_action = "escape"         # Escape metacharacters
path_action = "normalize"         # Resolve to safe paths
prompt_action = "wrap"            # Add safety boundaries
```

## Server Configuration

### Overview

Server configuration controls network exposure and connection handling.

### Critical Settings

```toml
[server]
stdio = true                      # Most secure (no network)
max_connections = 100             # Prevent resource exhaustion
request_timeout_secs = 30         # Prevent slow loris
```

### Security Implications

| Setting | Default | Security Impact | Recommendation |
|---------|---------|----------------|----------------|
| `stdio` | `true` | No network exposure | Use for local only |
| `port` | `8080` | Standard ports attract scanners | Use non-standard |
| `max_connections` | `100` | Lower = more DoS resistant | 10-500 |
| `request_timeout_secs` | `30` | Shorter = less attack window | 10-60 |

## Security Best Practices

### 1. Minimum Secure Configuration

```toml
[auth]
enabled = true
jwt_secret = "your-base64-secret"

[rate_limit]
enabled = true

[scanner]
# All enabled by default

[neutralization]
mode = "automatic"
```

### 2. File Permissions

- Config files: `600` or `640` (readable by owner/group only)
- Never commit secrets to version control
- Use environment variables for sensitive values

### 3. Regular Security Tasks

- **Weekly**: Review audit logs for anomalies
- **Monthly**: Update threat patterns
- **Quarterly**: Rotate JWT secrets
- **Annually**: Full security audit

### 4. Monitoring and Alerting

Monitor these security metrics:
- Authentication failures
- Rate limit violations
- Threat detection rates
- Neutralization actions

## Common Security Scenarios

### Scenario 1: Public API

High exposure, unknown clients:

```toml
[auth]
enabled = true
require_signature_verification = true

[rate_limit]
enabled = true
default_rpm = 30
adaptive = true
threat_penalty_multiplier = 0.2

[scanner]
enhanced_mode = true
max_scan_depth = 20

[neutralization]
mode = "automatic"
```

### Scenario 2: Internal Service

Known clients, performance critical:

```toml
[auth]
enabled = true
cache_ttl_seconds = 900

[rate_limit]
enabled = true
default_rpm = 300

[scanner]
enhanced_mode = false
max_scan_depth = 10

[neutralization]
mode = "automatic"
```

### Scenario 3: Development Environment

Balance security with developer productivity:

```toml
[auth]
enabled = false  # Only for local development!

[rate_limit]
enabled = false

[scanner]
# Keep all enabled for testing

[neutralization]
mode = "report_only"
```

## Validation

Always validate your configuration:

```rust
let config = Config::load()?;
config.validate_security()?;
```

This will check for:
- Disabled authentication
- Disabled rate limiting
- Weak JWT secrets
- Disabled threat detections

## Need Help?

- Review the [CLAUDE.md](../../CLAUDE.md) for development guidelines
- Check [SECURITY.md](../../SECURITY.md) for vulnerability reporting
- See [docs/CONFIGURATION.md](../../docs/CONFIGURATION.md) for full reference