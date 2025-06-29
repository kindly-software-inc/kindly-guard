# KindlyGuard API Documentation

KindlyGuard implements the Model Context Protocol (MCP) specification with additional security-focused endpoints.

## Table of Contents

- [Overview](#overview)
- [Authentication](#authentication)
- [Standard MCP Methods](#standard-mcp-methods)
- [Security Extensions](#security-extensions)
- [Tool Definitions](#tool-definitions)
- [Resource Definitions](#resource-definitions)
- [Error Codes](#error-codes)
- [Configuration API](#configuration-api)

## Overview

KindlyGuard is a security-focused MCP server that provides threat detection, rate limiting, and authentication for AI model interactions. All communication follows the JSON-RPC 2.0 protocol.

### Connection Methods

1. **stdio** - Standard input/output (recommended for MCP)
   ```bash
   kindly-guard --stdio
   ```

2. **Unix Socket** (via systemd socket activation)
   ```
   /var/run/kindly-guard/kindly-guard.sock
   ```

### Protocol Version

KindlyGuard supports MCP protocol version `2024-11-05`.

## Authentication

KindlyGuard implements OAuth 2.0 with Resource Indicators (RFC 8707) for secure authentication.

### Token Request

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&
client_id=your-client-id&
client_secret=your-client-secret&
resource=kindlyguard:v0.1.0&
scope=tools:execute resources:read
```

### Using Tokens

Include the access token in the Authorization header:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "scan_text",
    "arguments": {
      "text": "content to scan"
    }
  },
  "id": 1,
  "_meta": {
    "authorization": "Bearer <access_token>"
  }
}
```

### Available Scopes

- `tools:execute` - Execute security tools
- `resources:read` - Read security resources
- `admin:write` - Administrative operations
- `security:scan` - Perform security scans
- `security:verify` - Verify signatures
- `info:read` - Read security information

## Standard MCP Methods

### initialize

Initialize the MCP session.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "initialize",
  "params": {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": {
      "name": "example-client",
      "version": "1.0.0"
    }
  },
  "id": 1
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "protocolVersion": "2024-11-05",
    "capabilities": {
      "tools": {},
      "resources": {
        "subscribe": false
      },
      "logging": {}
    },
    "serverInfo": {
      "name": "KindlyGuard",
      "version": "0.1.0",
      "description": "Security-focused MCP server"
    }
  },
  "id": 1
}
```

### initialized

Notify server that client initialization is complete.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "initialized",
  "params": {}
}
```

### tools/list

List available security tools.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "tools/list",
  "params": {},
  "id": 2
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "tools": [
      {
        "name": "scan_text",
        "description": "Scan text for security threats",
        "inputSchema": {
          "type": "object",
          "properties": {
            "text": {
              "type": "string",
              "description": "Text to scan"
            }
          },
          "required": ["text"]
        }
      },
      {
        "name": "verify_signature",
        "description": "Verify message signature",
        "inputSchema": {
          "type": "object",
          "properties": {
            "message": {
              "type": "string",
              "description": "Message content"
            },
            "signature": {
              "type": "string",
              "description": "Base64 encoded signature"
            }
          },
          "required": ["message", "signature"]
        }
      }
    ]
  },
  "id": 2
}
```

### tools/call

Execute a security tool.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "scan_text",
    "arguments": {
      "text": "SELECT * FROM users; DROP TABLE users;"
    }
  },
  "id": 3
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "⚠️ Security threats detected:\n\n1. SQL Injection (Critical)\n   Location: offset 20\n   Description: SQL injection attempt detected\n   Remediation: Use parameterized queries"
      }
    ],
    "isError": false
  },
  "id": 3
}
```

### resources/list

List available security resources.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "resources/list",
  "params": {},
  "id": 4
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "resources": [
      {
        "uri": "kindlyguard://security/status",
        "name": "Security Status",
        "description": "Current security status and statistics",
        "mimeType": "application/json"
      },
      {
        "uri": "kindlyguard://threats/recent",
        "name": "Recent Threats",
        "description": "Recently detected security threats",
        "mimeType": "application/json"
      }
    ]
  },
  "id": 4
}
```

### resources/read

Read a security resource.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "resources/read",
  "params": {
    "uri": "kindlyguard://security/status"
  },
  "id": 5
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "contents": [
      {
        "uri": "kindlyguard://security/status",
        "mimeType": "application/json",
        "text": "{\"active\":true,\"threats_blocked\":42,\"uptime_seconds\":3600}"
      }
    ]
  },
  "id": 5
}
```

## Security Extensions

KindlyGuard adds custom security-focused methods:

### security/status

Get current security status.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "security/status",
  "params": {},
  "id": 6
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "shield": {
      "active": true,
      "mode": "enhanced",
      "color": "purple",
      "threats_blocked": 42,
      "last_threat": "2024-01-20T15:30:00Z"
    },
    "scanner": {
      "unicode_detection": true,
      "injection_detection": true,
      "total_scans": 1337
    },
    "rate_limit": {
      "enabled": true,
      "default_rpm": 60
    }
  },
  "id": 6
}
```

### security/threats

Get detailed threat information.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "security/threats",
  "params": {
    "limit": 10,
    "since": "2024-01-20T00:00:00Z"
  },
  "id": 7
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "threats": [
      {
        "timestamp": "2024-01-20T15:25:00Z",
        "type": "sql_injection",
        "severity": "critical",
        "blocked": true,
        "client_id": "suspicious-client",
        "details": {
          "pattern": "UNION SELECT",
          "location": "tool_argument"
        }
      }
    ],
    "summary": {
      "total": 42,
      "by_type": {
        "sql_injection": 15,
        "prompt_injection": 12,
        "unicode_exploit": 10,
        "path_traversal": 5
      }
    }
  },
  "id": 7
}
```

### security/rate_limit_status

Check rate limit status for a client.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "security/rate_limit_status",
  "params": {},
  "id": 8
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "status": {
      "global": {
        "allowed": true,
        "tokens_remaining": 45.5,
        "reset_after": 30,
        "burst_available": 8
      },
      "per_method": {
        "tools/call": {
          "allowed": true,
          "tokens_remaining": 28,
          "reset_after": 45
        }
      }
    }
  },
  "id": 8
}
```

## Tool Definitions

### scan_text

Scan text content for security threats including unicode attacks, injection attempts, and malicious patterns.

**Input Schema:**
```typescript
{
  text: string;           // Text to scan (required)
  context?: string;       // Additional context
  deep_scan?: boolean;    // Enable deep scanning
}
```

**Output:**
```typescript
{
  threats: Array<{
    type: string;         // Threat type
    severity: "low" | "medium" | "high" | "critical";
    location: string;     // Where threat was found
    description: string;  // Human-readable description
    remediation?: string; // Suggested fix
  }>;
  clean: boolean;        // True if no threats found
}
```

### verify_signature

Verify Ed25519 message signatures.

**Input Schema:**
```typescript
{
  message: string;       // Original message
  signature: string;     // Base64 encoded signature
  public_key?: string;   // Optional public key (uses server key if not provided)
}
```

**Output:**
```typescript
{
  valid: boolean;        // Signature validity
  signer?: string;       // Signer identity if known
  timestamp?: string;    // Signature timestamp if available
}
```

### get_security_info

Get detailed security information and recommendations.

**Input Schema:**
```typescript
{
  topic: "unicode" | "injection" | "config" | "best_practices";
}
```

**Output:**
```typescript
{
  info: string;          // Detailed information
  examples?: string[];   // Example threats/patterns
  recommendations?: string[]; // Security recommendations
}
```

## Resource Definitions

### kindlyguard://security/status

Current security system status.

**Format:** `application/json`

**Schema:**
```typescript
{
  active: boolean;
  uptime_seconds: number;
  shield: {
    mode: "standard" | "enhanced";
    color: "green" | "purple";
    threats_blocked: number;
  };
  scanner: {
    patterns_loaded: number;
    scans_performed: number;
  };
}
```

### kindlyguard://threats/recent

Recent security threats (last 24 hours).

**Format:** `application/json`

**Schema:**
```typescript
{
  threats: Array<{
    id: string;
    timestamp: string;  // ISO 8601
    type: string;
    severity: string;
    blocked: boolean;
    client_id?: string;
  }>;
}
```

### kindlyguard://config/current

Current server configuration (sanitized).

**Format:** `application/yaml`

Returns current configuration with sensitive values redacted.

## Error Codes

KindlyGuard uses standard JSON-RPC error codes plus custom security codes:

| Code | Constant | Description |
|------|----------|-------------|
| -32700 | Parse error | Invalid JSON |
| -32600 | Invalid request | Invalid JSON-RPC |
| -32601 | Method not found | Unknown method |
| -32602 | Invalid params | Invalid parameters |
| -32603 | Internal error | Server error |
| -32000 | THREAT_DETECTED | Security threat detected |
| -32001 | UNAUTHORIZED | Authentication required |
| -32002 | FORBIDDEN | Insufficient permissions |
| -32003 | RATE_LIMITED | Rate limit exceeded |
| -32004 | SIGNATURE_INVALID | Invalid signature |

**Error Response Example:**
```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32000,
    "message": "Security threat detected",
    "data": {
      "threats": [
        {
          "type": "sql_injection",
          "severity": "critical"
        }
      ]
    }
  },
  "id": 1
}
```

## Configuration API

### Configuration Structure

KindlyGuard configuration uses YAML format:

```yaml
# Scanner settings
scanner:
  unicode_detection: true
  injection_detection: true
  max_scan_depth: 10
  enable_event_buffer: false  # Enable for enhanced mode
  custom_patterns: null       # Path to custom patterns file

# Shield display
shield:
  display_enabled: true
  update_interval_ms: 1000
  show_timestamp: true
  show_stats: true

# Authentication
auth:
  enabled: true
  token_lifetime_secs: 3600
  allowed_clients:
    - client_id: "my-client"
      secret: "secret-key"
      allowed_scopes: ["tools:execute", "resources:read"]
      rate_limit_override: 120  # Custom RPM

# Rate limiting
rate_limit:
  enabled: true
  default_rpm: 60
  default_burst: 10
  per_method_limits:
    "tools/call": 30
    "resources/read": 120
  threat_penalty_multiplier: 2.0

# Message signing
signing:
  enabled: false
  algorithm: "Ed25519"
  private_key_path: "/path/to/key"
  require_signed_requests: false

# Event processor (enhanced mode)
event_processor:
  enabled: false  # Enable for purple shield
  buffer_size_mb: 10
  endpoint_limit: 1000
  pattern_detection: true

# Logging
log_level: "info"  # trace, debug, info, warn, error
```

### Environment Variables

Configuration can be overridden with environment variables:

- `KINDLY_GUARD_CONFIG` - Path to config file
- `RUST_LOG` - Logging configuration
- `KINDLY_GUARD_AUTH_ENABLED` - Enable/disable auth
- `KINDLY_GUARD_RATE_LIMIT_RPM` - Default rate limit

### Dynamic Configuration

Some settings can be updated at runtime via the admin API (requires `admin:write` scope):

```json
{
  "jsonrpc": "2.0",
  "method": "admin/update_config",
  "params": {
    "section": "rate_limit",
    "values": {
      "default_rpm": 120
    }
  },
  "id": 9
}
```

## Client Integration Examples

### Python
```python
import json
import subprocess

# Start KindlyGuard
proc = subprocess.Popen(
    ["kindly-guard", "--stdio"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    text=True
)

# Send request
request = {
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
        "name": "scan_text",
        "arguments": {"text": "test content"}
    },
    "id": 1
}
proc.stdin.write(json.dumps(request) + "\n")
proc.stdin.flush()

# Read response
response = json.loads(proc.stdout.readline())
```

### Node.js
```javascript
const { spawn } = require('child_process');

const kindly = spawn('kindly-guard', ['--stdio']);

kindly.stdout.on('data', (data) => {
  const response = JSON.parse(data.toString());
  console.log('Response:', response);
});

// Send request
const request = {
  jsonrpc: "2.0",
  method: "tools/call",
  params: {
    name: "scan_text",
    arguments: { text: "test content" }
  },
  id: 1
};
kindly.stdin.write(JSON.stringify(request) + '\n');
```

## Best Practices

1. **Always authenticate** - Use OAuth 2.0 tokens for production
2. **Handle rate limits** - Respect `X-RateLimit-*` headers
3. **Validate signatures** - Verify signed responses when enabled
4. **Monitor threats** - Subscribe to threat notifications
5. **Escape output** - Threat descriptions may contain malicious content
6. **Use connection pooling** - Reuse MCP sessions when possible
7. **Set appropriate timeouts** - Default timeout is 30 seconds
8. **Log security events** - Track blocked threats and patterns