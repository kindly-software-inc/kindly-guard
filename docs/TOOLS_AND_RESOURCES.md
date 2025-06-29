# KindlyGuard Tools and Resources

Detailed documentation of all MCP tools and resources provided by KindlyGuard.

## Table of Contents

- [Security Tools](#security-tools)
  - [scan_text](#scan_text)
  - [verify_signature](#verify_signature) 
  - [get_security_info](#get_security_info)
- [Resources](#resources)
  - [Security Status](#security-status)
  - [Recent Threats](#recent-threats)
  - [Configuration](#configuration)
  - [Scanner Stats](#scanner-stats)
- [Tool Categories](#tool-categories)
- [Permission Requirements](#permission-requirements)
- [Usage Examples](#usage-examples)

## Security Tools

### scan_text

Comprehensive text scanning for security threats.

#### Description
Scans text content for various security threats including:
- Unicode exploits (invisible characters, BiDi attacks, homographs)
- Injection attempts (SQL, Command, Path Traversal)
- Prompt injection patterns
- MCP-specific threats (session ID exposure, token theft)

#### Input Schema
```json
{
  "type": "object",
  "properties": {
    "text": {
      "type": "string",
      "description": "Text content to scan",
      "maxLength": 1000000
    },
    "context": {
      "type": "string", 
      "description": "Additional context (e.g., 'user_input', 'file_content')",
      "enum": ["user_input", "file_content", "api_response", "database", "other"]
    },
    "deep_scan": {
      "type": "boolean",
      "description": "Enable deeper pattern analysis (slower)",
      "default": false
    }
  },
  "required": ["text"]
}
```

#### Output Format
```json
{
  "threats": [
    {
      "type": "unicode_invisible",
      "severity": "high", 
      "location": {
        "offset": 42,
        "length": 1
      },
      "description": "Invisible Unicode character U+200B (Zero Width Space)",
      "remediation": "Remove or escape invisible Unicode characters"
    }
  ],
  "statistics": {
    "scan_time_ms": 12,
    "characters_scanned": 1024,
    "patterns_checked": 156
  },
  "clean": false
}
```

#### Threat Types Detected
- **Unicode Threats**
  - `unicode_invisible` - Zero-width and invisible characters
  - `unicode_bidi` - Right-to-left override attacks
  - `unicode_homograph` - Look-alike character attacks
  - `unicode_control` - Dangerous control characters

- **Injection Threats**
  - `sql_injection` - SQL injection attempts
  - `command_injection` - OS command injection
  - `path_traversal` - Directory traversal attempts
  - `prompt_injection` - LLM prompt manipulation

- **MCP-Specific Threats**
  - `session_id_exposure` - Session identifier leaks
  - `tool_poisoning` - Malicious tool definitions
  - `token_theft` - Authentication token exposure

#### Usage Example
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "scan_text",
    "arguments": {
      "text": "Hello\u200BWorld SELECT * FROM users",
      "context": "user_input",
      "deep_scan": true
    }
  },
  "id": 1
}
```

#### Performance Notes
- Basic scan: ~1ms per KB
- Deep scan: ~5ms per KB
- Memory usage: O(n) where n is text length
- Maximum text size: 1MB (configurable)

### verify_signature

Verify Ed25519 digital signatures.

#### Description
Verifies cryptographic signatures on messages to ensure authenticity and integrity.

#### Input Schema
```json
{
  "type": "object",
  "properties": {
    "message": {
      "type": "string",
      "description": "Original message content"
    },
    "signature": {
      "type": "string",
      "description": "Base64-encoded Ed25519 signature",
      "pattern": "^[A-Za-z0-9+/]*={0,2}$"
    },
    "public_key": {
      "type": "string",
      "description": "Base64-encoded public key (optional, uses server key if omitted)",
      "pattern": "^[A-Za-z0-9+/]*={0,2}$"
    },
    "timestamp": {
      "type": "integer",
      "description": "Expected timestamp (Unix epoch seconds)"
    }
  },
  "required": ["message", "signature"]
}
```

#### Output Format
```json
{
  "valid": true,
  "signer": "client-123",
  "timestamp": 1705762400,
  "age_seconds": 3600,
  "metadata": {
    "algorithm": "Ed25519",
    "key_id": "2024-01-20"
  }
}
```

#### Signature Format
KindlyGuard expects signatures in the format:
```
timestamp:message:nonce
```

The signature covers the concatenated string with colons as delimiters.

#### Usage Example
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "verify_signature",
    "arguments": {
      "message": "Important security update",
      "signature": "MEUCIQDxyz...",
      "timestamp": 1705762400
    }
  },
  "id": 2
}
```

### get_security_info

Retrieve security information and best practices.

#### Description
Provides detailed security information, threat examples, and recommendations.

#### Input Schema
```json
{
  "type": "object",
  "properties": {
    "topic": {
      "type": "string",
      "description": "Security topic to retrieve information about",
      "enum": [
        "unicode",
        "injection", 
        "authentication",
        "rate_limiting",
        "best_practices",
        "threat_examples",
        "configuration"
      ]
    },
    "format": {
      "type": "string",
      "description": "Output format preference",
      "enum": ["text", "markdown", "json"],
      "default": "markdown"
    }
  },
  "required": ["topic"]
}
```

#### Output Format
```json
{
  "topic": "unicode",
  "content": "# Unicode Security Threats\n\n## Overview\n...",
  "examples": [
    {
      "name": "Zero Width Space Attack",
      "description": "Invisible character injection",
      "sample": "user\u200Bname",
      "detection": "Unicode category Cf (Format)"
    }
  ],
  "recommendations": [
    "Normalize Unicode input using NFC",
    "Strip format and control characters",
    "Validate against allowed character sets"
  ],
  "references": [
    {
      "title": "Unicode Security Considerations",
      "url": "https://unicode.org/reports/tr36/"
    }
  ]
}
```

#### Available Topics
- `unicode` - Unicode attack vectors and defenses
- `injection` - Injection attack patterns and prevention
- `authentication` - OAuth 2.0 and security best practices
- `rate_limiting` - Rate limiting strategies
- `best_practices` - General security recommendations
- `threat_examples` - Real-world threat samples
- `configuration` - Secure configuration guidance

#### Usage Example
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "get_security_info",
    "arguments": {
      "topic": "injection",
      "format": "markdown"
    }
  },
  "id": 3
}
```

## Resources

### Security Status

Real-time security system status.

#### URI
`kindlyguard://security/status`

#### Format
`application/json`

#### Schema
```json
{
  "shield": {
    "active": true,
    "mode": "enhanced",
    "color": "purple", 
    "uptime_seconds": 3600,
    "last_restart": "2024-01-20T12:00:00Z"
  },
  "threats": {
    "total_blocked": 142,
    "last_24h": 23,
    "last_hour": 2,
    "by_severity": {
      "critical": 5,
      "high": 18,
      "medium": 67,
      "low": 52
    }
  },
  "scanner": {
    "patterns_loaded": 247,
    "custom_patterns": 12,
    "total_scans": 5892,
    "avg_scan_time_ms": 2.4
  },
  "authentication": {
    "enabled": true,
    "active_sessions": 3,
    "failed_attempts_24h": 7
  },
  "rate_limit": {
    "enabled": true,
    "throttled_clients": 2,
    "total_throttled_24h": 45
  }
}
```

#### Update Frequency
- Real-time data
- Cached for 1 second
- Stats aggregated every minute

### Recent Threats

Recently detected security threats.

#### URI
`kindlyguard://threats/recent`

#### Format
`application/json`

#### Schema
```json
{
  "threats": [
    {
      "id": "threat_9f8e7d6c",
      "timestamp": "2024-01-20T15:30:45Z",
      "type": "sql_injection",
      "severity": "critical",
      "client_id": "client_xyz",
      "blocked": true,
      "details": {
        "pattern": "'; DROP TABLE users; --",
        "location": "tool_argument",
        "tool": "database_query"
      },
      "action_taken": "blocked_and_logged"
    }
  ],
  "pagination": {
    "total": 142,
    "page": 1,
    "per_page": 50,
    "has_more": true
  },
  "filters": {
    "time_range": "24h",
    "min_severity": "medium",
    "blocked_only": false
  }
}
```

#### Query Parameters
- `limit` - Maximum threats to return (default: 50)
- `offset` - Pagination offset
- `since` - ISO 8601 timestamp
- `severity` - Minimum severity filter
- `type` - Filter by threat type
- `client_id` - Filter by client

### Configuration

Current server configuration (sanitized).

#### URI
`kindlyguard://config/current`

#### Format
`application/yaml`

#### Schema
Returns current configuration with sensitive values redacted:
```yaml
scanner:
  unicode_detection: true
  injection_detection: true
  max_scan_depth: 10
  enable_event_buffer: true  # Enhanced mode active

auth:
  enabled: true
  allowed_clients:
    - client_id: "app-1"
      secret: "[REDACTED]"
      allowed_scopes: ["tools:execute"]

rate_limit:
  enabled: true
  default_rpm: 60

# Sensitive fields removed:
# - private_key_path
# - client_secrets
# - database_credentials
```

### Scanner Stats

Detailed scanner performance statistics.

#### URI
`kindlyguard://scanner/stats`

#### Format
`application/json`

#### Schema
```json
{
  "performance": {
    "total_scans": 15892,
    "total_threats": 234,
    "detection_rate": 0.0147,
    "avg_scan_time_ms": 2.4,
    "p95_scan_time_ms": 8.2,
    "p99_scan_time_ms": 45.6
  },
  "patterns": {
    "unicode": {
      "patterns_active": 47,
      "matches": 89,
      "false_positives": 2
    },
    "injection": {
      "patterns_active": 156,
      "matches": 145,
      "false_positives": 8
    }
  },
  "cache": {
    "hit_rate": 0.73,
    "entries": 2048,
    "memory_bytes": 524288
  }
}
```

## Tool Categories

Tools are organized into categories for permission management:

### Security Tools
- `scan_text` - Threat scanning
- `verify_signature` - Signature verification
- `check_hash` - Hash verification

**Required scope**: `security:scan` or `security:verify`

### Information Tools
- `get_security_info` - Security information
- `list_threat_types` - Available threat types
- `get_pattern_info` - Pattern details

**Required scope**: `info:read`

### Administrative Tools
- `update_patterns` - Update threat patterns
- `clear_cache` - Clear scanner cache
- `reload_config` - Reload configuration

**Required scope**: `admin:write`

### Diagnostic Tools
- `test_pattern` - Test threat patterns
- `benchmark_scanner` - Performance testing
- `validate_config` - Configuration validation

**Required scope**: `tools:execute`

## Permission Requirements

### Scope Mapping

| Tool | Required Scopes | Threat Level |
|------|----------------|--------------|
| `scan_text` | `security:scan` | Any |
| `verify_signature` | `security:verify` | Any |
| `get_security_info` | `info:read` | Any |
| `update_patterns` | `admin:write` | Safe |
| `reload_config` | `admin:write` | Safe |

### Client Permissions

Tools can be restricted per client:
```yaml
permissions:
  per_client_permissions:
    "untrusted-app":
      allowed_tools: ["scan_text"]
      denied_tools: ["update_patterns"]
      max_threat_level: "medium"
```

## Usage Examples

### Python Client

```python
import asyncio
import json
from mcp import ClientSession, StdioServerParameters

async def scan_content():
    async with ClientSession(
        StdioServerParameters(
            command="kindly-guard",
            args=["--stdio"]
        )
    ) as session:
        # Initialize
        await session.initialize()
        
        # Call scan_text tool
        result = await session.call_tool(
            "scan_text",
            arguments={
                "text": "Check this: '; DROP TABLE users; --",
                "context": "user_input"
            }
        )
        
        threats = json.loads(result.content[0].text)
        if not threats["clean"]:
            print(f"Found {len(threats['threats'])} threats!")
```

### TypeScript Client

```typescript
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const transport = new StdioClientTransport({
  command: "kindly-guard",
  args: ["--stdio"],
});

const client = new Client({
  name: "security-app",
  version: "1.0.0",
}, {
  capabilities: {}
});

await client.connect(transport);

// Scan for threats
const result = await client.callTool({
  name: "scan_text",
  arguments: {
    text: userInput,
    deep_scan: true
  }
});

const threats = JSON.parse(result.content[0].text);
```

### Direct JSON-RPC

```bash
# Scan text for threats
echo '{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "scan_text",
    "arguments": {
      "text": "Test content with hidden\u200Bcharacters"
    }
  },
  "id": 1
}' | kindly-guard --stdio

# Read security status
echo '{
  "jsonrpc": "2.0",
  "method": "resources/read",
  "params": {
    "uri": "kindlyguard://security/status"
  },
  "id": 2
}' | kindly-guard --stdio
```

## Best Practices

1. **Cache Results** - Scan results for identical content can be cached
2. **Batch Operations** - Group multiple scans when possible
3. **Use Context** - Provide context for better threat detection
4. **Handle Errors** - Tools may fail on malformed input
5. **Respect Limits** - Stay within rate limits and size constraints
6. **Validate Output** - Threat descriptions may contain user content
7. **Monitor Performance** - Use scanner stats for optimization