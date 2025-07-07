# KindlyGuard MCP Multi-Tool Guide

KindlyGuard v0.15.0 introduces comprehensive MCP (Model Context Protocol) support with multiple security tools in a single server. This guide explains how to use and integrate these tools.

## Overview

The unified `kindlyguard` binary provides a complete MCP server with multiple security tools, eliminating the need for separate binaries or complex configurations.

## Installation

```bash
# Install via npm (recommended)
npm install -g kindlyguard

# Verify installation
kindlyguard --version
```

## Starting the MCP Server

```bash
# Default stdio mode for Claude Desktop
kindlyguard serve

# With real-time shield display
kindlyguard serve --shield

# HTTP API mode
kindlyguard serve --http --bind 127.0.0.1:8080

# Custom configuration
kindlyguard serve --config production.toml
```

## Available MCP Tools

### 1. scan_text

Scan text content for security threats.

**Parameters:**
- `text` (string, required): The text to scan
- `protection_mode` (string, optional): "auto", "interactive", or "report"

**Example:**
```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "scan_text",
    "arguments": {
      "text": "Check this text for threats",
      "protection_mode": "auto"
    }
  }
}
```

**Response:**
```json
{
  "threats_found": 0,
  "scan_complete": true,
  "message": "✅ No threats detected - content is safe!",
  "details": {
    "characters_scanned": 27,
    "scan_time_ms": 2
  }
}
```

### 2. scan_file

Scan files with optional quarantine support.

**Parameters:**
- `path` (string, required): Path to the file
- `quarantine` (boolean, optional): Whether to quarantine threats

**Example:**
```json
{
  "name": "scan_file",
  "arguments": {
    "path": "/path/to/suspicious.txt",
    "quarantine": true
  }
}
```

### 3. check_url

Validate URLs for safety.

**Parameters:**
- `url` (string, required): URL to check

**Example:**
```json
{
  "name": "check_url",
  "arguments": {
    "url": "https://example.com/page"
  }
}
```

### 4. neutralize

Clean threats from content while preserving meaning.

**Parameters:**
- `text` (string, required): Text containing threats
- `threat_id` (string, optional): Specific threat to neutralize

**Example:**
```json
{
  "name": "neutralize",
  "arguments": {
    "text": "Dangerous'; DROP TABLE users;--",
    "threat_id": "sql-injection-001"
  }
}
```

### 5. quarantine_list

View quarantined threats.

**Parameters:**
- `filter` (string, optional): Filter quarantine entries ("active", "compressed", "all")

**Example:**
```json
{
  "name": "quarantine_list",
  "arguments": {
    "filter": "active"
  }
}
```

### 6. get_statistics

Get real-time security statistics.

**Parameters:** None

**Example:**
```json
{
  "name": "get_statistics",
  "arguments": {}
}
```

## Claude Desktop Integration

### Automatic Setup

```bash
# Configure Claude Desktop automatically
kindlyguard mcp setup
```

### Manual Configuration

Add to your Claude Desktop config:

```json
{
  "mcpServers": {
    "kindlyguard": {
      "command": "kindlyguard",
      "args": ["serve", "--stdio"],
      "env": {}
    }
  }
}
```

## Protection Modes

KindlyGuard supports three protection modes:

1. **Auto-Protect** (default)
   - Threats are automatically neutralized
   - Original content is quarantined
   - Clean content is returned

2. **Interactive**
   - User is prompted for action on each threat
   - Choose to allow, block, or neutralize

3. **Report-Only**
   - Threats are detected and reported
   - No modification of content
   - Useful for monitoring

## Advanced Configuration

### Custom Threat Rules

Create a configuration file:

```toml
# ~/.kindlyguard/config.toml

[protection]
mode = "auto"
quarantine_enabled = true

[scanner]
sensitivity = "balanced"
custom_patterns = [
  { name = "api-key", pattern = "sk-[a-zA-Z0-9]{48}", severity = "high" },
  { name = "private-key", pattern = "-----BEGIN.*PRIVATE KEY-----", severity = "critical" }
]

[quarantine]
encrypt = true
retention_days = 90
compression_after_days = 30
```

### Environment Variables

```bash
# Set protection mode
export KINDLYGUARD_PROTECTION_MODE=interactive

# Enable debug logging
export RUST_LOG=kindlyguard=debug

# Custom config path
export KINDLYGUARD_CONFIG=/path/to/config.toml
```

## Integration Examples

### Python Integration

```python
import subprocess
import json

def scan_with_kindlyguard(text):
    result = subprocess.run(
        ['kindlyguard', 'serve', '--stdio'],
        input=json.dumps({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "scan_text",
                "arguments": {"text": text}
            }
        }).encode(),
        capture_output=True
    )
    return json.loads(result.stdout)
```

### Node.js Integration

```javascript
const { spawn } = require('child_process');

async function scanText(text) {
  const kindlyguard = spawn('kindlyguard', ['serve', '--stdio']);
  
  kindlyguard.stdin.write(JSON.stringify({
    jsonrpc: "2.0",
    method: "tools/call",
    params: {
      name: "scan_text",
      arguments: { text }
    }
  }));
  
  return new Promise((resolve) => {
    kindlyguard.stdout.on('data', (data) => {
      resolve(JSON.parse(data.toString()));
    });
  });
}
```

## Best Practices

1. **Use Auto-Protect Mode** for production environments
2. **Enable Quarantine** to preserve original content
3. **Monitor Statistics** regularly for security insights
4. **Configure Custom Patterns** for domain-specific threats
5. **Set Appropriate Retention** policies for quarantined content

## Troubleshooting

### MCP Server Not Starting

```bash
# Check if port is in use (HTTP mode)
lsof -i :8080

# Verify installation
kindlyguard --version

# Enable debug logging
RUST_LOG=debug kindlyguard serve
```

### Claude Desktop Not Connecting

```bash
# Verify MCP configuration
kindlyguard mcp verify

# Check Claude Desktop logs
# Location varies by OS
```

### Performance Issues

```bash
# Use enhanced mode for better performance
cargo build --release --features enhanced

# Adjust scanner sensitivity
kindlyguard serve --config low-sensitivity.toml
```

## Security Considerations

1. **Local Processing** - All scanning happens on your machine
2. **No Cloud Dependencies** - Works completely offline
3. **Encrypted Quarantine** - Threats are stored securely
4. **Audit Trail** - All actions are logged
5. **Zero Trust** - Every input is scanned

## Support

- GitHub Issues: https://github.com/kindly-software-inc/kindly-guard/issues
- Documentation: https://docs.kindlyguard.com
- Security: security@kindlyguard.com

---

**Remember:** KindlyGuard is kind to you, tough on threats!