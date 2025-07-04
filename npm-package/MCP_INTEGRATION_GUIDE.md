# KindlyGuard MCP Integration Guide

This guide explains how to integrate KindlyGuard as an MCP (Model Context Protocol) server with various AI tools and platforms.

## What is MCP?

The Model Context Protocol (MCP) is a standard protocol that allows AI assistants like Claude to communicate with external tools and services. KindlyGuard implements this protocol to provide real-time security scanning and protection.

## Quick Start

```bash
# No installation needed - just run:
npx @kindlyguard/kindlyguard --stdio
```

## Integration Methods

### 1. Claude Desktop Integration

Add KindlyGuard to your Claude Desktop configuration:

**macOS:**
```bash
open ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

**Windows:**
```
notepad %APPDATA%\Claude\claude_desktop_config.json
```

**Linux:**
```bash
nano ~/.config/Claude/claude_desktop_config.json
```

Add this configuration:

```json
{
  "mcpServers": {
    "kindlyguard": {
      "command": "npx",
      "args": ["@kindlyguard/kindlyguard", "--stdio"],
      "env": {
        "RUST_LOG": "info"
      }
    }
  }
}
```

### 2. VS Code Integration

For VS Code with MCP extension support:

```json
{
  "mcp.servers": {
    "kindlyguard": {
      "command": "npx",
      "args": ["@kindlyguard/kindlyguard", "--stdio"],
      "env": {
        "RUST_LOG": "debug"
      },
      "capabilities": {
        "tools": true,
        "resources": true,
        "prompts": false
      }
    }
  }
}
```

### 3. Programmatic Integration (Node.js)

```javascript
const { spawn } = require('child_process');

// Start KindlyGuard MCP server
const server = spawn('npx', ['@kindlyguard/kindlyguard', '--stdio'], {
  stdio: ['pipe', 'pipe', 'inherit']
});

// Send MCP messages
server.stdin.write(JSON.stringify({
  jsonrpc: "2.0",
  method: "initialize",
  params: { protocolVersion: "0.1.0" },
  id: 1
}) + '\n');

// Read responses
server.stdout.on('data', (data) => {
  const lines = data.toString().split('\n');
  lines.forEach(line => {
    if (line.trim()) {
      const message = JSON.parse(line);
      console.log('Received:', message);
    }
  });
});
```

### 4. Using the NPM Package

```javascript
const kindlyguard = require('@kindlyguard/kindlyguard');

// Create and start MCP server
const server = kindlyguard.create({ stdio: true });
const mcp = server.start();

// Use the convenient interface
mcp.send({
  jsonrpc: "2.0",
  method: "tools/list",
  id: 2
});

mcp.onMessage((message) => {
  console.log('MCP message:', message);
});
```

## MCP Tools Available

KindlyGuard exposes the following MCP tools:

### 1. `scan_text`
Scans text for unicode attacks and injection threats.

```json
{
  "name": "scan_text",
  "description": "Scan text for security threats",
  "inputSchema": {
    "type": "object",
    "properties": {
      "text": { "type": "string" }
    },
    "required": ["text"]
  }
}
```

### 2. `scan_file`
Scans a file for security threats.

```json
{
  "name": "scan_file",
  "description": "Scan a file for security threats",
  "inputSchema": {
    "type": "object",
    "properties": {
      "path": { "type": "string" }
    },
    "required": ["path"]
  }
}
```

### 3. `get_statistics`
Returns current threat detection statistics.

```json
{
  "name": "get_statistics",
  "description": "Get threat detection statistics",
  "inputSchema": {
    "type": "object",
    "properties": {}
  }
}
```

## Configuration Options

### Environment Variables

- `RUST_LOG`: Set logging level (error, warn, info, debug, trace)
- `KINDLY_GUARD_CONFIG`: Path to configuration file

### Configuration File

Create a `kindly-guard.toml` file:

```toml
[server]
host = "127.0.0.1"
port = 3000

[security]
unicode_checks = true
injection_checks = true
max_input_size = "10MB"
rate_limit = 100

[mcp]
protocol_version = "0.1.0"
enable_tools = true
enable_resources = true

[resilience]
enhanced_mode = false
circuit_breaker_threshold = 5
retry_max_attempts = 3
```

## Troubleshooting

### Server not starting

1. Check Node.js version:
   ```bash
   node --version  # Should be >= 14.0.0
   ```

2. Enable debug logging:
   ```bash
   RUST_LOG=debug npx @kindlyguard/kindlyguard --stdio
   ```

3. Test binary directly:
   ```bash
   npx @kindlyguard/kindlyguard status
   ```

### Claude Desktop not connecting

1. Verify config file location
2. Check for JSON syntax errors
3. Restart Claude Desktop
4. Look for errors in Claude Desktop developer console

### Performance issues

1. Reduce logging level:
   ```json
   "env": { "RUST_LOG": "warn" }
   ```

2. Adjust rate limiting in config
3. Use enhanced mode for better performance (if available)

## Security Considerations

1. **Input Validation**: All MCP inputs are validated before processing
2. **Rate Limiting**: Built-in protection against DoS attacks
3. **Resource Limits**: Memory and CPU usage are bounded
4. **Sandboxing**: Runs in isolated process
5. **No Network Access**: KindlyGuard doesn't make external network calls

## Example Use Cases

### 1. Protecting Chat Inputs
Claude Desktop automatically scans all inputs for threats before processing.

### 2. File Analysis
Scan uploaded files for hidden unicode attacks or injection attempts.

### 3. Code Review
Detect potential security issues in code snippets.

### 4. Data Validation
Ensure JSON/XML data doesn't contain malicious patterns.

## Support

- GitHub Issues: https://github.com/samduchaine/kindly-guard/issues
- Documentation: https://github.com/samduchaine/kindly-guard#readme
- NPM Package: https://www.npmjs.com/package/@kindlyguard/kindlyguard

## Version Compatibility

- MCP Protocol: 0.1.0
- Node.js: >= 14.0.0
- Claude Desktop: Latest version
- VS Code: With MCP extension