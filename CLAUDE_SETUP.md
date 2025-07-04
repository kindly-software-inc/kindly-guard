# Setting up KindlyGuard with Claude Code

## Quick Setup

1. **Copy the MCP configuration to Claude's config directory:**

```bash
# For macOS/Linux
mkdir -p ~/.config/claude
cp /path/to/kindly-guard/claude_mcp_config.json ~/.config/claude/mcp.json

# Or append to existing config:
# jq -s '.[0] * .[1]' ~/.config/claude/mcp.json /path/to/kindly-guard/claude_mcp_config.json > ~/.config/claude/mcp.tmp && mv ~/.config/claude/mcp.tmp ~/.config/claude/mcp.json
```

2. **Alternative: Manual configuration**

Edit `~/.config/claude/mcp.json` and add:

```json
{
  "mcpServers": {
    "kindly-guard": {
      "command": "/path/to/kindly-guard/target/release/kindly-guard",
      "args": ["--stdio"],
      "env": {
        "RUST_LOG": "info"
      }
    }
  }
}
```

## Using KindlyGuard in Claude

Once configured, Claude will automatically start KindlyGuard and you can use these tools:

### Security Scanning
```
# Scan text for threats
Use the scan_text tool to check "Hello\u202eWorld" for unicode attacks

# Scan for SQL injection
Use scan_text to check this query: SELECT * FROM users WHERE id = '1' OR '1'='1'

# Check for path traversal
Use scan_text to analyze: ../../etc/passwd
```

### Security Monitoring
```
# Get current security status
Use get_security_info tool

# Check shield protection status
Use get_shield_status tool
```

## Advanced Configuration

For custom settings, create a config file:

```toml
# ~/.config/kindly-guard.toml
[scanner]
unicode_detection = true
injection_detection = true
path_traversal_detection = true

[shield]
enabled = true

[rate_limit]
enabled = true
default_rpm = 60
```

Then update your MCP config:

```json
{
  "mcpServers": {
    "kindly-guard": {
      "command": "/path/to/kindly-guard/target/release/kindly-guard",
      "args": ["--stdio", "-c", "~/.config/kindly-guard.toml"],
      "env": {
        "RUST_LOG": "info"
      }
    }
  }
}
```

## Troubleshooting

1. **Check if KindlyGuard is running:**
   - Run `claude mcp` to see configured servers
   - Check Claude's logs for any startup errors

2. **Test the binary directly:**
   ```bash
   echo '{"jsonrpc": "2.0", "method": "initialize", "params": {"protocolVersion": "2024-11-05"}, "id": 1}' | /path/to/kindly-guard/target/release/kindly-guard --stdio
   ```

3. **Enable debug logging:**
   Update the env in your MCP config:
   ```json
   "env": {
     "RUST_LOG": "debug,kindly_guard=trace"
   }
   ```

## Features

- 🛡️ **Unicode Attack Detection**: Detects hidden characters, BiDi attacks, homoglyphs
- 💉 **Injection Prevention**: SQL, command, prompt, and template injection protection
- 📁 **Path Traversal Defense**: Blocks directory escape attempts
- 🔒 **Rate Limiting**: Protects against abuse
- 📊 **Security Monitoring**: Real-time threat statistics

KindlyGuard will automatically scan all text processed through Claude for security threats!