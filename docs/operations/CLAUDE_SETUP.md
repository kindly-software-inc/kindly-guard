# Setting up KindlyGuard with Claude Desktop

## Quick Setup (2 Minutes)

### 1. Install KindlyGuard

```bash
# Install via npm (recommended - no compilation needed!)
npm install -g kindlyguard
```

### 2. Configure Claude Desktop

```bash
# Automatic setup
kindlyguard mcp setup
```

That's it! Restart Claude Desktop and you're protected.

## Manual Configuration

If you prefer manual setup, edit your Claude Desktop config:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`  
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`  
**Linux**: `~/.config/Claude/claude_desktop_config.json`

Add this configuration:

```json
{
  "mcpServers": {
    "kindlyguard": {
      "command": "kindlyguard",
      "args": ["serve", "--stdio"],
      "env": {
        "RUST_LOG": "info"
      }
    }
  }
}
```

## Using KindlyGuard in Claude

Once configured, Claude will automatically start KindlyGuard. You now have access to multiple security tools:

### Available MCP Tools

1. **scan_text** - Scan text for threats
   ```
   Use scan_text to check "Hello\u202eWorld" for unicode attacks
   ```

2. **scan_file** - Scan files with quarantine support
   ```
   Use scan_file to check "/path/to/file.txt" with quarantine enabled
   ```

3. **check_url** - Validate URLs for safety
   ```
   Use check_url to validate "https://example.com"
   ```

4. **neutralize** - Clean threats from content
   ```
   Use neutralize to clean "dangerous'; DROP TABLE users;--"
   ```

5. **quarantine_list** - View quarantined threats
   ```
   Use quarantine_list to see all active quarantined items
   ```

6. **get_statistics** - Real-time security metrics
   ```
   Use get_statistics to see current security status
   ```

### Example Conversations

**Checking for SQL Injection:**
```
Claude, please use scan_text to check this query for SQL injection:
SELECT * FROM users WHERE id = '1' OR '1'='1'
```

**Scanning a file:**
```
Can you scan the file at /home/user/upload.txt for security threats?
```

**Viewing security status:**
```
Show me the current security statistics
```

## Advanced Configuration

For custom settings, create a config file:

```toml
# ~/.kindlyguard/config.toml
[protection]
mode = "auto"  # auto, interactive, or report

[scanner]
unicode_detection = true
injection_detection = true
path_traversal_detection = true
sensitivity = "balanced"  # low, balanced, high

[quarantine]
enabled = true
encrypt = true
retention_days = 90

[monitoring]
real_time_alerts = true
```

Then update your Claude Desktop config:

```json
{
  "mcpServers": {
    "kindlyguard": {
      "command": "kindlyguard",
      "args": ["serve", "--stdio", "--config", "~/.kindlyguard/config.toml"],
      "env": {
        "RUST_LOG": "info"
      }
    }
  }
}
```

## Protection Modes

- **Auto-Protect** (default): Automatically neutralizes threats
- **Interactive**: Asks before taking action
- **Report-Only**: Just reports, doesn't modify

Set via environment variable:
```bash
export KINDLYGUARD_PROTECTION_MODE=interactive
```

## Troubleshooting

### Verify Installation

```bash
# Check if KindlyGuard is installed
kindlyguard --version

# Verify MCP configuration
kindlyguard mcp verify

# Check MCP status
kindlyguard mcp status
```

### Common Issues

1. **Claude Desktop doesn't see KindlyGuard:**
   - Restart Claude Desktop after configuration
   - Check the config file location is correct
   - Run `kindlyguard mcp setup` again

2. **Tools not responding:**
   - Enable debug logging: `RUST_LOG=debug`
   - Check Claude Desktop developer console
   - Test directly: `echo '{"text":"test"}' | kindlyguard serve`

3. **Permission errors:**
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