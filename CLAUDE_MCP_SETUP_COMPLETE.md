# KindlyGuard MCP Setup for Claude Desktop & Claude Code

## ✅ Setup Complete for Both!

KindlyGuard v0.15.0 is now configured as an MCP server for:
- **Claude Desktop** ✓
- **Claude Code** ✓

## Configuration Locations

### 1. Claude Desktop
**File**: `~/.config/claude/claude_desktop_config.json`
```json
"kindly-guard": {
  "command": "/home/samuel/.local/bin/kindly-guard-mcp",
  "args": [],
  "env": {
    "RUST_LOG": "info"
  },
  "type": "stdio"
}
```

### 2. Claude Code (Global MCP)
**File**: `~/.config/claude/mcp.json`
```json
{
  "mcpServers": {
    "kindly-guard": {
      "command": "/home/samuel/.local/bin/kindly-guard-mcp",
      "args": [],
      "env": {
        "RUST_LOG": "info"
      },
      "description": "KindlyGuard v0.15.0 - Enhanced threat protection..."
    }
  }
}
```

### 3. Wrapper Script
**File**: `/home/samuel/.local/bin/kindly-guard-mcp`
- Executable wrapper that launches KindlyGuard in MCP mode
- Works for both Claude Desktop and Claude Code

## Required Restarts

### For Claude Desktop:
1. Close Claude Desktop completely
2. Restart Claude Desktop
3. Type `/mcp` to verify KindlyGuard appears

### For Claude Code:
1. Restart Claude Code (or reload window with Ctrl+R)
2. KindlyGuard should be available automatically

## Testing in Each Environment

### In Claude Desktop:
```
/mcp
```
Should show:
- kindly-guard (Running) ✅

### In Claude Code:
The MCP server will be available for code security scanning. Try:
```
Can you scan this code for security issues?
```

## Available Tools in Both

- `scan_text` - Scan text with protection modes
- `scan_file` - Scan files for threats
- `scan_json` - Scan JSON data
- `get_security_info` - Security statistics
- `verify_signature` - Verify signatures
- `get_shield_status` - Shield status
- `quarantine/*` - Quarantine management

## Protection Modes

Both Claude Desktop and Claude Code support:
- **auto** - Automatically neutralize (default)
- **interactive** - Ask for confirmation
- **report** - Only report threats

## Example Usage

### Claude Desktop:
```
Please scan this SQL query for injection threats:
SELECT * FROM users WHERE id='$userid'
```

### Claude Code:
```
Check this code file for security vulnerabilities
```

## Troubleshooting

### If not working in Claude Desktop:
1. Check: `~/.config/claude/claude_desktop_config.json`
2. Verify wrapper exists: `ls -la /home/samuel/.local/bin/kindly-guard-mcp`
3. Test: `echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | /home/samuel/.local/bin/kindly-guard-mcp`

### If not working in Claude Code:
1. Check: `~/.config/claude/mcp.json`
2. Reload Claude Code window
3. Check Claude Code logs

## Features in v0.15.0

Both environments get access to:
- 🛡️ **Automatic Threat Neutralization**
- 🔒 **Encrypted Quarantine System**
- 💬 **Friendly Messaging** ("Kind to you, tough on threats")
- 🔄 **Three Protection Modes**
- 📊 **Real-time Statistics**

## Files Created/Modified

1. `/home/samuel/.local/bin/kindly-guard-mcp` - Wrapper script
2. `~/.config/claude/claude_desktop_config.json` - Claude Desktop config
3. `~/.config/claude/mcp.json` - Global MCP config (Claude Code)
4. Backups created with timestamps

## Next Steps

1. Restart both Claude Desktop and Claude Code
2. Test security scanning in each
3. Enjoy automatic threat protection!

---

KindlyGuard is now your security guardian in both Claude environments! 🛡️✨