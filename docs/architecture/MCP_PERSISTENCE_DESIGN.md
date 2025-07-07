# KindlyGuard MCP Persistence

## How It Works

KindlyGuard persistence is automatic once properly installed. No additional scripts or configuration needed.

### Automatic Startup

When configured in `~/.mcp.json`, KindlyGuard automatically starts when Claude Code launches. The configuration acts as the persistence mechanism:

```json
{
  "mcpServers": {
    "kindly-guard": {
      "type": "stdio",
      "command": "/home/samuel/.claude/mcp-servers/kindly-guard/kindly-guard",
      "args": ["--config", "/home/samuel/.claude/mcp-servers/kindly-guard/config.toml"],
      "env": {}
    }
  }
}
```

### Installation Verification

To verify KindlyGuard persists across sessions:

1. **Check Installation**:
   ```bash
   ./verify_mcp_setup.sh
   ```

2. **Restart Claude Code**:
   - Close Claude Code completely
   - Reopen Claude Code
   - KindlyGuard will start automatically

3. **Verify in Claude Code**:
   - The MCP icon should appear
   - Tools from KindlyGuard should be available

### Standard MCP Practice

This follows standard MCP server practices:
- No daemon processes needed
- No shell scripts required
- No systemd services necessary
- Configuration-driven startup

### Troubleshooting Persistence Issues

If KindlyGuard doesn't start automatically:

1. **Check Binary Path**: Ensure the path in `~/.mcp.json` points to the actual binary
2. **Verify Permissions**: Binary must be executable (`chmod +x`)
3. **Check Logs**: Look for errors in Claude Code developer console
4. **Validate JSON**: Ensure `~/.mcp.json` is valid JSON

### Updating KindlyGuard

To update while maintaining persistence:

```bash
# Rebuild
cd /home/samuel/kindly-guard
cargo build --release

# Copy new binary
cp target/release/kindly-guard ~/.claude/mcp-servers/kindly-guard/

# Restart Claude Code to load new version
```

The MCP configuration remains unchanged, ensuring continued persistence.