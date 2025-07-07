# KindlyGuard MCP Server Setup for Claude Desktop

## ✅ Setup Complete!

KindlyGuard v0.15.0 has been configured as an MCP server for Claude Desktop.

## Configuration Added

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

## Next Steps

1. **Restart Claude Desktop** to load the new configuration
   - Close Claude Desktop completely
   - Start it again

2. **Verify in Claude Desktop**
   - Type `/mcp` in Claude
   - You should see "kindly-guard" in the list of available MCP servers
   - It should show as "Running" with a green status

## Available Tools

Once connected, you'll have access to these KindlyGuard tools:

- `scan_text` - Scan text for threats with protection modes
- `scan_file` - Scan files for security threats  
- `scan_json` - Scan JSON data
- `get_security_info` - Get security statistics
- `verify_signature` - Verify message signatures
- `get_shield_status` - Get shield status
- `quarantine/list` - List quarantined items
- `quarantine/retrieve` - Get quarantine entries
- `quarantine/delete` - Delete quarantine entries
- `quarantine/apply_retention` - Apply retention policies

## Example Usage in Claude

After restart, you can use KindlyGuard like this:

```
Can you scan this text for security threats: SELECT * FROM users WHERE id='1' OR '1'='1'
```

Claude will automatically use the KindlyGuard MCP server to scan and neutralize threats.

## Protection Modes

You can specify protection modes:
- **auto** - Automatically neutralize threats (default)
- **interactive** - Ask for confirmation
- **report** - Only report, don't modify

## Troubleshooting

If KindlyGuard doesn't appear in `/mcp`:

1. Check the wrapper script:
   ```bash
   ls -la /home/samuel/.local/bin/kindly-guard-mcp
   ```

2. Test the binary directly:
   ```bash
   /home/samuel/kindly-guard/target/debug/kindly-guard --stdio
   ```

3. Check Claude Desktop logs for errors

## Files Created

- `/home/samuel/.local/bin/kindly-guard-mcp` - Wrapper script
- Updated `~/.config/claude/claude_desktop_config.json`
- Backup at `~/.config/claude/claude_desktop_config.json.backup.*`