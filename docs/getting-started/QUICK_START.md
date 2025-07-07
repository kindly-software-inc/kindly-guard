# KindlyGuard Quick Start - Protected in 2 Minutes

Get immediate protection against unicode attacks, injection attempts, and security threats for your Claude Desktop.

## 1. One-Command Installation

```bash
# Install KindlyGuard with npm - no compilation needed!
npm install -g kindlyguard
```

That's it! The unified `kindlyguard` binary includes everything:
- MCP Security Server
- CLI Scanner Tools
- Real-time Monitor  
- Shield Display
- All protection features

## 2. Enable Protection for Claude Desktop

```bash
# Configure Claude Desktop to use KindlyGuard
kindlyguard mcp setup

# Start protected MCP server (stdio mode is default)
kindlyguard serve
```

Your Claude Desktop is now protected! KindlyGuard will scan all inputs and neutralize threats automatically.

## 3. Essential CLI Commands

```bash
# Scan a file for threats
kindlyguard scan suspicious_file.json

# Monitor threats in real-time
kindlyguard monitor

# Start server with shield display
kindlyguard serve --shield

# Check MCP status
kindlyguard mcp status

# List all MCP servers
kindlyguard mcp list
```

## 4. Verify Protection is Working

Test your protection with these commands:

```bash
# Test unicode attack detection
echo 'Hello\u202EWorld' | kindlyguard scan -

# Test injection detection  
echo "'; DROP TABLE users; --" | kindlyguard scan -

# Check the monitor to see blocked threats
kindlyguard monitor
```

You should see threats detected and neutralized in the output.

## 5. Next Steps

### Customize Security Rules
```bash
# Edit configuration
kindlyguard config edit

# View current configuration
kindlyguard config show

# Set protection mode
kindlyguard config set protection.mode interactive
```

### MCP Multi-Tool Features
```bash
# The unified binary provides multiple MCP tools:
# - scan_text: Scan text for threats
# - scan_file: Scan files with quarantine
# - check_url: Validate URLs
# - neutralize: Clean threats
# - quarantine_list: View isolated threats

# All available through the MCP protocol!
```

### Enable Advanced Features  
```bash
# Enable enhanced performance mode (Pro)
cargo build --release --features enhanced

# Setup persistent storage
kindlyguard config set storage.enabled true
```

### Integration Options
- **VS Code**: Install the KindlyGuard extension
- **CI/CD**: Add `kindly-guard scan` to your pipeline
- **API**: Use as a library in your Rust projects

## Need Help?

- Run `kindlyguard --help` for all commands
- Check logs: `RUST_LOG=debug kindlyguard serve`
- View MCP tools: `kindlyguard mcp list`
- Report issues: https://github.com/kindly-software-inc/kindly-guard/issues

---

**You're protected!** KindlyGuard is now actively scanning and neutralizing threats in your Claude Desktop environment.