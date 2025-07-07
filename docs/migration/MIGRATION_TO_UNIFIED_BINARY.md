# Migration Guide: Upgrading to KindlyGuard Unified Binary

This guide helps you migrate from KindlyGuard v0.14.x (multiple binaries) to v0.15.0+ (unified binary).

## Overview of Changes

### What's New
- **Single Binary**: All functionality in one `kindlyguard` command
- **npm Installation**: Instant setup without compilation
- **MCP Multi-Tool**: Multiple security tools in one MCP server
- **Simplified Commands**: Consistent interface across all features

### What's Deprecated
- Separate binaries: `kindly-guard`, `kindly-tools`, `kindly-shield`
- Complex build processes
- Multiple MCP server configurations

## Step-by-Step Migration

### 1. Backup Current Configuration

```bash
# Backup your current configuration
cp ~/.config/kindly-guard/config.toml ~/.config/kindly-guard/config.toml.backup

# If using Claude Desktop, backup MCP config
cp ~/Library/Application\ Support/Claude/claude_desktop_config.json ~/claude_config_backup.json
```

### 2. Uninstall Old Versions

```bash
# Remove cargo-installed binaries
cargo uninstall kindly-guard kindly-tools kindly-shield

# Remove from system paths (if manually installed)
sudo rm -f /usr/local/bin/kindly-guard
sudo rm -f /usr/local/bin/kindly-tools
sudo rm -f /usr/local/bin/kindly-shield
sudo rm -f /usr/local/bin/kindly
```

### 3. Install Unified Binary

```bash
# Install via npm (recommended)
npm install -g kindlyguard

# Verify installation
kindlyguard --version
```

### 4. Update Configuration Files

#### Configuration Location
Move configuration to the new location:

```bash
# Create new config directory
mkdir -p ~/.kindlyguard

# Move existing config
mv ~/.config/kindly-guard/config.toml ~/.kindlyguard/config.toml
```

#### Configuration Updates
Update any configuration references:

```toml
# Old format
[server]
binary = "kindly-guard-server"

# New format (remove binary references)
[server]
port = 8080
stdio = true
```

### 5. Update Claude Desktop Configuration

#### Old Configuration
```json
{
  "mcpServers": {
    "kindly-guard": {
      "command": "/path/to/kindly-guard",
      "args": ["--stdio"]
    }
  }
}
```

#### New Configuration
```json
{
  "mcpServers": {
    "kindlyguard": {
      "command": "kindlyguard",
      "args": ["serve", "--stdio"]
    }
  }
}
```

Or use automatic setup:
```bash
kindlyguard mcp setup
```

### 6. Update Scripts and Aliases

#### Shell Scripts
Update any scripts that reference old binaries:

```bash
# Old
kindly-guard server --stdio
kindly-tools scan file.txt
kindly monitor

# New
kindlyguard serve
kindlyguard scan file.txt
kindlyguard monitor
```

#### Shell Aliases
Update your `.bashrc`, `.zshrc`, or shell profile:

```bash
# Remove old aliases
unalias kindly 2>/dev/null
unalias kg 2>/dev/null

# Add new aliases
alias kg='kindlyguard'
alias kgs='kindlyguard serve'
alias kgm='kindlyguard monitor'
```

### 7. Update CI/CD Pipelines

#### GitHub Actions
```yaml
# Old
- name: Install KindlyGuard
  run: |
    cargo install kindly-guard kindly-tools

# New
- name: Install KindlyGuard
  run: |
    npm install -g kindlyguard
```

#### Docker
```dockerfile
# Old
FROM rust:latest
RUN cargo install kindly-guard kindly-tools

# New
FROM node:lts-alpine
RUN npm install -g kindlyguard
```

## Command Mapping Reference

| Old Command | New Command | Notes |
|------------|-------------|-------|
| `kindly-guard --stdio` | `kindlyguard serve` | Default stdio mode |
| `kindly-guard server --http` | `kindlyguard serve --http` | HTTP API mode |
| `kindly-tools scan` | `kindlyguard scan` | Same functionality |
| `kindly-tools wrap` | `kindlyguard wrap` | Same functionality |
| `kindly-tools monitor` | `kindlyguard monitor` | Same functionality |
| `kindly-shield` | `kindlyguard shield` | Interactive UI |
| `kindly config` | `kindlyguard config` | Configuration management |
| N/A | `kindlyguard mcp` | New MCP management commands |
| N/A | `kindlyguard dev` | New development mode |

## New Features to Explore

### MCP Multi-Tool Support
The unified binary exposes multiple tools through MCP:
- `scan_text` - Text scanning
- `scan_file` - File scanning with quarantine
- `check_url` - URL validation
- `neutralize` - Threat cleaning
- `quarantine_list` - View quarantined items
- `get_statistics` - Security metrics

### Development Mode
```bash
# Start all services for development
kindlyguard dev
```

### MCP Management
```bash
# Configure MCP integration
kindlyguard mcp setup

# Check MCP status
kindlyguard mcp status

# List MCP servers
kindlyguard mcp list
```

## Troubleshooting

### Binary Not Found
If `kindlyguard` is not found after npm installation:

```bash
# Check npm global bin directory
npm bin -g

# Add to PATH if needed
export PATH="$(npm bin -g):$PATH"
```

### Permission Issues
```bash
# If you get permission errors
sudo npm install -g kindlyguard

# Or use a Node version manager (recommended)
nvm use 18
npm install -g kindlyguard
```

### Configuration Not Loading
```bash
# Check config location
kindlyguard config show

# Verify config syntax
kindlyguard config validate
```

### Claude Desktop Not Connecting
```bash
# Verify MCP setup
kindlyguard mcp verify

# Re-run setup
kindlyguard mcp setup
```

## Getting Help

- **Documentation**: https://docs.kindlyguard.com
- **GitHub Issues**: https://github.com/kindly-software-inc/kindly-guard/issues
- **Discord**: https://discord.gg/kindlyguard

## Rollback Plan

If you need to rollback to the previous version:

```bash
# Uninstall unified binary
npm uninstall -g kindlyguard

# Reinstall old versions
cargo install --version 0.14.0 kindly-guard
cargo install --version 0.14.0 kindly-tools

# Restore old configuration
mv ~/.config/kindly-guard/config.toml.backup ~/.config/kindly-guard/config.toml
```

---

Welcome to the simplified world of KindlyGuard v0.15.0+!