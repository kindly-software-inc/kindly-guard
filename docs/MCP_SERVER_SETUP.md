# KindlyGuard MCP Server Setup Guide

## Table of Contents
1. [Overview](#overview)
2. [Installation](#installation)
3. [Manual Installation](#manual-installation)
4. [Configuration](#configuration)
5. [Ensuring Persistence](#ensuring-persistence)
6. [Troubleshooting](#troubleshooting)
7. [Updating and Uninstalling](#updating-and-uninstalling)
8. [Usage Examples](#usage-examples)
9. [Security Considerations](#security-considerations)

## Overview

KindlyGuard is a high-performance security shield that integrates with Claude Code as an MCP (Model Context Protocol) server. It provides real-time protection against various security threats including:

- Unicode-based attacks and homograph attacks
- Injection attempts (SQL, command, script)
- XSS (Cross-Site Scripting) patterns
- Path traversal attempts
- Malformed input detection

### Key Features
- **Real-time scanning**: Monitors all inputs and outputs
- **MCP integration**: Seamlessly works with Claude Desktop
- **Performance optimized**: Minimal overhead with Rust implementation
- **Configurable modes**: Standard and enhanced protection levels
- **Comprehensive logging**: Detailed security event tracking

### Architecture
KindlyGuard operates as a stdio-based MCP server that:
1. Receives requests from Claude Desktop via JSON-RPC
2. Scans content for security threats
3. Returns results and maintains statistics
4. Provides real-time threat notifications

## Installation

### Prerequisites
- **Rust toolchain** (1.70 or later): Install from [rustup.rs](https://rustup.rs/)
- **Git**: For cloning the repository
- **Claude Desktop**: Latest version installed
- **Operating System**: Linux, macOS, or Windows

### Quick Installation Using Script

The easiest way to install KindlyGuard is using the provided installation script:

```bash
# Clone the repository
git clone https://github.com/samduchaine/kindly-guard.git
cd kindly-guard

# Run the installation script
./install_mcp_server.sh
```

The script will:
1. Check for Rust installation
2. Build the server in release mode
3. Install the binary to `~/.claude/mcp-servers/kindly-guard/`
4. Create a default configuration file
5. Update your `~/.mcp.json` to register the server
6. Verify the installation

### Post-Installation
After installation, restart Claude Desktop to load the new MCP server.

## Manual Installation

If you prefer manual installation or the script fails, follow these steps:

### Step 1: Build the Server

```bash
# Clone the repository
git clone https://github.com/samduchaine/kindly-guard.git
cd kindly-guard

# Build in release mode
cargo build --release --package kindly-guard-server
```

### Step 2: Create Installation Directory

```bash
# Create MCP servers directory
mkdir -p ~/.claude/mcp-servers/kindly-guard
```

### Step 3: Copy Binary and Create Configuration

```bash
# Copy the binary
cp target/release/kindly-guard-server ~/.claude/mcp-servers/kindly-guard/

# Make it executable
chmod +x ~/.claude/mcp-servers/kindly-guard/kindly-guard-server

# Create configuration file
cat > ~/.claude/mcp-servers/kindly-guard/config.toml << 'EOF'
# Kindly Guard Configuration
mode = "standard"
log_level = "info"

[rate_limit]
window_secs = 60
max_requests = 100

[scanner]
max_input_size = 1048576  # 1MB
patterns_file = ""

[metrics]
enabled = true
export_interval_secs = 60

[auth]
require_auth = false
EOF
```

### Step 4: Update MCP Configuration

Edit `~/.mcp.json` (create if it doesn't exist):

```json
{
  "mcpServers": {
    "kindly-guard": {
      "type": "stdio",
      "command": "/home/YOUR_USERNAME/.claude/mcp-servers/kindly-guard/kindly-guard-server",
      "args": ["--config", "/home/YOUR_USERNAME/.claude/mcp-servers/kindly-guard/config.toml"],
      "env": {}
    }
  }
}
```

Replace `YOUR_USERNAME` with your actual username.

### Step 5: Verify Installation

```bash
# Test the binary
~/.claude/mcp-servers/kindly-guard/kindly-guard-server --version

# Check MCP configuration
cat ~/.mcp.json | jq '.mcpServers."kindly-guard"'
```

## Configuration

### Configuration File Location
Default: `~/.claude/mcp-servers/kindly-guard/config.toml`

### Configuration Options

```toml
# Operating mode: "standard" or "enhanced"
mode = "standard"

# Logging level: "error", "warn", "info", "debug", "trace"
log_level = "info"

# Server configuration
[server]
# Not used for stdio mode
host = "127.0.0.1"
port = 3000

# Rate limiting
[rate_limit]
window_secs = 60        # Time window in seconds
max_requests = 100      # Max requests per window

# Security scanner settings
[scanner]
max_input_size = 1048576           # Max input size in bytes (1MB)
patterns_file = ""                 # Custom patterns file (optional)
unicode_normalization = true       # Enable Unicode normalization
detect_homographs = true          # Detect homograph attacks
detect_invisible_chars = true     # Detect invisible characters

# Metrics collection
[metrics]
enabled = true
export_interval_secs = 60
retention_hours = 24

# Authentication (for future use)
[auth]
require_auth = false
# auth_token = ""

# Performance tuning
[performance]
scanner_threads = 4               # Number of scanner threads
batch_size = 100                 # Batch processing size
cache_size = 1000               # Pattern cache size

# Enhanced mode settings (if available)
[enhanced]
enabled = false
atomic_operations = true
zero_copy_buffers = true
shared_memory = false
```

### Environment Variables

You can also configure the server using environment variables:

```bash
# Set in ~/.mcp.json
{
  "mcpServers": {
    "kindly-guard": {
      "type": "stdio",
      "command": "...",
      "args": ["..."],
      "env": {
        "RUST_LOG": "info",
        "KINDLY_GUARD_MODE": "standard",
        "KINDLY_GUARD_MAX_INPUT_SIZE": "2097152"
      }
    }
  }
}
```

## Ensuring Persistence

### 1. Automatic Startup with Claude Desktop

The MCP configuration in `~/.mcp.json` ensures KindlyGuard starts automatically when Claude Desktop launches.

### 2. Backup Configuration

Create backups of your configuration:

```bash
# Backup MCP configuration
cp ~/.mcp.json ~/.mcp.json.backup

# Backup KindlyGuard configuration
cp ~/.claude/mcp-servers/kindly-guard/config.toml \
   ~/.claude/mcp-servers/kindly-guard/config.toml.backup
```

### 3. Version Pinning

To ensure consistency across updates:

```bash
# Save current version
~/.claude/mcp-servers/kindly-guard/kindly-guard-server --version > \
  ~/.claude/mcp-servers/kindly-guard/VERSION
```

### 4. System Service (Optional)

For system-wide protection, create a systemd service:

```ini
# /etc/systemd/system/kindly-guard.service
[Unit]
Description=KindlyGuard Security Shield
After=network.target

[Service]
Type=simple
User=YOUR_USERNAME
ExecStart=/home/YOUR_USERNAME/.claude/mcp-servers/kindly-guard/kindly-guard-server \
  --config /home/YOUR_USERNAME/.claude/mcp-servers/kindly-guard/config.toml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## Troubleshooting

### Common Issues

#### 1. Server Not Starting

**Symptoms**: Claude Desktop doesn't show KindlyGuard in available MCP servers

**Solutions**:
```bash
# Check binary permissions
ls -la ~/.claude/mcp-servers/kindly-guard/kindly-guard-server

# Test binary directly
~/.claude/mcp-servers/kindly-guard/kindly-guard-server --help

# Check logs
RUST_LOG=debug ~/.claude/mcp-servers/kindly-guard/kindly-guard-server
```

#### 2. Configuration Errors

**Symptoms**: Server starts but behaves unexpectedly

**Solutions**:
```bash
# Validate TOML syntax
cat ~/.claude/mcp-servers/kindly-guard/config.toml | python3 -m toml

# Check JSON syntax
cat ~/.mcp.json | jq .

# Use minimal configuration
mv config.toml config.toml.bak
echo 'mode = "standard"' > config.toml
```

#### 3. Permission Issues

**Symptoms**: "Permission denied" errors

**Solutions**:
```bash
# Fix binary permissions
chmod +x ~/.claude/mcp-servers/kindly-guard/kindly-guard-server

# Fix directory permissions
chmod 755 ~/.claude/mcp-servers/kindly-guard
chmod 644 ~/.claude/mcp-servers/kindly-guard/config.toml
```

#### 4. High Resource Usage

**Symptoms**: High CPU or memory usage

**Solutions**:
```toml
# Adjust configuration
[performance]
scanner_threads = 2      # Reduce threads
batch_size = 50         # Smaller batches
cache_size = 500        # Smaller cache

[scanner]
max_input_size = 524288  # 512KB limit
```

### Debug Mode

Enable detailed logging for troubleshooting:

```json
// In ~/.mcp.json
"env": {
  "RUST_LOG": "kindly_guard=debug,mcp=debug",
  "RUST_BACKTRACE": "1"
}
```

### Log Locations

- **Server logs**: Sent to stderr, visible in Claude Desktop developer console
- **Custom log file**: Configure in config.toml:
  ```toml
  [logging]
  file = "/tmp/kindly-guard.log"
  ```

## Updating and Uninstalling

### Updating KindlyGuard

```bash
# Navigate to repository
cd /path/to/kindly-guard
git pull

# Rebuild and reinstall
./install_mcp_server.sh
```

### Manual Update

```bash
# Backup current installation
cp -r ~/.claude/mcp-servers/kindly-guard \
      ~/.claude/mcp-servers/kindly-guard.backup

# Build new version
cd /path/to/kindly-guard
git pull
cargo build --release --package kindly-guard-server

# Replace binary
cp target/release/kindly-guard-server \
   ~/.claude/mcp-servers/kindly-guard/

# Restart Claude Desktop
```

### Uninstalling

```bash
# Remove installation directory
rm -rf ~/.claude/mcp-servers/kindly-guard

# Remove from MCP configuration
# Edit ~/.mcp.json and remove the "kindly-guard" entry

# Or use jq to remove it
jq 'del(.mcpServers."kindly-guard")' ~/.mcp.json > ~/.mcp.json.tmp && \
  mv ~/.mcp.json.tmp ~/.mcp.json
```

## Usage Examples

### Basic Text Scanning

When KindlyGuard is active, it automatically scans all inputs. You can also use it programmatically:

```typescript
// Claude will have access to these tools
await mcp.call('scan_text', {
  text: 'Check this text for threats'
});
```

### File Scanning

```typescript
await mcp.call('scan_file', {
  path: '/path/to/file.txt'
});
```

### Getting Statistics

```typescript
const stats = await mcp.call('get_statistics', {});
console.log(`Threats detected: ${stats.threats_detected}`);
console.log(`Scans performed: ${stats.total_scans}`);
```

### Integration with Claude Code

KindlyGuard automatically protects:
- User inputs and prompts
- File contents being processed
- Code snippets and scripts
- API responses and data

### Performance Monitoring

Monitor KindlyGuard's performance:

```bash
# View real-time metrics
curl http://localhost:3000/metrics  # If web interface enabled

# Or check logs
tail -f /tmp/kindly-guard.log | grep METRICS
```

## Security Considerations

### 1. Local-Only Operation

KindlyGuard runs entirely locally:
- No external network connections
- No data sent to remote servers
- All processing happens on your machine

### 2. Input Validation

All inputs are validated for:
- Size limits (configurable)
- Format compliance
- Resource consumption

### 3. Rate Limiting

Built-in protection against:
- Denial of Service attempts
- Resource exhaustion
- Excessive API calls

### 4. Secure Communication

MCP communication is:
- Local stdio only (no network exposure)
- JSON-RPC validated
- Input sanitized

### 5. Privacy

KindlyGuard:
- Doesn't store sensitive data
- Doesn't log full content (only metadata)
- Respects user privacy

### 6. Updates and Patches

Keep KindlyGuard updated:
```bash
# Check for updates
cd /path/to/kindly-guard
git fetch
git status

# View changelog
git log --oneline -10
```

### 7. Audit Trail

Enable comprehensive logging for security audits:

```toml
[audit]
enabled = true
log_file = "/var/log/kindly-guard-audit.log"
log_rotation = "daily"
retention_days = 30
```

### Best Practices

1. **Regular Updates**: Keep KindlyGuard updated for latest security patches
2. **Configuration Review**: Periodically review and adjust settings
3. **Monitor Logs**: Check logs for unusual patterns
4. **Resource Limits**: Set appropriate limits for your system
5. **Backup Configuration**: Maintain configuration backups

## Support and Resources

- **GitHub Repository**: [https://github.com/samduchaine/kindly-guard](https://github.com/samduchaine/kindly-guard)
- **Issue Tracker**: [GitHub Issues](https://github.com/samduchaine/kindly-guard/issues)
- **Documentation**: [Project Documentation](https://github.com/samduchaine/kindly-guard/tree/main/docs)
- **MCP Specification**: [Model Context Protocol](https://modelcontextprotocol.io/)

For additional help or questions, please open an issue on GitHub or consult the project documentation.