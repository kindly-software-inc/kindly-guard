# KindlyTools 🛠️

**Development tools and utilities for the KindlyGuard ecosystem**

KindlyTools provides a comprehensive set of command-line utilities for working with KindlyGuard, including installation management, MCP server configuration, security scanning, and development tools.

## Installation

```bash
# From source
cargo install --path .

# Or via cargo (when published)
cargo install kindly-tools
```

## Commands

### 🛡️ `shield` - AI CLI Protection (NEW!)

Automatically wrap AI CLI commands with security scanning to protect against prompt injection and other threats.

```bash
# Generate shell wrappers for AI commands
kindly shield auto-wrap -o ~/.kindly-shield.sh

# Add to your shell config
echo "source ~/.kindly-shield.sh" >> ~/.bashrc

# Now AI commands are automatically protected
claude "Help me write a script"  # Scanned for threats before execution
```

**[Full Shield Documentation](../docs/SHIELD_AUTO_WRAP.md)**

### 📊 `scan` - Security Scanning

Scan files or directories for security threats using the KindlyGuard scanner.

```bash
# Scan a single file
kindly scan suspicious.json

# Scan directory recursively
kindly scan ./src --recursive

# Output as JSON
kindly scan data.txt --format json

# Scan specific file types
kindly scan . --recursive --extensions json,txt,md
```

### 🎁 `install` - Component Installation

Install KindlyGuard components and dependencies with automatic platform detection.

```bash
# Install everything (recommended)
kindly install all

# Install specific components
kindly install kindlyguard    # Core KindlyGuard
kindly install mcp-servers    # Recommended MCP servers
kindly install dev-deps       # Development dependencies

# Platform-specific installation
kindly install --platform linux-gnu
```

### 🔌 `mcp` - MCP Server Management

Manage Model Context Protocol servers and configuration.

```bash
# List MCP servers
kindly mcp list

# Check server status
kindly mcp status

# Restart a server
kindly mcp restart kindlyguard

# Validate configuration
kindly mcp validate
```

### 🚀 `wrap` - Command Wrapping

Wrap any command with KindlyGuard protection.

```bash
# Wrap a command execution
kindly wrap -- curl -X POST https://api.example.com -d "data"

# Block on threat detection
kindly wrap --block -- python script.py "user input"

# Use custom server
kindly wrap --server http://localhost:8080 -- node app.js
```

### 📈 `monitor` - Server Monitoring

Monitor KindlyGuard server status in real-time.

```bash
# Monitor default server
kindly monitor

# Monitor specific server
kindly monitor --url http://localhost:8080

# Custom update interval
kindly monitor --interval 10
```

### 🔧 `dev` - Development Tools

Development utilities for working with KindlyGuard.

```bash
# Generate shell completions
kindly dev completions bash > /etc/bash_completion.d/kindly

# Check project setup
kindly dev check

# Run benchmarks
kindly dev bench
```

## Configuration

KindlyTools uses TOML configuration files:

### Global Config
`~/.kindlyguard/tools.toml`
```toml
[general]
default_server = "http://localhost:8080"
color_output = true

[scan]
default_format = "table"
max_file_size_mb = 10

[shield]
default_shell = "bash"
auto_wrap_commands = ["claude", "openai", "gemini"]
```

### Project Config
`.kindlyguard.toml` in project root
```toml
[project]
name = "my-project"
scan_extensions = ["js", "ts", "json"]
exclude_patterns = ["node_modules", "dist"]
```

## Environment Variables

- `KINDLY_SERVER_URL` - Default KindlyGuard server URL
- `KINDLY_CONFIG_DIR` - Configuration directory (default: `~/.kindlyguard`)
- `KINDLY_SHIELD_DISABLED` - Disable shield protection temporarily
- `NO_COLOR` - Disable colored output

## Examples

### CI/CD Integration
```yaml
# GitHub Actions
- name: Security Scan
  run: |
    cargo install kindly-tools
    kindly scan . --recursive --format json > scan-results.json
```

### Docker Usage
```dockerfile
FROM rust:latest
RUN cargo install kindly-tools
RUN kindly shield auto-wrap -o /etc/profile.d/kindly-shield.sh
```

### Shell Integration
```bash
# Add to ~/.bashrc or ~/.zshrc
if command -v kindly &> /dev/null; then
    source <(kindly dev completions bash)
    source ~/.kindly-shield.sh
fi
```

## Troubleshooting

### "Command not found"
Ensure `~/.cargo/bin` is in your PATH:
```bash
export PATH="$HOME/.cargo/bin:$PATH"
```

### MCP Connection Issues
```bash
# Validate MCP configuration
kindly mcp validate

# Check server logs
kindly mcp logs kindlyguard
```

### Performance Issues
```bash
# Run diagnostics
kindly dev diagnose

# Check system resources
kindly monitor --verbose
```

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for development setup and guidelines.

## License

Apache-2.0 - See [LICENSE](../LICENSE) for details.