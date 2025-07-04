# KindlyGuard v0.9.2 - Linux x64

Security-focused MCP (Model Context Protocol) server that protects against unicode attacks, injection attempts, and other threats.

## Installation

1. Extract the archive to your desired location
2. Add the `bin` directory to your PATH, or run the binaries directly

## Binaries Included

- `kindlyguard` - Main MCP server binary
- `kindlyguard-cli` - Command-line interface for scanning and configuration

## Quick Start

### Running the MCP Server
```bash
./bin/kindlyguard --stdio
```

### Using the CLI
```bash
# Scan a file for threats
./bin/kindlyguard-cli scan suspicious_file.json

# Start server with monitoring
./bin/kindlyguard-cli server --monitor

# View configuration
./bin/kindlyguard-cli config show
```

## System Requirements

- Linux x64 (tested on Ubuntu 20.04+, Debian 10+, Fedora 34+)
- glibc 2.31 or later
- 512MB RAM minimum (1GB recommended)

## Configuration

Create a `kindlyguard.toml` file in your config directory:
- Linux: `~/.config/kindlyguard/kindlyguard.toml`

Example configuration:
```toml
[server]
port = 3000
max_connections = 100

[security]
unicode_detection = true
injection_prevention = true
xss_protection = true

[logging]
level = "info"
```

## Support

- Documentation: https://github.com/samuelbmarks/kindly-guard/wiki
- Issues: https://github.com/samuelbmarks/kindly-guard/issues

## License

Apache-2.0