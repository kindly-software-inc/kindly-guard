# KindlyGuard

Security-focused MCP (Model Context Protocol) server for AI protection.

## Installation

Install KindlyGuard using cargo:

```bash
cargo install kindly-guard
```

This will install the `kindly-guard` command, which automatically downloads and manages the KindlyGuard binary for your platform.

## What is KindlyGuard?

KindlyGuard is a security-focused MCP server designed to protect AI systems from various threats including:

- **Unicode Attacks**: Detection and prevention of invisible characters and bidirectional text exploits
- **Injection Attempts**: Protection against prompt injection and command injection attacks  
- **Real-time Monitoring**: Live threat detection and response
- **MCP Protocol Hardening**: Security enhancements for the Model Context Protocol

## Usage

After installation, simply run:

```bash
# Start the MCP server
kindly-guard --stdio

# Or with a config file
kindly-guard --config /path/to/config.toml

# View all options
kindly-guard --help
```

The installer will automatically download the appropriate binary for your platform on first run.

## Supported Platforms

- Linux x86_64
- Linux aarch64
- macOS x86_64 (Intel)
- macOS aarch64 (Apple Silicon)
- Windows x86_64

## Binary Management

The KindlyGuard binary is installed to `~/.kindlyguard/bin/`. To update to the latest version:

```bash
kindlyguard --force-download
```

## Source Code

The complete KindlyGuard implementation is available at:
<https://github.com/samduchaine/kindly-guard>

## License

This project is licensed under the Apache License, Version 2.0.

## Author

Created by samduchaine