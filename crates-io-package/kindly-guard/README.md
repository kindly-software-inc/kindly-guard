# KindlyGuard

Security-focused MCP (Model Context Protocol) server for AI protection.

## Installation

Install KindlyGuard using cargo:

```bash
cargo install kindly-guard
```

This will install the `kindly-guard` command, which is the actual KindlyGuard server.

## What is KindlyGuard?

KindlyGuard is a security-focused MCP server designed to protect AI systems from various threats including:

- **Unicode Attacks**: Detection and prevention of invisible characters and bidirectional text exploits
- **Injection Attempts**: Protection against prompt injection and command injection attacks  
- **Real-time Monitoring**: Live threat detection and response
- **MCP Protocol Hardening**: Security enhancements for the Model Context Protocol

## Usage

After installation, you can use KindlyGuard as an MCP server:

```bash
# Start the MCP server
kindly-guard --stdio

# Or with a config file
kindly-guard --config /path/to/config.toml

# View all options
kindly-guard --help
```

## Features

- **Security Scanner**: Advanced threat detection for unicode attacks, injections, and XSS
- **Real-time Shield**: Live monitoring dashboard showing threat statistics
- **Neutralizer**: Automatic threat mitigation and sanitization
- **Resilience**: Built-in circuit breakers and retry logic for fault tolerance
- **Storage**: SQLite-based persistence for threat history and audit logs

## Configuration

KindlyGuard can be configured via a TOML file. Example configuration:

```toml
[server]
host = "127.0.0.1"
port = 8080

[scanner]
unicode_enabled = true
injection_enabled = true
xss_enabled = true

[resilience]
[resilience.circuit_breaker]
failure_threshold = 5
recovery_timeout = "30s"
```

## MCP Integration

KindlyGuard implements the Model Context Protocol (MCP) and can be used with any MCP-compatible client. It provides tools for:

- Text scanning and validation
- Security analysis of prompts
- Threat reporting and monitoring

## Source Code

The complete KindlyGuard implementation is available at:
<https://github.com/samduchaine/kindly-guard>

## License

This project is licensed under the Apache License, Version 2.0.

## Author

Created by samduchaine