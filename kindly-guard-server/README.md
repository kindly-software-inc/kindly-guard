# KindlyGuard Server

A security-focused MCP (Model Context Protocol) server that protects AI model interactions from various threats including Unicode attacks, injection attempts, and malicious patterns.

## Features

- **🛡️ Comprehensive Threat Detection**
  - Unicode exploit detection (invisible characters, BiDi attacks, homographs)
  - Injection prevention (SQL, command, path traversal, prompt injection)
  - Real-time threat scanning with visual shield indicator

- **🔐 Enterprise Security**
  - OAuth 2.0 with Resource Indicators (RFC 8707)
  - Ed25519 message signing and verification
  - Fine-grained tool-level permissions
  - Configurable rate limiting with circuit breakers

- **⚡ High Performance**
  - Lock-free concurrent operations
  - Zero-copy scanning algorithms
  - Optimized pattern matching

- **🎯 MCP Protocol Compliance**
  - Full JSON-RPC 2.0 implementation
  - Standard MCP tools and resources
  - Compatible with all MCP clients

## Installation

### From crates.io
```bash
cargo install kindly-guard-server
```

### From source
```bash
git clone https://github.com/kindlyguard/kindly-guard
cd kindly-guard
cargo build --release
```

## Quick Start

1. Create a configuration file:
```yaml
# kindly-guard.yaml
scanner:
  unicode_detection: true
  injection_detection: true

auth:
  enabled: true
  allowed_clients:
    - client_id: "my-app"
      secret: "change-me"
      allowed_scopes: ["tools:execute"]
```

2. Start the server:
```bash
kindly-guard --stdio
```

3. Connect with any MCP client!

## Usage

### Stdio Mode (Recommended for MCP)
```bash
kindly-guard --stdio
```

### With Configuration
```bash
kindly-guard --config /path/to/config.yaml --stdio
```

### Systemd Service
```bash
# Install service
sudo ./systemd/install.sh

# Start service
sudo systemctl start kindly-guard
```

## Configuration

See [CONFIGURATION.md](https://github.com/kindlyguard/kindly-guard/blob/main/docs/CONFIGURATION.md) for detailed configuration options.

### Minimal Configuration
```yaml
scanner:
  unicode_detection: true
  injection_detection: true

auth:
  enabled: false  # Only for testing!
```

### Production Configuration
```yaml
scanner:
  unicode_detection: true
  injection_detection: true
  max_scan_depth: 10

auth:
  enabled: true
  require_resource_indicators: true
  allowed_clients:
    - client_id: "production-app"
      secret: "$2b$10$..."  # bcrypt hash
      allowed_scopes: ["tools:execute", "resources:read"]

rate_limit:
  enabled: true
  default_rpm: 60
  threat_penalty_multiplier: 2.0

signing:
  enabled: true
  private_key_path: "/etc/kindly-guard/keys/private.pem"
```

## Tools

### scan_text
Scan text for security threats:
```json
{
  "name": "scan_text",
  "arguments": {
    "text": "Check this content",
    "context": "user_input"
  }
}
```

### verify_signature
Verify message signatures:
```json
{
  "name": "verify_signature",
  "arguments": {
    "message": "Important data",
    "signature": "base64-signature"
  }
}
```

### get_security_info
Get security information:
```json
{
  "name": "get_security_info",
  "arguments": {
    "topic": "unicode"
  }
}
```

## Security Features

### Shield Status Indicators
- 🟢 **Green Shield** - Active protection
- 🔴 **Red Shield** - Threat detected
- ⚫ **Gray Shield** - Inactive

### Threat Categories
- **Unicode Exploits** - Zero-width spaces, BiDi overrides, homographs
- **Injection Attacks** - SQL, command, path traversal, prompt injection
- **Authentication** - OAuth 2.0 with secure token management
- **Rate Limiting** - Configurable limits with automatic penalties

## API Documentation

See [API.md](https://github.com/kindlyguard/kindly-guard/blob/main/docs/API.md) for complete API documentation.

## Development

### Building
```bash
cargo build --release
```

### Testing
```bash
cargo test
```

### Benchmarks
```bash
cargo bench
```

## License

Licensed under either of:
- MIT license ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

## Security

For security issues, please email security@kindlyguard.dev instead of using the issue tracker.