# KindlyGuard

Security-focused MCP (Model Context Protocol) server that protects AI systems against unicode attacks, injection threats, and other vulnerabilities.

## Features

- **Unicode Attack Detection**: Identifies hidden characters, BiDi overrides, and homograph attacks
- **Injection Protection**: Detects SQL, command, and code injection attempts
- **Real-time Monitoring**: Live threat detection and statistics
- **MCP Integration**: Works seamlessly with Claude Desktop and other MCP clients
- **Cross-platform**: Supports Linux, macOS (Intel & Apple Silicon), and Windows

## Installation

```bash
npm install -g kindlyguard
```

Or use directly with npx:

```bash
npx kindlyguard --help
```

## Usage

### As an MCP Server

Add to your Claude Desktop configuration (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "kindly-guard": {
      "command": "npx",
      "args": ["kindlyguard", "--stdio"],
      "env": {
        "RUST_LOG": "info"
      }
    }
  }
}
```

### Command Line Interface

```bash
# Scan a file for threats
kindlyguard-cli scan suspicious.txt

# Monitor server status
kindlyguard-cli monitor

# Check security status
kindlyguard status
```

### Programmatic API

```javascript
const kindlyguard = require('kindlyguard');

// Start MCP server
const server = kindlyguard.startServer({
  stdio: true,
  logLevel: 'debug'
});

// Scan text for threats
const threats = await kindlyguard.scan('Hello\u202Eworld', {
  format: 'json'
});
```

## Configuration

Create a `kindly-guard.toml` file:

```toml
[server]
host = "127.0.0.1"
port = 3000

[security]
unicode_checks = true
injection_checks = true
max_input_size = "10MB"

[shield]
enabled = true
update_interval = "1s"
```

## Platform Support

KindlyGuard provides pre-built binaries for:

- Linux x64
- macOS x64 (Intel)
- macOS arm64 (Apple Silicon)
- Windows x64

The correct binary is automatically installed based on your platform.

## Building from Source

If you need to build from source:

```bash
git clone https://github.com/samduchaine/kindly-guard
cd kindly-guard
cargo build --release
```

## Security Features

### Unicode Attack Detection
- Invisible characters
- Right-to-Left overrides
- Homograph attacks
- Zero-width characters

### Injection Prevention
- SQL injection patterns
- Command injection
- Code injection
- Path traversal

### Rate Limiting
- Request throttling
- Resource protection
- DoS prevention

## Performance

KindlyGuard is built with Rust for maximum performance:
- Near-zero overhead
- Lock-free statistics
- Efficient pattern matching
- Minimal memory usage

## License

MIT

## Links

- [GitHub Repository](https://github.com/samduchaine/kindly-guard)
- [Documentation](https://github.com/samduchaine/kindly-guard#readme)
- [Issues](https://github.com/samduchaine/kindly-guard/issues)
- [NPM Package](https://www.npmjs.com/package/kindlyguard)