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
npm install -g @kindlyguard/kindlyguard
```

Or use directly with npx (no installation required):

```bash
npx @kindlyguard/kindlyguard --stdio
```

## Quick Start

### As an MCP Server with Claude Desktop

1. Add to your Claude Desktop configuration:
   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - Windows: `%APPDATA%\Claude\claude_desktop_config.json`
   - Linux: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "kindlyguard": {
      "command": "npx",
      "args": ["@kindlyguard/kindlyguard", "--stdio"],
      "env": {
        "RUST_LOG": "info"
      }
    }
  }
}
```

2. Restart Claude Desktop
3. KindlyGuard will automatically protect your AI interactions

### As an MCP Server with VS Code

Add to your VS Code settings:

```json
{
  "mcp.servers": {
    "kindlyguard": {
      "command": "npx",
      "args": ["@kindlyguard/kindlyguard", "--stdio"],
      "env": {
        "RUST_LOG": "debug"
      }
    }
  }
}
```

### Command Line Interface

```bash
# Start as MCP server (for Claude Desktop integration)
npx @kindlyguard/kindlyguard --stdio

# Scan a file for threats
npx @kindlyguard/kindlyguard scan suspicious.txt

# Scan text directly
npx @kindlyguard/kindlyguard scan "Hello\u202Eworld"

# Get JSON output
npx @kindlyguard/kindlyguard scan --format json data.json

# Check server status
npx @kindlyguard/kindlyguard status

# View help
npx @kindlyguard/kindlyguard --help
```

### Programmatic API

```javascript
const kindlyguard = require('@kindlyguard/kindlyguard');

// Example 1: Start MCP server
const server = kindlyguard.create({ stdio: true });
const mcp = server.start();

// Send MCP messages
mcp.send({
  jsonrpc: "2.0",
  method: "initialize",
  params: { protocolVersion: "0.1.0" },
  id: 1
});

// Handle responses
mcp.onMessage((message) => {
  console.log('Received:', message);
});

// Example 2: Quick threat scanning
const threats = await kindlyguard.scan('Hello\u202Eworld', {
  format: 'json'
});
console.log('Threats found:', threats);

// Example 3: Custom server with events
const customServer = kindlyguard.create({
  stdio: false,
  shield: true,
  onError: (error) => console.error('Server error:', error),
  onExit: (code) => console.log(`Server exited: ${code}`)
});
```

## Configuration

KindlyGuard can be configured using a TOML file. Pass the config path with `--config`:

```bash
npx @kindlyguard/kindlyguard --stdio --config ./my-config.toml
```

Example `kindly-guard.toml`:

```toml
[server]
host = "127.0.0.1"
port = 3000

[security]
unicode_checks = true
injection_checks = true
max_input_size = "10MB"
rate_limit = 100  # requests per minute

[shield]
enabled = true
update_interval = "1s"

[resilience]
enhanced_mode = false  # Enable advanced resilience features
```

## Platform Support

KindlyGuard provides pre-built binaries for:

- Linux x64
- macOS x64 (Intel)
- macOS arm64 (Apple Silicon)
- Windows x64

The correct binary is automatically installed based on your platform.

## Examples

See the `examples/` directory for more usage examples:

- `claude_desktop_config.json` - Claude Desktop configuration
- `vscode_mcp_config.json` - VS Code MCP configuration
- `nodejs_usage.js` - Node.js integration examples

## Troubleshooting

### KindlyGuard not starting

1. Check if the binary is installed:
   ```bash
   npx @kindlyguard/kindlyguard status
   ```

2. Enable debug logging:
   ```bash
   RUST_LOG=debug npx @kindlyguard/kindlyguard --stdio
   ```

3. Verify your configuration file syntax

### Claude Desktop not detecting KindlyGuard

1. Ensure the config file is in the correct location
2. Restart Claude Desktop after configuration changes
3. Check Claude Desktop logs for errors

## Building from Source

If you need to build from source:

```bash
git clone https://github.com/samduchaine/kindly-guard
cd kindly-guard
cargo build --release
```

## Security Features

### Unicode Attack Detection
- Invisible characters (U+200B, U+200C, U+200D)
- Right-to-Left overrides (U+202E)
- Homograph attacks using similar-looking characters
- Zero-width characters and joiners
- Bidirectional text manipulation

### Injection Prevention
- SQL injection patterns
- Command injection (shell commands)
- Code injection (JavaScript, Python)
- Path traversal attempts
- LDAP injection
- XSS patterns

### Protection Mechanisms
- Real-time threat scanning
- Rate limiting and DoS prevention
- Request size limits
- Pattern-based detection
- Context-aware analysis

## Performance

KindlyGuard is built with Rust for maximum performance:
- Near-zero overhead threat detection
- Lock-free statistics collection
- SIMD-optimized pattern matching
- Minimal memory footprint (<10MB)
- Sub-millisecond response times

## License

Apache-2.0

## Links

- [GitHub Repository](https://github.com/samduchaine/kindly-guard)
- [Documentation](https://github.com/samduchaine/kindly-guard#readme)
- [Issues](https://github.com/samduchaine/kindly-guard/issues)
- [NPM Package](https://www.npmjs.com/package/@kindlyguard/kindlyguard)