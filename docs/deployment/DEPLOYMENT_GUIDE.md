# KindlyGuard Deployment Guide

This guide provides comprehensive instructions for deploying KindlyGuard across multiple platforms and distribution channels.

## Table of Contents

- [Binary Releases](#binary-releases)
- [Platform-Specific Instructions](#platform-specific-instructions)
  - [Linux](#linux)
  - [macOS](#macos)
  - [Windows](#windows)
- [Distribution Channels](#distribution-channels)
  - [Crates.io (Rust)](#cratesio-rust)
  - [NPM](#npm)
  - [Docker](#docker)
  - [GitHub Releases](#github-releases)
- [CI/CD with GitHub Actions](#cicd-with-github-actions)
- [Testing Your Installation](#testing-your-installation)

## Binary Releases

KindlyGuard provides pre-built binaries for the following platforms:

- **Linux x64**: `kindlyguard-linux-x64.tar.gz`
- **macOS x64**: `kindlyguard-darwin-x64.tar.gz`
- **macOS ARM64**: `kindlyguard-darwin-arm64.tar.gz`

Each release contains:
- `kindlyguard` - The main MCP server binary
- `kindlyguard-cli` - Command-line interface for scanning and configuration

## Platform-Specific Instructions

### Linux

#### Installation from Binary

```bash
# Download the latest release
wget https://github.com/yourusername/kindly-guard/releases/latest/download/kindlyguard-linux-x64.tar.gz

# Extract the archive
tar -xzf kindlyguard-linux-x64.tar.gz

# Move binaries to PATH
sudo mv kindlyguard-linux-x64/kindlyguard /usr/local/bin/
sudo mv kindlyguard-linux-x64/kindlyguard-cli /usr/local/bin/

# Make executable
sudo chmod +x /usr/local/bin/kindlyguard
sudo chmod +x /usr/local/bin/kindlyguard-cli
```

#### Running the Server

```bash
# Run as MCP server (stdio mode)
kindlyguard --stdio

# Run with custom config
kindlyguard --config /path/to/config.toml

# Run with debug logging
RUST_LOG=kindly_guard=debug kindlyguard --stdio
```

#### Using the CLI

```bash
# Scan a file for threats
kindlyguard-cli scan suspicious_file.json

# Start server with monitoring
kindlyguard-cli server --monitor

# Generate configuration
kindlyguard-cli config generate > config.toml
```

### macOS

#### Installation from Binary

```bash
# For Intel Macs (x64)
curl -L https://github.com/yourusername/kindly-guard/releases/latest/download/kindlyguard-darwin-x64.tar.gz -o kindlyguard.tar.gz

# For Apple Silicon (M1/M2/M3)
curl -L https://github.com/yourusername/kindly-guard/releases/latest/download/kindlyguard-darwin-arm64.tar.gz -o kindlyguard.tar.gz

# Extract and install
tar -xzf kindlyguard.tar.gz
sudo mv kindlyguard-*/kindlyguard /usr/local/bin/
sudo mv kindlyguard-*/kindlyguard-cli /usr/local/bin/

# Remove quarantine attribute (macOS Gatekeeper)
xattr -d com.apple.quarantine /usr/local/bin/kindlyguard
xattr -d com.apple.quarantine /usr/local/bin/kindlyguard-cli
```

#### macOS-Specific Configuration

Add to your MCP configuration (`~/.mcp.json`):

```json
{
  "mcpServers": {
    "kindlyguard": {
      "command": "/usr/local/bin/kindlyguard",
      "args": ["--stdio"],
      "env": {
        "RUST_LOG": "kindly_guard=info"
      }
    }
  }
}
```

### Windows

Windows support is planned for future releases. For now, Windows users can:
1. Use WSL2 with the Linux binaries
2. Build from source using Rust toolchain
3. Use the Docker container

## Distribution Channels

### Crates.io (Rust)

For Rust developers who want to build from source or integrate as a library:

#### Publishing to Crates.io

```bash
# Update version in Cargo.toml files
cd kindly-guard
vim kindly-guard-server/Cargo.toml  # Update version
vim kindly-guard-cli/Cargo.toml     # Update version

# Run tests
cargo test --all

# Dry run
cargo publish --dry-run -p kindly-guard-server
cargo publish --dry-run -p kindly-guard-cli

# Publish
cargo publish -p kindly-guard-server
cargo publish -p kindly-guard-cli
```

#### Installation from Crates.io

```bash
# Install the CLI tool globally
cargo install kindlyguard-cli

# Install the server
cargo install kindlyguard-server

# Or add as dependency
# In Cargo.toml:
# [dependencies]
# kindly-guard-server = "0.9.4"
```

### NPM

For JavaScript/TypeScript developers using KindlyGuard as an MCP server:

#### Publishing to NPM

1. Create `package.json` in the project root:

```json
{
  "name": "@kindlyguard/mcp-server",
  "version": "0.9.4",
  "description": "Security-focused MCP server for threat detection",
  "bin": {
    "kindlyguard": "./dist/kindlyguard",
    "kindlyguard-cli": "./dist/kindlyguard-cli"
  },
  "scripts": {
    "postinstall": "node scripts/postinstall.js"
  },
  "files": [
    "dist/",
    "scripts/",
    "README.md"
  ],
  "keywords": ["mcp", "security", "unicode", "injection", "xss"],
  "license": "MIT",
  "repository": {
    "type": "git",
    "url": "https://github.com/yourusername/kindly-guard.git"
  }
}
```

2. Create `scripts/postinstall.js`:

```javascript
#!/usr/bin/env node
const { platform, arch } = process;
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const BINARY_MAP = {
  'darwin-x64': 'kindlyguard-darwin-x64',
  'darwin-arm64': 'kindlyguard-darwin-arm64',
  'linux-x64': 'kindlyguard-linux-x64',
};

const platformKey = `${platform}-${arch}`;
const binaryName = BINARY_MAP[platformKey];

if (!binaryName) {
  console.error(`Unsupported platform: ${platformKey}`);
  process.exit(1);
}

// Download and extract appropriate binary
const downloadUrl = `https://github.com/yourusername/kindly-guard/releases/latest/download/${binaryName}.tar.gz`;
console.log(`Downloading KindlyGuard for ${platformKey}...`);

try {
  execSync(`curl -L ${downloadUrl} | tar -xz -C ./dist/`, { stdio: 'inherit' });
  
  // Make binaries executable
  fs.chmodSync(path.join(__dirname, '../dist/kindlyguard'), 0o755);
  fs.chmodSync(path.join(__dirname, '../dist/kindlyguard-cli'), 0o755);
  
  console.log('KindlyGuard installed successfully!');
} catch (error) {
  console.error('Failed to install KindlyGuard:', error.message);
  process.exit(1);
}
```

3. Publish to NPM:

```bash
npm login
npm publish --access public
```

#### Installation from NPM

```bash
# Global installation
npm install -g @kindlyguard/mcp-server

# Project dependency
npm install --save-dev @kindlyguard/mcp-server

# Use in package.json scripts
{
  "scripts": {
    "security-check": "kindlyguard-cli scan src/"
  }
}
```

### Docker

#### Creating the Docker Image

1. Create `Dockerfile`:

```dockerfile
# Build stage
FROM rust:1.75-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build
COPY . .

# Build the binaries
RUN cargo build --release --target x86_64-unknown-linux-musl

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates

# Copy binaries from builder
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/kindlyguard /usr/local/bin/
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/kindlyguard-cli /usr/local/bin/

# Create non-root user
RUN adduser -D -s /bin/sh kindlyguard
USER kindlyguard

# Default config directory
RUN mkdir -p /home/kindlyguard/.config/kindlyguard
VOLUME ["/home/kindlyguard/.config/kindlyguard"]

# MCP server runs on stdio by default
ENTRYPOINT ["/usr/local/bin/kindlyguard"]
CMD ["--stdio"]
```

2. Build and publish:

```bash
# Build the image
docker build -t kindlyguard/mcp-server:latest .
docker build -t kindlyguard/mcp-server:0.9.4 .

# Test the image
docker run --rm kindlyguard/mcp-server:latest --version

# Push to Docker Hub
docker push kindlyguard/mcp-server:latest
docker push kindlyguard/mcp-server:0.9.4
```

#### Using the Docker Image

```bash
# Run as MCP server
docker run --rm -i kindlyguard/mcp-server:latest --stdio

# Run with custom config
docker run --rm -i \
  -v $(pwd)/config.toml:/home/kindlyguard/.config/kindlyguard/config.toml \
  kindlyguard/mcp-server:latest --config /home/kindlyguard/.config/kindlyguard/config.toml

# Use CLI for scanning
docker run --rm -v $(pwd):/scan kindlyguard/mcp-server:latest \
  kindlyguard-cli scan /scan/suspicious.json
```

#### Docker Compose Example

```yaml
version: '3.8'

services:
  kindlyguard:
    image: kindlyguard/mcp-server:latest
    stdin_open: true
    tty: true
    volumes:
      - ./config:/home/kindlyguard/.config/kindlyguard
    environment:
      - RUST_LOG=kindly_guard=info
    command: ["--stdio"]
```

### GitHub Releases

#### Automated Release Workflow

Create `.github/workflows/release.yml`:

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

permissions:
  contents: write

jobs:
  build-linux:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
        with:
          targets: x86_64-unknown-linux-gnu
      
      - name: Build
        run: |
          cd kindly-guard-server
          cargo build --release --target x86_64-unknown-linux-gnu
          cd ../kindly-guard-cli
          cargo build --release --target x86_64-unknown-linux-gnu
      
      - name: Package
        run: |
          mkdir -p dist/kindlyguard-linux-x64
          cp target/x86_64-unknown-linux-gnu/release/kindlyguard dist/kindlyguard-linux-x64/
          cp target/x86_64-unknown-linux-gnu/release/kindlyguard-cli dist/kindlyguard-linux-x64/
          cd dist
          tar czf kindlyguard-linux-x64.tar.gz kindlyguard-linux-x64/
      
      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: kindlyguard-linux-x64
          path: dist/kindlyguard-linux-x64.tar.gz

  build-macos:
    runs-on: macos-latest
    strategy:
      matrix:
        target: [x86_64-apple-darwin, aarch64-apple-darwin]
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}
      
      - name: Build
        run: |
          cd kindly-guard-server
          cargo build --release --target ${{ matrix.target }}
          cd ../kindly-guard-cli
          cargo build --release --target ${{ matrix.target }}
      
      - name: Package
        run: |
          mkdir -p dist/kindlyguard-${{ matrix.target }}
          cp target/${{ matrix.target }}/release/kindlyguard dist/kindlyguard-${{ matrix.target }}/
          cp target/${{ matrix.target }}/release/kindlyguard-cli dist/kindlyguard-${{ matrix.target }}/
          cd dist
          tar czf kindlyguard-${{ matrix.target }}.tar.gz kindlyguard-${{ matrix.target }}/
      
      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: kindlyguard-${{ matrix.target }}
          path: dist/kindlyguard-${{ matrix.target }}.tar.gz

  create-release:
    needs: [build-linux, build-macos]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Download artifacts
        uses: actions/download-artifact@v4
        with:
          path: artifacts
      
      - name: Create Release
        uses: softprops/action-gh-release@v1
        with:
          files: artifacts/**/*.tar.gz
          draft: false
          prerelease: false
          generate_release_notes: true
          body: |
            ## Installation
            
            ### Quick Install (Linux/macOS)
            ```bash
            curl -sSL https://raw.githubusercontent.com/yourusername/kindly-guard/main/install.sh | sh
            ```
            
            ### Manual Installation
            Download the appropriate binary for your platform and follow the [installation guide](https://github.com/yourusername/kindly-guard/blob/main/DEPLOYMENT_GUIDE.md).
            
            ## What's Changed
            See the full changelog below.

  publish-crates:
    needs: create-release
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
      
      - name: Publish to crates.io
        env:
          CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}
        run: |
          cd kindly-guard-server
          cargo publish --no-verify
          cd ../kindly-guard-cli
          cargo publish --no-verify

  publish-npm:
    needs: create-release
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          registry-url: 'https://registry.npmjs.org'
      
      - name: Prepare NPM package
        run: |
          # Copy package.json and scripts
          cp npm/package.json .
          cp -r npm/scripts .
      
      - name: Publish to NPM
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
        run: npm publish --access public

  publish-docker:
    needs: create-release
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3
      
      - name: Login to Docker Hub
        uses: docker/login-action@v3
        with:
          username: ${{ secrets.DOCKERHUB_USERNAME }}
          password: ${{ secrets.DOCKERHUB_TOKEN }}
      
      - name: Extract version
        id: version
        run: echo "VERSION=${GITHUB_REF#refs/tags/v}" >> $GITHUB_OUTPUT
      
      - name: Build and push
        uses: docker/build-push-action@v5
        with:
          context: .
          platforms: linux/amd64,linux/arm64
          push: true
          tags: |
            kindlyguard/mcp-server:latest
            kindlyguard/mcp-server:${{ steps.version.outputs.VERSION }}
```

## CI/CD with GitHub Actions

### Continuous Integration Workflow

Create `.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

env:
  CARGO_TERM_COLOR: always

jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest]
        rust: [stable, beta]
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Rust
        uses: dtolnay/rust-toolchain@master
        with:
          toolchain: ${{ matrix.rust }}
          components: rustfmt, clippy
      
      - name: Cache dependencies
        uses: Swatinem/rust-cache@v2
      
      - name: Check formatting
        run: cargo fmt --all -- --check
      
      - name: Clippy
        run: cargo clippy --all-targets --all-features -- -D warnings
      
      - name: Test
        run: cargo test --all --verbose
      
      - name: Security Audit
        run: |
          cargo install cargo-audit
          cargo audit

  coverage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install Rust
        uses: dtolnay/rust-toolchain@stable
      
      - name: Install tarpaulin
        run: cargo install cargo-tarpaulin
      
      - name: Generate coverage
        run: cargo tarpaulin --out Xml
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

## Testing Your Installation

### Basic Functionality Test

```bash
# Check version
kindlyguard --version
kindlyguard-cli --version

# Test threat detection
echo '{"text": "Hello\u202EWorld"}' | kindlyguard-cli scan -

# Run server test
kindlyguard --stdio <<EOF
{"jsonrpc": "2.0", "method": "initialize", "params": {"capabilities": {}}, "id": 1}
EOF
```

### MCP Integration Test

1. Add to your MCP configuration:

```json
{
  "mcpServers": {
    "kindlyguard": {
      "command": "kindlyguard",
      "args": ["--stdio"],
      "env": {
        "RUST_LOG": "info"
      }
    }
  }
}
```

2. Test with Claude:
   - Open Claude with the configuration
   - The KindlyGuard tools should appear in the tools list
   - Try scanning some text for threats

### Performance Test

```bash
# Generate test data
for i in {1..1000}; do
  echo "{\"text\": \"Test $i with potential SQL injection: ' OR 1=1\"}" >> test_data.jsonl
done

# Run performance test
time kindlyguard-cli scan test_data.jsonl
```

## Troubleshooting

### Common Issues

1. **Binary not found**: Ensure the binary is in your PATH or use absolute paths
2. **Permission denied**: Make sure binaries are executable (`chmod +x`)
3. **macOS Gatekeeper**: Use `xattr -d com.apple.quarantine` on the binaries
4. **Missing dependencies**: Install system dependencies if needed

### Debug Mode

Enable detailed logging:

```bash
RUST_LOG=kindly_guard=debug,kindly_guard_server=trace kindlyguard --stdio
```

### Support

- GitHub Issues: https://github.com/yourusername/kindly-guard/issues
- Documentation: https://github.com/yourusername/kindly-guard/wiki
- Discord: https://discord.gg/kindlyguard

## Security Considerations

1. Always verify checksums of downloaded binaries
2. Run with minimal privileges required
3. Use configuration files with restricted permissions
4. Enable audit logging in production
5. Regular security updates via automated workflows

## Next Steps

1. Set up automated releases with GitHub Actions
2. Configure your MCP client to use KindlyGuard
3. Customize threat detection rules
4. Monitor security events through the dashboard
5. Contribute improvements back to the project