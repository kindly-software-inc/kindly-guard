# 🚀 KindlyGuard v0.15.0: Unified Binary & Instant npm Installation

## Major Release Highlights

### 1. **One Binary to Rule Them All**

The new `kindlyguard` binary combines everything:
- MCP Security Server
- CLI Scanner Tools
- Real-time Monitor
- Shield Display
- Configuration Management

No more separate binaries or complex setups!

### 2. **Instant npm Installation**

```bash
npm install -g kindlyguard
```

That's it! No Rust compilation, no waiting. Works immediately on:
- Windows
- macOS (Intel & Apple Silicon)
- Linux (x64 & ARM)

### 3. **MCP Multi-Tool Support**

Single MCP server exposes multiple security tools:
- `scan_text` - Scan text for threats
- `scan_file` - Scan files with quarantine
- `check_url` - Validate URLs
- `neutralize` - Clean threats
- `quarantine_list` - View isolated threats
- `get_statistics` - Real-time metrics

## Quick Start

### For Claude Desktop Users

```bash
# Install
npm install -g kindlyguard

# Configure Claude Desktop
kindlyguard mcp setup

# Done! Restart Claude Desktop
```

### For Developers

```bash
# Install
npm install -g kindlyguard

# Start MCP server
kindlyguard serve

# Scan files
kindlyguard scan file.txt

# Monitor threats
kindlyguard monitor

# Development mode
kindlyguard dev
```

## What Changed?

### Before (v0.14.x and earlier)
- Multiple binaries: `kindly-guard`, `kindly-tools`, `kindly-shield`
- Complex installation requiring Rust
- Separate MCP servers for different features
- Manual configuration required

### Now (v0.15.0+)
- Single binary: `kindlyguard`
- Instant npm installation
- One MCP server with all tools
- Automatic configuration with `mcp setup`

## Migration Guide

### From Previous Versions

1. **Uninstall old binaries:**
   ```bash
   cargo uninstall kindly-guard kindly-tools
   ```

2. **Install new unified binary:**
   ```bash
   npm install -g kindlyguard
   ```

3. **Update configurations:**
   - Replace `kindly-guard` with `kindlyguard` in scripts
   - Update `kindly-tools` commands to `kindlyguard`
   - MCP config now uses `kindlyguard serve` instead of separate binaries

### Command Mapping

| Old Command | New Command |
|------------|-------------|
| `kindly-guard server --stdio` | `kindlyguard serve` |
| `kindly-tools scan file.txt` | `kindlyguard scan file.txt` |
| `kindly-tools monitor` | `kindlyguard monitor` |
| `kindly-tools wrap` | `kindlyguard wrap` |
| `kindly-shield` | `kindlyguard shield` |

## Technical Details

### Binary Architecture

The unified binary uses Rust's powerful module system to combine all functionality while keeping the binary size optimized through:
- Link-time optimization (LTO)
- Dead code elimination
- Conditional compilation for platform-specific features

### npm Package Structure

```
kindlyguard/
├── package.json
├── bin/
│   └── kindlyguard (wrapper script)
├── lib/
│   ├── postinstall.js (platform detection)
│   └── main.js (binary management)
└── npm/
    ├── darwin-x64/
    ├── darwin-arm64/
    ├── linux-x64/
    ├── linux-arm64/
    └── win32-x64/
```

### Platform Support

| Platform | Architecture | Binary Size | Status |
|----------|-------------|-------------|---------|
| macOS | x64 | ~8MB | ✅ Supported |
| macOS | ARM64 | ~8MB | ✅ Supported |
| Linux | x64 | ~10MB | ✅ Supported |
| Linux | ARM64 | ~10MB | ✅ Supported |
| Windows | x64 | ~9MB | ✅ Supported |

## Benefits

1. **Simplicity**: One command for everything
2. **Speed**: Instant installation via npm
3. **Consistency**: Same interface across all platforms
4. **Maintenance**: Single codebase to maintain
5. **Distribution**: Leverages npm's global CDN
6. **Updates**: Simple `npm update -g kindlyguard`

## Future Plans

- [ ] Homebrew formula with bottle support
- [ ] Chocolatey package for Windows
- [ ] Snap package for Linux
- [ ] Docker image with multi-arch support
- [ ] GitHub Action for CI/CD integration

## Support

- **Documentation**: https://docs.kindlyguard.com
- **Issues**: https://github.com/kindly-software-inc/kindly-guard/issues
- **Security**: security@kindlyguard.com

---

**KindlyGuard v0.15.0** - Kind to you, tough on threats. Now simpler than ever!