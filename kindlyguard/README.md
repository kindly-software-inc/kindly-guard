# KindlyGuard - Unified Security Tool

**Preview Release v0.11.16**

This is the unified `kindlyguard` binary that combines the MCP server and CLI tools into a single executable.

## Features

- **Server Mode**: Run as an MCP security server
- **CLI Tools**: Direct command-line security utilities
- **Smart Installer**: Sophisticated OS detection and error recovery
- **Self-Update**: Built-in update functionality

## Installation

```bash
cargo install kindlyguard
```

## Usage

### Server Commands
```bash
# Run MCP server (stdio mode)
kindlyguard serve --stdio

# Run HTTP API server
kindlyguard serve --http --bind 127.0.0.1:8080

# Run with shield display
kindlyguard serve --shield
```

### Tool Commands
```bash
# Scan files for threats
kindlyguard scan file.txt
kindlyguard scan ./src --recursive

# Wrap command execution
kindlyguard wrap -- npm install suspicious-package

# Monitor server
kindlyguard monitor --server http://localhost:8080

# Display security shield
kindlyguard shield
```

### Management Commands
```bash
# Install components
kindlyguard install --detect
kindlyguard install shield
kindlyguard install --all

# Update
kindlyguard update --check
kindlyguard update

# Diagnostics
kindlyguard doctor
kindlyguard doctor --detailed --fix
```

## Architecture

This unified binary includes:

1. **Server Module** - Full MCP server functionality from kindly-guard-server
2. **Tools Module** - CLI tools (scan, wrap, monitor, shield)
3. **Installer Module** - Sophisticated installation with OS detection
4. **Shared Module** - Common utilities

## Benefits

- Single binary installation
- Consistent command interface
- Shared configuration
- Reduced disk usage
- Simplified updates

## Migration from Separate Binaries

If you have the old separate binaries installed:

1. Uninstall old versions:
   ```bash
   cargo uninstall kindly-guard
   cargo uninstall kindly-tools
   ```

2. Install unified version:
   ```bash
   cargo install kindlyguard
   ```

3. Update any scripts to use new commands:
   - `kindly-guard --stdio` → `kindlyguard serve --stdio`
   - `kindly-tools scan` → `kindlyguard scan`

## Status

This is a preview release. Some features are still being implemented:
- Command wrapping
- Real-time monitoring
- Shield display
- Self-update installation

## License

Apache-2.0