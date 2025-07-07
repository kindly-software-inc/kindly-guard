# KindlyGuard v0.9.2 Release

## Available Binaries

### Linux x64 (x86_64-unknown-linux-gnu) ✅

Located in `linux-x64/` directory:

- **kindly-guard** (8.1MB) - Main MCP server executable
  - SHA256: `4313afa3f8d9a19b5f1b49cf7c5e3bad5316b136d4e2d99143a7adeee791c242`
- **kindly-guard-cli** (5.5MB) - Command-line interface
  - SHA256: `faa113c5dd026a2515792197b2045d9082c1d00cf9130e39bfeee3f4ccd545ec`

### Installation

#### Linux
```bash
# Navigate to the linux-x64 directory
cd linux-x64/

# Make binaries executable (if needed)
chmod +x kindly-guard kindly-guard-cli

# Copy to system path (optional)
sudo cp kindly-guard /usr/local/bin/
sudo cp kindly-guard-cli /usr/local/bin/

# Or run directly
./kindly-guard --stdio
./kindly-guard-cli --help
```

## Usage Examples

### Running the MCP Server
```bash
# Start the MCP server in stdio mode
kindly-guard --stdio

# Or with custom config
kindly-guard --config /path/to/config.toml
```

### Using the CLI
```bash
# Scan a file for security threats
kindly-guard-cli scan suspicious_file.json

# Monitor real-time threats
kindly-guard-cli monitor

# Show version
kindly-guard-cli --version
```

## Build Information

- **Build Date**: January 20, 2025
- **Rust Version**: Latest stable
- **Target**: x86_64-unknown-linux-gnu
- **Build Type**: Release (optimized)
- **Features**: Standard features enabled

## System Requirements

### Linux
- x86_64 architecture
- glibc 2.17 or newer
- Linux kernel 3.2.0 or newer

## Missing Platforms

The following platforms require additional setup for cross-compilation:

- **Windows x64**: Requires mingw-w64 toolchain
- **macOS x64/ARM64**: Requires macOS build environment or osxcross

See `RELEASE_NOTES.md` for build instructions for other platforms.

## Verification

Run the included verification script:
```bash
./verify_binaries.sh
```

## Support

For issues or questions, please refer to the main project documentation.